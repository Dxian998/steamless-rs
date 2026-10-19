use std::path::PathBuf;

use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind};

use crate::options::Options;
use crate::pattern;
use crate::pe::{PeFile, SaveParameters};
use crate::{Error, Result};

pub const DRM_FLAG_NO_ENCRYPTION: u32 = 0x04;

pub(crate) fn read_range(pe: &PeFile, file_offset: u64, size: usize) -> Result<Vec<u8>> {
    let start = file_offset as usize;
    let end = start.checked_add(size).ok_or(Error::OutOfBounds)?;
    Ok(pe.data.get(start..end).ok_or(Error::OutOfBounds)?.to_vec())
}

pub(crate) fn find_pattern_in_section(pe: &PeFile, section: &str, pat: &str) -> Result<usize> {
    let data = pe
        .get_section_data_by_name(section)
        .ok_or_else(|| Error::Unpack(format!(".{section} section missing")))?;
    pattern::find_pattern(data, pat)
}

pub(crate) fn remove_bind_section(pe: &mut PeFile, options: &Options) -> Result<bool> {
    if options.keep_bind_section {
        return Ok(false);
    }

    let (bind_rva, bind_size, index) = {
        let bind = pe
            .get_section(".bind")
            .ok_or_else(|| Error::Unpack(".bind section not found".into()))?;
        if !bind.is_valid() {
            return Err(Error::Unpack(".bind section is invalid".into()));
        }
        let index = pe
            .section_index_of(bind)
            .ok_or_else(|| Error::Unpack(".bind section not found".into()))?;
        (bind.virtual_address, bind.virtual_size, index)
    };

    pe.removed_bind_rva = Some(bind_rva);
    pe.removed_bind_size = Some(bind_size);

    pe.remove_section(index);
    pe.file_header.number_of_sections = pe.file_header.number_of_sections.saturating_sub(1);
    Ok(true)
}

pub(crate) fn maybe_dump_drmp(pe: &PeFile, options: &Options, data: &[u8]) {
    if !options.dump_steam_drmp_to_disk {
        return;
    }
    let dir = pe
        .path
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    let target = dir.join("SteamDRMP.dll");
    let _ = std::fs::write(target, data);
}

pub(crate) fn maybe_dump_payload(pe: &PeFile, options: &Options, data: &[u8]) {
    if !options.dump_payload_to_disk {
        return;
    }
    let mut target = pe.path.as_os_str().to_owned();
    target.push(".payload");
    let _ = std::fs::write(PathBuf::from(target), data);
}

pub(crate) fn save(pe: &mut PeFile, options: &Options, entry_point: u32) -> Result<PathBuf> {
    save_full(pe, options, entry_point, None)
}

pub(crate) fn save_full(pe: &mut PeFile, options: &Options, entry_point: u32, code_section: Option<(usize, &[u8])>) -> Result<PathBuf> {
    pe.rebuild_sections(options.realign_sections);

    let target = PathBuf::from(format!("{}.unpacked.exe", pe.path.display()));

    let dos_stub = if options.zero_dos_stub_data && pe.dos_stub_size > 0 {
        Some(vec![0u8; pe.dos_stub_size])
    } else {
        None
    };

    let params = SaveParameters {
        dos_stub: dos_stub.as_deref(),
        address_of_entry_point: entry_point,
        checksum: 0,
        code_section,
    };
    pe.save_unpacked(&target, &params)?;

    if options.recalculate_file_checksum {
        crate::pe::update_checksum(&target)?;
    }

    Ok(target)
}

pub(crate) fn decode_block(data: &[u8], start: usize, max_len: usize, ip: u64) -> Vec<Instruction> {
    let end = start.saturating_add(max_len).min(data.len());
    if start >= end {
        return Vec::new();
    }

    let mut decoder = Decoder::with_ip(32, &data[start..end], ip, DecoderOptions::NONE);
    let mut out = Vec::new();
    let mut insn = Instruction::default();
    while decoder.can_decode() {
        decoder.decode_out(&mut insn);
        out.push(insn);
    }
    out
}

pub(crate) fn op1_immediate(instr: &Instruction) -> Option<u64> {
    (instr.op_count() > 1 && matches_op_imm(instr.op_kind(1))).then(|| instr.immediate(1))
}

fn matches_op_imm(kind: OpKind) -> bool {
    matches!(
        kind,
        OpKind::Immediate8
            | OpKind::Immediate8_2nd
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate64
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate32to64
    )
}

pub(crate) fn is_mov_reg_imm(instr: &Instruction) -> Option<u64> {
    if instr.mnemonic() != Mnemonic::Mov || instr.op_kind(0) != OpKind::Register {
        return None;
    }
    op1_immediate(instr)
}

pub(crate) fn is_mov_mem_imm(instr: &Instruction) -> Option<u64> {
    if instr.mnemonic() != Mnemonic::Mov || instr.op_kind(0) != OpKind::Memory {
        return None;
    }
    op1_immediate(instr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_mov_instructions() {
        // 60 81 EC 00 10 00 00 BE 78 56 34 12 B9 6A 00 00 00
        // pushad; sub esp,0x1000; mov esi,0x12345678; mov ecx,0x6a
        let code = [
            0x60u8, 0x81, 0xec, 0x00, 0x10, 0x00, 0x00, 0xbe, 0x78, 0x56, 0x34, 0x12, 0xb9, 0x6a,
            0x00, 0x00, 0x00,
        ];
        let insns = decode_block(&code, 0, code.len(), 0x1000);
        assert_eq!(insns.len(), 4);

        assert_eq!(is_mov_reg_imm(&insns[2]), Some(0x1234_5678));
        assert_eq!(is_mov_reg_imm(&insns[3]), Some(0x6a));
        assert_eq!(is_mov_mem_imm(&insns[0]), None);
    }
}
