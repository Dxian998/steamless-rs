use iced_x86::{Mnemonic, OpKind};
use crate::crypto::aes::{AesHelper, AesMode};
use crate::crypto::xtea::{steam_drmp_pass1, steam_xor};
use crate::logger::{Level, Logger};
use crate::options::Options;
use crate::pe::{Buf, PeFile};
use crate::variants::common::{self, is_mov_mem_imm, is_mov_reg_imm, op1_immediate};
use crate::{Error, Result};

pub struct Variant21;

const BIND_PATTERN: &str = "53 51 52 56 57 55 8B EC 81 EC 00 10 00 00 C7";
const SCAN_LENGTH: usize = 4096;
const OFFSET_BLOCK_SIZE: usize = 1024;
const DRMP_PATTERNS: [&str; 3] = [
    "8B ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 05",
    "8B ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 8B",
    "8B ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? A3 ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? A3 ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? A3 ?? ?? ?? ?? 8B",
];

struct Header {
    payload_va: u32,
    payload_size: u32,
    drmp_va_off: usize,
    drmp_size_off: usize,
    xtea_keys_off: usize,
}

impl crate::variants::Unpacker for Variant21 {
    fn name(&self) -> &'static str {
        "SteamStub Variant 2.1 Unpacker (x86)"
    }

    fn can_process(&self, pe: &PeFile) -> bool {
        if pe.is_file_64() || !pe.has_section(".bind") {
            return false;
        }
        common::find_pattern_in_section(pe, ".bind", BIND_PATTERN).is_ok()
    }

    fn process(&self, pe: &mut PeFile, options: &Options, logger: &dyn Logger) -> Result<()> {
        logger.log(Level::Info, "File is packed with SteamStub Variant 2.1!");

        logger.log(
            Level::Info,
            "Step 1 - Read, disassemble and decode the SteamStub DRM header.",
        );
        let (header, xor_key) = self.step1(pe)?;

        logger.log(
            Level::Info,
            "Step 2 - Read, decode and process the payload data.",
        );
        let payload = self.step2(pe, options, &header, xor_key, logger)?;

        logger.log(
            Level::Info,
            "Step 3 - Read, decode and dump the SteamDRMP.dll file.",
        );
        let steam_drmp = self.step3(pe, options, &header, &payload, logger)?;

        logger.log(
            Level::Info,
            "Step 4 - Scan, dump and pull needed offsets from within the SteamDRMP.dll file.",
        );
        let offsets = self.step4(&steam_drmp, &payload, logger)?;

        logger.log(
            Level::Info,
            "Step 5 - Read, decrypt and process the main code section.",
        );
        self.step5(pe, options, &payload, &offsets, logger)?;

        logger.log(Level::Info, "Step 6 - Rebuild and save the unpacked file.");
        let entry_point =
            pe.get_rva_from_va(payload_u32(&payload, offsets[2] as u32) as u64) as u32;
        let target = common::save(pe, options, entry_point)?;

        logger.log(Level::Success, " --> Unpacked file saved to disk!");
        logger.log(
            Level::Success,
            &format!(" --> File Saved As: {}", target.display()),
        );
        Ok(())
    }
}

impl Variant21 {
    fn step1(&self, pe: &PeFile) -> Result<(Header, u32)> {
        let file_offset = pe.get_file_offset_from_rva(pe.optional.address_of_entry_point as u64);

        let sig_off = file_offset.checked_sub(4).ok_or_else(|| Error::Unpack("entry point is too small".into()))?;
        let signature = pe.data.rd_u32(sig_off as usize).ok_or(Error::OutOfBounds)?;
        if signature != 0xC0DEC0DE {
            return Err(Error::Unpack("missing 0xC0DEC0DE signature".into()));
        }

        let (struct_offset, struct_size, struct_xor_key) = self.disassemble_file(pe)?;

        let struct_file_offset = pe.get_file_offset_from_rva(struct_offset);
        let mut header_data = common::read_range(pe, struct_file_offset, struct_size as usize)?;

        let size = header_data.len() as u32;
        let xor_key = steam_xor(&mut header_data, size, struct_xor_key);

        let header = if (struct_size / 4) == 0xD0 {
            Header {
                payload_va: header_data.rd_u32(32).ok_or(Error::OutOfBounds)?,
                payload_size: header_data.rd_u32(36).ok_or(Error::OutOfBounds)?,
                drmp_va_off: header_data.rd_u32(56).ok_or(Error::OutOfBounds)? as usize,
                drmp_size_off: header_data.rd_u32(60).ok_or(Error::OutOfBounds)? as usize,
                xtea_keys_off: header_data.rd_u32(64).ok_or(Error::OutOfBounds)? as usize,
            }
        } else {
            Header {
                payload_va: header_data.rd_u32(36).ok_or(Error::OutOfBounds)?,
                payload_size: header_data.rd_u32(40).ok_or(Error::OutOfBounds)?,
                drmp_va_off: header_data.rd_u32(60).ok_or(Error::OutOfBounds)? as usize,
                drmp_size_off: header_data.rd_u32(64).ok_or(Error::OutOfBounds)? as usize,
                xtea_keys_off: header_data.rd_u32(68).ok_or(Error::OutOfBounds)? as usize,
            }
        };

        Ok((header, xor_key))
    }

    fn disassemble_file(&self, pe: &PeFile) -> Result<(u64, u32, u32)> {
        let entry_offset = pe.get_file_offset_from_rva(pe.optional.address_of_entry_point as u64);

        let mut struct_offset = 0u64;
        let mut struct_size = 0u32;
        let mut struct_xor_key = 0u32;

        let image_base = pe.optional.image_base;

        for insn in common::decode_block(&pe.data, entry_offset as usize, SCAN_LENGTH, entry_offset)
        {
            if struct_offset > 0 && struct_size > 0 && struct_xor_key > 0 {
                return Ok((struct_offset, struct_size, struct_xor_key));
            }

            if let Some(imm) = is_mov_mem_imm(&insn) {
                if struct_offset == 0 {
                    struct_offset = imm - image_base;
                } else {
                    struct_xor_key = imm as u32;
                }
            }

            if let Some(imm) = is_mov_reg_imm(&insn) {
                struct_size = (imm * 4) as u32;
            }
        }

        Err(Error::Unpack(
            "failed to locate the DRM header information".into(),
        ))
    }

    fn step2(&self, pe: &PeFile, options: &Options, header: &Header, xor_key: u32, logger: &dyn Logger) -> Result<Vec<u8>> {

        let payload_rva = pe.get_rva_from_va(header.payload_va as u64);
        let payload_addr = pe.get_file_offset_from_rva(payload_rva);
        let mut payload = common::read_range(pe, payload_addr, header.payload_size as usize)?;

        let _ = steam_xor(&mut payload, header.payload_size, xor_key);

        if options.dump_payload_to_disk {
            common::maybe_dump_payload(pe, options, &payload);
            logger.log(Level::Debug, " --> Saved payload to disk!");
        }

        Ok(payload)
    }

    fn step3(&self, pe: &PeFile, options: &Options, header: &Header, payload: &[u8], logger: &dyn Logger,) -> Result<Vec<u8>> {
        logger.log(Level::Debug, " --> File has SteamDRMP.dll file!");

        let drmp_va = payload_u32(payload, header.drmp_va_off as u32);
        let drmp_size = payload_u32(payload, header.drmp_size_off as u32);
        let drmp_rva = pe.get_rva_from_va(drmp_va as u64);
        let drmp_addr = pe.get_file_offset_from_rva(drmp_rva);
        let mut drmp_data = common::read_range(pe, drmp_addr, drmp_size as usize)?;

        let key_count = (payload.len().saturating_sub(header.xtea_keys_off)) / 4;
        let mut keys = Vec::with_capacity(key_count);
        for x in 0..key_count {
            let off = header.xtea_keys_off + x * 4;
            keys.push(payload_u32(payload, off as u32));
        }

        steam_drmp_pass1(&mut drmp_data, drmp_size, &keys);
        let data = drmp_data.clone();

        if options.dump_steam_drmp_to_disk {
            common::maybe_dump_drmp(pe, options, &data);
            logger.log(Level::Debug, " --> Saved SteamDRMP.dll to disk!");
        }

        Ok(data)
    }

    fn step4(&self, steam_drmp: &[u8], payload: &[u8], logger: &dyn Logger) -> Result<Vec<i32>> {
        for pat in DRMP_PATTERNS {
            let drmp_offset = match crate::pattern::find_pattern(steam_drmp, pat) {
                Ok(off) => off,
                Err(_) => continue,
            };

            let block_end = (drmp_offset + OFFSET_BLOCK_SIZE).min(steam_drmp.len());
            if block_end.saturating_sub(drmp_offset) < 76 {
                continue;
            }
            let block = &steam_drmp[drmp_offset..block_end];

            for use_fallback in [false, true] {
                if let Some(offsets) = get_drmp_offsets(block, use_fallback) {
                    if validate_steam_drmp_offsets(&offsets, payload) {
                        return Ok(offsets);
                    }
                }
            }

            let dyn_offsets = get_drmp_offsets_dynamic(block);
            if validate_steam_drmp_offsets(&dyn_offsets, payload) {
                logger.log(Level::Debug, " --> Using dynamic offset extraction.");
                return Ok(dyn_offsets);
            }

            logger.log(
                Level::Debug,
                " --> Scanning for correct offset layout in DRMP data block...",
            );
            if let Some(found) = scan_steam_drmp_offsets(steam_drmp, drmp_offset, payload, logger) {
                logger.log(Level::Debug, " --> Found valid offsets via scan.");
                return Ok(found);
            }

            logger.log(
                Level::Debug,
                " --> Pattern matched but could not find valid offsets, trying next pattern.",
            );
        }

        Err(Error::Unpack(
            "failed to extract the SteamDRMP.dll offsets".into(),
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn step5(&self, pe: &mut PeFile, options: &Options, payload: &[u8], offsets: &[i32], logger: &dyn Logger,) -> Result<()> {
        if common::remove_bind_section(pe, options)? {
            logger.log(
                Level::Debug,
                " --> .bind section was removed from the file.",
            );
        } else {
            logger.log(Level::Debug, " --> .bind section was kept in the file.");
        }

        let mut main_section = None;

        if offsets[3] != 0 {
            let code_section_va = payload_u32(payload, offsets[3] as u32);
            let main_rva = pe.get_rva_from_va(code_section_va as u64);
            if let Some(sec) = pe.get_owner_section(main_rva) {
                if sec.pointer_to_raw_data != 0 && sec.size_of_raw_data != 0 {
                    main_section = Some(*sec);
                }
            }
        }

        if main_section.is_none() {
            let oep_va = payload_u32(payload, offsets[2] as u32);
            let oep_rva = pe.get_rva_from_va(oep_va as u64);
            let sec = pe
                .get_owner_section(oep_rva)
                .ok_or_else(|| Error::Unpack("main code section not found via OEP".into()))?;
            if sec.pointer_to_raw_data == 0 || sec.size_of_raw_data == 0 {
                return Err(Error::Unpack("main code section is invalid".into()));
            }

            logger.log(
                Level::Debug,
                &format!(" --> Code section VA offset was 0; resolved via OEP 0x{oep_va:08X}."),
            );
            main_section = Some(*sec);
        }

        let main_section = main_section.unwrap();

        logger.log(
            Level::Debug,
            &format!(
                " --> {} linked as main code section.",
                main_section.name_str()
            ),
        );

        let code_index = pe
            .section_index_of(&main_section)
            .ok_or_else(|| Error::Unpack("main code section not found".into()))?;

        let section_offset = pe.get_file_offset_from_rva(main_section.virtual_address as u64);

        let flags = payload_u32(payload, offsets[0] as u32);
        let code_section_data =
            if (flags & common::DRM_FLAG_NO_ENCRYPTION) == common::DRM_FLAG_NO_ENCRYPTION {
                logger.log(
                    Level::Debug,
                    &format!(" --> {} section is not encrypted.", main_section.name_str()),
                );
                common::read_range(pe, section_offset, main_section.size_of_raw_data as usize)?
            } else {
                logger.log(
                    Level::Debug,
                    &format!(" --> {} section is encrypted.", main_section.name_str()),
                );

                let aes_key = payload_get(payload, offsets[5] as u32, 32)?;
                let aes_iv = payload_get(payload, offsets[6] as u32, 16)?;
                let code_stolen = payload_get(payload, offsets[7] as u32, 16)?;
                let encrypted_size = payload_u32(payload, offsets[4] as u32);

                let mut merged = code_stolen.to_vec();
                merged.extend(common::read_range(
                    pe,
                    section_offset,
                    encrypted_size as usize,
                )?);

                let mut aes = AesHelper::new(aes_key, aes_iv);
                aes.rebuild_iv(Some(aes_iv));
                aes.decrypt(&merged, AesMode::Cbc)
            };

        let section_data_len = pe.section_data[code_index].len();
        let copy_len = code_section_data.len().min(section_data_len);
        let mut merged_section = pe.section_data[code_index].clone();
        merged_section[..copy_len].copy_from_slice(&code_section_data[..copy_len]);
        pe.section_data[code_index] = merged_section;

        Ok(())
    }
}

fn payload_get(data: &[u8], offset: u32, len: usize) -> Result<&[u8]> {
    let start = offset as usize;
    data.get(start..start.saturating_add(len))
        .ok_or(Error::OutOfBounds)
}

fn payload_u32(data: &[u8], offset: u32) -> u32 {
    u32::from_le_bytes(
        data.get(offset as usize..offset as usize + 4).map(|b| [b[0], b[1], b[2], b[3]]).unwrap_or([0; 4]),
    )
}

fn rd_i32(data: &[u8], off: usize) -> Option<i32> {
    data.get(off..off + 4)
        .map(|b| i32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn validate_steam_drmp_offsets(offsets: &[i32], payload: &[u8]) -> bool {
    if offsets.len() != 8 {
        return false;
    }

    let payload_len = payload.len();
    let check_bound = |val: i32, size: usize| -> bool {
        if val < 0 {
            return false;
        }
        (val as usize).checked_add(size).is_some_and(|end| end <= payload_len)
    };

    if !check_bound(offsets[0], 4) || !check_bound(offsets[2], 4) || !check_bound(offsets[3], 4) {
        return false;
    }

    let flags = payload_u32(payload, offsets[0] as u32);
    if (flags & common::DRM_FLAG_NO_ENCRYPTION) != common::DRM_FLAG_NO_ENCRYPTION {
        if !check_bound(offsets[4], 4)
            || !check_bound(offsets[5], 32)
            || !check_bound(offsets[6], 16)
            || !check_bound(offsets[7], 16)
        {
            return false;
        }
    }

    true
}

fn scan_steam_drmp_offsets(steam_drmp: &[u8], scan_offset: usize, payload: &[u8], logger: &dyn Logger,) -> Option<Vec<i32>> {
    let copy_size = 1024.min(steam_drmp.len().saturating_sub(scan_offset));
    if copy_size < 28 {
        return None;
    }
    let data = &steam_drmp[scan_offset..scan_offset + copy_size];
    let payload_limit = payload.len();

    let check_bound = |val: i32, size: usize| -> bool {
        if val < 0 {
            return false;
        }
        (val as usize)
            .checked_add(size)
            .is_some_and(|end| end <= payload_limit)
    };

    for start in (0..data.len().saturating_sub(28)).step_by(2) {
        let mut vals = Vec::with_capacity(8);
        for j in 0..6 {
            vals.push(rd_i32(data, start + j * 4)?);
        }
        let iv_offset = rd_i32(data, start + 6 * 4)?;
        vals.push(iv_offset);
        vals.push(iv_offset.checked_add(16)?);

        if !check_bound(vals[0], 4) {
            continue;
        }

        let flags = payload_u32(payload, vals[0] as u32);
        let no_enc = (flags & common::DRM_FLAG_NO_ENCRYPTION) == common::DRM_FLAG_NO_ENCRYPTION;

        if !check_bound(vals[3], 4) {
            continue;
        }

        if !no_enc {
            if !check_bound(vals[4], 4)
                || !check_bound(vals[5], 32)
                || !check_bound(vals[6], 16)
                || !check_bound(vals[7], 16)
            {
                continue;
            }
            if vals[5].checked_add(32)? > vals[6] {
                continue;
            }
            if vals[6].checked_add(16)? != vals[7] {
                continue;
            }
        }

        logger.log(
            Level::Debug,
            &format!(" --> Found valid offset layout at byte offset {start} in data block!"),
        );
        return Some(vals);
    }

    None
}

fn get_drmp_offsets(data: &[u8], fallback: bool) -> Option<Vec<i32>> {
    let offset0 = 2; // Flags
    let offset1 = 14; // Steam App Id
    let offset2 = if fallback { 25 } else { 26 }; // OEP
    let offset3 = if fallback { 36 } else { 38 }; // Code Section Virtual Address
    let offset4 = if fallback { 47 } else { 50 }; // Code Section Virtual Size (Encrypted Size)
    let offset5 = if fallback { 61 } else { 62 }; // Code Section AES Key
    let offset6 = if fallback { 72 } else { 67 }; // Code Section AES Iv

    let aes_iv_offset = rd_i32(data, offset6)?;
    Some(vec![
        rd_i32(data, offset0)?,
        rd_i32(data, offset1)?,
        rd_i32(data, offset2)?,
        rd_i32(data, offset3)?,
        rd_i32(data, offset4)?,
        rd_i32(data, offset5)?,
        aes_iv_offset,
        aes_iv_offset.checked_add(16)?,
    ])
}

fn get_drmp_offsets_dynamic(data: &[u8]) -> Vec<i32> {
    let mut offsets = Vec::new();
    let mut count = 0u32;
    let mut skip_mov = false;

    for insn in common::decode_block(data, 0, data.len(), 0) {
        if count >= 8 {
            break;
        }

        // ex: mov eax, [eax+1234]
        if !skip_mov
            && insn.mnemonic() == Mnemonic::Mov
            && insn.op_kind(0) == OpKind::Register
            && insn.op_kind(1) == OpKind::Memory
        {
            count += 1;
            offsets.push(insn.memory_displacement64() as i32);
        }

        // ex: lea eax, [eax+1234]
        if insn.mnemonic() == Mnemonic::Lea
            && insn.op_kind(0) == OpKind::Register
            && insn.op_kind(1) == OpKind::Memory
        {
            count += 2;
            let disp = insn.memory_displacement64() as i32;
            offsets.push(disp);
            offsets.push(disp + 16);
            skip_mov = true;
        }

        // ex: add eax, 1234
        if insn.mnemonic() == Mnemonic::Add
            && insn.op_kind(0) == OpKind::Register
            && matches!(
                insn.op_kind(1),
                OpKind::Immediate8 | OpKind::Immediate16 | OpKind::Immediate32
            )
        {
            count += 1;
            offsets.push(op1_immediate(&insn).unwrap_or(0) as i32);
        }
    }

    offsets
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drmp_offsets_fallback_selection() {
        // Build a 1024 byte block with the primary layout at offset 2.
        let mut data = vec![0u8; OFFSET_BLOCK_SIZE];
        // Flags @2, SteamAppId @14, OEP @26, CodeSectionVA @38, Size @50, Key @62, Iv @67.
        data[2..6].copy_from_slice(&1u32.to_le_bytes());
        data[14..18].copy_from_slice(&730i32.to_le_bytes());
        data[26..30].copy_from_slice(&0x14000i32.to_le_bytes());
        data[38..42].copy_from_slice(&0x401000i32.to_le_bytes());
        data[50..54].copy_from_slice(&0x8000u32.to_le_bytes());
        data[62..66].fill(0xAB);
        data[67..71].copy_from_slice(&0x100u32.to_le_bytes());

        let offsets = get_drmp_offsets(&data, false).unwrap();
        assert_eq!(offsets.len(), 8);
        assert_eq!(offsets[0], 1);
        assert_eq!(offsets[1], 730);
        assert_eq!(offsets[2], 0x14000);
        assert_eq!(offsets[3], 0x401000);
        assert_eq!(offsets[4], 0x8000);
        assert_eq!(offsets[5], i32::from_le_bytes([0xAB, 0xAB, 0xAB, 0xAB]));
        assert_eq!(offsets[6], 0x100);
        assert_eq!(offsets[7], 0x110);
    }

    #[test]
    fn validate_and_scan_drmp_offsets() {
        let payload = vec![0u8; 0x1000];
        let valid_offsets = vec![2, 14, 26, 38, 50, 0x100, 0x200, 0x210];
        assert!(validate_steam_drmp_offsets(&valid_offsets, &payload));

        // Invalid: key offset past payload length
        let invalid_offsets = vec![2, 14, 26, 38, 50, 0x1000, 0x200, 0x210];
        assert!(!validate_steam_drmp_offsets(&invalid_offsets, &payload));

        // Test scanning fallback when primary block is shifted
        let mut data = vec![0xFFu8; 2048];
        let shift = 256;
        let test_offsets: [i32; 7] = [10, 20, 30, 40, 50, 100, 200];
        for (i, &val) in test_offsets.iter().enumerate() {
            data[shift + i * 4..shift + (i + 1) * 4].copy_from_slice(&val.to_le_bytes());
        }

        let logger = crate::logger::NullLogger;
        let scanned = scan_steam_drmp_offsets(&data, 0, &payload, &logger).unwrap();
        assert_eq!(scanned.len(), 8);
        assert_eq!(scanned[0], 10);
        assert_eq!(scanned[1], 20);
        assert_eq!(scanned[6], 200);
        assert_eq!(scanned[7], 216);
    }
}
