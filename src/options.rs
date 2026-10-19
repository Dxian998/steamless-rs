use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Options {
    pub verbose_output: bool,
    pub keep_bind_section: bool,
    pub dump_payload_to_disk: bool,
    pub dump_steam_drmp_to_disk: bool,
    pub use_experimental_features: bool,
    pub realign_sections: bool,
    pub zero_dos_stub_data: bool,
    pub recalculate_file_checksum: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            verbose_output: true,
            keep_bind_section: false,
            dump_payload_to_disk: false,
            dump_steam_drmp_to_disk: false,
            use_experimental_features: false,
            realign_sections: false,
            zero_dos_stub_data: true,
            recalculate_file_checksum: false,
        }
    }
}
