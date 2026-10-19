pub mod common;
pub mod var10;
pub mod var20;
pub mod var21;
pub mod var30;
pub mod var31;
pub(crate) mod var_3x;

use crate::logger::Logger;
use crate::options::Options;
use crate::pe::PeFile;
use crate::Result;

pub trait Unpacker {
    fn name(&self) -> &'static str;
    fn can_process(&self, pe: &PeFile) -> bool;
    fn process(&self, pe: &mut PeFile, options: &Options, logger: &dyn Logger) -> Result<()>;
}

pub fn unpackers() -> Vec<Box<dyn Unpacker>> {
    vec![
        Box::new(var10::Variant10),
        Box::new(var20::Variant20),
        Box::new(var21::Variant21),
        Box::new(var30::Variant30::x64()),
        Box::new(var30::Variant30::x86()),
        Box::new(var31::Variant31::x64()),
        Box::new(var31::Variant31::x86()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_order_matches_csharp_cli() {
        let names: Vec<String> = unpackers().iter().map(|u| u.name().to_string()).collect();
        assert!(names[0].contains("1.0"));
        assert!(names[1].contains("2.0"));
        assert!(names[2].contains("2.1"));
        assert!(names[3].contains("3.0") && names[3].contains("x64"));
        assert!(names[4].contains("3.0") && names[4].contains("x86"));
        assert!(names[5].contains("3.1") && names[5].contains("x64"));
        assert!(names[6].contains("3.1") && names[6].contains("x86"));
    }
}
