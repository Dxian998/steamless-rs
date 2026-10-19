use std::path::{Path, PathBuf};
use thiserror::Error;

pub mod crypto;
pub mod logger;
pub mod options;
pub mod pattern;
pub mod pe;
pub mod variants;

pub use logger::{Level, Logger, NullLogger};
pub use options::Options;
pub use pe::{ImageBits, PeFile};
pub use variants::{unpackers, Unpacker};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnpackResult {
    pub variant: &'static str,
    pub output_path: PathBuf,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("failed to read input file: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid PE file: {0}")]
    InvalidPe(String),
    #[error("unexpected end of data")]
    OutOfBounds,
    #[error("unpack failed: {0}")]
    Unpack(String),
    #[error("pattern not found")]
    PatternNotFound,
    #[error("no SteamStub variant matched file (is it packed with SteamStub?)")]
    NoMatchingVariant,
}

pub fn unpack_file(path: impl AsRef<Path>, options: &Options, logger: &dyn Logger,) -> Result<UnpackResult> {
    let path = path.as_ref();
    let pe = PeFile::parse(path)?;

    for unpacker in unpackers() {
        if !unpacker.can_process(&pe) {
            continue;
        }

        logger.log(
            Level::Info,
            &format!("File is packed with {}!", unpacker.name()),
        );

        let mut fresh = PeFile::parse(path)?;
        match unpacker.process(&mut fresh, options, logger) {
            Ok(()) => {
                let output_path = PathBuf::from(format!("{}.unpacked.exe", path.display()));
                return Ok(UnpackResult {
                    variant: unpacker.name(),
                    output_path,
                });
            }
            Err(err) => {
                logger.log(
                    Level::Error,
                    &format!("Failed to unpack with {}: {err}", unpacker.name()),
                );
            }
        }
    }

    Err(Error::NoMatchingVariant)
}

pub fn unpack(path: impl AsRef<Path>) -> Result<UnpackResult> {
    unpack_file(path, &Options::default(), &logger::NullLogger)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unpack_nonexistent_file_errors() {
        let err = unpack("nonexistent_file_xyz.exe");
        assert!(err.is_err());
    }
}

