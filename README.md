# steamless-rs

Cross-platform Rust library for SteamStub DRM unpacking, ported from Steamless.

This crate serves as the reusable library engine. If you are looking for the full standalone CLI and toolset application, see [RustySteamless (`dev` branch)](https://github.com/Dxian998/RustySteamless/tree/dev).

## Supported Variants

- SteamStub Variant 1.0 (x86)
- SteamStub Variant 2.0 (x86)
- SteamStub Variant 2.1 (x86)
- SteamStub Variant 3.0 (x86 & x64)
- SteamStub Variant 3.1 (x86 & x64)

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
steamless-rs = { git = "https://github.com/Dxian998/steamless-rs" }
```

### Unpack

```rust
use steamless_rs::{unpack, Options, unpack_file};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Basic unpacking with default options:
    let result = steamless_rs::unpack("path/to/game.exe")?;
    println!("Unpacked with {}: {}", result.variant, result.output_path.display());

    // Or with custom options and a logger:
    let mut options = Options::default();
    options.verbose_output = true;

    struct MyLogger;
    impl steamless_rs::Logger for MyLogger {
        fn log(&self, level: steamless_rs::Level, msg: &str) {
            println!("[{:?}] {}", level, msg);
        }
    }

    let result = unpack_file("path/to/game.exe", &options, &MyLogger)?;
    Ok(())
}
```

## Notice
This project is licensed under `The Unlicense`. I am not liable for anything related to this project, use it at your own risk.

## Credits & Attributions

- **atom0s**: Original creator of [Steamless](https://github.com/atom0s/Steamless) in C#.
- **[notwinterdust](https://github.com/notwinterdust)**: Initial Rust port in [RustySteamless](https://github.com/notwinterdust/RustySteamless).
- **[Me](https://github.com/Dxian998)**: Fixes and in resolving unpacker failures, code section fixups, and OEP recovery:
  - [`5145569`](https://github.com/Dxian998/RustySteamless/commit/5145569800c4d7b1edf7f6bfd7cebf592eac9b1b): Improve variant unpacking robustness, PE fixups (Import Descriptor relocation, Security directory cleanup), and pattern detection.
  - [`5434f08`](https://github.com/Dxian998/RustySteamless/commit/5434f08931c7de277747619558fde63018f7561b): Fix variant 3.0 and 3.1 header size detection, `.bind` section fallback scans, and TLS OEP recovery.
  - [`231003b`](https://github.com/Dxian998/RustySteamless/commit/231003b6e1fc453acbc0d96a159665d315b403aa): Variant 2.1 SteamDRMP multi-pattern and dynamic/layout scanning fallbacks, code section OEP resolution, and PE file fixups.
