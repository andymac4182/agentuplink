//! `tunnel-authority`: see the library documentation (`src/lib.rs`).

#![forbid(unsafe_code)]

use std::process::ExitCode;

#[cfg(unix)]
fn main() -> ExitCode {
    tunnel_authority::run(std::env::args_os().skip(1).collect())
}

/// The signing tools refuse a private key unless it is mode `0600` in a
/// `0700` directory, and Windows has no such mode, so a Windows build refuses
/// every command rather than read a key it cannot protect (task row M6-C22).
#[cfg(not(unix))]
fn main() -> ExitCode {
    eprintln!(
        "tunnel-authority: the signing tools run only on Linux and macOS, where the private key's file mode can be enforced"
    );
    ExitCode::from(2)
}
