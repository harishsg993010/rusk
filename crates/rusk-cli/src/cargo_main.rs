//! Entry point for `cargo rusk` subcommand.
//!
//! Cargo invokes this as `cargo-rusk rusk <args...>`, so we strip the
//! extra "rusk" argument before delegating to the real `rusk` binary.

fn main() {
    // When invoked as `cargo rusk install`, cargo passes args as:
    // ["cargo-rusk", "rusk", "install", ...]
    // Strip the "rusk" subcommand that cargo injects.
    let args: Vec<String> = std::env::args().collect();
    let filtered: Vec<String> = if args.len() > 1 && args[1] == "rusk" {
        std::iter::once(args[0].clone())
            .chain(args[2..].iter().cloned())
            .collect()
    } else {
        args
    };

    // Locate the `rusk` binary next to this `cargo-rusk` binary.
    let exe = std::env::current_exe().unwrap();
    let rusk_exe = exe.with_file_name(if cfg!(windows) { "rusk.exe" } else { "rusk" });

    let status = std::process::Command::new(rusk_exe)
        .args(&filtered[1..])
        .status()
        .unwrap_or_else(|e| {
            eprintln!("cargo-rusk: failed to execute rusk: {e}");
            std::process::exit(1);
        });

    std::process::exit(status.code().unwrap_or(1));
}
