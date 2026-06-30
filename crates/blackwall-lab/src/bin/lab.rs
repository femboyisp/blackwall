//! The `lab` binary entry point.

use std::process::ExitCode;

fn main() -> ExitCode {
    blackwall_lab::cli::main_dispatch()
}
