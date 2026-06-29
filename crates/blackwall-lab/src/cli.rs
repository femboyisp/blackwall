//! Command-line interface for the `lab` binary.

use crate::exec::runner;
use std::process::ExitCode;

/// Parse args and dispatch. Returns process exit code.
#[must_use]
pub fn main_dispatch() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("test") => match args.get(1) {
            Some(path) => run_test(path, args.get(2).map(String::as_str)),
            None => usage(),
        },
        Some("up") => match args.get(1) {
            Some(path) => with_text(path, runner::up),
            None => usage(),
        },
        Some("down") => match args.get(1) {
            Some(path) => with_text(path, runner::down_scenario),
            None => match runner::down_all() {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => fail(&e.to_string()),
            },
        },
        Some("status") => match runner::status() {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(&e.to_string()),
        },
        Some("shell") => match (args.get(1), args.get(2)) {
            (Some(path), Some(node)) => shell(path, node),
            _ => usage(),
        },
        _ => usage(),
    }
}

fn run_test(path: &str, junit: Option<&str>) -> ExitCode {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => return fail(&format!("read {path}: {e}")),
    };
    match runner::run_test(&text, junit) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => fail(&e.to_string()),
    }
}

/// Read a scenario file and run a `Result<(), LabError>`-returning action.
fn with_text(
    path: &str,
    action: impl FnOnce(&str) -> Result<(), crate::error::LabError>,
) -> ExitCode {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => return fail(&format!("read {path}: {e}")),
    };
    match action(&text) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => fail(&e.to_string()),
    }
}

fn shell(path: &str, node: &str) -> ExitCode {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => return fail(&format!("read {path}: {e}")),
    };
    match runner::shell(&text, node) {
        // Map the interactive shell's exit code onto the process exit code.
        Ok(0) => ExitCode::SUCCESS,
        Ok(_) => ExitCode::FAILURE,
        Err(e) => fail(&e.to_string()),
    }
}

fn usage() -> ExitCode {
    eprintln!(
        "usage: lab test <scenario.kdl> [junit-out.xml]\n       lab up <scenario.kdl>\n       lab down [<scenario.kdl>]\n       lab status\n       lab shell <scenario.kdl> <node>"
    );
    ExitCode::FAILURE
}

fn fail(msg: &str) -> ExitCode {
    eprintln!("lab: {msg}");
    ExitCode::FAILURE
}
