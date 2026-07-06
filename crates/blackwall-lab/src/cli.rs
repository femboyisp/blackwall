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

/// Default overall `lab test` deadline in seconds, overridable via
/// `LAB_TEST_TIMEOUT_SECS`. Comfortably under the CI gate's 300s outer
/// `sudo timeout`, so the watchdog spawned by [`spawn_test_watchdog`]
/// self-terminates the process with a clear diagnostic before the CI
/// harness would SIGKILL it opaquely (blackwall#88).
const DEFAULT_TEST_TIMEOUT_SECS: u64 = 240;

/// Spawn a daemon watchdog thread enforcing an overall wall-clock deadline
/// on `lab test`.
///
/// The deadline is read from `LAB_TEST_TIMEOUT_SECS` (parsed as a `u64`
/// count of seconds), defaulting to [`DEFAULT_TEST_TIMEOUT_SECS`] when unset
/// or unparsable. After the deadline elapses the thread prints a diagnostic
/// to stderr naming the timeout and force-exits the whole process with
/// status 124 (the conventional timeout exit code) via
/// [`std::process::exit`].
///
/// This is a last-resort backstop for a wedged root-spawned child that
/// escapes every inner bound (e.g. a `cargo test` grandchild that outlives
/// `netns::run_bounded`'s per-command timeout because a daemon holds it
/// open) — it guarantees `lab test` cannot hang past this deadline no
/// matter where in the run it is stuck. `std::process::exit` skips the
/// runner's `Drop`-based namespace/daemon cleanup (`runner::Teardown`)
/// entirely; that is an accepted tradeoff here because CI runners are
/// ephemeral (torn down after the job regardless of lab state) and a local
/// developer run self-cleans on the next `lab` invocation (`lab down`
/// sweeps stale `bw-*` namespaces and pidfiles). Only wired into the `test`
/// subcommand path, since `up`/`shell` intentionally leave namespaces
/// standing.
fn spawn_test_watchdog() {
    let secs = std::env::var("LAB_TEST_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(DEFAULT_TEST_TIMEOUT_SECS);
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(secs));
        eprintln!(
            "lab: overall test deadline ({secs}s) exceeded — forcing exit; a step or daemon \
             hung. This force-exit skips the runner's normal namespace/daemon cleanup (no Drop \
             runs); that's fine on ephemeral CI runners, and a local run self-cleans on the next \
             `lab` invocation."
        );
        std::process::exit(124);
    });
}

fn run_test(path: &str, junit: Option<&str>) -> ExitCode {
    spawn_test_watchdog();
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
