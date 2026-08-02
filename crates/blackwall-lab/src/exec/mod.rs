//! Thin I/O layer: realize plans in network namespaces. Coverage-excluded.

pub(crate) mod netns;
pub(crate) mod proc;
pub mod runner;

/// SIGKILL the process group led by `pid` (best-effort).
///
/// Signals via `kill(2)` rather than shelling out to `kill(1)`. That is not a
/// style preference: `kill(1)`'s parsing of a leading-dash process-group
/// operand is implementation-specific, and one common implementation gets it
/// catastrophically — not merely ineffectively — wrong.
///
/// procps-ng 3.3.17 is the `kill` in `catthehacker/ubuntu:act-22.04`, the image
/// every CI lab gate runs in. Given `kill -KILL -<pgid>` (no `--`) it reads the
/// second dash-argument as another *signal* spec, is left with no PID operands,
/// and signals **its own process group**. That group is inherited from `lab`,
/// so the helper SIGKILLs `lab` itself; under CI's `sudo timeout … lab` wrapper
/// it also takes down `timeout`, which made itself the group leader via
/// `setpgid(0,0)`. The gate therefore died as `<pid> Killed … sudo timeout …`
/// with exit 137 *after* every assertion had passed and JUnit had been written,
/// leaving teardown abandoned partway — leaking the run's netns, its BIRD
/// daemon and its scratch dir.
///
/// util-linux's `kill` parses the same argv correctly, which is why the
/// blackwall#88 teardown fix (8b42717, 2026-06-29) looked green on a dev box
/// while killing every CI lab gate from that commit onward.
///
/// A negative pid means "that process group" to `kill(2)`; ESRCH is the
/// expected no-op for a child that never became a group leader.
pub(crate) fn kill_process_group(pid: u32) {
    let Ok(pid) = i32::try_from(pid) else { return };
    // SAFETY: `kill(2)` takes scalars and touches no memory we own. A negative
    // target is the documented "signal the process group" form.
    unsafe { libc::kill(-pid, libc::SIGKILL) };
}

/// SIGKILL a single process (best-effort), for the same reason as
/// [`kill_process_group`]: no shell-out, no argv parsing.
///
/// Rejects non-positive pids so a malformed pidfile can never become the
/// `kill(-1, …)` "every process we may signal" form.
pub(crate) fn kill_pid(pid: i32) {
    if pid <= 0 {
        return;
    }
    // SAFETY: as above; `pid` is positive, so this targets exactly one process.
    unsafe { libc::kill(pid, libc::SIGKILL) };
}

#[cfg(test)]
mod tests {
    /// No file in this module may signal by spawning `kill(1)`.
    ///
    /// Deliberately a source-level guard rather than a behavioural test. The
    /// bug this protects against exists only under procps-ng's argv parsing,
    /// so a test that actually spawned `kill` would pass on a util-linux dev
    /// box whether or not the bug were present — a check that cannot fail, and
    /// exactly how the original defect shipped green. Asserting the shell-out
    /// is absent is verifiable on every platform, including the one where the
    /// failure reproduces.
    #[test]
    fn no_source_file_shells_out_to_kill() {
        // Built at runtime so this needle cannot match its own source text.
        let needle = format!("Command::new({q}kill{q})", q = '"');
        for (name, src) in [
            ("exec/mod.rs", include_str!("mod.rs")),
            ("exec/netns.rs", include_str!("netns.rs")),
            ("exec/proc.rs", include_str!("proc.rs")),
            ("exec/runner.rs", include_str!("runner.rs")),
        ] {
            assert!(
                !src.contains(&needle),
                "{name} spawns kill(1); use exec::kill_process_group / exec::kill_pid instead. \
                 procps-ng reads `kill -KILL -<pgid>` as a second signal spec, is left with no \
                 PID operands, and SIGKILLs the caller's own process group."
            );
        }
    }
}
