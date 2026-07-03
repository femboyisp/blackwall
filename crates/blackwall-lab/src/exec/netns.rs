//! Thin shell-outs to `ip` for namespace and link management.

use crate::assert::Captured;
use crate::error::LabError;
use std::io::Read;
use std::net::IpAddr;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// Hard ceiling on any single lab command (blackwall#88).
///
/// A stuck child — e.g. `cargo test` blocking on the Cargo build-directory
/// lock — is killed rather than hanging the whole gate silently until CI's
/// 6-minute step timeout. Generous enough for a warm-cache `cargo test`
/// assert, comfortably under that step timeout so a hang fails its own step
/// fast with a named error instead of a zero-output wall.
const CMD_TIMEOUT: Duration = Duration::from_secs(180);

/// Run a command to completion, returning captured stdout/stderr/exit.
///
/// Bounded by [`CMD_TIMEOUT`] via [`run_bounded`].
pub(crate) fn run(cmd: &mut Command) -> Result<Captured, LabError> {
    run_bounded(cmd, CMD_TIMEOUT)
}

/// Run `cmd`, killing it (and its process group) if it outlives `timeout`.
///
/// The child is placed in its own process group so the kill reaches any
/// grandchildren (`sh -c "cargo …"` spawns a tree). Both pipes are drained on
/// threads so a chatty child cannot deadlock on a full pipe buffer while we
/// poll for the deadline. On timeout, returns [`LabError::Exec`] naming the
/// timeout so the failing step is diagnosable instead of a silent hang.
pub(crate) fn run_bounded(cmd: &mut Command, timeout: Duration) -> Result<Captured, LabError> {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut child = cmd
        .spawn()
        .map_err(|e| LabError::Exec(format!("spawn failed: {e}")))?;
    let mut out_pipe = child.stdout.take().expect("stdout was piped");
    let mut err_pipe = child.stderr.take().expect("stderr was piped");
    let out_h = thread::spawn(move || {
        let mut b = Vec::new();
        let _ = out_pipe.read_to_end(&mut b);
        b
    });
    let err_h = thread::spawn(move || {
        let mut b = Vec::new();
        let _ = err_pipe.read_to_end(&mut b);
        b
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) => {
                if Instant::now() >= deadline {
                    // Kill the whole process group (negative PID), then reap.
                    let pid = child.id();
                    let _ = Command::new("kill")
                        .args(["-KILL", &format!("-{pid}")])
                        .status();
                    let _ = child.wait();
                    let _ = out_h.join();
                    let _ = err_h.join();
                    return Err(LabError::Exec(format!(
                        "command timed out after {timeout:?} (killed)"
                    )));
                }
                thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(LabError::Exec(format!("wait failed: {e}"))),
        }
    };
    let stdout = out_h.join().unwrap_or_default();
    let stderr = err_h.join().unwrap_or_default();
    Ok(Captured {
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
        // exit code 0..=255 fits i32 without a lossy `as` cast.
        exit: status.code().unwrap_or(-1),
    })
}

/// `ip netns add <ns>` (idempotent: ignores "File exists").
pub(crate) fn netns_add(ns: &str) -> Result<(), LabError> {
    let c = run(Command::new("ip").args(["netns", "add", ns]))?;
    if c.exit != 0 && !c.stderr.contains("File exists") {
        return Err(LabError::Exec(format!("netns add {ns}: {}", c.stderr)));
    }
    Ok(())
}

/// `ip netns del <ns>` (idempotent: ignores absence).
pub(crate) fn netns_del(ns: &str) -> Result<(), LabError> {
    let _ = run(Command::new("ip").args(["netns", "del", ns]))?;
    Ok(())
}

/// `ip netns exec <ns> <argv...>` capturing output.
pub(crate) fn nsexec(ns: &str, argv: &[&str]) -> Result<Captured, LabError> {
    let mut cmd = Command::new("ip");
    cmd.args(["netns", "exec", ns]).args(argv);
    run(&mut cmd)
}

/// `ip link set lo up` inside `ns` (bring loopback up).
pub(crate) fn loopback_up(ns: &str) -> Result<(), LabError> {
    let c = nsexec(ns, &["ip", "link", "set", "lo", "up"])?;
    if c.exit != 0 {
        return Err(LabError::Exec(format!("loopback up in {ns}: {}", c.stderr)));
    }
    Ok(())
}

/// `ip link add <a> type veth peer name <b>` in root namespace.
///
/// Creates a veth pair; both ends start in the root namespace.
pub(crate) fn veth_add(a: &str, b: &str) -> Result<(), LabError> {
    let c = run(Command::new("ip").args(["link", "add", a, "type", "veth", "peer", "name", b]))?;
    if c.exit != 0 && !c.stderr.contains("File exists") {
        return Err(LabError::Exec(format!("veth add {a}/{b}: {}", c.stderr)));
    }
    Ok(())
}

/// `ip link set <iface> netns <ns>` — move interface into namespace.
pub(crate) fn iface_to_ns(iface: &str, ns: &str) -> Result<(), LabError> {
    let c = run(Command::new("ip").args(["link", "set", iface, "netns", ns]))?;
    if c.exit != 0 {
        return Err(LabError::Exec(format!(
            "move {iface} -> {ns}: {}",
            c.stderr
        )));
    }
    Ok(())
}

/// `ip -n <ns> link set <iface> up` inside namespace.
pub(crate) fn iface_up(ns: &str, iface: &str) -> Result<(), LabError> {
    let c = run(Command::new("ip").args(["-n", ns, "link", "set", iface, "up"]))?;
    if c.exit != 0 {
        return Err(LabError::Exec(format!(
            "iface up {iface} in {ns}: {}",
            c.stderr
        )));
    }
    Ok(())
}

/// `ip -n <ns> addr add <addr>/<prefix> dev <iface>` inside namespace.
pub(crate) fn addr_add(ns: &str, iface: &str, addr: IpAddr, prefix: u8) -> Result<(), LabError> {
    let cidr = format!("{addr}/{prefix}");
    let c = run(Command::new("ip").args(["-n", ns, "addr", "add", &cidr, "dev", iface]))?;
    if c.exit != 0 && !c.stderr.contains("File exists") {
        return Err(LabError::Exec(format!(
            "addr add {cidr} on {iface} in {ns}: {}",
            c.stderr
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // These drive `sh` directly (no netns / CAP_NET_ADMIN), so they exercise
    // the bounded-exec machinery — the actual fix for blackwall#88 — in a plain
    // unit test.

    #[test]
    fn run_bounded_kills_a_hung_command() {
        let start = Instant::now();
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "sleep 30"]);
        let r = run_bounded(&mut cmd, Duration::from_millis(500));
        let elapsed = start.elapsed();
        let err = r.expect_err("a command exceeding the timeout must error");
        assert!(
            err.to_string().contains("timed out"),
            "error should name the timeout, got: {err}"
        );
        // Killed promptly, not after the full 30s sleep.
        assert!(
            elapsed < Duration::from_secs(5),
            "hung command was not killed promptly: {elapsed:?}"
        );
    }

    #[test]
    fn run_bounded_captures_output_and_exit_of_a_fast_command() {
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "printf hello; printf oops >&2; exit 3"]);
        let c = run_bounded(&mut cmd, Duration::from_secs(5)).expect("fast command runs");
        assert_eq!(c.stdout, "hello");
        assert_eq!(c.stderr, "oops");
        assert_eq!(c.exit, 3);
    }

    #[test]
    fn run_bounded_drains_a_chatty_command_without_deadlock() {
        // Emit far more than a pipe buffer (~64KiB) to prove the reader threads
        // prevent a write-side deadlock under the deadline poll.
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "yes abcdefghij | head -c 200000"]);
        let c = run_bounded(&mut cmd, Duration::from_secs(10)).expect("chatty command runs");
        assert_eq!(c.stdout.len(), 200_000);
        assert_eq!(c.exit, 0);
    }
}
