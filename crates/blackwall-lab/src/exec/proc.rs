//! Thin process launch + readiness polling.

use crate::assert::Captured;
use crate::error::LabError;
use crate::exec::netns;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

/// Path to a node's BIRD control socket for this run.
pub(crate) fn bird_ctl(run_id: &str, node: &str) -> String {
    format!("/run/blackwall-lab/{run_id}/{node}.ctl")
}

/// Poll `probe` in `ns` until it passes or `timeout` elapses.
///
/// Supported probes: `bgp-established`, `port-open:<port>`, `file-present:<path>`.
pub(crate) fn wait_until(
    run_id: &str,
    node: &str,
    ns: &str,
    probe: &str,
    timeout: Duration,
) -> Result<(), LabError> {
    let deadline = Instant::now() + timeout;
    loop {
        if probe_passes(run_id, node, ns, probe)? {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(LabError::Exec(format!(
                "probe `{probe}` timed out after {timeout:?}"
            )));
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn probe_passes(run_id: &str, node: &str, ns: &str, probe: &str) -> Result<bool, LabError> {
    if probe == "bgp-established" {
        let ctl = bird_ctl(run_id, node);
        let c = netns::nsexec(ns, &["birdc", "-s", &ctl, "show", "protocols"])?;
        Ok(c.stdout.contains("Established"))
    } else if let Some(port) = probe.strip_prefix("port-open:") {
        let c = netns::nsexec(ns, &["ss", "-lnt"])?;
        Ok(c.stdout.contains(&format!(":{port} ")))
    } else if let Some(path) = probe.strip_prefix("file-present:") {
        Ok(std::path::Path::new(path).exists())
    } else {
        Err(LabError::Exec(format!("unknown probe `{probe}`")))
    }
}

/// Run an assert command in `ns`. If the command starts with `birdc `, inject
/// `-s <ctl>` so it talks to this run's BIRD socket.
pub(crate) fn assert_cmd(
    run_id: &str,
    node: &str,
    ns: &str,
    cmd: &str,
) -> Result<Captured, LabError> {
    let rewritten = if let Some(rest) = cmd.strip_prefix("birdc ") {
        format!("birdc -s {} {rest}", bird_ctl(run_id, node))
    } else {
        cmd.to_owned()
    };
    netns::nsexec(ns, &["sh", "-c", &rewritten])
}

/// Write config and launch BIRD inside `ns` for this run.
///
/// Creates `/run/blackwall-lab/<run_id>/` if absent, writes `<node>.conf`,
/// and starts `bird` in the background. The process is detached (no handle
/// retained); BIRD exits on namespace teardown.
pub(crate) fn spawn_bird(
    run_id: &str,
    node: &str,
    ns: &str,
    config_contents: &str,
) -> Result<(), LabError> {
    let dir = format!("/run/blackwall-lab/{run_id}");
    std::fs::create_dir_all(&dir)
        .map_err(|e| LabError::Exec(format!("create run dir {dir}: {e}")))?;

    let conf_path = format!("{dir}/{node}.conf");
    std::fs::write(&conf_path, config_contents)
        .map_err(|e| LabError::Exec(format!("write bird config {conf_path}: {e}")))?;

    let ctl = bird_ctl(run_id, node);
    let pid_path = format!("{dir}/{node}.pid");

    // Launch BIRD in the background; it daemonizes itself.
    let status = Command::new("ip")
        .args([
            "netns", "exec", ns, "bird", "-c", &conf_path, "-s", &ctl, "-P", &pid_path,
        ])
        .status()
        .map_err(|e| LabError::Exec(format!("spawn bird in {ns}: {e}")))?;

    if !status.success() {
        return Err(LabError::Exec(format!(
            "bird exited with code {} in {ns}",
            status.code().unwrap_or(-1)
        )));
    }
    Ok(())
}

/// Base dir for a knot node's working tree (config + zone + LMDB databases).
///
/// Deliberately on real disk (`/var/lib`), NOT the tmpfs `/run` base the rest
/// of the lab uses: knot keeps its journal/timer/kasp state in LMDB, and LMDB's
/// lock-file robust mutex fails with EPERM on tmpfs (`journal update failed
/// (operation not permitted)`). Bird is unaffected (no LMDB) so it stays on
/// `/run`. The teardown paths in `runner.rs` clean this base too.
pub(crate) fn knot_base(run_id: &str, node: &str) -> String {
    format!("/var/lib/blackwall-lab/{run_id}/{node}")
}

/// Launch `knotd` for a node in its namespace. Writes the rendered config and
/// zone into a per-node disk-backed subdir ([`knot_base`]) and runs knotd with
/// that dir as cwd, so the config's relative `storage`/`rundir`/`file: zone.db`
/// resolve there. Backgrounded; reaped when the namespace is deleted at teardown.
pub(crate) fn spawn_knot(
    run_id: &str,
    node: &str,
    ns: &str,
    conf: &str,
    zone: &str,
) -> Result<(), LabError> {
    let dir = knot_base(run_id, node);
    std::fs::create_dir_all(&dir).map_err(|e| LabError::Exec(format!("mkdir {dir}: {e}")))?;
    std::fs::write(format!("{dir}/knot.conf"), conf)
        .map_err(|e| LabError::Exec(format!("write knot.conf: {e}")))?;
    std::fs::write(format!("{dir}/zone.db"), zone)
        .map_err(|e| LabError::Exec(format!("write zone.db: {e}")))?;
    let mut cmd = std::process::Command::new("ip");
    cmd.args(["netns", "exec", ns, "knotd", "-c", "knot.conf"])
        .current_dir(&dir);
    cmd.spawn()
        .map_err(|e| LabError::Exec(format!("spawn knotd: {e}")))?;
    Ok(())
}

/// Launch a process inside `ns` with resolved environment, returning a child
/// handle the runner kills at teardown.
///
/// Runs: `ip netns exec <ns> env <KEY=VAL...> sh -c "<cmd>"`
pub(crate) fn spawn_run(
    ns: &str,
    cmd: &str,
    env_resolved: &[(String, String)],
) -> Result<Child, LabError> {
    let mut args: Vec<String> = vec![
        "netns".to_owned(),
        "exec".to_owned(),
        ns.to_owned(),
        "env".to_owned(),
    ];
    for (k, v) in env_resolved {
        args.push(format!("{k}={v}"));
    }
    args.extend(["sh".to_owned(), "-c".to_owned(), cmd.to_owned()]);

    let child = Command::new("ip")
        .args(&args)
        .spawn()
        .map_err(|e| LabError::Exec(format!("spawn run in {ns}: {e}")))?;
    Ok(child)
}
