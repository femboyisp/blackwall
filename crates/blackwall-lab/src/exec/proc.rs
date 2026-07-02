//! Thin process launch + readiness polling.

use crate::assert::Captured;
use crate::error::LabError;
use crate::exec::netns;
use std::os::unix::process::CommandExt as _;
use std::process::{Child, Command, Stdio};
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

/// Kill any daemon that wrote a `*.pid` file under `run_dir` (best-effort).
///
/// BIRD daemonizes itself and returns no [`Child`] handle, so it is not
/// reaped by the runner's tracked-children teardown; it writes a pidfile
/// instead (`-P <path>` at [`spawn_bird`]). Callers must invoke this before
/// removing a run's scratch dir so the daemon is not orphaned. A missing or
/// stale pidfile, or an already-dead pid, is a harmless no-op. Killing by
/// PID works from the root netns because `ip netns exec` shares the root PID
/// namespace with the process it spawns.
pub(crate) fn kill_pidfiles(run_dir: &str) {
    let Ok(entries) = std::fs::read_dir(run_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("pid") {
            continue;
        }
        let Ok(contents) = std::fs::read_to_string(&path) else {
            continue;
        };
        let pid = contents.trim();
        if pid.is_empty() {
            continue;
        }
        // Guard against PID reuse (issue #81): only kill if the live process is
        // actually the lab's BIRD daemon. A recycled PID (an unrelated process)
        // has a different `comm`, and a dead pid has no `/proc/<pid>/comm` — both
        // are skipped.
        let Ok(comm) = std::fs::read_to_string(format!("/proc/{pid}/comm")) else {
            continue;
        };
        if comm.trim() != "bird" {
            continue;
        }
        let _ = Command::new("kill").args(["-KILL", pid]).status();
    }
}

/// Write config and launch BIRD inside `ns` for this run.
///
/// Creates `/run/blackwall-lab/<run_id>/` if absent, writes `<node>.conf`,
/// and starts `bird` in the background. The process is detached (no handle
/// retained); BIRD daemonizes itself and writes a pidfile at `-P <path>`, so
/// teardown kills it by pidfile via [`kill_pidfiles`] instead of a tracked
/// `Child` — deleting the namespace alone does NOT stop a running BIRD.
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

/// Launch `knotd` for a node in its namespace. Writes the rendered config and
/// zone into a per-node run subdir and runs knotd with that dir as cwd, so the
/// config's relative `database storage`/`storage`/`rundir`/`file: zone.db`
/// resolve there (the rendered config sets `database storage: "."` so knot's
/// LMDB databases land here, not its unwritable compiled default). Backgrounded;
/// reaped when the namespace is deleted at teardown.
pub(crate) fn spawn_knot(
    run_id: &str,
    node: &str,
    ns: &str,
    conf: &str,
    zone: &str,
) -> Result<Child, LabError> {
    let dir = format!("/run/blackwall-lab/{run_id}/{node}");
    std::fs::create_dir_all(&dir).map_err(|e| LabError::Exec(format!("mkdir {dir}: {e}")))?;
    std::fs::write(format!("{dir}/knot.conf"), conf)
        .map_err(|e| LabError::Exec(format!("write knot.conf: {e}")))?;
    std::fs::write(format!("{dir}/zone.db"), zone)
        .map_err(|e| LabError::Exec(format!("write zone.db: {e}")))?;
    // knotd runs in the foreground; redirect its (verbose) output to a log file
    // so it does not inherit and hold the lab's stdout pipe open after the run.
    let log = std::fs::File::create(format!("{dir}/knotd.log"))
        .map_err(|e| LabError::Exec(format!("create knotd.log: {e}")))?;
    let log_err = log
        .try_clone()
        .map_err(|e| LabError::Exec(format!("clone knotd.log handle: {e}")))?;
    let child = Command::new("ip")
        .args(["netns", "exec", ns, "knotd", "-c", "knot.conf"])
        .current_dir(&dir)
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(log_err))
        .spawn()
        .map_err(|e| LabError::Exec(format!("spawn knotd: {e}")))?;
    Ok(child)
}

/// Module dir + binary for the from-source hsflowd build (see the lab CI/install).
const HSFLOWD_BIN: &str = "/opt/host-sflow/hsflowd";
const HSFLOWD_MODDIR: &str = "/opt/host-sflow";
/// sFlow collector port (standard) the in-namespace driver binds.
const SFLOW_COLLECTOR_PORT: u16 = 6343;
/// 1-in-N packet sampling (pinned; see the live-gate validation).
const HSFLOWD_SAMPLING: u32 = 4;

/// Launch hsflowd in `ns`, sampling the node's veth via mod_pcap and exporting
/// sFlow v5 to 127.0.0.1:6343. Foreground (`-d`), root (`-P`, needed for pcap);
/// output redirected so it cannot hold the lab's stdout pipe. Killed at teardown.
pub(crate) fn spawn_hsflowd(run_id: &str, node: &str, ns: &str) -> Result<Child, LabError> {
    // Discover the node's veth inside its namespace (first non-lo/ifb iface).
    let out = Command::new("ip")
        .args(["netns", "exec", ns, "ip", "-o", "link", "show"])
        .output()
        .map_err(|e| LabError::Exec(format!("ip link in {ns}: {e}")))?;
    let iface = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| {
            l.split(':')
                .nth(1)
                .map(str::trim)
                .and_then(|n| n.split('@').next())
                .map(str::trim)
        })
        .find(|n| !n.is_empty() && *n != "lo" && !n.starts_with("ifb"))
        .ok_or_else(|| LabError::Exec(format!("no veth in {ns}")))?
        .to_owned();

    let dir = format!("/run/blackwall-lab/{run_id}/{node}");
    std::fs::create_dir_all(&dir).map_err(|e| LabError::Exec(format!("mkdir {dir}: {e}")))?;
    let conf = crate::render::render_hsflowd_conf(
        &iface,
        "127.0.0.1",
        SFLOW_COLLECTOR_PORT,
        HSFLOWD_SAMPLING,
    );
    let conf_path = format!("{dir}/hsflowd.conf");
    std::fs::write(&conf_path, conf)
        .map_err(|e| LabError::Exec(format!("write hsflowd.conf: {e}")))?;

    let log = std::fs::File::create(format!("{dir}/hsflowd.log"))
        .map_err(|e| LabError::Exec(format!("create hsflowd.log: {e}")))?;
    let log_err = log
        .try_clone()
        .map_err(|e| LabError::Exec(format!("clone log handle: {e}")))?;
    let child = Command::new("ip")
        .args([
            "netns",
            "exec",
            ns,
            HSFLOWD_BIN,
            "-d",
            "-P",
            "-f",
            &conf_path,
            "-l",
            HSFLOWD_MODDIR,
        ])
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(log_err))
        .spawn()
        .map_err(|e| LabError::Exec(format!("spawn hsflowd: {e}")))?;
    Ok(child)
}

/// Launch a process inside `ns` with resolved environment, returning a child
/// handle the runner kills at teardown.
///
/// Runs: `ip netns exec <ns> env <KEY=VAL...> sh -c "<cmd>"`
///
/// The child leads its own process group (`process_group(0)`) so teardown can
/// signal the entire `ip → sh → <cmd>` tree, not just the `ip` parent — a
/// long-lived `run` (e.g. a `cargo test` that serves forever) spawns a
/// grandchild test binary that would otherwise survive `child.kill()` as an
/// orphan. Its output is redirected to `<rundir>/<name>/run.log` so that even a
/// momentarily-surviving descendant cannot hold the lab's stdout pipe open
/// (the same hazard handled for `knotd` in [`spawn_knot`]).
pub(crate) fn spawn_run(
    run_id: &str,
    name: &str,
    ns: &str,
    cmd: &str,
    env_resolved: &[(String, String)],
) -> Result<Child, LabError> {
    let dir = format!("/run/blackwall-lab/{run_id}/{name}");
    std::fs::create_dir_all(&dir).map_err(|e| LabError::Exec(format!("mkdir {dir}: {e}")))?;
    let log = std::fs::File::create(format!("{dir}/run.log"))
        .map_err(|e| LabError::Exec(format!("create run.log: {e}")))?;
    let log_err = log
        .try_clone()
        .map_err(|e| LabError::Exec(format!("clone run.log handle: {e}")))?;

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
        .process_group(0)
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(log_err))
        .spawn()
        .map_err(|e| LabError::Exec(format!("spawn run in {ns}: {e}")))?;
    Ok(child)
}
