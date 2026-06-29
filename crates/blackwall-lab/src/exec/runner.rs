//! Orchestrate a lab run: realize plan -> run scenario -> report -> teardown.

use crate::addr::{allocate, resolve_env, AddressMap};
use crate::assert::{evaluate, StepOutcome};
use crate::error::LabError;
use crate::exec::{netns, proc};
use crate::plan::{compile, ExecutionPlan, Op};
use crate::report::{to_junit, to_tap, RunReport, ScenarioResult, StepResult};
use crate::topology::model::{DaemonKind, Manifest, Step};
use crate::topology::{parse_manifest, validate};
use std::process::Child;
use std::sync::atomic::{AtomicU32, Ordering};

static RUN_SEQ: AtomicU32 = AtomicU32::new(0);

/// Generate a short (6-char) run id, unique within this host/process.
/// Used by `lab test` (self-tearing-down, so it needs no later discovery).
fn run_id() -> String {
    let pid = std::process::id();
    let seq = RUN_SEQ.fetch_add(1, Ordering::Relaxed);
    // 6 lowercase hex chars from pid+seq; not cryptographic.
    format!(
        "{:06x}",
        (pid.wrapping_mul(31).wrapping_add(seq)) & 0x00ff_ffff
    )
}

/// Deterministic run id derived from a topology name, so interactive
/// `up` / `shell` / `down <scenario>` all compute the same namespace names.
/// (FNV-1a 32-bit, low 24 bits hex-encoded.) Concurrent runs of the *same*
/// scenario would collide — acceptable interactively; `test` uses the unique
/// id above for CI concurrency.
fn run_id_stable(topology: &str) -> String {
    let mut hash: u32 = 0x811c_9dc5;
    for b in topology.bytes() {
        hash ^= u32::from(b);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    format!("{:06x}", hash & 0x00ff_ffff)
}

/// Guard that tears down a run's namespaces and kills tracked children on drop.
struct Teardown {
    run_id: String,
    netns: Vec<String>,
    children: Vec<Child>,
}

impl Drop for Teardown {
    fn drop(&mut self) {
        for child in &mut self.children {
            // Runs lead their own process group (see `proc::spawn_run`), so kill
            // the whole `ip → sh → <cmd>` tree by its negative pgid — otherwise a
            // long-lived grandchild (e.g. a `cargo test` serving forever) is
            // orphaned and holds the lab's stdout pipe open, hanging the caller.
            // Best-effort: daemons that are not group leaders (knotd's `ip`) have
            // no such group and the signal is a harmless no-op; `child.kill()`
            // below still reaps them as before.
            let _ = std::process::Command::new("kill")
                .args(["-KILL", &format!("-{}", child.id())])
                .status();
            let _ = child.kill();
            let _ = child.wait();
        }
        for ns in &self.netns {
            let _ = netns::netns_del(ns);
        }
        // Remove this run's scratch dir (bird + knot config/state/sockets).
        let _ = std::fs::remove_dir_all(format!("/run/blackwall-lab/{}", self.run_id));
    }
}

/// Realize a plan's namespaces/links/daemons/runs.
///
/// Returns handles to any background-spawned run processes so the caller's
/// [`Teardown`] guard can kill them at teardown.
fn realize(plan: &ExecutionPlan, map: &AddressMap) -> Result<Vec<Child>, LabError> {
    let mut children = Vec::new();

    for op in &plan.ops {
        match op {
            Op::CreateNetns(ns) => netns::netns_add(ns)?,
            Op::SetLoopbackUp(ns) => netns::loopback_up(ns)?,
            Op::CreateVethPair { a, b } => netns::veth_add(a, b)?,
            Op::MoveIface { iface, netns: ns } => netns::iface_to_ns(iface, ns)?,
            Op::SetIfaceUp { netns: ns, iface } => netns::iface_up(ns, iface)?,
            Op::AddAddr {
                netns: ns,
                iface,
                addr,
                prefix,
            } => {
                netns::addr_add(ns, iface, *addr, *prefix)?;
            }
            Op::WriteConfig { .. } => {
                // Contents are rendered; the owning daemon (spawn_bird/spawn_knot)
                // writes them to its run dir at spawn time.
            }
            Op::SpawnDaemon {
                netns: ns,
                node,
                config_key,
                kind,
            } => {
                let lookup = |key: &str| {
                    plan.ops.iter().find_map(|o| match o {
                        Op::WriteConfig { key: k, contents } if k == key => Some(contents.clone()),
                        _ => None,
                    })
                };
                let contents = lookup(config_key)
                    .ok_or_else(|| LabError::Exec(format!("missing config {config_key}")))?;
                match kind {
                    DaemonKind::Bird => proc::spawn_bird(&plan.run_id, node, ns, &contents)?,
                    DaemonKind::Knot => {
                        let zone = lookup(&format!("knot-zone:{node}"))
                            .ok_or_else(|| LabError::Exec(format!("missing zone for {node}")))?;
                        // knotd runs in the foreground; track it so teardown
                        // kills it (unlike bird, which daemonizes itself).
                        let child = proc::spawn_knot(&plan.run_id, node, ns, &contents, &zone)?;
                        children.push(child);
                    }
                    DaemonKind::WireGuard => {
                        return Err(LabError::Exec(format!("daemon {kind:?} not realized")));
                    }
                }
            }
            Op::SpawnRun {
                netns: ns,
                name,
                cmd,
                env,
            } => {
                let resolved: Vec<(String, String)> = env
                    .iter()
                    .map(|(k, v)| Ok((k.clone(), resolve_env(v, map)?)))
                    .collect::<Result<_, LabError>>()?;
                let child = proc::spawn_run(&plan.run_id, name, ns, cmd, &resolved)?;
                children.push(child);
            }
        }
    }
    Ok(children)
}

/// `lab test` for a single scenario file: returns true if all steps passed.
pub(crate) fn run_test(manifest_text: &str, junit_path: Option<&str>) -> Result<bool, LabError> {
    let manifest = parse_manifest(manifest_text)?;
    validate(&manifest.topology)?;
    let id = run_id();
    let map = allocate(&manifest.topology)?;
    let plan = compile(&manifest.topology, &map, &id)?;

    let mut guard = Teardown {
        run_id: id.clone(),
        netns: plan.netns.clone(),
        children: Vec::new(),
    };
    {
        let cleanup = plan.netns.clone();
        // Best-effort SIGINT cleanup; Drop covers normal/panic/error exits.
        // Captures only this run's namespaces, so it assumes one `run_test` per
        // process — a second `set_handler` returns Err and is ignored here.
        let _ = ctrlc::set_handler(move || {
            for ns in &cleanup {
                let _ = netns::netns_del(ns);
            }
            std::process::exit(130);
        });
    }

    guard.children = realize(&plan, &map)?;

    let mut scenarios = Vec::new();
    let mut all_pass = true;
    for sc in &manifest.scenarios {
        let mut steps = Vec::new();
        for step in &sc.steps {
            let (name, outcome) = run_step(&id, &manifest, step);
            if matches!(outcome, StepOutcome::Fail(_)) {
                all_pass = false;
            }
            steps.push(StepResult { name, outcome });
        }
        scenarios.push(ScenarioResult {
            name: sc.name.clone(),
            steps,
        });
    }

    let report = RunReport { scenarios };
    print!("{}", to_tap(&report));
    if let Some(path) = junit_path {
        std::fs::write(path, to_junit(&report))
            .map_err(|e| LabError::Exec(format!("write junit: {e}")))?;
    }
    Ok(all_pass)
}

/// Resolve the namespace for a node by name.
fn ns_for(manifest: &Manifest, id: &str, node: &str) -> String {
    manifest
        .topology
        .nodes
        .iter()
        .find(|n| n.name == node)
        .and_then(|n| n.netns.clone())
        .unwrap_or_else(|| crate::plan::netns_name(id, node))
}

/// Execute one scenario step, returning (label, outcome).
fn run_step(id: &str, manifest: &Manifest, step: &Step) -> (String, StepOutcome) {
    match step {
        Step::Wait {
            node,
            until,
            timeout,
        } => {
            let ns = ns_for(manifest, id, node);
            let label = format!("wait {until}");
            match proc::wait_until(id, node, &ns, until, *timeout) {
                Ok(()) => (label, StepOutcome::Pass),
                Err(e) => (label, StepOutcome::Fail(e.to_string())),
            }
        }
        Step::Exec { node, action, cmd } => {
            let ns = ns_for(manifest, id, node);
            let line = cmd.clone().or_else(|| action.clone()).unwrap_or_default();
            let label = format!("exec {line}");
            match proc::assert_cmd(id, node, &ns, &line) {
                Ok(_) => (label, StepOutcome::Pass),
                Err(e) => (label, StepOutcome::Fail(e.to_string())),
            }
        }
        Step::Assert {
            node,
            cmd,
            matcher,
            timeout,
        } => {
            let ns = ns_for(manifest, id, node);
            let label = format!("assert {cmd}");
            let deadline = std::time::Instant::now() + *timeout;
            loop {
                match proc::assert_cmd(id, node, &ns, cmd) {
                    Ok(cap) => {
                        if let StepOutcome::Pass = evaluate(matcher, &cap) {
                            return (label, StepOutcome::Pass);
                        }
                        if std::time::Instant::now() >= deadline {
                            return (label, evaluate(matcher, &cap));
                        }
                    }
                    Err(e) => {
                        if std::time::Instant::now() >= deadline {
                            return (label, StepOutcome::Fail(e.to_string()));
                        }
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(250));
            }
        }
    }
}

/// Tear down every lab namespace on this host (`lab down` with no arg).
pub(crate) fn down_all() -> Result<(), LabError> {
    let c = netns::run(std::process::Command::new("ip").args(["netns", "list"]))?;
    for line in c.stdout.lines() {
        if let Some(ns) = line.split_whitespace().next() {
            if ns.starts_with("bw-") {
                netns::netns_del(ns)?;
            }
        }
    }
    // Remove every run's scratch dir along with the namespace sweep.
    let _ = std::fs::remove_dir_all("/run/blackwall-lab");
    Ok(())
}

/// `lab up`: realize the topology with a stable id and leave it standing.
pub(crate) fn up(manifest_text: &str) -> Result<(), LabError> {
    let manifest = parse_manifest(manifest_text)?;
    validate(&manifest.topology)?;
    let id = run_id_stable(&manifest.topology.name);
    let map = allocate(&manifest.topology)?;
    let plan = compile(&manifest.topology, &map, &id)?;
    // Children are intentionally leaked — the namespaces stay up.
    let _ = realize(&plan, &map)?;
    println!(
        "lab up: {} ({} namespaces)",
        manifest.topology.name,
        plan.netns.len()
    );
    for ns in &plan.netns {
        println!("  {ns}");
    }
    println!("shell in with: lab shell <scenario.kdl> <node>");
    Ok(())
}

/// `lab down <scenario>`: tear down just this scenario's namespaces.
pub(crate) fn down_scenario(manifest_text: &str) -> Result<(), LabError> {
    let manifest = parse_manifest(manifest_text)?;
    let id = run_id_stable(&manifest.topology.name);
    for node in &manifest.topology.nodes {
        let ns = node
            .netns
            .clone()
            .unwrap_or_else(|| crate::plan::netns_name(&id, &node.name));
        netns::netns_del(&ns)?;
    }
    // Remove this scenario's run scratch dir (stable id).
    let _ = std::fs::remove_dir_all(format!("/run/blackwall-lab/{id}"));
    Ok(())
}

/// `lab status`: list standing lab namespaces on this host.
pub(crate) fn status() -> Result<(), LabError> {
    let c = netns::run(std::process::Command::new("ip").args(["netns", "list"]))?;
    for line in c.stdout.lines() {
        if let Some(ns) = line.split_whitespace().next() {
            if ns.starts_with("bw-") {
                println!("{ns}");
            }
        }
    }
    Ok(())
}

/// `lab shell <scenario> <node>`: open an interactive shell in a node's
/// namespace (inherits this process's stdio). Returns the shell's exit code.
pub(crate) fn shell(manifest_text: &str, node: &str) -> Result<i32, LabError> {
    let manifest = parse_manifest(manifest_text)?;
    let id = run_id_stable(&manifest.topology.name);
    let target = manifest
        .topology
        .nodes
        .iter()
        .find(|n| n.name == node)
        .ok_or_else(|| LabError::Exec(format!("unknown node `{node}`")))?;
    let ns = target
        .netns
        .clone()
        .unwrap_or_else(|| crate::plan::netns_name(&id, node));
    let sh = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_owned());
    let status = std::process::Command::new("ip")
        .args(["netns", "exec", &ns, &sh])
        .status()
        .map_err(|e| LabError::Exec(format!("shell: {e}")))?;
    Ok(status.code().unwrap_or(-1))
}
