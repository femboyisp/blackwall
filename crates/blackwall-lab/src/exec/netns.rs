//! Thin shell-outs to `ip` for namespace and link management.

use crate::assert::Captured;
use crate::error::LabError;
use std::net::IpAddr;
use std::process::Command;

/// Run a command, returning captured stdout/stderr/exit.
pub(crate) fn run(cmd: &mut Command) -> Result<Captured, LabError> {
    let out = cmd
        .output()
        .map_err(|e| LabError::Exec(format!("spawn failed: {e}")))?;
    Ok(Captured {
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        // exit code 0..=255 fits i32 without a lossy `as` cast.
        exit: out.status.code().unwrap_or(-1),
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
