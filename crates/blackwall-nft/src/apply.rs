//! Apply a rendered ruleset to the running kernel.

use crate::error::NftError;
use blackwall_core::Policy;
use nftables::helper;

/// Render `policy` and apply it to the kernel. Each call fully flushes and
/// replaces the prior `inet blackwall` table: the rendered ruleset first adds
/// the table (creating it if absent), then flushes it (atomically removing any
/// stale sets/chains from a previous apply), then re-adds all sets and chains
/// from the current policy. Services removed from the policy are therefore
/// guaranteed to be absent after apply completes.
///
/// Requires `CAP_NET_ADMIN` (run as root).
pub fn apply(policy: &Policy) -> Result<(), NftError> {
    let ruleset = crate::render::render(policy).map_err(|e| NftError::Apply(e.to_string()))?;
    helper::apply_ruleset(&ruleset).map_err(|e| NftError::Apply(e.to_string()))?;
    ensure_tproxy_route()?;
    Ok(())
}

/// Remove the deception dataplane on shutdown: delete the `inet blackwall` nft
/// table and the TPROXY policy route (fwmark rule + table). This is essential on
/// a graceful stop — if the ruleset were left in place while the engine is down,
/// the box would keep `tproxy`-diverting deception traffic to a now-dead socket
/// and silently black-hole most of the managed address space. Every step is
/// best-effort (a missing table/rule is not an error); needs `CAP_NET_ADMIN`.
pub fn teardown() {
    use std::process::Command;
    // Delete the ruleset. `.output()` swallows the "No such file" if it was
    // never applied.
    let _ = Command::new("nft")
        .args(["delete", "table", "inet", "blackwall"])
        .output();

    let table = crate::render::TPROXY_ROUTE_TABLE.to_string();
    let mark = format!("0x{:x}", crate::render::TPROXY_MARK);
    for family in [&[][..], &["-6"][..]] {
        let _ = Command::new("ip")
            .args(family)
            .args(["rule", "del", "fwmark", &mark, "lookup", &table])
            .output();
        let _ = Command::new("ip")
            .args(family)
            .args(["route", "flush", "table", &table])
            .output();
    }
}

/// Install the TPROXY policy route so deception TCP packets the ruleset marked
/// (`meta mark set` [`crate::render::TPROXY_MARK`]) are delivered to the local
/// transparent engine socket instead of being forwarded onward. Without this,
/// deception only works when the managed address is local to the box; a routed
/// managed prefix (the production case) silently fails to divert.
///
/// Sets, for IPv4 and IPv6:
///   `ip rule add fwmark <mark> lookup <table>`  (only if absent — idempotent)
///   `ip route replace local default dev lo table <table>`  (idempotent)
///
/// Needs `CAP_NET_ADMIN`. IPv6 setup is best-effort (skipped if IPv6 is off).
fn ensure_tproxy_route() -> Result<(), NftError> {
    use std::process::Command;
    let mark = format!("0x{:x}", crate::render::TPROXY_MARK);
    let table = crate::render::TPROXY_ROUTE_TABLE.to_string();

    // v4 rule (idempotent: check-then-add, since `ip rule add` never dedupes).
    let want = format!("fwmark {mark} lookup {table}");
    let shown = Command::new("ip")
        .args(["rule", "show"])
        .output()
        .map_err(|e| NftError::Apply(format!("ip rule show: {e}")))?;
    if !String::from_utf8_lossy(&shown.stdout).contains(&want) {
        let st = Command::new("ip")
            .args(["rule", "add", "fwmark", &mark, "lookup", &table])
            .status()
            .map_err(|e| NftError::Apply(format!("ip rule add: {e}")))?;
        if !st.success() {
            return Err(NftError::Apply("ip rule add fwmark failed".to_owned()));
        }
    }
    // v4 local route (replace is idempotent).
    let st = Command::new("ip")
        .args([
            "route", "replace", "local", "default", "dev", "lo", "table", &table,
        ])
        .status()
        .map_err(|e| NftError::Apply(format!("ip route replace: {e}")))?;
    if !st.success() {
        return Err(NftError::Apply("ip route replace (v4) failed".to_owned()));
    }

    // v6: best-effort (a host without IPv6 has no `ip -6` tables).
    let shown6 = Command::new("ip").args(["-6", "rule", "show"]).output();
    if let Ok(out) = shown6 {
        if !String::from_utf8_lossy(&out.stdout).contains(&want) {
            let _ = Command::new("ip")
                .args(["-6", "rule", "add", "fwmark", &mark, "lookup", &table])
                .status();
        }
        let _ = Command::new("ip")
            .args([
                "-6", "route", "replace", "local", "default", "dev", "lo", "table", &table,
            ])
            .status();
    }
    Ok(())
}
