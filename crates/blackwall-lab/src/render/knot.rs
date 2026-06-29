//! Render Knot DNS config + initial zone for a `knot` daemon.

use crate::error::LabError;
use crate::topology::model::Daemon;

fn get<'a>(daemon: &'a Daemon, key: &str) -> Result<&'a str, LabError> {
    daemon
        .settings
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| LabError::Plan(format!("knot daemon missing `{key}`")))
}

/// Render `knot.conf` for a `knot` daemon from its settings (`zone`,
/// `tsig-name`, `tsig-algo`, `tsig-secret`). Uses fixed relative paths
/// (`storage: "."`, `file: zone.db`) so the executor's per-node cwd resolves
/// them; listens on `0.0.0.0@53`; grants TSIG-keyed `update` ACL.
///
/// # Errors
/// Returns [`LabError::Plan`] if a required setting is absent.
pub fn render_knot_conf(daemon: &Daemon) -> Result<String, LabError> {
    let zone = get(daemon, "zone")?;
    let name = get(daemon, "tsig-name")?;
    let algo = get(daemon, "tsig-algo")?;
    let secret = get(daemon, "tsig-secret")?;
    Ok(format!(
        "server:\n    rundir: \".\"\n    listen: 0.0.0.0@53\n\nkey:\n  - id: {name}\n    algorithm: {algo}\n    secret: {secret}\n\nacl:\n  - id: {name}-acl\n    key: {name}\n    action: update\n\ntemplate:\n  - id: default\n    storage: \".\"\n    zonefile-sync: -1\n    zonefile-load: difference\n    journal-content: changes\n\nzone:\n  - domain: {zone}\n    file: zone.db\n    acl: {name}-acl\n"
    ))
}

/// Render the initial zone file (SOA + NS) for the daemon's `zone`. DDNS adds
/// the A/AAAA records at runtime.
///
/// # Errors
/// Returns [`LabError::Plan`] if `zone` is absent.
pub fn render_zone(daemon: &Daemon) -> Result<String, LabError> {
    let zone = get(daemon, "zone")?;
    Ok(format!(
        "$ORIGIN {zone}.\n\
$TTL 3600\n\
@   SOA ns.{zone}. admin.{zone}. 1 3600 600 86400 30\n\
@   NS  ns.{zone}.\n\
ns  A   127.0.0.1\n"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::topology::model::{Daemon, DaemonKind};
    use std::collections::BTreeMap;

    fn knot_daemon() -> Daemon {
        let mut settings = BTreeMap::new();
        settings.insert("zone".to_owned(), "lab.test".to_owned());
        settings.insert("tsig-name".to_owned(), "lab-key".to_owned());
        settings.insert("tsig-algo".to_owned(), "hmac-sha256".to_owned());
        settings.insert("tsig-secret".to_owned(), "aGVsbG8tdGhpcy1pcy1hLWxhYi1rZXk=".to_owned());
        Daemon { kind: DaemonKind::Knot, settings }
    }

    #[test]
    fn renders_knot_conf() {
        let out = render_knot_conf(&knot_daemon()).unwrap();
        let expected = concat!(
            "server:\n",
            "    rundir: \".\"\n",
            "    listen: 0.0.0.0@53\n",
            "\n",
            "key:\n",
            "  - id: lab-key\n",
            "    algorithm: hmac-sha256\n",
            "    secret: aGVsbG8tdGhpcy1pcy1hLWxhYi1rZXk=\n",
            "\n",
            "acl:\n",
            "  - id: lab-key-acl\n",
            "    key: lab-key\n",
            "    action: update\n",
            "\n",
            "template:\n",
            "  - id: default\n",
            "    storage: \".\"\n",
            "    zonefile-sync: -1\n",
            "    zonefile-load: difference\n",
            "    journal-content: changes\n",
            "\n",
            "zone:\n",
            "  - domain: lab.test\n",
            "    file: zone.db\n",
            "    acl: lab-key-acl\n",
        );
        assert_eq!(out, expected);
    }

    #[test]
    fn renders_zone() {
        let out = render_zone(&knot_daemon()).unwrap();
        let expected = concat!(
            "$ORIGIN lab.test.\n",
            "$TTL 3600\n",
            "@   SOA ns.lab.test. admin.lab.test. 1 3600 600 86400 30\n",
            "@   NS  ns.lab.test.\n",
            "ns  A   127.0.0.1\n",
        );
        assert_eq!(out, expected);
    }

    #[test]
    fn errors_on_missing_setting() {
        let mut d = knot_daemon();
        d.settings.remove("tsig-secret");
        assert!(matches!(render_knot_conf(&d), Err(LabError::Plan(_))));
    }
}
