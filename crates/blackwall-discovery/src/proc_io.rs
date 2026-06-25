//! Reads the real `/proc/net` files. Thin I/O wrapper around the pure parser
//! in `host.rs`; root/daemon-bound and excluded from coverage.

use crate::error::DiscoveryError;
use crate::host::{parse_proc_net, ListeningSocket};
use blackwall_core::L4Proto;
use std::path::Path;

/// Scan all four `/proc/net` socket files under `proc_root` (normally `/proc`)
/// and return every listening socket.
pub fn scan_host_sockets(proc_root: &Path) -> Result<Vec<ListeningSocket>, DiscoveryError> {
    let mut out = Vec::new();
    for (file, proto, v6) in [
        ("tcp", L4Proto::Tcp, false),
        ("tcp6", L4Proto::Tcp, true),
        ("udp", L4Proto::Udp, false),
        ("udp6", L4Proto::Udp, true),
    ] {
        let path = proc_root.join("net").join(file);
        match std::fs::read_to_string(&path) {
            Ok(contents) => out.extend(parse_proc_net(&contents, proto, v6)?),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => return Err(DiscoveryError::Io(err)),
        }
    }
    Ok(out)
}
