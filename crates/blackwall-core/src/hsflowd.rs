//! Byte-exact renderer for `hsflowd.conf` (host-sflow `mod_pcap`).
//!
//! Samples a POP's uplink and exports sFlow v5 to the home `flow` collector.
//! The exact grammar was confirmed against host-sflow 2.1.26 during the
//! increment-2 feasibility spike.
//!
//! This is a deliberate ~6-line duplication of `blackwall-lab`'s
//! `render/hsflowd.rs` renderer: `blackwalld` must not depend on the lab
//! crate, so the shipped renderer lives here instead of being shared.

/// Render an `hsflowd.conf` that samples `iface` via `mod_pcap` at 1-in-`sampling`
/// and exports sFlow v5 to `collector_ip:collector_port`.
#[must_use]
pub fn render_hsflowd_conf(
    iface: &str,
    collector_ip: &str,
    collector_port: u16,
    sampling: u32,
) -> String {
    format!(
        "sflow {{\n  sampling = {sampling}\n  polling = 0\n  collector {{ ip = {collector_ip}  udpport = {collector_port} }}\n  pcap {{ dev = {iface} }}\n}}\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_known_good_config() {
        let got = render_hsflowd_conf("v123a", "127.0.0.1", 6343, 4);
        let want = "\
sflow {
  sampling = 4
  polling = 0
  collector { ip = 127.0.0.1  udpport = 6343 }
  pcap { dev = v123a }
}
";
        assert_eq!(got, want);
    }
}
