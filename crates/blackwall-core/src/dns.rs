//! DNS fast-flux configuration parsed from the policy DSL.

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

/// Configuration for rotating a DNS name's A/AAAA records over time via
/// TSIG-authenticated RFC-2136 dynamic updates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsFluxConfig {
    /// Authoritative server to send UPDATEs to (port defaults to 53 in the parser).
    pub server: SocketAddr,
    /// Zone to update (FQDN).
    pub zone: String,
    /// Record name to flux (FQDN).
    pub name: String,
    /// Prefix the address pool is drawn from.
    pub prefix: IpNet,
    /// Pool size: the first `count` host addresses of `prefix`.
    pub count: usize,
    /// Records returned per window (`set <= count`).
    pub set: usize,
    /// How long each window stays active before the next set is selected.
    pub period: Duration,
    /// Record TTL in seconds.
    pub ttl: u32,
    /// Path to the BIND-format TSIG key file.
    pub tsig_path: PathBuf,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_flux_config_round_trips_through_json() {
        let c = DnsFluxConfig {
            server: "192.0.2.53:53".parse().unwrap(),
            zone: "example.com".to_owned(),
            name: "www.example.com".to_owned(),
            prefix: "203.0.113.0/24".parse().unwrap(),
            count: 8,
            set: 3,
            period: Duration::from_secs(300),
            ttl: 30,
            tsig_path: PathBuf::from("/etc/blackwall/knot.tsig"),
        };
        let json = serde_json::to_string(&c).unwrap();
        assert_eq!(c, serde_json::from_str(&json).unwrap());
    }
}
