//! How a speedtest binds its local source (IP or interface).

use std::net::IpAddr;

/// The local source a speedtest provider binds its connections to.
///
/// On a multi-homed host this selects which uplink is measured.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum SpeedtestSource {
    /// Use the host's default route (no binding).
    #[default]
    Default,
    /// Bind to a specific local source IP.
    Ip(IpAddr),
    /// Bind to a network interface by name (Linux `SO_BINDTODEVICE`; needs `CAP_NET_RAW`).
    Iface(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn default_is_default_variant() {
        assert_eq!(SpeedtestSource::default(), SpeedtestSource::Default);
    }

    #[test]
    fn variants_are_distinct() {
        let ip = SpeedtestSource::Ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)));
        let iface = SpeedtestSource::Iface("eth0".to_owned());
        assert_ne!(ip, iface);
        assert_ne!(ip, SpeedtestSource::Default);
    }
}
