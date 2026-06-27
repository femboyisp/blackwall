//! The RFC-2136 change to apply, as plain data (mapped to the wire in `send_net`).

use std::net::IpAddr;

/// A DNS record family this milestone fluxes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordKind {
    /// IPv4 `A`.
    A,
    /// IPv6 `AAAA`.
    Aaaa,
}

/// The set of changes for one update: clear both families at the name, then add
/// the window's addresses at `ttl`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdatePlan {
    /// RRset families to delete at the name (always both, to clear stale records).
    pub deletes: Vec<RecordKind>,
    /// Records to add: each address with its family.
    pub adds: Vec<(IpAddr, RecordKind)>,
    /// TTL (seconds) for the added records.
    pub ttl: u32,
}

/// Build the update plan for `ips` at `ttl`: delete A + AAAA, add each ip as its
/// family's record.
pub fn build_update(ttl: u32, ips: &[IpAddr]) -> UpdatePlan {
    let adds = ips
        .iter()
        .map(|ip| {
            let kind = match ip {
                IpAddr::V4(_) => RecordKind::A,
                IpAddr::V6(_) => RecordKind::Aaaa,
            };
            (*ip, kind)
        })
        .collect();
    UpdatePlan {
        deletes: vec![RecordKind::A, RecordKind::Aaaa],
        adds,
        ttl,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn build_update_deletes_both_families_and_adds_per_ip() {
        let ips = vec![
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8)),
        ];
        let plan = build_update(30, &ips);
        assert_eq!(plan.deletes, vec![RecordKind::A, RecordKind::Aaaa]);
        assert_eq!(plan.adds.len(), 2);
        assert!(plan.adds.iter().all(|(_, k)| *k == RecordKind::A));
        assert_eq!(plan.ttl, 30);
    }

    #[test]
    fn build_update_maps_v6_to_aaaa() {
        let ips = vec!["2001:db8::1".parse().unwrap()];
        let plan = build_update(60, &ips);
        assert_eq!(plan.adds[0].1, RecordKind::Aaaa);
    }
}
