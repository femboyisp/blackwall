//! Per-instance kernel-resource identity.
//!
//! Multiple `blackwalld` instances on one box (e.g. one per ingress path — the
//! main uplink and a separate IX-peering NIC) share three global kernel
//! resources that would otherwise collide:
//!
//! 1. the nft table (`inet blackwall`) — every apply does `add table` +
//!    `flush table`, so two instances flush-wipe each other's rules on every
//!    apply;
//! 2. the TPROXY fwmark — the mark the ruleset stamps and the policy route
//!    matches;
//! 3. the TPROXY policy route table — teardown runs `ip rule del fwmark …` +
//!    `ip route flush table …`, so one instance stopping rips out the shared
//!    tproxy plumbing the other still needs.
//!
//! [`InstanceIds`] derives all three from the optional `instance=<name>`
//! directive so distinct instances never touch each other's resources. With no
//! `instance=` set (the default and only prior behaviour) the identity is
//! exactly today's: table `blackwall`, mark `0x1`, route table `100`.

use std::borrow::Cow;

/// Default nft table name (no `instance=` set).
pub const DEFAULT_NFT_TABLE: &str = "blackwall";
/// Default TPROXY fwmark (no `instance=` set).
pub const DEFAULT_TPROXY_MARK: u32 = 0x1;
/// Default TPROXY policy-route table id (no `instance=` set).
pub const DEFAULT_ROUTE_TABLE: u32 = 100;

/// The nft table name, TPROXY fwmark, and policy-route table id for one
/// `blackwalld` instance. Build with [`InstanceIds::derive`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceIds {
    /// nft table name: `blackwall` (default) or `blackwall_<name>`.
    pub nft_table: Cow<'static, str>,
    /// TPROXY fwmark stamped by the ruleset and matched by the policy route.
    pub tproxy_mark: u32,
    /// Policy-route table id for the TPROXY local-delivery route.
    pub route_table: u32,
}

impl InstanceIds {
    /// Derive the identity from an optional `instance=<name>`.
    ///
    /// `None` → today's exact defaults (`blackwall` / `0x1` / `100`), so
    /// existing single-instance deployments are unchanged. `Some(name)` →
    /// `blackwall_<name>` plus a mark and a route-table id taken from two
    /// **independent** 32-bit halves of a 64-bit hash of `name`. The mark always
    /// has bit 31 set (so it is never the default `0x1`, and never equals the
    /// route id, which has bit 31 clear); the route id is always ≥ `0x4000_0000`
    /// (so never the default `100`, and a valid 32-bit kernel table id). Because
    /// the mark and route id come from different halves, a collision between two
    /// distinct names is ~1/2³¹ on each — effectively never — and the table name
    /// (which embeds `name` verbatim) never collides at all. Distinct instances
    /// MUST use distinct names.
    #[must_use]
    pub fn derive(instance: Option<&str>) -> Self {
        match instance {
            None => Self {
                nft_table: Cow::Borrowed(DEFAULT_NFT_TABLE),
                tproxy_mark: DEFAULT_TPROXY_MARK,
                route_table: DEFAULT_ROUTE_TABLE,
            },
            Some(name) => {
                let h = fnv1a64(name);
                let lo = (h & 0xffff_ffff) as u32;
                let hi = (h >> 32) as u32;
                Self {
                    nft_table: Cow::Owned(format!("blackwall_{name}")),
                    // Bit 31 set: never the default 0x1, never equals route_table.
                    tproxy_mark: 0x8000_0000 | (lo & 0x7fff_ffff),
                    // Bit 30 set, bit 31 clear: a valid 32-bit kernel table id,
                    // never the default 100, drawn from the OTHER hash half.
                    route_table: 0x4000_0000 | (hi & 0x3fff_ffff),
                }
            }
        }
    }
}

/// 64-bit FNV-1a hash — small, dependency-free, and stable across runs (so an
/// instance keeps the same mark/route-table id across restarts). The two 32-bit
/// halves are used independently for the mark and the route id.
fn fnv1a64(s: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.bytes() {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn none_yields_todays_defaults() {
        let ids = InstanceIds::derive(None);
        assert_eq!(ids.nft_table, "blackwall");
        assert_eq!(ids.tproxy_mark, 0x1);
        assert_eq!(ids.route_table, 100);
    }

    #[test]
    fn named_instance_namespaces_all_three_resources() {
        let ids = InstanceIds::derive(Some("ix"));
        assert_eq!(ids.nft_table, "blackwall_ix");
        // Never the defaults.
        assert_ne!(ids.tproxy_mark, DEFAULT_TPROXY_MARK);
        assert_ne!(ids.route_table, DEFAULT_ROUTE_TABLE);
        // Mark and route id are distinct numbers (different high words).
        assert_ne!(ids.tproxy_mark, ids.route_table);
    }

    #[test]
    fn distinct_names_get_distinct_resources() {
        let a = InstanceIds::derive(Some("ix"));
        let b = InstanceIds::derive(Some("wan"));
        assert_ne!(a.nft_table, b.nft_table);
        assert_ne!(a.tproxy_mark, b.tproxy_mark);
        assert_ne!(a.route_table, b.route_table);
    }

    #[test]
    fn derivation_is_stable_across_calls() {
        // An instance must keep the same mark/route id across restarts, or a
        // restart would orphan the prior instance's tproxy rule/route.
        assert_eq!(
            InstanceIds::derive(Some("ix")),
            InstanceIds::derive(Some("ix"))
        );
    }
}
