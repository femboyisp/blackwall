//! Deterministic, time-bucketed selection of the address pool and window.

use crate::error::DnsError;
use ipnet::IpNet;
use std::net::IpAddr;
use std::time::Duration;

/// The first `count` host addresses of `prefix`. Errors if the prefix yields
/// fewer than `count` hosts (the operator asked for more than it provides).
///
/// "Hosts" follows [`IpNet::hosts`]: for IPv4 the network and broadcast
/// addresses are excluded (and `/31`, `/32` collapse to their address(es)), and
/// IPv6 excludes the anycast/subnet-router address on prefixes shorter than
/// `/127`. `count` must therefore fit the *usable* host count, not `2^hostbits`.
pub fn flux_pool(prefix: &IpNet, count: usize) -> Result<Vec<IpAddr>, DnsError> {
    let pool: Vec<IpAddr> = prefix.hosts().take(count).collect();
    if pool.len() < count {
        return Err(DnsError::Config(format!(
            "prefix {prefix} yields {} hosts, need {count}",
            pool.len()
        )));
    }
    Ok(pool)
}

/// The `set` addresses active at `now_unix`: a sliding window
/// `pool[(bucket + i) % len]` for `i in 0..set`, `bucket = now / period`.
/// Stable within a period, slides by one each period, restart-stable.
///
/// The `unwrap_or` fallbacks are defensive and unreachable in practice: `len`
/// is non-zero (the empty pool returned above), `period_secs` is floored to 1,
/// and both `u64::try_from(i)`/`usize::try_from(offset % len)` fit their targets
/// on any supported platform. They keep the function total rather than panicking.
pub fn flux_window(pool: &[IpAddr], set: usize, now_unix: u64, period_secs: u64) -> Vec<IpAddr> {
    if pool.is_empty() || set == 0 {
        return Vec::new();
    }
    let len = u64::try_from(pool.len()).unwrap_or(1);
    let bucket = now_unix / period_secs.max(1);
    (0..set)
        .map(|i| {
            let offset = bucket.wrapping_add(u64::try_from(i).unwrap_or(0)) % len;
            pool[usize::try_from(offset).unwrap_or(0)]
        })
        .collect()
}

/// Time until the next period boundary after `now_unix`; a full period at an
/// exact boundary (never zero), so the push loop never spins.
pub fn next_boundary_delay(now_unix: u64, period_secs: u64) -> Duration {
    let period = period_secs.max(1);
    Duration::from_secs(period - (now_unix % period))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn flux_pool_takes_first_n_hosts_v4() {
        let pool = flux_pool(&"203.0.113.0/24".parse().unwrap(), 4).unwrap();
        assert_eq!(
            pool,
            vec![
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2)),
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 3)),
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 4)),
            ]
        );
    }

    #[test]
    fn flux_pool_errors_when_prefix_too_small() {
        // a /30 has 2 usable hosts; asking for 4 errors.
        assert!(flux_pool(&"203.0.113.0/30".parse().unwrap(), 4).is_err());
    }

    #[test]
    fn flux_pool_v6_family() {
        let pool = flux_pool(&"2001:db8::/120".parse().unwrap(), 2).unwrap();
        assert!(pool.iter().all(|ip| ip.is_ipv6()));
        assert_eq!(pool.len(), 2);
    }

    #[test]
    fn flux_window_slides_and_wraps() {
        let pool: Vec<IpAddr> = (1..=4)
            .map(|n| IpAddr::V4(Ipv4Addr::new(10, 0, 0, n)))
            .collect();
        // period 100, set 2
        assert_eq!(flux_window(&pool, 2, 0, 100), vec![pool[0], pool[1]]); // bucket 0
        assert_eq!(flux_window(&pool, 2, 100, 100), vec![pool[1], pool[2]]); // bucket 1 (slides)
        assert_eq!(flux_window(&pool, 2, 300, 100), vec![pool[3], pool[0]]); // bucket 3 wraps
        assert_eq!(flux_window(&pool, 2, 99, 100), vec![pool[0], pool[1]]); // same bucket as 0 (restart-stable)
    }

    #[test]
    fn flux_window_defensive() {
        let pool: Vec<IpAddr> = vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))];
        assert_eq!(flux_window(&pool, 1, 5, 0), vec![pool[0]]); // period 0 -> no panic
        assert!(flux_window(&[], 2, 5, 100).is_empty()); // empty pool
        assert!(flux_window(&pool, 0, 5, 100).is_empty()); // set 0
    }

    #[test]
    fn next_boundary_delay_never_zero_at_boundary() {
        assert_eq!(
            next_boundary_delay(0, 100),
            std::time::Duration::from_secs(100)
        );
        assert_eq!(
            next_boundary_delay(30, 100),
            std::time::Duration::from_secs(70)
        );
        assert_eq!(
            next_boundary_delay(100, 100),
            std::time::Duration::from_secs(100)
        );
    }
}
