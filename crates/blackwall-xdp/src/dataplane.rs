//! aya userspace data plane: load + attach the `xdp_filter` program and read
//! and write its four maps.
//!
//! This module is the sole I/O boundary between the pure control plane
//! ([`crate::control`]/[`crate::manager`]) and the live kernel eBPF maps. It is
//! **coverage-excluded**: every call here is an aya syscall requiring
//! `CAP_NET_ADMIN` and a live kernel, so it is exercised by the root
//! `prog_test_run` integration test and the lab gate rather than unit tests.
//!
//! The map byte layouts are the contract defined once in `blackwall-xdp-common`
//! and consumed by the eBPF program in `blackwall-xdp-ebpf`; this loader mirrors
//! them exactly. In particular the 16-byte `RATE` key is built byte-identically
//! to the eBPF side (v4 zero-padded into the low four bytes) so rate-limit
//! lookups actually match — see the `rate_key` helper.

use crate::keys::{encode_cookie_key, lpm_key, LpmKey};
use crate::manager::{XdpExecError, XdpExecutor};
use crate::XdpAction;
use async_trait::async_trait;
use aya::maps::lpm_trie::Key;
use aya::maps::{HashMap, LpmTrie, MapData, PerCpuArray};
use aya::programs::{Xdp, XdpFlags};
use aya::Ebpf;
use blackwall_core::XdpMode;
use blackwall_xdp_common::{
    CookieKeyValue, RateBucket, Stat, REASON_BLOCKLIST, REASON_PASS, REASON_RATELIMIT,
};
use ipnet::IpNet;
use std::net::IpAddr;
use std::sync::Mutex;

/// A loaded, attached `xdp_filter` program together with typed handles to its
/// four maps.
///
/// The live map writes go through a [`Mutex`] so the [`XdpExecutor`] trait
/// (whose `apply` takes `&self`) can lock and mutate them, while the aya map
/// APIs (which require `&mut`) are satisfied inside the guard. The loaded
/// [`Ebpf`] is retained to keep the program and its XDP link alive for the
/// lifetime of the data plane.
pub struct XdpDataplane {
    /// Kept alive so the loaded program and its attachment link are not dropped.
    _ebpf: Ebpf,
    /// The writable/readable map handles, behind a mutex for interior mutability.
    maps: Mutex<DataplaneMaps>,
}

/// The four typed, owned map handles taken out of the loaded [`Ebpf`].
struct DataplaneMaps {
    /// IPv4 source blocklist (`{prefixlen:u32, addr:[u8;4]}` LPM key).
    block_v4: LpmTrie<MapData, [u8; 4], u8>,
    /// IPv6 source blocklist (`{prefixlen:u32, addr:[u8;16]}` LPM key).
    block_v6: LpmTrie<MapData, [u8; 16], u8>,
    /// Per-source token buckets, keyed by the 16-byte source (v4 zero-padded).
    rate: HashMap<MapData, [u8; 16], RateBucketPod>,
    /// Per-CPU decision counters, indexed by `REASON_*`.
    stats: PerCpuArray<MapData, StatPod>,
    /// Single-entry (key `0`) map carrying the SYN-cookie secret the in-kernel
    /// fast path reads before minting a cookie.
    cookie_key: HashMap<MapData, u32, CookieKeyPod>,
    /// Protected IPv4 deception prefixes (`{prefixlen:u32, addr:[u8;4]}` LPM
    /// key); the SYN-cookie fast path answers a SYN only if its destination IP
    /// LPM-matches an entry here (B2.3b gating).
    protect_v4: LpmTrie<MapData, [u8; 4], u8>,
    /// Protected TCP destination (deception) ports, keyed by the host-native
    /// `u16` port value; the fast path answers a SYN only if its destination
    /// port is present here (B2.3b gating).
    protect_port: HashMap<MapData, u16, u8>,
}

/// Fixed map key of the sole `COOKIE_KEY` entry (mirrors the eBPF
/// `COOKIE_KEY_SLOT`).
const COOKIE_KEY_SLOT: u32 = 0;

/// `#[repr(transparent)]` newtype so the foreign [`RateBucket`] POD can carry an
/// [`aya::Pod`] impl (the orphan rule forbids implementing it directly).
#[repr(transparent)]
#[derive(Clone, Copy)]
struct RateBucketPod(RateBucket);

// SAFETY: `RateBucket` is a `#[repr(C)]` `Copy + 'static` plain-old-data struct
// of `u64` fields; `#[repr(transparent)]` makes `RateBucketPod` share its exact
// layout, so it is byte-for-byte valid as a BPF map value.
unsafe impl aya::Pod for RateBucketPod {}

/// `#[repr(transparent)]` newtype giving the foreign [`Stat`] POD an
/// [`aya::Pod`] impl for the per-CPU stats array.
#[repr(transparent)]
#[derive(Clone, Copy, Default)]
struct StatPod(Stat);

// SAFETY: `Stat` is a `#[repr(C)]` `Copy + 'static` plain-old-data struct of
// `u64` fields; `#[repr(transparent)]` makes `StatPod` share its exact layout,
// so it is byte-for-byte valid as a per-CPU BPF map value.
unsafe impl aya::Pod for StatPod {}

/// `#[repr(transparent)]` newtype giving the foreign [`CookieKeyValue`] POD an
/// [`aya::Pod`] impl for the `COOKIE_KEY` map value.
#[repr(transparent)]
#[derive(Clone, Copy)]
struct CookieKeyPod(CookieKeyValue);

// SAFETY: `CookieKeyValue` is a `#[repr(C)]` `Copy + 'static` plain-old-data
// struct of two `u64` fields; `#[repr(transparent)]` makes `CookieKeyPod` share
// its exact layout, so it is byte-for-byte valid as a BPF map value.
unsafe impl aya::Pod for CookieKeyPod {}

/// A snapshot of the data plane's per-CPU decision counters plus current map
/// occupancy.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct XdpStats {
    /// Packets/bytes that were passed (`REASON_PASS`), summed across CPUs.
    pub passed: Stat,
    /// Packets/bytes dropped by the blocklist (`REASON_BLOCKLIST`).
    pub dropped_blocklist: Stat,
    /// Packets/bytes dropped by the rate limiter (`REASON_RATELIMIT`).
    pub dropped_ratelimit: Stat,
    /// Number of blocklist entries (`BLOCK_V4` + `BLOCK_V6`).
    pub blocked_entries: u64,
    /// Number of rate-limit entries (`RATE`).
    pub ratelimit_entries: u64,
}

/// An error from loading, attaching, or writing the XDP data plane.
#[derive(Debug, thiserror::Error)]
pub enum XdpError {
    /// Loading the eBPF object or a program/map failed.
    #[error("XDP load error: {0}")]
    Load(String),
    /// Verifying or attaching the program to the interface failed.
    #[error("XDP attach error: {0}")]
    Attach(String),
    /// A map read or write failed.
    #[error("XDP map error: {0}")]
    Map(String),
}

/// Build the 16-byte `RATE` map key for `addr`, byte-identical to the eBPF side.
///
/// The eBPF program (`blackwall-xdp-ebpf/src/main.rs`) keys `RATE` as:
/// - IPv4: `let mut key16 = [0u8; 16]; key16[..4].copy_from_slice(&src);`
///   where `src = (*ip).src_addr().octets()` — the four big-endian address
///   bytes in the low four bytes, the remaining twelve left zero.
/// - IPv6: `over_rate(src)` with `src = (*ip).src_addr().octets()` — the full
///   sixteen big-endian address bytes.
///
/// This reproduces both exactly; any deviation would make rate-limit lookups
/// silently never match.
fn rate_key(addr: IpAddr) -> [u8; 16] {
    match addr {
        IpAddr::V4(a) => {
            let mut key = [0u8; 16];
            key[..4].copy_from_slice(&a.octets());
            key
        }
        IpAddr::V6(a) => a.octets(),
    }
}

/// Translate the configured [`XdpMode`] into the concrete attach flags,
/// applying them to `prog`. `Auto` tries driver mode and, on failure, retries
/// in generic (skb) mode with a warning.
fn attach_with_mode(prog: &mut Xdp, iface: &str, mode: XdpMode) -> Result<(), XdpError> {
    match mode {
        XdpMode::Native => prog
            .attach(iface, XdpFlags::DRV_MODE)
            .map(drop)
            .map_err(|e| XdpError::Attach(e.to_string())),
        XdpMode::Generic => prog
            .attach(iface, XdpFlags::SKB_MODE)
            .map(drop)
            .map_err(|e| XdpError::Attach(e.to_string())),
        XdpMode::Auto => match prog.attach(iface, XdpFlags::DRV_MODE) {
            Ok(_) => Ok(()),
            Err(e) => {
                tracing::warn!(
                    interface = iface,
                    error = %e,
                    "XDP: driver-mode attach failed; retrying in generic (skb) mode"
                );
                prog.attach(iface, XdpFlags::SKB_MODE)
                    .map(drop)
                    .map_err(|e| XdpError::Attach(e.to_string()))
            }
        },
    }
}

impl XdpDataplane {
    /// Load the embedded `xdp_filter` object, verify and attach it to `iface`
    /// under `mode`, and open typed handles to its four maps.
    ///
    /// The program is loaded and attached first (so its map relocations resolve
    /// against the in-collection maps), after which the maps are taken out of
    /// the [`Ebpf`] into owned typed handles.
    ///
    /// # Errors
    ///
    /// Returns [`XdpError::Load`] if the object, program, or any map cannot be
    /// opened, or [`XdpError::Attach`] if verification/attachment fails.
    pub fn attach(iface: &str, mode: XdpMode) -> Result<Self, XdpError> {
        let mut ebpf =
            Ebpf::load(crate::PROGRAM_OBJECT).map_err(|e| XdpError::Load(e.to_string()))?;

        {
            let prog: &mut Xdp = ebpf
                .program_mut("xdp_filter")
                .ok_or_else(|| XdpError::Load("xdp_filter program missing".to_owned()))?
                .try_into()
                .map_err(|e: aya::programs::ProgramError| XdpError::Load(e.to_string()))?;
            prog.load().map_err(|e| XdpError::Attach(e.to_string()))?;
            attach_with_mode(prog, iface, mode)?;
        }

        let maps = DataplaneMaps {
            block_v4: take_map(&mut ebpf, "BLOCK_V4")?,
            block_v6: take_map(&mut ebpf, "BLOCK_V6")?,
            rate: take_map(&mut ebpf, "RATE")?,
            stats: take_map(&mut ebpf, "STATS")?,
            cookie_key: take_map(&mut ebpf, "COOKIE_KEY")?,
            protect_v4: take_map(&mut ebpf, "PROTECT_V4")?,
            protect_port: take_map(&mut ebpf, "PROTECT_PORT")?,
        };

        Ok(Self {
            _ebpf: ebpf,
            maps: Mutex::new(maps),
        })
    }

    /// Insert `net` into the appropriate source blocklist.
    ///
    /// # Errors
    ///
    /// Returns [`XdpError::Map`] if the map write fails.
    pub fn block(&mut self, net: IpNet) -> Result<(), XdpError> {
        self.locked()?.block(net)
    }

    /// Remove `net` from the appropriate source blocklist.
    ///
    /// # Errors
    ///
    /// Returns [`XdpError::Map`] if the map delete fails.
    pub fn unblock(&mut self, net: IpNet) -> Result<(), XdpError> {
        self.locked()?.unblock(net)
    }

    /// Install a per-source token bucket rate limit for `addr`.
    ///
    /// # Errors
    ///
    /// Returns [`XdpError::Map`] if the map write fails.
    pub fn rate_limit(&mut self, addr: IpAddr, pps: u64, burst: u64) -> Result<(), XdpError> {
        self.locked()?.rate_limit(addr, pps, burst)
    }

    /// Remove any rate limit installed for `addr`.
    ///
    /// # Errors
    ///
    /// Returns [`XdpError::Map`] if the map delete fails.
    pub fn clear_rate_limit(&mut self, addr: IpAddr) -> Result<(), XdpError> {
        self.locked()?.clear_rate_limit(addr)
    }

    /// Install the 128-bit SYN-cookie secret into the `COOKIE_KEY` map so the
    /// in-kernel fast path can mint cookies. Until this is called the SYN
    /// handler falls through to `XDP_PASS` (never minting under a garbage key).
    ///
    /// The 16 bytes are split into the SipHash `(k0, k1)` little-endian pair
    /// ([`encode_cookie_key`]), byte-identical to how the userspace deception
    /// tier derives its key, so both tiers authenticate the same cookies.
    ///
    /// B2.3c: the shared secret becomes cross-daemon config-driven rather than a
    /// caller-supplied literal.
    ///
    /// # Errors
    ///
    /// Returns [`XdpError::Map`] if the map write fails.
    pub fn set_cookie_key(&mut self, key: [u8; 16]) -> Result<(), XdpError> {
        self.locked()?.set_cookie_key(key)
    }

    /// Install the box's own protected deception prefixes into `PROTECT_V4`.
    ///
    /// The in-kernel SYN-cookie fast path answers a SYN only if its destination
    /// IP LPM-matches one of these prefixes (and its destination port is a
    /// protected port). Until at least one prefix is installed the fast path
    /// answers no SYNs at all, so real services are never hijacked. Entries are
    /// additive; existing entries are retained.
    ///
    /// IPv6 prefixes are ignored here — v6 SYN-cookie gating is B2.3c (the
    /// in-kernel fast path is IPv4-only today).
    ///
    /// # Errors
    ///
    /// Returns [`XdpError::Map`] if a map write fails.
    pub fn set_protected_prefixes(&self, prefixes: &[IpNet]) -> Result<(), XdpError> {
        self.locked()?.set_protected_prefixes(prefixes)
    }

    /// Install the configured deception ports into `PROTECT_PORT`.
    ///
    /// The in-kernel SYN-cookie fast path answers a SYN only if its destination
    /// TCP port is one of these (and its destination IP matches a protected
    /// prefix). Ports are the host-native `u16` values, matching the numeric
    /// port the eBPF program reads from the packet. Entries are additive.
    ///
    /// # Errors
    ///
    /// Returns [`XdpError::Map`] if a map write fails.
    pub fn set_protected_ports(&self, ports: &[u16]) -> Result<(), XdpError> {
        self.locked()?.set_protected_ports(ports)
    }

    /// Snapshot the per-CPU stats counters and current map occupancy.
    ///
    /// Read errors are logged and reported as zeroed counters rather than
    /// surfaced, since this is a best-effort observability read.
    #[must_use]
    pub fn stats(&self) -> XdpStats {
        match self.maps.lock() {
            Ok(mut maps) => maps.stats().unwrap_or_else(|e| {
                tracing::warn!(error = %e, "XDP: stats read failed; reporting zeros");
                XdpStats::default()
            }),
            Err(_) => {
                tracing::warn!("XDP: stats read skipped; maps mutex poisoned");
                XdpStats::default()
            }
        }
    }

    /// Lock the map guard, mapping a poisoned mutex to [`XdpError::Map`].
    fn locked(&self) -> Result<std::sync::MutexGuard<'_, DataplaneMaps>, XdpError> {
        self.maps
            .lock()
            .map_err(|_| XdpError::Map("dataplane maps mutex poisoned".to_owned()))
    }
}

/// Take a map out of `ebpf` by `name` and convert it into an owned typed handle.
fn take_map<M>(ebpf: &mut Ebpf, name: &str) -> Result<M, XdpError>
where
    M: TryFrom<aya::maps::Map, Error = aya::maps::MapError>,
{
    let map = ebpf
        .take_map(name)
        .ok_or_else(|| XdpError::Load(format!("map {name} missing")))?;
    M::try_from(map).map_err(|e| XdpError::Load(format!("map {name}: {e}")))
}

impl DataplaneMaps {
    /// Insert `net` into the appropriate blocklist trie.
    fn block(&mut self, net: IpNet) -> Result<(), XdpError> {
        match lpm_key(net) {
            LpmKey::V4(k) => self
                .block_v4
                .insert(&Key::new(k.prefixlen, k.addr), 1, 0)
                .map_err(map_err),
            LpmKey::V6(k) => self
                .block_v6
                .insert(&Key::new(k.prefixlen, k.addr), 1, 0)
                .map_err(map_err),
        }
    }

    /// Remove `net` from the appropriate blocklist trie.
    fn unblock(&mut self, net: IpNet) -> Result<(), XdpError> {
        match lpm_key(net) {
            LpmKey::V4(k) => self
                .block_v4
                .remove(&Key::new(k.prefixlen, k.addr))
                .map_err(map_err),
            LpmKey::V6(k) => self
                .block_v6
                .remove(&Key::new(k.prefixlen, k.addr))
                .map_err(map_err),
        }
    }

    /// Install a fresh token bucket for `addr`.
    fn rate_limit(&mut self, addr: IpAddr, pps: u64, burst: u64) -> Result<(), XdpError> {
        let bucket = RateBucket {
            tokens: burst,
            last_ns: 0,
            rate_pps: pps,
            burst,
        };
        self.rate
            .insert(rate_key(addr), RateBucketPod(bucket), 0)
            .map_err(map_err)
    }

    /// Remove any token bucket installed for `addr`.
    fn clear_rate_limit(&mut self, addr: IpAddr) -> Result<(), XdpError> {
        self.rate.remove(&rate_key(addr)).map_err(map_err)
    }

    /// Write the SYN-cookie secret into the single-entry `COOKIE_KEY` map.
    fn set_cookie_key(&mut self, key: [u8; 16]) -> Result<(), XdpError> {
        self.cookie_key
            .insert(COOKIE_KEY_SLOT, CookieKeyPod(encode_cookie_key(key)), 0)
            .map_err(map_err)
    }

    /// Insert each IPv4 prefix into the `PROTECT_V4` trie (v6 prefixes ignored;
    /// v6 gating is B2.3c). Reuses the shared `lpm_key` encoding so the key
    /// layout is byte-identical to the blocklist trie.
    fn set_protected_prefixes(&mut self, prefixes: &[IpNet]) -> Result<(), XdpError> {
        for &net in prefixes {
            match lpm_key(net) {
                LpmKey::V4(k) => self
                    .protect_v4
                    .insert(&Key::new(k.prefixlen, k.addr), 1, 0)
                    .map_err(map_err)?,
                // B2.3c: IPv6 deception-prefix gating (the fast path is v4-only).
                LpmKey::V6(_) => {}
            }
        }
        Ok(())
    }

    /// Insert each deception port into the `PROTECT_PORT` set. The key is the
    /// host-native `u16` value, matching the numeric destination port the eBPF
    /// program reads via its big-endian packet load; the stored `1u8` value is
    /// an ignored presence marker.
    fn set_protected_ports(&mut self, ports: &[u16]) -> Result<(), XdpError> {
        for &port in ports {
            self.protect_port.insert(port, 1_u8, 0).map_err(map_err)?;
        }
        Ok(())
    }

    /// Sum the per-CPU counters and count the blocklist/rate map entries.
    fn stats(&mut self) -> Result<XdpStats, XdpError> {
        Ok(XdpStats {
            passed: self.sum_reason(REASON_PASS)?,
            dropped_blocklist: self.sum_reason(REASON_BLOCKLIST)?,
            dropped_ratelimit: self.sum_reason(REASON_RATELIMIT)?,
            blocked_entries: count_keys(self.block_v4.keys()) + count_keys(self.block_v6.keys()),
            ratelimit_entries: count_keys(self.rate.keys()),
        })
    }

    /// Sum a single reason's per-CPU counters into one [`Stat`].
    fn sum_reason(&self, reason: u32) -> Result<Stat, XdpError> {
        let values = self.stats.get(&reason, 0).map_err(map_err)?;
        let mut total = Stat::default();
        for v in values.iter() {
            total.packets = total.packets.saturating_add(v.0.packets);
            total.bytes = total.bytes.saturating_add(v.0.bytes);
        }
        Ok(total)
    }
}

/// Count the entries yielded by a map key iterator (errors end the count).
fn count_keys<I, K>(keys: I) -> u64
where
    I: IntoIterator<Item = Result<K, aya::maps::MapError>>,
{
    let mut n: u64 = 0;
    for k in keys {
        if k.is_err() {
            break;
        }
        n = n.saturating_add(1);
    }
    n
}

/// Map an aya [`aya::maps::MapError`] into [`XdpError::Map`].
fn map_err(e: aya::maps::MapError) -> XdpError {
    XdpError::Map(e.to_string())
}

/// Forwarding [`XdpExecutor`] impl for a shared handle, so the same attached
/// data plane can be moved into the [`crate::manager::XdpManager`] (as its
/// executor) while a clone is retained by the daemon for `stats()` reads
/// (`/metrics`). Delegates straight to the inner [`XdpDataplane`].
#[async_trait]
impl XdpExecutor for std::sync::Arc<XdpDataplane> {
    async fn apply(&self, action: XdpAction) -> Result<(), XdpExecError> {
        (**self).apply(action).await
    }
}

#[async_trait]
impl XdpExecutor for XdpDataplane {
    async fn apply(&self, action: XdpAction) -> Result<(), XdpExecError> {
        let result = {
            let mut maps = self.maps.lock().map_err(|_| XdpExecError)?;
            match action {
                XdpAction::Block { net } => maps.block(net),
                XdpAction::Unblock { net } => maps.unblock(net),
                XdpAction::RateLimit {
                    src, pps, burst, ..
                } => maps.rate_limit(src, pps, burst),
                XdpAction::ClearRate { src } => maps.clear_rate_limit(src),
            }
        };
        result.map_err(|e| {
            tracing::warn!(error = %e, ?action, "XDP: data-plane apply failed");
            XdpExecError
        })
    }
}
