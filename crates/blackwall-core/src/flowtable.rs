//! nftables flowtable configuration: which forwarding devices to accelerate.

use serde::{Deserialize, Serialize};

/// Configuration for the nftables flowtable software fast path.
///
/// A flowtable offloads *established forwarded* flows — real-service traffic to
/// a backing host, VM, or container — to the kernel's conntrack-based fast path,
/// bypassing the normal per-packet forwarding path. It only accelerates
/// forwarded traffic: deception traffic is TPROXY-diverted to the local engine
/// and never offloaded, and the box's own traffic is not forwarded.
///
/// `devices` must list every interface a real-service flow traverses — both the
/// ingress (the managed uplink) and the egress (toward the backend, e.g. a
/// container bridge). The kernel only engages offload once *both* directions'
/// devices are members of the flowtable, so an incomplete list silently
/// disables acceleration rather than misrouting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowTableConfig {
    /// Interfaces whose forwarded flows are eligible for offload. Non-empty.
    pub devices: Vec<String>,
}
