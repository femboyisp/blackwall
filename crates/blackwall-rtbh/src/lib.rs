//! Remotely-triggered blackhole (RTBH): turn a detected attack into a BGP
//! blackhole announcement. A pure [`RtbhController`] decides; a thin sink
//! (added next) executes via the BGP speaker.

pub mod controller;
pub mod manager;
pub mod sink;

pub use controller::{BlackholeOrigin, RtbhAction, RtbhConfig, RtbhController};
pub use manager::{
    ApplyOutcome, BgpError, BgpExecutor, BlackholeJournal, JournalError, RtbhManager,
};
pub use sink::RtbhSink;

/// Executes BGP commands against a live session via [`blackwall_bgp::BgpHandle`].
#[async_trait::async_trait]
impl manager::BgpExecutor for blackwall_bgp::BgpHandle {
    async fn announce(&self, route: blackwall_bgp::Route) -> Result<(), manager::BgpError> {
        blackwall_bgp::BgpHandle::announce(self, route)
            .await
            .map_err(Into::into)
    }
    async fn withdraw(&self, prefix: ipnet::IpNet) -> Result<(), manager::BgpError> {
        blackwall_bgp::BgpHandle::withdraw(self, prefix)
            .await
            .map_err(Into::into)
    }
}
