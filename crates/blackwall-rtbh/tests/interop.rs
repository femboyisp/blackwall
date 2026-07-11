//! Manual/netns interop exercise: drives an `RtbhManager` (auto-detection +
//! operator-manual paths) against a real BGP peer to announce /32 blackholes
//! (community 65535:666) via the native speaker. Ignored in CI; run by the
//! lab's rtbh-bird scenario.
//!   BW_BGP_PEER=10.0.0.1:179 cargo test -p blackwall-rtbh --test interop -- --ignored --nocapture

use async_trait::async_trait;
use blackwall_bgp::{spawn, PeerConfig};
use blackwall_flow::{AttackKind, Detection, DetectionEvent, Severity};
use blackwall_rtbh::{
    ApplyOutcome, BlackholeJournal, BlackholeOrigin, JournalError, RtbhConfig, RtbhController,
    RtbhManager,
};
use std::net::IpAddr;
use std::time::Duration;

/// A no-op journal: this test only exercises the BGP path against real BIRD,
/// not persistence (covered elsewhere with fakes / real Postgres).
struct NoopJournal;

#[async_trait]
impl BlackholeJournal for NoopJournal {
    async fn record_announce(
        &self,
        _target: IpAddr,
        _origin: BlackholeOrigin,
        _at_ms: u64,
    ) -> Result<(), JournalError> {
        Ok(())
    }
    async fn record_withdraw(&self, _target: IpAddr, _at_ms: u64) -> Result<(), JournalError> {
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a live BGP peer (BIRD); run in the netns lab"]
async fn blackholes_a_detected_target() {
    let peer: std::net::SocketAddr = std::env::var("BW_BGP_PEER")
        .expect("set BW_BGP_PEER=ip:179")
        .parse()
        .unwrap();
    let (handle, _join) = spawn(PeerConfig {
        local_asn: 214_806,
        peer_asn: 214_806,
        peer_addr: peer,
        router_id: "10.222.255.99".parse().unwrap(),
        hold_time: 90,
        md5: None,
        gtsm_hops: None,
    })
    .expect("valid iBGP config");
    tokio::time::sleep(Duration::from_secs(3)).await; // let the session establish

    let controller = RtbhController::new(RtbhConfig {
        eligible_prefixes: vec!["203.0.113.0/24".parse().unwrap()],
        blackhole_communities: vec![(65535, 666)],
        next_hop_v4: Some("10.222.255.99".parse().unwrap()),
        next_hop_v6: None,
        max_blackholes: 64,
        hold_down: Duration::from_secs(0),
        max_ttl: None,
    });
    let mut manager = RtbhManager::new(controller, handle, NoopJournal);

    // Auto path: a synthetic detection drives the controller to announce.
    manager
        .apply_event(
            &DetectionEvent::Opened(Detection {
                target: "203.0.113.7".parse().unwrap(),
                kind: AttackKind::Volumetric,
                observed_pps: 200_000.0,
                observed_bps: 2e9,
                proto: 17,
                top_sources: vec![],
                top_ports: vec![],
                pops: vec![],
                top_source_blocks: vec![],
                severity: Severity::High,
                first_seen_ms: 0,
                last_seen_ms: 0,
            }),
            1000,
            1000,
        )
        .await;

    // Manual path: an operator directly blackholes a second target.
    let outcome = manager
        .apply_add("203.0.113.8".parse().unwrap(), 1000, 1000)
        .await;
    assert_eq!(outcome, ApplyOutcome::Applied);

    tokio::time::sleep(Duration::from_secs(5)).await; // let BIRD import + the scenario assert
}
