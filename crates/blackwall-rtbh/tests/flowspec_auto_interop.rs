//! Auto-mitigation gate: drives the pure concentration-based `select()` from
//! `blackwall-flow` against two synthetic detections, then executes the
//! chosen mitigation's manager against a real BGP peer (BIRD2):
//!   - a concentrated attack (one dominant port) selects FlowSpec, and the
//!     `FlowSpecManager` announces a flow-scoped drop rule for it;
//!   - a diffuse attack (weight spread across many ports) selects RTBH, and
//!     the `RtbhManager` announces a /32 blackhole for it.
//!
//! This proves the whole path — selection, codec, session — end to end
//! against real BIRD, not just the pure `select()` unit tests (Task 2) or
//! the individual FlowSpec/RTBH BIRD gates (C2a/C1b) in isolation.
//!
//! Same RFC 8955 §6 "safe update" validation gotcha as `flowspec_interop.rs`
//! (in `blackwall-bgp/tests`): BIRD only accepts a FlowSpec route whose
//! destination is covered by a unicast route from the same origin AS, so we
//! announce a covering `203.0.113.0/24` route before the FlowSpec rule.
//!   BW_BGP_PEER=10.0.0.1:179 cargo test -p blackwall-rtbh --test flowspec_auto_interop -- --ignored --nocapture

use async_trait::async_trait;
use blackwall_bgp::{spawn, FlowSpecRule, Origin, PeerConfig, Route};
use blackwall_flow::{
    select, AttackKind, Detection, DetectionEvent, Mitigation, SelectionConfig, Severity,
};
use blackwall_rtbh::{
    BlackholeJournal, BlackholeOrigin, FlowSpecConfig, FlowSpecController, FlowSpecJournal,
    FlowSpecManager, JournalError, RtbhConfig, RtbhController, RtbhManager,
};
use std::net::IpAddr;
use std::time::Duration;

/// A no-op RTBH journal: this test only exercises the BGP path against real
/// BIRD, not persistence (covered elsewhere with fakes / real Postgres).
struct NoopBlackholeJournal;

#[async_trait]
impl BlackholeJournal for NoopBlackholeJournal {
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

/// A no-op FlowSpec journal, for the same reason.
struct NoopFlowSpecJournal;

#[async_trait]
impl FlowSpecJournal for NoopFlowSpecJournal {
    async fn record_announce(
        &self,
        _rule: FlowSpecRule,
        _origin: BlackholeOrigin,
        _at_ms: u64,
    ) -> Result<(), JournalError> {
        Ok(())
    }
    async fn record_withdraw(&self, _rule: FlowSpecRule, _at_ms: u64) -> Result<(), JournalError> {
        Ok(())
    }
}

fn concentrated_detection() -> Detection {
    Detection {
        target: "203.0.113.7".parse().unwrap(),
        kind: AttackKind::Volumetric,
        observed_pps: 200_000.0,
        observed_bps: 2e9,
        proto: 17,
        top_sources: vec![],
        top_ports: vec![(53, 0.95)],
        pops: vec![],
        top_source_blocks: vec![],
        severity: Severity::High,
        first_seen_ms: 0,
        last_seen_ms: 0,
    }
}

fn diffuse_detection() -> Detection {
    Detection {
        target: "203.0.113.8".parse().unwrap(),
        kind: AttackKind::Volumetric,
        observed_pps: 200_000.0,
        observed_bps: 2e9,
        proto: 17,
        top_sources: vec![],
        top_ports: vec![
            (1, 0.1),
            (2, 0.1),
            (3, 0.1),
            (4, 0.1),
            (5, 0.1),
            (6, 0.1),
            (7, 0.1),
            (8, 0.1),
        ],
        pops: vec![],
        top_source_blocks: vec![],
        severity: Severity::High,
        first_seen_ms: 0,
        last_seen_ms: 0,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a live BGP peer (BIRD); run in the netns lab"]
async fn selection_routes_to_flowspec_and_rtbh_on_real_bird() {
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

    // Covering unicast route (RFC 8955 §6 "safe update" validation): without
    // this, BIRD rejects the FlowSpec rule below as unvalidated.
    handle
        .announce(Route {
            prefix: "203.0.113.0/24".parse().unwrap(),
            next_hop: "10.0.0.1".parse().unwrap(),
            origin: Origin::Igp,
            communities: vec![],
            large_communities: vec![],
        })
        .await
        .expect("announce covering route");

    let cfg = SelectionConfig {
        concentration: 0.8,
        max_flows: 4,
        rate: 0.0,
    };

    let mut flowspec_mgr = FlowSpecManager::new(
        FlowSpecController::new(FlowSpecConfig {
            eligible_prefixes: vec!["203.0.113.0/24".parse().unwrap()],
            max_rules: 64,
            hold_down: Duration::from_secs(0),
            max_ttl: None,
        }),
        handle.clone(),
        NoopFlowSpecJournal,
    );
    let mut rtbh_mgr = RtbhManager::new(
        RtbhController::new(RtbhConfig {
            eligible_prefixes: vec!["203.0.113.0/24".parse().unwrap()],
            blackhole_communities: vec![(65535, 666)],
            next_hop_v4: Some("10.222.255.99".parse().unwrap()),
            next_hop_v6: None,
            max_blackholes: 64,
            hold_down: Duration::from_secs(0),
            max_ttl: None,
        }),
        handle,
        NoopBlackholeJournal,
    );

    // Concentrated: a single dominant port (53/udp at 95%) selects FlowSpec —
    // a flow-scoped drop rule, leaving the rest of the victim's traffic alone.
    let concentrated = concentrated_detection();
    match select(&concentrated, &cfg) {
        Mitigation::FlowSpec(rules) => {
            flowspec_mgr
                .apply_open(concentrated.target, &rules, 0, 1000)
                .await;
        }
        other => panic!("expected FlowSpec for the concentrated detection, got {other:?}"),
    }

    // Diffuse: weight spread thin across many ports selects RTBH — no small
    // flow set can stop the attack, so the whole victim IP is blackholed.
    let diffuse = diffuse_detection();
    match select(&diffuse, &cfg) {
        Mitigation::Rtbh => {
            rtbh_mgr
                .apply_event(&DetectionEvent::Opened(diffuse.clone()), 0, 1000)
                .await;
        }
        other => panic!("expected RTBH for the diffuse detection, got {other:?}"),
    }

    tokio::time::sleep(Duration::from_secs(5)).await; // let BIRD import + the scenario assert
}
