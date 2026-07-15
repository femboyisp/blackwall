//! Armed-mode gate: protected-prefix skip (C1) + FlowSpec rate re-announce
//! on action change (C4) against a real BGP peer (BIRD2). Ignored in CI; run
//! by the lab's `armed-protect-reannounce-bird` scenario.
//!   BW_BGP_PEER=10.0.0.1:179 cargo test -p blackwall-rtbh --test armed_protect_reannounce_interop -- --ignored --nocapture
//!
//! Same RFC 8955 §6 "safe update" validation gotcha as `flowspec_interop.rs`
//! (in `blackwall-bgp/tests`): BIRD only accepts a FlowSpec route whose
//! destination is covered by a unicast route from the same origin AS, so we
//! announce a covering `203.0.113.0/24` route before any FlowSpec rule —
//! all three targets below (.7, .8, .9) fall inside it.

use async_trait::async_trait;
use blackwall_bgp::{spawn, FlowAction, FlowSpecRule, Origin, PeerConfig, Route};
use blackwall_rtbh::{
    ApplyOutcome, BlackholeOrigin, FlowSpecConfig, FlowSpecController, FlowSpecJournal,
    FlowSpecManager, JournalError,
};
use std::time::Duration;

/// A no-op journal: this test only exercises the BGP path against real BIRD,
/// not persistence (covered elsewhere with fakes / real Postgres).
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

fn rule(dst: &str, rate: f32) -> FlowSpecRule {
    FlowSpecRule {
        dst: dst.parse().unwrap(),
        protocol: Some(17),
        dst_port: Some(53),
        action: FlowAction::TrafficRate(rate),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a live BGP peer (BIRD); run in the netns lab"]
async fn protected_skip_and_rate_reannounce_on_real_bird() {
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
        local_addr: std::env::var("BW_BGP_LOCAL_ADDR")
            .ok()
            .map(|s| s.parse().expect("BW_BGP_LOCAL_ADDR must be an IP address")),
    })
    .expect("valid iBGP config");
    tokio::time::sleep(Duration::from_secs(3)).await; // let the session establish

    // Covering unicast route (RFC 8955 §6 "safe update" validation): without
    // this, BIRD rejects every FlowSpec rule below as unvalidated.
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

    let mut mgr = FlowSpecManager::new(
        FlowSpecController::new(FlowSpecConfig {
            eligible_prefixes: vec!["203.0.113.0/24".parse().unwrap()],
            max_rules: 64,
            hold_down: Duration::from_secs(0),
            max_ttl: None,
            // .9 is the "own anycast VIP" stand-in (C1): inside the eligible
            // prefix, but never mitigated.
            protected_prefixes: vec!["203.0.113.9/32".parse().unwrap()],
        }),
        handle,
        NoopFlowSpecJournal,
    );

    // C1: a target inside a `protect`ed prefix is rejected outright — the
    // manager never reaches the BGP executor for it, so BIRD's RIB must
    // never see it (asserted by the lab scenario).
    let protected_outcome = mgr.apply_add(rule("203.0.113.9/32", 0.0), 0, 0).await;
    assert!(
        matches!(protected_outcome, ApplyOutcome::Rejected(_)),
        "protected target must be rejected, got {protected_outcome:?}"
    );

    // Control: a normal eligible target IS announced — proves the absence
    // above is the protected-skip guard at work, not e.g. a broken session.
    let normal_outcome = mgr.apply_add(rule("203.0.113.7/32", 0.0), 0, 0).await;
    assert_eq!(normal_outcome, ApplyOutcome::Applied);

    // C4: re-asserting an already-active rule with a changed rate (0 ->
    // 1,000,000 bytes/sec) must re-announce the new action, not silently
    // keep serving the stale one.
    let initial = mgr.apply_add(rule("203.0.113.8/32", 0.0), 1000, 1000).await;
    assert_eq!(initial, ApplyOutcome::Applied);
    let reannounced = mgr
        .apply_add(rule("203.0.113.8/32", 1_000_000.0), 2000, 2000)
        .await;
    assert_eq!(reannounced, ApplyOutcome::Applied);

    tokio::time::sleep(Duration::from_secs(5)).await; // let BIRD import + the scenario assert
}
