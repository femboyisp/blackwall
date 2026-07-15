//! In-daemon disarm gate (C5): after RTBH + FlowSpec routes are announced to
//! real BIRD, `SIGUSR1` must withdraw everything from BIRD's RIB while the
//! process keeps running — proving `RtbhManager::disarm` /
//! `FlowSpecManager::disarm` (Task 9) end to end against real BIRD. Mirrors
//! `blackwalld`'s own `disarm_signal_task` (bin/blackwalld/src/main.rs)
//! narrowed to just the two managers under test — no DB/Postgres dependency,
//! same `Noop*Journal` pattern as the sibling interop drivers. Ignored in
//! CI; run by the lab's `armed-disarm-bird` scenario.
//!   BW_BGP_PEER=10.0.0.1:179 cargo test -p blackwall-rtbh --test armed_disarm_interop -- --ignored --nocapture

use async_trait::async_trait;
use blackwall_bgp::{spawn, FlowAction, FlowSpecRule, Origin, PeerConfig, Route};
use blackwall_rtbh::{
    ApplyOutcome, BlackholeJournal, BlackholeOrigin, FlowSpecConfig, FlowSpecController,
    FlowSpecJournal, FlowSpecManager, JournalError, RtbhConfig, RtbhController, RtbhManager,
};
use std::net::IpAddr;
use std::time::Duration;
use tokio::signal::unix::{signal, SignalKind};

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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a live BGP peer (BIRD); run in the netns lab"]
async fn sigusr1_withdraws_all_and_keeps_running() {
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

    // Install the SIGUSR1 handler BEFORE announcing anything: a signal that
    // arrives between "route is live" and "handler installed" would be lost
    // under the default disposition, wedging the scenario's `step exec`.
    let mut usr1 = signal(SignalKind::user_defined1()).expect("install SIGUSR1 handler");

    let mut rtbh_mgr = RtbhManager::new(
        RtbhController::new(RtbhConfig {
            eligible_prefixes: vec!["203.0.113.0/24".parse().unwrap()],
            blackhole_communities: vec![(65535, 666)],
            next_hop_v4: Some("10.222.255.99".parse().unwrap()),
            next_hop_v6: None,
            max_blackholes: 64,
            hold_down: Duration::from_secs(0),
            max_ttl: None,
            protected_prefixes: Vec::new(),
        }),
        handle.clone(),
        NoopBlackholeJournal,
    );
    let mut flowspec_mgr = FlowSpecManager::new(
        FlowSpecController::new(FlowSpecConfig {
            eligible_prefixes: vec!["203.0.113.0/24".parse().unwrap()],
            max_rules: 64,
            hold_down: Duration::from_secs(0),
            max_ttl: None,
            protected_prefixes: Vec::new(),
        }),
        handle,
        NoopFlowSpecJournal,
    );

    assert_eq!(
        rtbh_mgr
            .apply_add("203.0.113.20".parse().unwrap(), 0, 0)
            .await,
        ApplyOutcome::Applied
    );
    assert_eq!(
        flowspec_mgr
            .apply_add(
                FlowSpecRule {
                    dst: "203.0.113.21/32".parse().unwrap(),
                    protocol: Some(17),
                    dst_port: Some(53),
                    action: FlowAction::TrafficRate(0.0),
                },
                0,
                0,
            )
            .await,
        ApplyOutcome::Applied
    );

    tokio::time::sleep(Duration::from_secs(3)).await; // let BIRD import both before the scenario disarms

    usr1.recv().await.expect("SIGUSR1 channel closed");

    // Mirrors `disarm_signal_task`: fan the disarm out to every manager.
    rtbh_mgr.disarm(1000).await;
    flowspec_mgr.disarm(1000).await;

    // Prove the process is alive well past the signal — the scenario sends
    // SIGUSR1, then polls both for continued liveness (`pgrep`) and for the
    // RIB entries disappearing, all inside this window — before exiting
    // normally (never crashing on receipt, unlike an unhandled default
    // SIGUSR1 disposition would).
    tokio::time::sleep(Duration::from_secs(15)).await;
}
