//! Manual/netns interop exercise: a synthetic detection drives the RTBH sink to
//! announce a /32 blackhole (community 65535:666) via the speaker to a real BGP
//! peer. Ignored in CI; run by the lab's rtbh-bird scenario.
//!   BW_BGP_PEER=10.0.0.1:179 cargo test -p blackwall-rtbh --test interop -- --ignored --nocapture

use blackwall_bgp::{spawn, PeerConfig};
use blackwall_flow::{AttackKind, Detection, DetectionEvent, MitigationSink, Severity};
use blackwall_rtbh::{RtbhConfig, RtbhController, RtbhSink};
use std::time::Duration;

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
    });
    let sink = RtbhSink::new(controller, handle);

    sink.handle(&DetectionEvent::Opened(Detection {
        target: "203.0.113.7".parse().unwrap(),
        kind: AttackKind::Volumetric,
        observed_pps: 200_000.0,
        observed_bps: 2e9,
        proto: 17,
        top_sources: vec![],
        top_ports: vec![],
        severity: Severity::High,
        first_seen_ms: 0,
        last_seen_ms: 0,
    }))
    .await;

    tokio::time::sleep(Duration::from_secs(5)).await; // let BIRD import + the scenario assert
}
