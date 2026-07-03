// FlowSpec gate: a native BGP speaker announces a FlowSpec rule (RFC 8955)
// to a real BIRD2 peer via SAFI 133; BIRD must show the rule in `flow4` —
// proving the whole codec + session path end to end against real BIRD.
//
// RFC 8955 §6 validation gotcha: BIRD only accepts a FlowSpec route whose
// destination is covered by a *unicast* route from the same origin AS (the
// "safe update" check) — confirmed live against BIRD 2.17.1, which logs
// `rejected by protocol flow4` for a bare flow4-only announce. We resolve
// this the same way a real operator would: announce a covering unicast
// route for 203.0.113.0/24 over the same session first, so BIRD's
// validator finds a same-peer covering route before the FlowSpec rule
// arrives.
//   BW_BGP_PEER=10.0.0.1:179 cargo test -p blackwall-bgp --test flowspec_interop -- --ignored --nocapture

use blackwall_bgp::{spawn, FlowAction, FlowSpecRule, Origin, PeerConfig, Route};
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a live BGP peer (BIRD); run in the netns lab"]
async fn flowspec_rule_reaches_bird() {
    let peer_addr: std::net::SocketAddr = std::env::var("BW_BGP_PEER")
        .expect("set BW_BGP_PEER=ip:179")
        .parse()
        .unwrap();
    let (handle, _j) = spawn(PeerConfig {
        local_asn: 214_806,
        peer_asn: 214_806,
        peer_addr,
        router_id: "10.222.255.99".parse().unwrap(),
        hold_time: 90,
        md5: None,
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

    handle
        .announce_flowspec(FlowSpecRule {
            dst: "203.0.113.7/32".parse().unwrap(),
            protocol: Some(17),
            dst_port: Some(53),
            action: FlowAction::TrafficRate(0.0),
        })
        .await
        .expect("announce");

    tokio::time::sleep(Duration::from_secs(5)).await; // let BIRD import + the scenario assert
}
