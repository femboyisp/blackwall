//! Manual/netns interop exercise: peer with a real BGP neighbor and announce a /32.
//! Ignored in CI (needs a live peer). Run with the peer address in BW_BGP_PEER:
//!   BW_BGP_PEER=10.222.255.12:179 cargo test -p blackwall-bgp --test interop -- --ignored --nocapture

#[tokio::test]
#[ignore = "needs a live BGP peer (BIRD); run in the netns lab"]
async fn announces_a_host_route() {
    let peer: std::net::SocketAddr = std::env::var("BW_BGP_PEER")
        .expect("set BW_BGP_PEER=ip:179")
        .parse()
        .unwrap();
    let cfg = blackwall_bgp::PeerConfig {
        local_asn: std::env::var("BW_BGP_ASN")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(214_806),
        peer_asn: std::env::var("BW_BGP_ASN")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(214_806),
        peer_addr: peer,
        router_id: "10.222.255.99".parse().unwrap(),
        hold_time: 90,
    };
    let (handle, _join) = blackwall_bgp::spawn(cfg);
    tokio::time::sleep(std::time::Duration::from_secs(3)).await; // let it establish
    handle
        .announce(blackwall_bgp::Route {
            prefix: "203.0.113.7/32".parse().unwrap(),
            next_hop: "10.222.255.99".parse().unwrap(),
            origin: blackwall_bgp::Origin::Igp,
            communities: vec![(65535, 666)],
            large_communities: vec![],
        })
        .await;
    tokio::time::sleep(std::time::Duration::from_secs(5)).await; // observe on the peer
                                                                 // verify on the peer side: `birdc show route 203.0.113.7/32` should list it.
}
