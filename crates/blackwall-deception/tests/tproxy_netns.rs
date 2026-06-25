//! Exercises the transparent listener end-to-end. Skips unless
//! `BLACKWALL_NETNS_TESTS=1` and running as root with nftables tproxy rules in
//! place (the CI privileged job / a manual netns sets this up).

fn enabled() -> bool {
    std::env::var("BLACKWALL_NETNS_TESTS").as_deref() == Ok("1")
}

#[test]
fn transparent_listener_binds() {
    if !enabled() {
        eprintln!("BLACKWALL_NETNS_TESTS != 1; skipping");
        return;
    }
    // Binding a transparent socket requires CAP_NET_ADMIN; assert it succeeds.
    let addr = "127.0.0.1:0".parse().unwrap();
    blackwall_deception::transport::TproxyListener::bind(addr).expect("bind transparent listener");
}
