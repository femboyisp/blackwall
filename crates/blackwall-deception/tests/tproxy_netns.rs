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

#[test]
fn tproxy_transport_name() {
    if !enabled() {
        eprintln!("BLACKWALL_NETNS_TESTS != 1; skipping");
        return;
    }
    // Building a `TproxyTransport` needs a real bound `TproxyListener`
    // (CAP_NET_ADMIN), same as `transparent_listener_binds` above; `name()`
    // itself does no I/O, so this only checks the wrapper reports the
    // expected interactive-tier name.
    use blackwall_deception::transport::{DeceptionTransport, TproxyListener, TproxyTransport};
    use blackwall_deception::{default_registry, BannerStore, EmulatorRegistry, EngineLimits};
    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;

    let addr = "127.0.0.1:0".parse().unwrap();
    let listener = TproxyListener::bind(addr).expect("bind transparent listener");
    let banners = BannerStore::from_text("").expect("empty banner store");
    let registry: Arc<EmulatorRegistry> = Arc::new(default_registry(Arc::new(banners)));
    let (tx, _rx) = tokio::sync::mpsc::channel(1);
    let limits = EngineLimits {
        max_concurrent: 1,
        session_timeout: std::time::Duration::from_secs(1),
    };
    let transport = TproxyTransport::new(
        listener,
        registry,
        tx,
        limits,
        Arc::new(AtomicUsize::new(0)),
    );
    assert_eq!(transport.name(), "tproxy-interactive");
}
