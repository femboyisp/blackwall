//! Manual/netns interop exercise: push a flux window to a live Knot primary
//! over TSIG, exactly as `blackwalld`'s dns-flux loop does. Ignored in unit CI
//! (needs a live knotd); run by the lab harness's dns-knot scenario.
//!
//!   BW_DNS_SERVER=10.0.0.1:53 BW_DNS_ZONE=lab.test BW_DNS_NAME=host.lab.test \
//!   BW_DNS_PREFIX=10.9.9.0/24 BW_DNS_KEYNAME=lab-key BW_DNS_ALGO=hmac-sha256 \
//!   BW_DNS_SECRET=<base64> cargo test -p blackwall-dns --test interop -- --ignored

use base64::Engine as _;
use blackwall_dns::{build_update, flux_pool, flux_window, send_update, TsigAlgorithm, TsigKey};
use ipnet::IpNet;
use std::net::SocketAddr;
use std::time::Duration;

fn env(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| panic!("set {key}"))
}

fn parse_algo(s: &str) -> TsigAlgorithm {
    match s {
        "hmac-sha256" => TsigAlgorithm::HmacSha256,
        "hmac-sha512" => TsigAlgorithm::HmacSha512,
        "hmac-sha1" => TsigAlgorithm::HmacSha1,
        other => panic!("unknown TSIG algorithm {other}"),
    }
}

#[tokio::test]
#[ignore = "needs a live Knot primary (knotd); run in the netns lab"]
async fn pushes_a_flux_window() {
    let server: SocketAddr = env("BW_DNS_SERVER").parse().expect("BW_DNS_SERVER ip:port");
    let zone = env("BW_DNS_ZONE");
    let name = env("BW_DNS_NAME");
    let prefix: IpNet = env("BW_DNS_PREFIX").parse().expect("BW_DNS_PREFIX cidr");
    let secret = base64::engine::general_purpose::STANDARD
        .decode(env("BW_DNS_SECRET"))
        .expect("BW_DNS_SECRET base64");
    let key = TsigKey {
        name: env("BW_DNS_KEYNAME"),
        algorithm: parse_algo(&env("BW_DNS_ALGO")),
        secret,
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let pool = flux_pool(&prefix, 4).expect("flux_pool");
    let ips = flux_window(&pool, 2, now, 300);
    let plan = build_update(30, &ips);

    // The run launches concurrently with knotd; retry until the primary is up.
    let mut last = String::new();
    for _ in 0..40 {
        match send_update(server, &zone, &name, &plan, &key).await {
            Ok(()) => return,
            Err(e) => {
                last = e.to_string();
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }
    }
    panic!("send_update never succeeded: {last}");
}
