//! Self-asserting integration exercise: drive real sFlow v5 datagrams through
//! the production `run_collector` + `ThresholdDetector` pipeline and verify a
//! volumetric detection fires. Ignored in unit CI (real-UDP + timing); run by
//! the lab harness's flow-sflow scenario, which gates on this test's exit code.
//!
//!   cargo test -p blackwall-flow --test interop -- detects_volumetric_attack --ignored --nocapture

use async_trait::async_trait;
use blackwall_flow::{run_collector, DetectionEvent, MitigationSink, ThresholdDetector};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// A sink that records whether an `Opened` detection has been seen.
#[derive(Default)]
struct CountingSink {
    opened: AtomicBool,
}

impl CountingSink {
    fn opened(&self) -> bool {
        self.opened.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl MitigationSink for CountingSink {
    async fn handle(&self, event: &DetectionEvent) {
        if matches!(event, DetectionEvent::Opened(_)) {
            self.opened.store(true, Ordering::SeqCst);
        }
    }
}

/// `u32` as 4 big-endian bytes.
fn be(v: u32) -> [u8; 4] {
    v.to_be_bytes()
}

/// An Ethernet/IPv4/UDP frame `198.51.100.9 -> 203.0.113.7` (dst inside the
/// detector's `203.0.113.0/24` prefix). Mirrors `sflow.rs`'s test builder.
fn sample_eth_ipv4_udp() -> Vec<u8> {
    use etherparse::PacketBuilder;
    let builder = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
        .ipv4([198, 51, 100, 9], [203, 0, 113, 7], 64)
        .udp(12345, 53);
    let payload = [0u8; 8];
    let mut buf = Vec::new();
    builder.write(&mut buf, &payload).unwrap();
    buf
}

/// Assemble a one-flow-sample sFlow v5 datagram around `header`. Mirrors
/// `sflow.rs`'s test builder (which is `#[cfg(test)]` and not importable here).
fn sflow_datagram(header: &[u8], sampling_rate: u32) -> Vec<u8> {
    let mut d = Vec::new();
    d.extend_from_slice(&be(5)); // version
    d.extend_from_slice(&be(1)); // agent type ipv4
    d.extend_from_slice(&[10, 0, 0, 1]); // agent addr
    d.extend_from_slice(&be(0)); // sub agent
    d.extend_from_slice(&be(1)); // seq
    d.extend_from_slice(&be(1000)); // uptime
    d.extend_from_slice(&be(1)); // num_samples

    let header_len = header.len();
    let pad = (4 - (header_len % 4)) % 4;
    let mut rec = Vec::new();
    rec.extend_from_slice(&be(1)); // header_protocol = ethernet
    rec.extend_from_slice(&be(1500)); // frame_length
    rec.extend_from_slice(&be(0)); // stripped
    rec.extend_from_slice(&be(u32::try_from(header_len).unwrap())); // header_length
    rec.extend_from_slice(header);
    rec.extend(std::iter::repeat_n(0u8, pad));

    let mut flow = Vec::new();
    flow.extend_from_slice(&be(1)); // flow seq
    flow.extend_from_slice(&be(0)); // source_id
    flow.extend_from_slice(&be(sampling_rate)); // sampling_rate
    flow.extend_from_slice(&be(0)); // sample_pool
    flow.extend_from_slice(&be(0)); // drops
    flow.extend_from_slice(&be(0)); // input
    flow.extend_from_slice(&be(0)); // output
    flow.extend_from_slice(&be(1)); // num_records
    flow.extend_from_slice(&be(1)); // record_type = raw header
    flow.extend_from_slice(&be(u32::try_from(rec.len()).unwrap())); // record_length
    flow.extend_from_slice(&rec);

    d.extend_from_slice(&be(1)); // sample_type = flow sample
    d.extend_from_slice(&be(u32::try_from(flow.len()).unwrap())); // sample_length
    d.extend_from_slice(&flow);
    d
}

#[tokio::test]
#[ignore = "real-UDP sFlow->detector pipeline; run in the lab"]
async fn detects_volumetric_attack() {
    let listen: SocketAddr = "127.0.0.1:16343".parse().unwrap();
    let sink = Arc::new(CountingSink::default());
    // prefix 203.0.113.0/24; pps 100k; bps effectively off; window 1s; hold-down 2s.
    let detector = ThresholdDetector::new(
        vec!["203.0.113.0/24".parse().unwrap()],
        100_000.0,
        1e15,
        1000,
        2000,
    );
    let collector = tokio::spawn(run_collector(
        listen,
        Box::new(detector),
        sink.clone(),
        1000,
    ));
    tokio::time::sleep(Duration::from_millis(300)).await; // let the collector bind

    // 200 samples * sampling_rate 1024 = 204800 est pps in a 1s window > 100k -> Opened.
    let dgram = sflow_datagram(&sample_eth_ipv4_udp(), 1024);
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for _ in 0..200 {
        sock.send_to(&dgram, listen).await.unwrap();
    }

    for _ in 0..50 {
        if sink.opened() {
            collector.abort();
            return;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    collector.abort();
    panic!("no detection fired within ~10s");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs hsflowd + a netns; run by the lab's flow-sflow-live scenario"]
async fn detects_live_sflow_attack() {
    let sentinel = "/run/blackwall-lab/flow-live-detected";
    let _ = std::fs::remove_file(sentinel); // fresh for the scenario's file-present probe

    // Monitor the victim's prefix; threshold below the lab flood's estimated pps.
    let detector = Box::new(ThresholdDetector::new(
        vec!["10.0.0.0/30".parse().expect("prefix")],
        20_000.0,      // pps; pinned in Task 5 validation
        f64::INFINITY, // bps not gated here
        1000,          // window_ms
        2000,          // hold_down_ms
    ));
    let sink = Arc::new(CountingSink::default());
    let listen: SocketAddr = "127.0.0.1:6343".parse().expect("addr");
    tokio::spawn(run_collector(listen, detector, sink.clone(), 250));

    // Poll for hsflowd's real samples to drive an Opened event.
    for _ in 0..120 {
        if sink.opened() {
            std::fs::write(sentinel, b"ok").expect("write sentinel");
            return;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("no live volumetric detection fired");
}
