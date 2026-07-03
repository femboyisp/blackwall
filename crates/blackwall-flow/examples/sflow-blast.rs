//! Smoke-test helper: craft and UDP-blast a volumetric-attack sFlow v5 stream at
//! a running collector, so the flow-mitigation smoke (`scripts/smoke-flow.sh`)
//! can exercise the real detection path without hsflowd/netns sampling.
//!
//! Each datagram carries one raw-header flow sample of a UDP frame to the victim
//! with a high `sampling_rate`, so a burst estimates well past the pps threshold
//! and the detector opens a detection for the victim.
//!
//!   cargo run -p blackwall-flow --example sflow-blast -- <collector-ip:port> <victim-ip> [count] [rate]
//!
//! Not shipped in the daemon; a lab/smoke tool only. Mirrors the datagram layout
//! in `tests/interop.rs`.

use std::net::UdpSocket;

fn be(v: u32) -> [u8; 4] {
    v.to_be_bytes()
}

/// An Ethernet/IPv4/UDP frame `198.51.100.9 -> <victim>:53`.
fn frame_to(victim: [u8; 4]) -> Vec<u8> {
    use etherparse::PacketBuilder;
    let builder = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
        .ipv4([198, 51, 100, 9], victim, 64)
        .udp(12345, 53);
    let mut buf = Vec::new();
    builder.write(&mut buf, &[0u8; 8]).unwrap();
    buf
}

/// A one-flow-sample sFlow v5 datagram wrapping `header`.
fn sflow_datagram(header: &[u8], sampling_rate: u32) -> Vec<u8> {
    let mut d = Vec::new();
    d.extend_from_slice(&be(5)); // version
    d.extend_from_slice(&be(1)); // agent type ipv4
    d.extend_from_slice(&[10, 0, 0, 1]); // agent addr
    d.extend_from_slice(&be(0)); // sub agent
    d.extend_from_slice(&be(1)); // seq
    d.extend_from_slice(&be(1000)); // uptime
    d.extend_from_slice(&be(1)); // num_samples

    let pad = (4 - (header.len() % 4)) % 4;
    let mut rec = Vec::new();
    rec.extend_from_slice(&be(1)); // header_protocol = ethernet
    rec.extend_from_slice(&be(1500)); // frame_length
    rec.extend_from_slice(&be(0)); // stripped
    rec.extend_from_slice(&be(u32::try_from(header.len()).unwrap())); // header_length
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

fn main() {
    let mut args = std::env::args().skip(1);
    let target = args.next().unwrap_or_else(|| "127.0.0.1:16343".to_owned());
    let victim_s = args.next().unwrap_or_else(|| "203.0.113.7".to_owned());
    let count: u32 = args.next().and_then(|s| s.parse().ok()).unwrap_or(400);
    let rate: u32 = args.next().and_then(|s| s.parse().ok()).unwrap_or(1024);

    let victim: std::net::Ipv4Addr = victim_s.parse().expect("victim must be an IPv4 address");
    let dgram = sflow_datagram(&frame_to(victim.octets()), rate);

    let sock = UdpSocket::bind("0.0.0.0:0").expect("bind udp");
    for _ in 0..count {
        sock.send_to(&dgram, &target).expect("send sflow");
    }
    println!("sflow-blast: sent {count} samples (rate {rate}) for victim {victim} -> {target}");
}
