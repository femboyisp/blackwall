//! Decode REAL sFlow v5 datagrams captured from hsflowd (host-sflow 2.1.26,
//! mod_pcap) during the increment-2 feasibility spike. hsflowd emits *expanded*
//! flow samples (type 3); these fixtures pin that `decode_datagram` handles
//! real-agent output, which crafted-datagram tests (L2c) cannot prove.

use blackwall_flow::decode_datagram;
use std::net::{IpAddr, Ipv4Addr};

/// (fixture, expected flow-observation count) — measured from the real capture.
const FIXTURES: &[(&[u8], usize)] = &[
    (include_bytes!("fixtures/hsflowd-expanded-1.bin"), 1),
    (include_bytes!("fixtures/hsflowd-expanded-2.bin"), 7),
    (include_bytes!("fixtures/hsflowd-expanded-3.bin"), 7),
    (include_bytes!("fixtures/hsflowd-expanded-4.bin"), 2),
    (include_bytes!("fixtures/hsflowd-expanded-5.bin"), 7),
    (include_bytes!("fixtures/hsflowd-expanded-6.bin"), 5),
    (include_bytes!("fixtures/hsflowd-expanded-7.bin"), 2),
    (include_bytes!("fixtures/hsflowd-expanded-8.bin"), 7),
];

#[test]
fn decodes_real_hsflowd_expanded_flow_samples() {
    let victim = IpAddr::V4(Ipv4Addr::new(10, 9, 0, 2));
    let mut total = 0;
    for (bytes, expected) in FIXTURES {
        let obs = decode_datagram(bytes).expect("decode real hsflowd datagram");
        assert_eq!(obs.len(), *expected, "observation count for a fixture");
        for o in &obs {
            assert_eq!(o.dst, victim, "all flood packets target the victim");
            assert_eq!(o.dst_port, 80);
            assert!(o.proto == 17 || o.proto == 6, "udp or tcp, got {}", o.proto);
        }
        total += obs.len();
    }
    assert_eq!(
        total, 38,
        "38 flow observations across the 8 real datagrams"
    );
}
