//! Pure pcap encoding for XDP-captured packets (sub-project B4.1).
//!
//! This module is the tested core of the capture feature: it parses the raw
//! [`CaptureFrame`] ring records the eBPF program writes (see
//! [`parse_record`]) and serialises the captured packets into the classic pcap
//! file format ([`to_pcap`]) so the output opens directly in
//! `tcpdump`/`wireshark`. Both functions are pure (bytes in, bytes out) and
//! carry no I/O, so they are unit-tested and coverage-counted; the live ring
//! drain and flag toggling live in the coverage-excluded [`crate::capture`].
//!
//! # Link type
//!
//! The eBPF program snapshots each frame from **offset 0**, i.e. the Ethernet
//! header (XDP sees the L2 frame). The pcap global header therefore declares
//! link-type [`LINKTYPE_ETHERNET`] (1), so readers dissect the snapshot starting
//! at the Ethernet header.
//!
//! # Timestamps
//!
//! [`CaptureRecord::timestamp_ns`] is `bpf_ktime_get_ns()` — nanoseconds since
//! boot on `CLOCK_MONOTONIC`, **not** wall-clock epoch time. It is written into
//! the pcap per-packet timestamp verbatim (seconds + microseconds), so inter-
//! packet deltas are accurate but the absolute date is boot-relative. Correlating
//! to wall-clock time is a follow-up.

use blackwall_xdp_common::{CaptureRecord, CAP_SNAP_LEN};

/// pcap magic number (`0xa1b2c3d4`) written little-endian, declaring
/// microsecond-resolution timestamps and little-endian field order to readers.
const PCAP_MAGIC: u32 = 0xa1b2_c3d4;
/// pcap format major version.
const PCAP_VERSION_MAJOR: u16 = 2;
/// pcap format minor version.
const PCAP_VERSION_MINOR: u16 = 4;
/// Link-layer header type: Ethernet (`DLT_EN10MB`). The eBPF program snapshots
/// from the L2 Ethernet header, so this is the correct dissector root.
const LINKTYPE_ETHERNET: u32 = 1;
/// Bytes in the pcap global (file) header.
const GLOBAL_HEADER_LEN: usize = 24;
/// Bytes in each pcap per-packet record header.
const PACKET_HEADER_LEN: usize = 16;
/// Nanoseconds per second, for splitting the boot-time timestamp.
const NS_PER_SEC: u64 = 1_000_000_000;
/// Nanoseconds per microsecond, for the pcap sub-second field.
const NS_PER_USEC: u64 = 1_000;

/// A single captured packet: the decoded [`CaptureRecord`] header plus the
/// snapshot bytes (`header.cap_len` of them) the eBPF program copied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapturedPacket {
    /// The decoded record header (verdict, reason, lengths, timestamp).
    pub record: CaptureRecord,
    /// The packet snapshot — exactly `record.cap_len` bytes.
    pub data: Vec<u8>,
}

/// Parse one raw [`blackwall_xdp_common::CaptureFrame`] ring record into a
/// [`CapturedPacket`].
///
/// `bytes` is one item drained from the `CAPTURE` ring: a 24-byte
/// [`CaptureRecord`] header (host-native byte order) followed by the fixed
/// [`CAP_SNAP_LEN`]-byte snapshot buffer, of which only `cap_len` leading bytes
/// are meaningful.
///
/// Returns `None` if `bytes` is too short to hold the header, or if the record's
/// `cap_len` exceeds what the frame can carry (a corrupt/short record) — a
/// defensive check so a malformed ring item can never over-read.
#[must_use]
pub fn parse_record(bytes: &[u8]) -> Option<CapturedPacket> {
    let header = bytes.get(..24)?;
    // Host-native byte order: the eBPF writer and this reader share the machine's
    // endianness (as the other shared map PODs already assume).
    let timestamp_ns = u64::from_ne_bytes(header[0..8].try_into().ok()?);
    let reason = u32::from_ne_bytes(header[8..12].try_into().ok()?);
    let verdict = u32::from_ne_bytes(header[12..16].try_into().ok()?);
    let pkt_len = u32::from_ne_bytes(header[16..20].try_into().ok()?);
    let cap_len = u32::from_ne_bytes(header[20..24].try_into().ok()?);

    let cap = usize::try_from(cap_len).ok()?;
    if cap > CAP_SNAP_LEN {
        return None;
    }
    let data = bytes.get(24..24 + cap)?.to_vec();
    Some(CapturedPacket {
        record: CaptureRecord {
            timestamp_ns,
            reason,
            verdict,
            pkt_len,
            cap_len,
        },
        data,
    })
}

/// Encode captured packets into a classic-format pcap byte stream.
///
/// Writes the 24-byte global header (magic, version 2.4, snap length
/// [`CAP_SNAP_LEN`], link-type Ethernet) once, then a 16-byte record header
/// (timestamp seconds/microseconds, included length, original length) followed
/// by the snapshot bytes for each packet. All multi-byte fields are little-
/// endian, matching [`PCAP_MAGIC`]. The result opens directly in
/// `tcpdump -r`/`wireshark`.
#[must_use]
pub fn to_pcap(packets: &[CapturedPacket]) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        GLOBAL_HEADER_LEN
            + packets
                .iter()
                .map(|p| PACKET_HEADER_LEN + p.data.len())
                .sum::<usize>(),
    );

    // --- global header ---
    out.extend_from_slice(&PCAP_MAGIC.to_le_bytes());
    out.extend_from_slice(&PCAP_VERSION_MAJOR.to_le_bytes());
    out.extend_from_slice(&PCAP_VERSION_MINOR.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes()); // thiszone (GMT offset)
    out.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
    let snaplen = u32::try_from(CAP_SNAP_LEN).unwrap_or(u32::MAX);
    out.extend_from_slice(&snaplen.to_le_bytes());
    out.extend_from_slice(&LINKTYPE_ETHERNET.to_le_bytes());

    // --- per-packet records ---
    for p in packets {
        let ts_sec = u32::try_from(p.record.timestamp_ns / NS_PER_SEC).unwrap_or(u32::MAX);
        let ts_usec =
            u32::try_from((p.record.timestamp_ns % NS_PER_SEC) / NS_PER_USEC).unwrap_or(u32::MAX);
        // Included length is what we actually stored; clamp to the real snapshot
        // so incl_len can never claim more bytes than follow it.
        let incl_len = u32::try_from(p.data.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&ts_sec.to_le_bytes());
        out.extend_from_slice(&ts_usec.to_le_bytes());
        out.extend_from_slice(&incl_len.to_le_bytes());
        out.extend_from_slice(&p.record.pkt_len.to_le_bytes());
        out.extend_from_slice(&p.data);
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use blackwall_xdp_common::REASON_BLOCKLIST;

    /// Build the 120-byte raw ring record for a `CaptureFrame` with `data`
    /// snapshotted (host-native header, fixed-length snapshot buffer).
    fn raw_frame(rec: &CaptureRecord, data: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&rec.timestamp_ns.to_ne_bytes());
        b.extend_from_slice(&rec.reason.to_ne_bytes());
        b.extend_from_slice(&rec.verdict.to_ne_bytes());
        b.extend_from_slice(&rec.pkt_len.to_ne_bytes());
        b.extend_from_slice(&rec.cap_len.to_ne_bytes());
        b.extend_from_slice(data);
        // Pad the snapshot buffer out to the fixed CAP_SNAP_LEN, as the eBPF ring
        // record does.
        b.resize(24 + CAP_SNAP_LEN, 0);
        b
    }

    #[test]
    fn parse_record_round_trips_header_and_snapshot() {
        let rec = CaptureRecord {
            timestamp_ns: 0x1122_3344_5566_7788,
            reason: REASON_BLOCKLIST,
            verdict: 1,
            pkt_len: 1500,
            cap_len: 4,
        };
        let snapshot = [0xde, 0xad, 0xbe, 0xef];
        let raw = raw_frame(&rec, &snapshot);

        let parsed = parse_record(&raw).expect("parses");
        assert_eq!(parsed.record, rec);
        assert_eq!(parsed.data, snapshot);
    }

    #[test]
    fn parse_record_rejects_short_header() {
        assert!(parse_record(&[0u8; 10]).is_none());
        assert!(parse_record(&[]).is_none());
    }

    #[test]
    fn parse_record_rejects_oversized_cap_len() {
        let rec = CaptureRecord {
            timestamp_ns: 0,
            reason: 0,
            verdict: 2,
            pkt_len: 64,
            // Larger than CAP_SNAP_LEN — a corrupt record.
            cap_len: u32::try_from(CAP_SNAP_LEN).unwrap() + 1,
        };
        let raw = raw_frame(&rec, &[]);
        assert!(parse_record(&raw).is_none());
    }

    #[test]
    fn parse_record_rejects_cap_len_past_end() {
        // Header claims 8 snapshot bytes but only 2 follow.
        let mut raw = Vec::new();
        raw.extend_from_slice(&0u64.to_ne_bytes());
        raw.extend_from_slice(&0u32.to_ne_bytes());
        raw.extend_from_slice(&2u32.to_ne_bytes());
        raw.extend_from_slice(&64u32.to_ne_bytes());
        raw.extend_from_slice(&8u32.to_ne_bytes()); // cap_len = 8
        raw.extend_from_slice(&[0xaa, 0xbb]); // only 2 bytes present
        assert!(parse_record(&raw).is_none());
    }

    #[test]
    fn to_pcap_empty_is_just_global_header() {
        let out = to_pcap(&[]);
        assert_eq!(out.len(), GLOBAL_HEADER_LEN);
        // Magic little-endian.
        assert_eq!(&out[0..4], &[0xd4, 0xc3, 0xb2, 0xa1]);
        // version 2.4
        assert_eq!(&out[4..6], &2u16.to_le_bytes());
        assert_eq!(&out[6..8], &4u16.to_le_bytes());
        // snaplen = CAP_SNAP_LEN
        let snaplen = u32::try_from(CAP_SNAP_LEN).unwrap();
        assert_eq!(&out[16..20], &snaplen.to_le_bytes());
        // link-type Ethernet (1)
        assert_eq!(&out[20..24], &1u32.to_le_bytes());
    }

    #[test]
    fn to_pcap_encodes_exact_bytes_for_one_packet() {
        let pkt = CapturedPacket {
            record: CaptureRecord {
                // 3.000002 seconds since boot: 3 s + 2 us.
                timestamp_ns: 3 * NS_PER_SEC + 2 * NS_PER_USEC,
                reason: REASON_BLOCKLIST,
                verdict: 1,
                pkt_len: 90,
                cap_len: 4,
            },
            data: vec![0x01, 0x02, 0x03, 0x04],
        };
        let out = to_pcap(std::slice::from_ref(&pkt));

        // Global header + one 16-byte record header + 4 payload bytes.
        assert_eq!(out.len(), GLOBAL_HEADER_LEN + PACKET_HEADER_LEN + 4);

        let rec = &out[GLOBAL_HEADER_LEN..];
        assert_eq!(&rec[0..4], &3u32.to_le_bytes(), "ts_sec");
        assert_eq!(&rec[4..8], &2u32.to_le_bytes(), "ts_usec");
        assert_eq!(&rec[8..12], &4u32.to_le_bytes(), "incl_len");
        assert_eq!(&rec[12..16], &90u32.to_le_bytes(), "orig_len");
        assert_eq!(&rec[16..20], &[0x01, 0x02, 0x03, 0x04], "payload");
    }

    #[test]
    fn to_pcap_round_trips_through_parse() {
        let rec = CaptureRecord {
            timestamp_ns: 42 * NS_PER_SEC,
            reason: 4,
            verdict: 3,
            pkt_len: 200,
            cap_len: 3,
        };
        let raw = raw_frame(&rec, &[0x11, 0x22, 0x33]);
        let parsed = parse_record(&raw).expect("parse");
        let out = to_pcap(std::slice::from_ref(&parsed));

        // Two packets concatenate their records after the single global header.
        let two = to_pcap(&[parsed.clone(), parsed]);
        assert_eq!(two.len(), GLOBAL_HEADER_LEN + 2 * (PACKET_HEADER_LEN + 3));
        assert_eq!(&two[..GLOBAL_HEADER_LEN], &out[..GLOBAL_HEADER_LEN]);
    }
}
