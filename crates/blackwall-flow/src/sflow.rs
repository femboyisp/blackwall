//! sFlow v5 datagram decoder.
//!
//! Decodes sFlow v5 UDP payloads into a flat list of [`FlowObservation`]s.
//! Regular flow samples (sample format 1) and expanded flow samples (format 3,
//! emitted by real agents such as hsflowd) containing raw Ethernet headers
//! (record format 1, header protocol 1) that etherparse can parse to an IP
//! packet produce observations.  Everything else is skipped silently.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use etherparse::{LaxNetSlice, LaxSlicedPacket, TransportSlice};

use crate::{FlowError, FlowObservation};

/// A bounds-checked big-endian cursor over a byte slice.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Read a big-endian `u32`, advancing the cursor by 4 bytes.
    fn read_u32(&mut self) -> Result<u32, FlowError> {
        let end = self.pos.checked_add(4).ok_or_else(|| {
            FlowError::Decode("sFlow datagram truncated (u32 read overflow)".into())
        })?;
        let bytes = self.buf.get(self.pos..end).ok_or_else(|| {
            FlowError::Decode("sFlow datagram truncated (u32 read past end)".into())
        })?;
        self.pos = end;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Consume exactly `n` bytes, returning a sub-slice.
    fn take(&mut self, n: usize) -> Result<&'a [u8], FlowError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| FlowError::Decode("sFlow datagram truncated (take overflow)".into()))?;
        let slice = self
            .buf
            .get(self.pos..end)
            .ok_or_else(|| FlowError::Decode("sFlow datagram truncated (take past end)".into()))?;
        self.pos = end;
        Ok(slice)
    }
}

/// Decode an sFlow v5 UDP payload into a list of [`FlowObservation`]s, plus a
/// count of samples that failed to decode.
///
/// Each raw Ethernet header record inside a flow sample that can be parsed
/// to an IP packet yields one observation.  Counter samples, non-Ethernet
/// header protocols, and headers that etherparse cannot decode to an IP
/// layer are silently skipped.
///
/// hsflowd (and other real agents) batch many flow samples into one
/// datagram; one structurally malformed sample must not discard the valid
/// observations already decoded from the same datagram. The outer per-sample
/// framing (`sample_type`/`sample_length`) is read and validated first — once
/// that succeeds, the exact bounds of the sample body are known regardless of
/// what is inside it, so a failure *within* a sample (e.g. a record length
/// past the sample body) cannot desynchronize parsing of the samples that
/// follow. Such per-sample/record errors are therefore caught, counted in the
/// returned `u32`, and skipped — decoding continues with the next sample.
///
/// # Errors
///
/// Returns [`FlowError::Decode`] only for **envelope-level** framing errors:
/// the fixed datagram header (version, agent address, sample count) or a
/// per-sample header (`sample_type`/`sample_length`) running past the end of
/// the buffer. These corrupt the cursor position itself, so — unlike a bad
/// record inside an already-bounded sample body — decoding cannot safely
/// continue past them.
pub fn decode_datagram(bytes: &[u8]) -> Result<(Vec<FlowObservation>, u32), FlowError> {
    let mut cur = Cursor::new(bytes);
    let mut observations = Vec::new();
    let mut sample_errors: u32 = 0;

    // Datagram envelope.
    let _version = cur.read_u32()?;
    let agent_addr_type = cur.read_u32()?;
    let agent: IpAddr = match agent_addr_type {
        1 => {
            let b = cur.take(4)?;
            IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3]))
        }
        2 => {
            let b = cur.take(16)?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(b);
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        t => {
            return Err(FlowError::Decode(format!(
                "unknown sFlow agent address type {t}"
            )))
        }
    };
    let _sub_agent = cur.read_u32()?;
    let _sequence = cur.read_u32()?;
    let _uptime = cur.read_u32()?;
    let num_samples = cur.read_u32()?;

    for _ in 0..num_samples {
        let sample_type = cur.read_u32()?;
        let sample_length = usize::try_from(cur.read_u32()?)
            .map_err(|_| FlowError::Decode("length overflow".into()))?;
        let sample_body = cur.take(sample_length)?;

        // Flow samples: regular (format 1) and expanded (format 3, used by
        // real agents such as hsflowd). Other sample types (counters) are
        // skipped. A decode error inside a sample is caught and counted
        // rather than propagated: the outer `take` above already bounded
        // this sample's exact extent, so the cursor is safe to continue with
        // the next sample regardless of what went wrong inside this one.
        let result = match sample_type & 0xFFF {
            1 => decode_flow_sample(sample_body, agent, &mut observations),
            3 => decode_expanded_flow_sample(sample_body, agent, &mut observations),
            _ => continue,
        };
        if result.is_err() {
            sample_errors += 1;
        }
    }

    Ok((observations, sample_errors))
}

/// Parse a flow-sample body and append any decoded observations.
///
/// Returns `Err(FlowError::Decode)` only when a length field in the sample
/// runs past the sample body (structural truncation).  Non-raw records,
/// non-Ethernet header protocols, and etherparse failures are skipped.
fn decode_flow_sample(
    body: &[u8],
    agent: IpAddr,
    out: &mut Vec<FlowObservation>,
) -> Result<(), FlowError> {
    let mut cur = Cursor::new(body);

    let _sequence = cur.read_u32()?;
    let _source_id = cur.read_u32()?;
    let sampling_rate = cur.read_u32()?;
    let _sample_pool = cur.read_u32()?;
    let _drops = cur.read_u32()?;
    let _input = cur.read_u32()?;
    let _output = cur.read_u32()?;
    let num_records = cur.read_u32()?;

    for _ in 0..num_records {
        let record_type = cur.read_u32()?;
        let record_length = usize::try_from(cur.read_u32()?)
            .map_err(|_| FlowError::Decode("length overflow".into()))?;
        let record_body = cur.take(record_length)?;

        // Only raw packet header records (enterprise=0, format=1).
        if record_type & 0xFFF != 1 {
            continue;
        }

        if let Some(obs) = decode_raw_header_record(record_body, sampling_rate, agent) {
            out.push(obs);
        }
    }

    Ok(())
}

/// Parse an EXPANDED flow-sample body (sample type 3) and append observations.
///
/// The expanded layout splits the regular flow sample's `source_id` into
/// `ds_class`/`ds_index` and its `input`/`output` into `format`/`value` pairs
/// (three extra `u32`s); the inner flow records are identical, so they are
/// decoded the same way as the regular path.
fn decode_expanded_flow_sample(
    body: &[u8],
    agent: IpAddr,
    out: &mut Vec<FlowObservation>,
) -> Result<(), FlowError> {
    let mut cur = Cursor::new(body);
    let _sequence = cur.read_u32()?;
    let _ds_class = cur.read_u32()?;
    let _ds_index = cur.read_u32()?;
    let sampling_rate = cur.read_u32()?;
    let _sample_pool = cur.read_u32()?;
    let _drops = cur.read_u32()?;
    let _input_format = cur.read_u32()?;
    let _input_value = cur.read_u32()?;
    let _output_format = cur.read_u32()?;
    let _output_value = cur.read_u32()?;
    let num_records = cur.read_u32()?;

    for _ in 0..num_records {
        let record_type = cur.read_u32()?;
        let record_length = usize::try_from(cur.read_u32()?)
            .map_err(|_| FlowError::Decode("length overflow".into()))?;
        let record_body = cur.take(record_length)?;

        // Only raw packet header records (enterprise=0, format=1).
        if record_type & 0xFFF != 1 {
            continue;
        }

        if let Some(obs) = decode_raw_header_record(record_body, sampling_rate, agent) {
            out.push(obs);
        }
    }

    Ok(())
}

/// Parse one raw-header record body and return an observation if possible.
fn decode_raw_header_record(
    body: &[u8],
    sampling_rate: u32,
    agent: IpAddr,
) -> Option<FlowObservation> {
    let mut cur = Cursor::new(body);

    let header_protocol = cur.read_u32().ok()?;
    let frame_len = cur.read_u32().ok()?;
    let _stripped = cur.read_u32().ok()?;
    let header_length = usize::try_from(cur.read_u32().ok()?).ok()?;
    let header_bytes = cur.take(header_length).ok()?;

    // Only Ethernet (ISO 88023) is supported.
    if header_protocol != 1 {
        return None;
    }

    // Real agents (hsflowd header-sampling) truncate the packet to a snaplen, so
    // the captured header's IP total-length field exceeds the bytes present. The
    // strict `SlicedPacket::from_ethernet` rejects that with a `LenError` and the
    // sample is silently dropped (the detector goes blind to all real sFlow); the
    // lax parser reads the headers that ARE present, which is all the volume math
    // and flow-key need (ports/addrs live in the captured header, and `frame_len`
    // comes from the sFlow record below, not the truncated slice).
    let sliced = LaxSlicedPacket::from_ethernet(header_bytes).ok()?;

    let (src, dst, proto) = match sliced.net.as_ref()? {
        LaxNetSlice::Ipv4(ipv4) => {
            let hdr = ipv4.header();
            let src = IpAddr::V4(hdr.source_addr());
            let dst = IpAddr::V4(hdr.destination_addr());
            let proto = hdr.protocol().0;
            (src, dst, proto)
        }
        LaxNetSlice::Ipv6(ipv6) => {
            let hdr = ipv6.header();
            let src = IpAddr::V6(hdr.source_addr());
            let dst = IpAddr::V6(hdr.destination_addr());
            // Use the payload IP number as the effective protocol.
            let proto = ipv6.payload().ip_number.0;
            (src, dst, proto)
        }
        _ => return None,
    };

    let (src_port, dst_port, tcp_flags) = match sliced.transport.as_ref() {
        Some(TransportSlice::Udp(udp)) => (udp.source_port(), udp.destination_port(), 0u8),
        Some(TransportSlice::Tcp(tcp)) => {
            let flags = tcp_flags_byte(tcp);
            (tcp.source_port(), tcp.destination_port(), flags)
        }
        _ => (0u16, 0u16, 0u8),
    };

    Some(FlowObservation {
        src,
        dst,
        proto,
        src_port,
        dst_port,
        frame_len,
        sampling_rate,
        tcp_flags,
        agent,
    })
}

/// Pack individual TCP flag bits into a single byte (RFC 793 order).
///
/// Bit layout (LSB → MSB): FIN SYN RST PSH ACK URG ECE CWR.
fn tcp_flags_byte(tcp: &etherparse::TcpSlice<'_>) -> u8 {
    let mut f = 0u8;
    if tcp.fin() {
        f |= 0x01;
    }
    if tcp.syn() {
        f |= 0x02;
    }
    if tcp.rst() {
        f |= 0x04;
    }
    if tcp.psh() {
        f |= 0x08;
    }
    if tcp.ack() {
        f |= 0x10;
    }
    if tcp.urg() {
        f |= 0x20;
    }
    if tcp.ece() {
        f |= 0x40;
    }
    if tcp.cwr() {
        f |= 0x80;
    }
    f
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    /// Build a minimal Ethernet+IPv4+UDP frame (dst 203.0.113.7, src 198.51.100.9,
    /// UDP 12345 -> 53) using etherparse, returning the raw bytes.
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

    fn be(v: u32) -> [u8; 4] {
        v.to_be_bytes()
    }

    /// Assemble the sFlow v5 envelope (version, agent address, sub-agent, seq,
    /// uptime, num_samples=1) for a datagram carrying exactly one sample.
    fn envelope(agent_addr_type: u32, agent_addr: &[u8]) -> Vec<u8> {
        let mut d = Vec::new();
        d.extend_from_slice(&be(5)); // version
        d.extend_from_slice(&be(agent_addr_type));
        d.extend_from_slice(agent_addr);
        d.extend_from_slice(&be(0)); // sub agent
        d.extend_from_slice(&be(1)); // seq
        d.extend_from_slice(&be(1000)); // uptime
        d.extend_from_slice(&be(1)); // num_samples
        d
    }

    /// Build a regular (type 1) flow-sample body wrapping one raw-header
    /// record around `header`, padded to a 4-byte boundary.
    fn flow_sample_body(header: &[u8], sampling_rate: u32) -> Vec<u8> {
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
        flow
    }

    /// Assemble a one-flow-sample sFlow v5 datagram with a given agent
    /// address type/bytes around `header`.
    fn datagram_with_agent(
        agent_addr_type: u32,
        agent_addr: &[u8],
        header: &[u8],
        sampling_rate: u32,
    ) -> Vec<u8> {
        let mut d = envelope(agent_addr_type, agent_addr);
        let flow = flow_sample_body(header, sampling_rate);
        d.extend_from_slice(&be(1)); // sample_type = flow sample
        d.extend_from_slice(&be(u32::try_from(flow.len()).unwrap())); // sample_length
        d.extend_from_slice(&flow);
        d
    }

    /// Assemble a one-flow-sample sFlow v5 datagram around `header`.
    fn sflow_datagram(header: &[u8], sampling_rate: u32) -> Vec<u8> {
        datagram_with_agent(1, &[10, 0, 0, 1], header, sampling_rate)
    }

    /// Build a datagram with a given IPv4 agent address (addr type 1)
    /// containing one raw-header flow sample.
    fn build_test_datagram_v4_agent(agent: [u8; 4]) -> Vec<u8> {
        datagram_with_agent(1, &agent, &sample_eth_ipv4_udp(), 1024)
    }

    /// Build a datagram with a given IPv6 agent address (addr type 2)
    /// containing one raw-header flow sample.
    fn build_test_datagram_v6_agent(agent: [u8; 16]) -> Vec<u8> {
        datagram_with_agent(2, &agent, &sample_eth_ipv4_udp(), 1024)
    }

    /// Assemble a one-flow-sample sFlow v5 datagram using the EXPANDED (type-3)
    /// flow-sample format around `header`.  The expanded header replaces the
    /// regular `source_id` with `ds_class`/`ds_index` and `input`/`output` with
    /// `input_format`/`input_value`/`output_format`/`output_value` — three extra
    /// `u32`s.  The raw-header record framing is otherwise identical.
    fn sflow_datagram_expanded(header: &[u8], sampling_rate: u32) -> Vec<u8> {
        let mut d = Vec::new();
        d.extend_from_slice(&be(5)); // version
        d.extend_from_slice(&be(1)); // agent type ipv4
        d.extend_from_slice(&[10, 0, 0, 1]); // agent addr
        d.extend_from_slice(&be(0)); // sub agent
        d.extend_from_slice(&be(1)); // seq
        d.extend_from_slice(&be(1000)); // uptime
        d.extend_from_slice(&be(1)); // num_samples

        // --- raw-header record (identical to regular path) ---
        let header_len = header.len();
        let pad = (4 - (header_len % 4)) % 4;
        let mut rec = Vec::new();
        rec.extend_from_slice(&be(1)); // header_protocol = ethernet
        rec.extend_from_slice(&be(1500)); // frame_length
        rec.extend_from_slice(&be(0)); // stripped
        rec.extend_from_slice(&be(u32::try_from(header_len).unwrap())); // header_length
        rec.extend_from_slice(header);
        rec.extend(std::iter::repeat_n(0u8, pad));

        // --- expanded flow-sample body (10 header u32s, then 1 record) ---
        let mut flow = Vec::new();
        flow.extend_from_slice(&be(1)); // sequence
        flow.extend_from_slice(&be(0)); // ds_class   (replaces source_id)
        flow.extend_from_slice(&be(0)); // ds_index
        flow.extend_from_slice(&be(sampling_rate)); // sampling_rate
        flow.extend_from_slice(&be(0)); // sample_pool
        flow.extend_from_slice(&be(0)); // drops
        flow.extend_from_slice(&be(0)); // input_format  (replaces input)
        flow.extend_from_slice(&be(0)); // input_value
        flow.extend_from_slice(&be(0)); // output_format (replaces output)
        flow.extend_from_slice(&be(0)); // output_value
        flow.extend_from_slice(&be(1)); // num_records
        flow.extend_from_slice(&be(1)); // record_type = raw header
        flow.extend_from_slice(&be(u32::try_from(rec.len()).unwrap())); // record_length
        flow.extend_from_slice(&rec);

        d.extend_from_slice(&be(3)); // sample_type = expanded flow sample
        d.extend_from_slice(&be(u32::try_from(flow.len()).unwrap())); // sample_length
        d.extend_from_slice(&flow);
        d
    }

    #[test]
    fn decodes_flow_sample_ipv4_udp() {
        let header = sample_eth_ipv4_udp();
        let dg = sflow_datagram(&header, 1024);
        let (obs, sample_errors) = decode_datagram(&dg).unwrap();
        assert_eq!(sample_errors, 0);
        assert_eq!(obs.len(), 1);
        let o = obs[0];
        assert_eq!(o.src, IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)));
        assert_eq!(o.dst, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)));
        assert_eq!(o.proto, 17); // UDP
        assert_eq!(o.dst_port, 53);
        assert_eq!(o.src_port, 12345);
        assert_eq!(o.frame_len, 1500);
        assert_eq!(o.sampling_rate, 1024);
    }

    #[test]
    fn expanded_flow_sample_decodes_same_observation() {
        let header = sample_eth_ipv4_udp();
        // Expanded (type 3) — must produce one observation identical to type 1.
        let dg_expanded = sflow_datagram_expanded(&header, 512);
        let (obs, sample_errors) = decode_datagram(&dg_expanded).unwrap();
        assert_eq!(sample_errors, 0);
        assert_eq!(obs.len(), 1, "expanded flow sample yields one observation");
        let o = obs[0];
        assert_eq!(o.dst, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)));
        assert_eq!(o.proto, 17); // UDP
        assert_eq!(o.dst_port, 53);
        assert_eq!(o.sampling_rate, 512);

        // Regular (type 1) — regression: must still decode after the dispatch change.
        let dg_regular = sflow_datagram(&header, 256);
        let (obs_reg, sample_errors_reg) = decode_datagram(&dg_regular).unwrap();
        assert_eq!(sample_errors_reg, 0);
        assert_eq!(
            obs_reg.len(),
            1,
            "regular flow sample still decodes (regression)"
        );
    }

    /// Build an Ethernet+IPv4+TCP frame with a 100-byte payload (so the IPv4
    /// total-length field is 140), then truncate the bytes to a snaplen that
    /// keeps only eth(14)+ipv4(20)+tcp(20)=54 bytes — mirroring how a real
    /// `hsflowd` header-sampling agent captures only the packet header. The IPv4
    /// total-length field inside the captured bytes still says 140 while only 40
    /// bytes of IP are present: the strict parser rejects this (LenError), the
    /// lax parser reads the headers that ARE present.
    fn truncated_snaplen_eth_ipv4_tcp() -> Vec<u8> {
        use etherparse::PacketBuilder;
        let builder = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
            .ipv4([198, 51, 100, 9], [203, 0, 113, 7], 64)
            .tcp(40000, 443, 1, 1024);
        let payload = [0u8; 100];
        let mut buf = Vec::new();
        builder.write(&mut buf, &payload).unwrap();
        buf.truncate(54); // eth + ipv4 + tcp headers only; payload dropped
        buf
    }

    #[test]
    fn truncated_snaplen_header_still_decodes() {
        // Regression for the M0 kc pilot: a real hsflowd snaplen-truncated header
        // (IPv4 total-length > captured bytes) must still yield an observation.
        // Before the lax-parser fix this produced ZERO observations (the detector
        // was blind to all real sFlow) while reporting no decode error.
        let header = truncated_snaplen_eth_ipv4_tcp();
        let dg = sflow_datagram_expanded(&header, 1000);
        let (obs, sample_errors) = decode_datagram(&dg).unwrap();
        assert_eq!(sample_errors, 0, "truncation is not a decode error");
        assert_eq!(
            obs.len(),
            1,
            "a snaplen-truncated header must still decode to one observation"
        );
        let o = obs[0];
        assert_eq!(o.src, IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)));
        assert_eq!(o.dst, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)));
        assert_eq!(o.proto, 6, "TCP");
        assert_eq!(o.src_port, 40000);
        assert_eq!(o.dst_port, 443);
        assert_eq!(o.frame_len, 1500, "volume math uses the sFlow frame_length");
    }

    #[test]
    fn truncated_datagram_errors() {
        assert!(decode_datagram(&[0, 0, 0, 5]).is_err()); // version only, nothing else
    }

    #[test]
    fn empty_or_non_flow_yields_no_observations() {
        // A valid envelope claiming 0 samples -> empty, no error.
        let mut d = Vec::new();
        for v in [5u32, 1, /*agent*/ 0, 0, 1, 1000, 0] {
            d.extend_from_slice(&v.to_be_bytes());
        }
        // note: agent addr (4 bytes) — insert after agent type; rebuild precisely:
        let mut dd = Vec::new();
        dd.extend_from_slice(&5u32.to_be_bytes());
        dd.extend_from_slice(&1u32.to_be_bytes()); // ipv4
        dd.extend_from_slice(&[10, 0, 0, 1]);
        dd.extend_from_slice(&0u32.to_be_bytes()); // sub agent
        dd.extend_from_slice(&1u32.to_be_bytes()); // seq
        dd.extend_from_slice(&1000u32.to_be_bytes()); // uptime
        dd.extend_from_slice(&0u32.to_be_bytes()); // num_samples = 0
        let (obs, sample_errors) = decode_datagram(&dd).unwrap();
        assert!(obs.is_empty());
        assert_eq!(sample_errors, 0);
    }

    #[test]
    fn inner_record_length_past_sample_errors() {
        // Build a datagram whose flow sample has num_records=1, record_length=9999
        // (far past the sample body end). The outer per-sample framing
        // (sample_type/sample_length) is intact — only the record *inside*
        // the sample is malformed — so this is a per-sample error, not an
        // envelope-level one: the datagram must still decode (0 valid
        // observations from the bad sample, 1 sample-error counted), not
        // propagate as `Err`.
        let mut d = Vec::new();
        d.extend_from_slice(&be(5)); // version
        d.extend_from_slice(&be(1)); // agent type ipv4
        d.extend_from_slice(&[10, 0, 0, 1]); // agent addr
        d.extend_from_slice(&be(0)); // sub agent
        d.extend_from_slice(&be(1)); // seq
        d.extend_from_slice(&be(1000)); // uptime
        d.extend_from_slice(&be(1)); // num_samples

        // Flow sample body: header fields + 1 record claiming huge length
        let mut flow = Vec::new();
        flow.extend_from_slice(&be(1)); // flow seq
        flow.extend_from_slice(&be(0)); // source_id
        flow.extend_from_slice(&be(1)); // sampling_rate
        flow.extend_from_slice(&be(0)); // sample_pool
        flow.extend_from_slice(&be(0)); // drops
        flow.extend_from_slice(&be(0)); // input
        flow.extend_from_slice(&be(0)); // output
        flow.extend_from_slice(&be(1)); // num_records
        flow.extend_from_slice(&be(1)); // record_type = raw header
        flow.extend_from_slice(&be(9999)); // record_length — far past body

        d.extend_from_slice(&be(1)); // sample_type = flow sample
        d.extend_from_slice(&be(u32::try_from(flow.len()).unwrap()));
        d.extend_from_slice(&flow);

        let (obs, sample_errors) = decode_datagram(&d).expect("envelope framing is intact");
        assert!(obs.is_empty(), "the malformed record yields no observation");
        assert_eq!(sample_errors, 1, "the malformed sample is counted");
    }

    #[test]
    fn one_bad_sample_does_not_discard_the_datagram() {
        // A datagram with [valid flow sample, malformed flow sample] must yield
        // the valid observation (not lose the whole datagram) plus a
        // sample-error count of 1 for the malformed one.
        let header = sample_eth_ipv4_udp();
        let valid_flow = flow_sample_body(&header, 1024);

        // Malformed flow sample: num_records=1, record_length=9999 (far past
        // the sample body) — a per-sample/record structural error.
        let mut malformed_flow = Vec::new();
        malformed_flow.extend_from_slice(&be(1)); // flow seq
        malformed_flow.extend_from_slice(&be(0)); // source_id
        malformed_flow.extend_from_slice(&be(1)); // sampling_rate
        malformed_flow.extend_from_slice(&be(0)); // sample_pool
        malformed_flow.extend_from_slice(&be(0)); // drops
        malformed_flow.extend_from_slice(&be(0)); // input
        malformed_flow.extend_from_slice(&be(0)); // output
        malformed_flow.extend_from_slice(&be(1)); // num_records
        malformed_flow.extend_from_slice(&be(1)); // record_type = raw header
        malformed_flow.extend_from_slice(&be(9999)); // record_length — far past body

        let mut d = Vec::new();
        d.extend_from_slice(&be(5)); // version
        d.extend_from_slice(&be(1)); // agent type ipv4
        d.extend_from_slice(&[10, 0, 0, 1]); // agent addr
        d.extend_from_slice(&be(0)); // sub agent
        d.extend_from_slice(&be(1)); // seq
        d.extend_from_slice(&be(1000)); // uptime
        d.extend_from_slice(&be(2)); // num_samples = 2

        d.extend_from_slice(&be(1)); // sample_type = flow sample (valid)
        d.extend_from_slice(&be(u32::try_from(valid_flow.len()).unwrap()));
        d.extend_from_slice(&valid_flow);

        d.extend_from_slice(&be(1)); // sample_type = flow sample (malformed)
        d.extend_from_slice(&be(u32::try_from(malformed_flow.len()).unwrap()));
        d.extend_from_slice(&malformed_flow);

        let (obs, sample_errors) = decode_datagram(&d).expect("envelope ok");
        assert_eq!(obs.len(), 1, "the valid sample's observation survives");
        assert_eq!(
            sample_errors, 1,
            "the malformed sample is counted, not propagated as Err"
        );
    }

    #[test]
    fn envelope_truncation_still_errors() {
        // A datagram cut off inside the fixed envelope header (before even the
        // sample count can be read) is a framing error and must still be Err.
        assert!(decode_datagram(&[0, 0, 0, 5]).is_err());
    }

    #[test]
    fn unknown_agent_type_errors() {
        // agent_address_type = 3 (invalid) — must return Err.
        let mut d = Vec::new();
        d.extend_from_slice(&be(5)); // version
        d.extend_from_slice(&be(3)); // agent type unknown
                                     // no agent addr bytes — decoder should error before reading them
        d.extend_from_slice(&be(0)); // sub agent (garbage but shouldn't be reached)
        d.extend_from_slice(&be(1)); // seq
        d.extend_from_slice(&be(1000)); // uptime
        d.extend_from_slice(&be(0)); // num_samples

        assert!(decode_datagram(&d).is_err());
    }

    #[test]
    fn decodes_agent_address_v4() {
        // Build a datagram with agent 10.222.3.8 (addr type 1) containing one
        // raw-header flow sample (reuse the existing sample-building helper).
        let dg = build_test_datagram_v4_agent([10, 222, 3, 8]);
        let (obs, sample_errors) = decode_datagram(&dg).unwrap();
        assert_eq!(sample_errors, 0);
        assert!(!obs.is_empty());
        assert!(obs
            .iter()
            .all(|o| o.agent == IpAddr::V4(Ipv4Addr::new(10, 222, 3, 8))));
    }

    #[test]
    fn decodes_agent_address_v6() {
        let dg =
            build_test_datagram_v6_agent([0x2a, 0x12, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8]);
        let (obs, sample_errors) = decode_datagram(&dg).unwrap();
        assert_eq!(sample_errors, 0);
        assert!(!obs.is_empty());
        assert!(obs.iter().all(|o| matches!(o.agent, IpAddr::V6(_))));
    }
}
