//! sFlow v5 datagram decoder.
//!
//! Decodes sFlow v5 UDP payloads into a flat list of [`FlowObservation`]s.
//! Only flow samples (sample format 1) containing raw Ethernet headers
//! (record format 1, header protocol 1) that etherparse can parse to an IP
//! packet produce observations.  Everything else is skipped silently.

use std::net::IpAddr;

use etherparse::{NetSlice, SlicedPacket, TransportSlice};

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

/// Decode an sFlow v5 UDP payload into a list of [`FlowObservation`]s.
///
/// Each raw Ethernet header record inside a flow sample that can be parsed
/// to an IP packet yields one observation.  Counter samples, non-Ethernet
/// header protocols, and headers that etherparse cannot decode to an IP
/// layer are silently skipped.
///
/// # Errors
///
/// Returns [`FlowError::Decode`] only when the datagram is structurally
/// truncated (a length field would read past the end of the buffer).
pub fn decode_datagram(bytes: &[u8]) -> Result<Vec<FlowObservation>, FlowError> {
    let mut cur = Cursor::new(bytes);
    let mut observations = Vec::new();

    // Datagram envelope.
    let _version = cur.read_u32()?;
    let agent_addr_type = cur.read_u32()?;
    let agent_addr_len: usize = match agent_addr_type {
        1 => 4,
        2 => 16,
        t => {
            return Err(FlowError::Decode(format!(
                "unknown sFlow agent address type {t}"
            )))
        }
    };
    cur.take(agent_addr_len)?; // skip agent address
    let _sub_agent = cur.read_u32()?;
    let _sequence = cur.read_u32()?;
    let _uptime = cur.read_u32()?;
    let num_samples = cur.read_u32()?;

    for _ in 0..num_samples {
        let sample_type = cur.read_u32()?;
        let sample_length = usize::try_from(cur.read_u32()?)
            .map_err(|_| FlowError::Decode("length overflow".into()))?;
        let sample_body = cur.take(sample_length)?;

        // Only process flow samples (enterprise=0, format=1).
        if sample_type & 0xFFF != 1 {
            continue;
        }

        decode_flow_sample(sample_body, &mut observations)?;
    }

    Ok(observations)
}

/// Parse a flow-sample body and append any decoded observations.
///
/// Returns `Err(FlowError::Decode)` only when a length field in the sample
/// runs past the sample body (structural truncation).  Non-raw records,
/// non-Ethernet header protocols, and etherparse failures are skipped.
fn decode_flow_sample(body: &[u8], out: &mut Vec<FlowObservation>) -> Result<(), FlowError> {
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

        if let Some(obs) = decode_raw_header_record(record_body, sampling_rate) {
            out.push(obs);
        }
    }

    Ok(())
}

/// Parse one raw-header record body and return an observation if possible.
fn decode_raw_header_record(body: &[u8], sampling_rate: u32) -> Option<FlowObservation> {
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

    let sliced = SlicedPacket::from_ethernet(header_bytes).ok()?;

    let (src, dst, proto) = match sliced.net.as_ref()? {
        NetSlice::Ipv4(ipv4) => {
            let hdr = ipv4.header();
            let src = IpAddr::V4(hdr.source_addr());
            let dst = IpAddr::V4(hdr.destination_addr());
            let proto = hdr.protocol().0;
            (src, dst, proto)
        }
        NetSlice::Ipv6(ipv6) => {
            let hdr = ipv6.header();
            let src = IpAddr::V6(hdr.source_addr());
            let dst = IpAddr::V6(hdr.destination_addr());
            // Use the payload IP number as the effective protocol.
            let proto = ipv6.payload().ip_number.0;
            (src, dst, proto)
        }
        NetSlice::Arp(_) => return None,
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

    /// Assemble a one-flow-sample sFlow v5 datagram around `header`.
    fn sflow_datagram(header: &[u8], sampling_rate: u32) -> Vec<u8> {
        let mut d = Vec::new();
        d.extend_from_slice(&be(5)); // version
        d.extend_from_slice(&be(1)); // agent type ipv4
        d.extend_from_slice(&[10, 0, 0, 1]); // agent addr
        d.extend_from_slice(&be(0)); // sub agent
        d.extend_from_slice(&be(1)); // seq
        d.extend_from_slice(&be(1000)); // uptime
        d.extend_from_slice(&be(1)); // num_samples

        // --- flow sample ---
        // record (header) bytes, padded to 4-byte boundary
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

    #[test]
    fn decodes_flow_sample_ipv4_udp() {
        let header = sample_eth_ipv4_udp();
        let dg = sflow_datagram(&header, 1024);
        let obs = decode_datagram(&dg).unwrap();
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
        assert!(decode_datagram(&dd).unwrap().is_empty());
    }

    #[test]
    fn inner_record_length_past_sample_errors() {
        // Build a datagram whose flow sample has num_records=1, record_length=9999
        // (far past the sample body end) — must propagate as Err.
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

        assert!(decode_datagram(&d).is_err());
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
}
