//! BGP message framing and the control messages (OPEN/KEEPALIVE/NOTIFICATION).

use crate::error::BgpError;

// ── New types added in Task 3 ────────────────────────────────────────────────

/// A BGP NOTIFICATION message body (RFC 4271 §4.5).
///
/// Carries an error `code`, an error `subcode`, and optional diagnostic `data`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotificationMsg {
    /// Error code (see RFC 4271 §4.5 for defined values).
    pub code: u8,
    /// Error sub-code qualifying the error code.
    pub subcode: u8,
    /// Optional diagnostic data (may be empty).
    pub data: Vec<u8>,
}

/// A decoded BGP message ready for dispatch.
///
/// `Update` is a *unit* variant: Blackwall is injection-only and does not
/// parse inbound NLRI, so the body is validated by framing only.
#[derive(Debug)]
pub enum BgpMessage {
    /// A BGP OPEN message.
    Open(OpenMsg),
    /// A BGP KEEPALIVE message (header only).
    Keepalive,
    /// A BGP UPDATE message (body treated as opaque).
    Update,
    /// A BGP NOTIFICATION message.
    Notification(NotificationMsg),
}

/// Encode a BGP KEEPALIVE message (header only, type 4, total length 19).
pub fn encode_keepalive() -> Vec<u8> {
    encode_header(MsgType::Keepalive.code(), &[])
}

/// Encode a BGP NOTIFICATION message (header + `[code, subcode, data…]`).
pub fn encode_notification(n: &NotificationMsg) -> Vec<u8> {
    let mut body = Vec::with_capacity(2 + n.data.len());
    body.push(n.code);
    body.push(n.subcode);
    body.extend_from_slice(&n.data);
    encode_header(MsgType::Notification.code(), &body)
}

/// Decode a BGP NOTIFICATION body (bytes *after* the 19-byte header).
///
/// Returns [`BgpError::Decode`] if fewer than 2 bytes are present.
pub fn decode_notification(body: &[u8]) -> Result<NotificationMsg, BgpError> {
    if body.len() < 2 {
        return Err(BgpError::Decode(format!(
            "NOTIFICATION body too short: {} bytes",
            body.len()
        )));
    }
    Ok(NotificationMsg {
        code: body[0],
        subcode: body[1],
        data: body[2..].to_vec(),
    })
}

/// Parse a complete BGP message from a byte buffer.
///
/// Validates the header, ensures `bytes.len() >= total_len` (returns
/// [`BgpError::Decode`] otherwise), dispatches by type, and returns
/// `(message, total_len)` so a stream reader can advance by exactly
/// `total_len` bytes.
pub fn decode_message(bytes: &[u8]) -> Result<(BgpMessage, usize), BgpError> {
    let (msg_type, total_len) = parse_header(bytes)?;
    if bytes.len() < total_len {
        return Err(BgpError::Decode(format!(
            "buffer too short: need {} bytes, have {}",
            total_len,
            bytes.len()
        )));
    }
    let body = &bytes[HEADER_LEN..total_len];
    let msg = match MsgType::from_code(msg_type) {
        Some(MsgType::Open) => BgpMessage::Open(decode_open(body)?),
        Some(MsgType::Notification) => BgpMessage::Notification(decode_notification(body)?),
        Some(MsgType::Keepalive) => BgpMessage::Keepalive,
        Some(MsgType::Update) => BgpMessage::Update,
        None => {
            return Err(BgpError::Decode(format!(
                "unknown BGP message type {msg_type}"
            )))
        }
    };
    Ok((msg, total_len))
}

/// The 16-byte all-ones BGP marker.
pub const MARKER: [u8; 16] = [0xFF; 16];
/// The fixed BGP message header length.
pub const HEADER_LEN: usize = 19;

/// BGP message type codes (RFC 4271 §4).
///
/// Use [`MsgType::code`] to get the wire byte — avoids `as` casts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsgType {
    /// BGP OPEN (session establishment).
    Open = 1,
    /// BGP UPDATE (route advertisement/withdrawal).
    Update = 2,
    /// BGP NOTIFICATION (error, session teardown).
    Notification = 3,
    /// BGP KEEPALIVE (session liveness).
    Keepalive = 4,
}

impl MsgType {
    /// Return the one-byte wire type code for this message type.
    pub fn code(self) -> u8 {
        match self {
            MsgType::Open => 1,
            MsgType::Update => 2,
            MsgType::Notification => 3,
            MsgType::Keepalive => 4,
        }
    }

    /// Parse a one-byte wire type code, or `None` for an unknown type.
    ///
    /// Inverse of [`MsgType::code`]; lets [`decode_message`] dispatch on the
    /// enum rather than bare integer literals, keeping the decode side
    /// symmetric with the [`MsgType::code`]-based encode side.
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(MsgType::Open),
            2 => Some(MsgType::Update),
            3 => Some(MsgType::Notification),
            4 => Some(MsgType::Keepalive),
            _ => None,
        }
    }
}

/// A BGP OPEN message payload (RFC 4271 §4.2, RFC 6793 §4).
///
/// `version` is always 4 and is not stored; it is emitted by [`encode_open`].
/// When `asn > 65535` the legacy `My Autonomous System` field is set to
/// `AS_TRANS` (23456) and the real ASN is carried in the 4-octet-AS capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenMsg {
    /// The local BGP speaker's 4-octet Autonomous System number.
    pub asn: u32,
    /// The proposed Hold Time in seconds (0 or ≥ 3).
    pub hold_time: u16,
    /// The BGP Identifier (Router-ID) as a 32-bit big-endian integer.
    pub router_id: u32,
    /// Advertise MP-BGP capability for IPv4 Unicast (AFI 1 / SAFI 1).
    pub ipv4_unicast: bool,
    /// Advertise MP-BGP capability for IPv6 Unicast (AFI 2 / SAFI 1).
    pub ipv6_unicast: bool,
    /// Advertise MP-BGP capability for IPv4 FlowSpec (AFI 1 / SAFI 133).
    pub flowspec_v4: bool,
    /// Advertise MP-BGP capability for IPv6 FlowSpec (AFI 2 / SAFI 133).
    pub flowspec_v6: bool,
}

/// AS_TRANS (RFC 6793): used in the legacy 2-octet MY_AS field when the real
/// ASN does not fit in 16 bits.
const AS_TRANS: u16 = 23456;

/// Cap code: 4-octet AS number (RFC 6793).
const CAP_4OCTET_AS: u8 = 65;
/// Cap code: Multiprotocol Extensions (RFC 4760).
const CAP_MP_BGP: u8 = 1;

/// Encode a BGP OPEN message (19-byte header + body) with the 4-octet-AS
/// capability (always present) and MP-BGP capabilities for each enabled AFI.
pub fn encode_open(o: &OpenMsg) -> Vec<u8> {
    // Build capabilities.
    let mut caps: Vec<u8> = Vec::new();

    // 4-octet-AS capability: [65, 4, <asn 4 bytes>]
    caps.push(CAP_4OCTET_AS);
    caps.push(4);
    caps.extend_from_slice(&o.asn.to_be_bytes());

    // MP-BGP capability for IPv4 Unicast: AFI=1, SAFI=1
    if o.ipv4_unicast {
        caps.push(CAP_MP_BGP);
        caps.push(4);
        caps.extend_from_slice(&1u16.to_be_bytes()); // AFI 1
        caps.push(0); // reserved
        caps.push(1); // SAFI 1
    }

    // MP-BGP capability for IPv6 Unicast: AFI=2, SAFI=1
    if o.ipv6_unicast {
        caps.push(CAP_MP_BGP);
        caps.push(4);
        caps.extend_from_slice(&2u16.to_be_bytes()); // AFI 2
        caps.push(0); // reserved
        caps.push(1); // SAFI 1
    }

    // MP-BGP capability for IPv4 FlowSpec: AFI=1, SAFI=133
    if o.flowspec_v4 {
        caps.push(CAP_MP_BGP);
        caps.push(4);
        caps.extend_from_slice(&1u16.to_be_bytes());
        caps.push(0);
        caps.push(133);
    }
    // MP-BGP capability for IPv6 FlowSpec: AFI=2, SAFI=133
    if o.flowspec_v6 {
        caps.push(CAP_MP_BGP);
        caps.push(4);
        caps.extend_from_slice(&2u16.to_be_bytes());
        caps.push(0);
        caps.push(133);
    }

    // Optional Parameter type 2 (Capabilities): [2, param_len, <caps>]
    let param_len = u8::try_from(caps.len()).expect("BGP OPEN capabilities exceed u8 length");
    let mut opt_params: Vec<u8> = Vec::new();
    opt_params.push(2); // type: Capabilities
    opt_params.push(param_len);
    opt_params.extend_from_slice(&caps);

    let opt_param_len =
        u8::try_from(opt_params.len()).expect("BGP OPEN capabilities exceed u8 length");

    // Legacy MY_AS: AS_TRANS if asn > 65535, else the real asn.
    let my_as: u16 = u16::try_from(o.asn).unwrap_or(AS_TRANS);

    // Build the OPEN body.
    let mut body: Vec<u8> = Vec::new();
    body.push(4); // BGP version 4
    body.extend_from_slice(&my_as.to_be_bytes());
    body.extend_from_slice(&o.hold_time.to_be_bytes());
    body.extend_from_slice(&o.router_id.to_be_bytes());
    body.push(opt_param_len);
    body.extend_from_slice(&opt_params);

    encode_header(MsgType::Open.code(), &body)
}

/// Parse a BGP OPEN body (the bytes *after* the 19-byte header).
///
/// Walks optional parameters to recover the real 4-octet ASN and the
/// MP-BGP AFIs the peer advertised.  Falls back to the legacy `My AS`
/// field if no 4-octet-AS capability is present.
pub fn decode_open(body: &[u8]) -> Result<OpenMsg, BgpError> {
    // Fixed-length portion: version(1) + my_as(2) + hold_time(2) + router_id(4) + opt_param_len(1) = 10
    if body.len() < 10 {
        return Err(BgpError::Decode(format!(
            "OPEN body too short: {} bytes",
            body.len()
        )));
    }

    // version (ignored beyond checking it exists)
    let _version = body[0];

    let my_as = u16::from_be_bytes([body[1], body[2]]);
    let hold_time = u16::from_be_bytes([body[3], body[4]]);
    let router_id = u32::from_be_bytes([body[5], body[6], body[7], body[8]]);
    let opt_param_len = usize::from(body[9]);

    // Bounds-check the optional parameters region.
    let opt_end = 10 + opt_param_len;
    if body.len() < opt_end {
        return Err(BgpError::Decode(format!(
            "OPEN opt_param_len {} exceeds body length {}",
            opt_param_len,
            body.len()
        )));
    }
    let opt_region = &body[10..opt_end];

    let mut asn_4octet: Option<u32> = None;
    let mut ipv4_unicast = false;
    let mut ipv6_unicast = false;
    let mut flowspec_v4 = false;
    let mut flowspec_v6 = false;

    // Walk optional parameters.
    let mut i = 0usize;
    while i < opt_region.len() {
        // Each param: [type(1), len(1), value(len)]
        if i + 2 > opt_region.len() {
            return Err(BgpError::Decode(
                "truncated optional parameter header".to_owned(),
            ));
        }
        let param_type = opt_region[i];
        let param_len = usize::from(opt_region[i + 1]);
        let param_value_start = i + 2;
        let param_value_end = param_value_start + param_len;
        if param_value_end > opt_region.len() {
            return Err(BgpError::Decode(
                "truncated optional parameter value".to_owned(),
            ));
        }

        // Type 2 = Capabilities optional parameter.
        if param_type == 2 {
            let cap_region = &opt_region[param_value_start..param_value_end];
            let mut j = 0usize;
            while j < cap_region.len() {
                // Each capability: [cap_code(1), cap_len(1), value(cap_len)]
                if j + 2 > cap_region.len() {
                    return Err(BgpError::Decode("truncated capability header".to_owned()));
                }
                let cap_code = cap_region[j];
                let cap_len = usize::from(cap_region[j + 1]);
                let cap_value_start = j + 2;
                let cap_value_end = cap_value_start + cap_len;
                if cap_value_end > cap_region.len() {
                    return Err(BgpError::Decode("truncated capability value".to_owned()));
                }
                let cap_value = &cap_region[cap_value_start..cap_value_end];

                match cap_code {
                    CAP_4OCTET_AS if cap_len == 4 => {
                        asn_4octet = Some(u32::from_be_bytes([
                            cap_value[0],
                            cap_value[1],
                            cap_value[2],
                            cap_value[3],
                        ]));
                    }
                    CAP_MP_BGP if cap_len == 4 => {
                        let afi = u16::from_be_bytes([cap_value[0], cap_value[1]]);
                        let safi = cap_value[3];
                        match (afi, safi) {
                            (1, 1) => ipv4_unicast = true,
                            (2, 1) => ipv6_unicast = true,
                            (1, 133) => flowspec_v4 = true,
                            (2, 133) => flowspec_v6 = true,
                            _ => {}
                        }
                    }
                    _ => {}
                }

                j = cap_value_end;
            }
        }

        i = param_value_end;
    }

    // Resolve ASN: prefer 4-octet cap, fall back to legacy my_as.
    let asn = asn_4octet.unwrap_or_else(|| u32::from(my_as));

    Ok(OpenMsg {
        asn,
        hold_time,
        router_id,
        ipv4_unicast,
        ipv6_unicast,
        flowspec_v4,
        flowspec_v6,
    })
}

/// Prepend the 19-byte BGP header (marker + total length + type) to `body`.
pub fn encode_header(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let total = HEADER_LEN + body.len();
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&MARKER);
    out.extend_from_slice(
        &u16::try_from(total)
            .expect("BGP message exceeds u16 length")
            .to_be_bytes(),
    );
    out.push(msg_type);
    out.extend_from_slice(body);
    out
}

/// Validate and parse a BGP header. Returns `(msg_type, total_len)`.
pub fn parse_header(bytes: &[u8]) -> Result<(u8, usize), BgpError> {
    if bytes.len() < HEADER_LEN {
        return Err(BgpError::Decode("short header".to_owned()));
    }
    if bytes[0..16] != MARKER {
        return Err(BgpError::Decode("bad marker".to_owned()));
    }
    let total = usize::from(u16::from_be_bytes([bytes[16], bytes[17]]));
    if !(HEADER_LEN..=4096).contains(&total) {
        return Err(BgpError::Decode(format!("bad length {total}")));
    }
    Ok((bytes[18], total))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keepalive_header_round_trips() {
        // KEEPALIVE = header only, type 4, length 19.
        let bytes = encode_header(4, &[]);
        assert_eq!(bytes.len(), 19);
        assert_eq!(&bytes[0..16], &[0xFF; 16]);
        assert_eq!(u16::from_be_bytes([bytes[16], bytes[17]]), 19);
        assert_eq!(bytes[18], 4);
        let (ty, total) = parse_header(&bytes).unwrap();
        assert_eq!(ty, 4);
        assert_eq!(total, 19);
    }

    #[test]
    fn encode_header_sets_length_including_body() {
        let bytes = encode_header(2, &[0xAA, 0xBB]);
        assert_eq!(u16::from_be_bytes([bytes[16], bytes[17]]), 21); // 19 + 2
        assert_eq!(&bytes[19..], &[0xAA, 0xBB]);
    }

    #[test]
    fn parse_header_rejects_bad_marker_and_short() {
        let mut bad = encode_header(4, &[]);
        bad[0] = 0x00; // corrupt marker
        assert!(parse_header(&bad).is_err());
        assert!(parse_header(&[0xFF; 5]).is_err()); // too short
    }

    #[test]
    fn parse_header_rejects_overlength() {
        let mut bytes = encode_header(4, &[]);
        // overwrite the 2-byte length field with 4097 (one above the 4096 limit)
        bytes[16..18].copy_from_slice(&4097u16.to_be_bytes());
        assert!(parse_header(&bytes).is_err());
    }

    #[test]
    fn open_encodes_with_4octet_as_and_mpbgp() {
        let o = OpenMsg {
            asn: 214_806,
            hold_time: 90,
            router_id: 0x0A_DE_FF_0C,
            ipv4_unicast: true,
            ipv6_unicast: true,
            flowspec_v4: false,
            flowspec_v6: false,
        };
        let bytes = encode_open(&o);
        // header
        let (ty, total) = parse_header(&bytes).unwrap();
        assert_eq!(ty, 1); // OPEN
        assert_eq!(total, bytes.len());
        // body: version 4
        assert_eq!(bytes[19], 4);
        // my_as = AS_TRANS because 214806 > 65535
        assert_eq!(u16::from_be_bytes([bytes[20], bytes[21]]), 23456);
        // hold time
        assert_eq!(u16::from_be_bytes([bytes[22], bytes[23]]), 90);
        // router id
        assert_eq!(
            u32::from_be_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]),
            0x0A_DE_FF_0C
        );
        // decode recovers the real ASN + AFIs
        let back = decode_open(&bytes[19..]).unwrap();
        assert_eq!(back.asn, 214_806);
        assert!(back.ipv4_unicast && back.ipv6_unicast);
        assert_eq!(back.hold_time, 90);
    }

    #[test]
    fn open_advertises_flowspec_capabilities() {
        let o = OpenMsg {
            asn: 214806,
            hold_time: 90,
            router_id: 0x0A00_0001,
            ipv4_unicast: true,
            ipv6_unicast: true,
            flowspec_v4: true,
            flowspec_v6: true,
        };
        let msg = encode_open(&o);
        // MP-BGP cap [CAP_MP_BGP,4, AFI, 0, SAFI]; SAFI 133 = 0x85 for AFI 1 and AFI 2.
        assert!(msg.windows(4).any(|w| w == [0x00, 0x01, 0x00, 0x85])); // AFI1 SAFI133
        assert!(msg.windows(4).any(|w| w == [0x00, 0x02, 0x00, 0x85])); // AFI2 SAFI133
    }

    #[test]
    fn open_small_asn_uses_real_value_in_legacy_field() {
        let o = OpenMsg {
            asn: 64512,
            hold_time: 180,
            router_id: 1,
            ipv4_unicast: true,
            ipv6_unicast: false,
            flowspec_v4: false,
            flowspec_v6: false,
        };
        let bytes = encode_open(&o);
        assert_eq!(u16::from_be_bytes([bytes[20], bytes[21]]), 64512);
        let back = decode_open(&bytes[19..]).unwrap();
        assert_eq!(back.asn, 64512);
        assert!(back.ipv4_unicast && !back.ipv6_unicast);
    }

    #[test]
    fn decode_open_rejects_truncation() {
        assert!(decode_open(&[4, 0x00]).is_err());
    }

    #[test]
    fn keepalive_encodes_and_dispatches() {
        let bytes = encode_keepalive();
        let (msg, consumed) = decode_message(&bytes).unwrap();
        assert_eq!(consumed, 19);
        assert!(matches!(msg, BgpMessage::Keepalive));
    }

    #[test]
    fn notification_round_trips() {
        let n = NotificationMsg {
            code: 4,
            subcode: 0,
            data: vec![],
        }; // hold timer expired
        let bytes = encode_notification(&n);
        let (msg, _) = decode_message(&bytes).unwrap();
        match msg {
            BgpMessage::Notification(got) => assert_eq!(got, n),
            other => panic!("expected notification, got {other:?}"),
        }
    }

    #[test]
    fn update_body_is_opaque_but_framed() {
        // a minimal UPDATE: withdrawn_len 0, total_path_attr_len 0, no NLRI
        let body = [0u8, 0, 0, 0];
        let bytes = encode_header(2, &body);
        let (msg, consumed) = decode_message(&bytes).unwrap();
        assert!(matches!(msg, BgpMessage::Update));
        assert_eq!(consumed, bytes.len());
    }

    #[test]
    fn decode_message_rejects_length_past_buffer() {
        let mut bytes = encode_keepalive();
        bytes[17] = 0xFF; // claim length 0xFF.. past the 19-byte buffer
        assert!(decode_message(&bytes).is_err());
    }

    #[test]
    fn msgtype_from_code_roundtrips_and_rejects_unknown() {
        for ty in [
            MsgType::Open,
            MsgType::Update,
            MsgType::Notification,
            MsgType::Keepalive,
        ] {
            assert_eq!(MsgType::from_code(ty.code()), Some(ty));
        }
        assert_eq!(MsgType::from_code(0), None);
        assert_eq!(MsgType::from_code(5), None);
    }
}
