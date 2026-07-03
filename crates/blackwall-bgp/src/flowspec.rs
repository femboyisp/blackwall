//! BGP FlowSpec (RFC 8955 v4 / RFC 8956 v6) rule encoding — SAFI 133.
//!
//! Injection-only: we encode announce/withdraw UPDATEs; we never decode
//! FlowSpec NLRI. Minimal DDoS-drop match set (destination-prefix, IP-protocol,
//! destination-port) with a traffic-rate action.

use crate::message::encode_header;
use crate::route::Origin;
use crate::update::{
    push_attr, ATTR_AS_PATH, ATTR_EXTENDED_COMMUNITIES, ATTR_MP_REACH_NLRI, ATTR_MP_UNREACH_NLRI,
    ATTR_ORIGIN, FLAG_OPT_NON_TRANS, FLAG_OPT_TRANS, FLAG_WELL_KNOWN,
};
use ipnet::IpNet;
use std::net::IpAddr;

/// A FlowSpec traffic-filter rule.
#[derive(Debug, Clone, PartialEq)]
pub struct FlowSpecRule {
    /// Destination-prefix match (component type 1). Host bits are truncated.
    pub dst: IpNet,
    /// IP-protocol match (component type 3), e.g. `17` = UDP; `None` omits it.
    pub protocol: Option<u8>,
    /// Destination-port match (component type 5), e.g. `53`; `None` omits it.
    pub dst_port: Option<u16>,
    /// The traffic-filtering action.
    pub action: FlowAction,
}

/// A FlowSpec traffic-filtering action (RFC 8955 §7).
#[derive(Debug, Clone, PartialEq)]
pub enum FlowAction {
    /// Rate-limit to N bytes/sec (`0.0` = discard/drop). RFC 8955 §7.1.
    TrafficRate(f32),
}

/// FlowSpec NLRI component type codes (RFC 8955 §4.2).
const COMP_DST_PREFIX: u8 = 1;
const COMP_IP_PROTO: u8 = 3;
const COMP_DST_PORT: u8 = 5;

/// Encode a single-value numeric operator + value (RFC 8955 §4.2.1.1).
///
/// Emits one `{op, value}` pair with the end-of-list bit set and `eq` true.
/// The value length bit reflects `len_bytes` (1 or 2 here).
fn push_numeric_eq(out: &mut Vec<u8>, value: u64, len_bytes: usize) {
    // op byte: e(0x80) | len(bits 2-3) | eq(0x01). len field: 1B->00, 2B->01.
    let len_field: u8 = match len_bytes {
        1 => 0b00,
        2 => 0b01,
        4 => 0b10,
        _ => 0b11,
    };
    let op = 0x80 | (len_field << 4) | 0x01;
    out.push(op);
    // big-endian value, low `len_bytes` octets.
    let bytes = value.to_be_bytes();
    out.extend_from_slice(&bytes[8 - len_bytes..]);
}

/// Encode the FlowSpec NLRI value (components) prefixed by its length.
pub(crate) fn encode_flowspec_nlri(rule: &FlowSpecRule) -> Vec<u8> {
    let mut comps: Vec<u8> = Vec::new();

    // Type 1 — destination prefix (ascending type order first).
    let dst = rule.dst.trunc();
    comps.push(COMP_DST_PREFIX);
    let bits = dst.prefix_len();
    comps.push(bits);
    let nbytes = usize::from(bits.div_ceil(8));
    match dst.addr() {
        IpAddr::V4(a) => comps.extend_from_slice(&a.octets()[..nbytes]),
        IpAddr::V6(a) => {
            // RFC 8956: v6 destination-prefix carries an offset byte (0 here).
            comps.push(0);
            comps.extend_from_slice(&a.octets()[..nbytes]);
        }
    }

    // Type 3 — IP protocol (== value, 1 byte).
    if let Some(proto) = rule.protocol {
        comps.push(COMP_IP_PROTO);
        push_numeric_eq(&mut comps, u64::from(proto), 1);
    }

    // Type 5 — destination port (== value, 1 byte if < 256 else 2).
    if let Some(port) = rule.dst_port {
        comps.push(COMP_DST_PORT);
        let len_bytes = if port < 256 { 1 } else { 2 };
        push_numeric_eq(&mut comps, u64::from(port), len_bytes);
    }

    // Prefix with the NLRI length (RFC 8955 §4): 1 byte if < 240, else 0xF000|len.
    let mut out = Vec::with_capacity(comps.len() + 2);
    if let Ok(len) = u8::try_from(comps.len()) {
        if len < 0xF0 {
            out.push(len);
        } else {
            push_two_byte_len(&mut out, comps.len());
        }
    } else {
        push_two_byte_len(&mut out, comps.len());
    }
    out.extend_from_slice(&comps);
    out
}

/// Two-byte extended NLRI length: `0xF000 | (len & 0x0FFF)` (RFC 8955 §4).
fn push_two_byte_len(out: &mut Vec<u8>, len: usize) {
    let l = u16::try_from(len).expect("FlowSpec NLRI exceeds 4095 bytes");
    out.extend_from_slice(&(0xF000 | l).to_be_bytes());
}

/// SAFI for FlowSpec (RFC 8955 §3 / RFC 8956).
const SAFI_FLOWSPEC: u8 = 133;

/// Encode the traffic-rate extended community (RFC 8955 §7.1): `80 06 <AS=0>
/// <IEEE-754 f32 rate bytes/sec>`. `0.0` = discard.
fn traffic_rate_community(rate: f32) -> [u8; 8] {
    let mut c = [0u8; 8];
    c[0] = 0x80;
    c[1] = 0x06;
    // c[2..4] = AS (0, informational)
    c[4..8].copy_from_slice(&rate.to_be_bytes());
    c
}

fn afi_of(rule: &FlowSpecRule) -> u16 {
    match rule.dst {
        IpNet::V4(_) => 1,
        IpNet::V6(_) => 2,
    }
}

/// Build a FlowSpec announce UPDATE for `rule`.
#[must_use]
pub fn build_flowspec_announce(rule: &FlowSpecRule) -> Vec<u8> {
    let nlri = encode_flowspec_nlri(rule);
    let FlowAction::TrafficRate(rate) = rule.action;

    let mut mp_reach: Vec<u8> = Vec::new();
    mp_reach.extend_from_slice(&afi_of(rule).to_be_bytes());
    mp_reach.push(SAFI_FLOWSPEC);
    mp_reach.push(0); // next-hop length: FlowSpec has none
    mp_reach.push(0); // reserved
    mp_reach.extend_from_slice(&nlri);

    let mut attrs: Vec<u8> = Vec::new();
    push_attr(
        &mut attrs,
        FLAG_WELL_KNOWN,
        ATTR_ORIGIN,
        &[Origin::Igp.wire()],
    );
    push_attr(&mut attrs, FLAG_WELL_KNOWN, ATTR_AS_PATH, &[]);
    push_attr(
        &mut attrs,
        FLAG_OPT_TRANS,
        ATTR_EXTENDED_COMMUNITIES,
        &traffic_rate_community(rate),
    );
    push_attr(
        &mut attrs,
        FLAG_OPT_NON_TRANS,
        ATTR_MP_REACH_NLRI,
        &mp_reach,
    );

    let total_attr_len = u16::try_from(attrs.len()).expect("path attributes exceed 65535 bytes");
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(&0u16.to_be_bytes()); // withdrawn_routes_len = 0
    body.extend_from_slice(&total_attr_len.to_be_bytes());
    body.extend_from_slice(&attrs);
    encode_header(2, &body)
}

/// Build a FlowSpec withdraw UPDATE for `rule` (identical NLRI in MP_UNREACH).
#[must_use]
pub fn build_flowspec_withdraw(rule: &FlowSpecRule) -> Vec<u8> {
    let nlri = encode_flowspec_nlri(rule);
    let mut mp_unreach: Vec<u8> = Vec::new();
    mp_unreach.extend_from_slice(&afi_of(rule).to_be_bytes());
    mp_unreach.push(SAFI_FLOWSPEC);
    mp_unreach.extend_from_slice(&nlri);

    let mut attrs: Vec<u8> = Vec::new();
    push_attr(
        &mut attrs,
        FLAG_OPT_NON_TRANS,
        ATTR_MP_UNREACH_NLRI,
        &mp_unreach,
    );

    let total_attr_len = u16::try_from(attrs.len()).expect("path attributes exceed 65535 bytes");
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(&0u16.to_be_bytes());
    body.extend_from_slice(&total_attr_len.to_be_bytes());
    body.extend_from_slice(&attrs);
    encode_header(2, &body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule_v4() -> FlowSpecRule {
        FlowSpecRule {
            dst: "203.0.113.7/32".parse().unwrap(),
            protocol: Some(17),
            dst_port: Some(53),
            action: FlowAction::TrafficRate(0.0),
        }
    }

    #[test]
    fn nlri_v4_encodes_dst_proto_port_in_type_order() {
        // length 0x0C, then type1 dst /32, type3 proto ==17, type5 port ==53.
        assert_eq!(
            encode_flowspec_nlri(&rule_v4()),
            vec![0x0C, 0x01, 0x20, 0xCB, 0x00, 0x71, 0x07, 0x03, 0x81, 0x11, 0x05, 0x81, 0x35]
        );
    }

    #[test]
    fn nlri_two_byte_port_uses_len_bit() {
        // port 8080 needs 2 value bytes: op 0x91 (end-of-list|len=01|eq), value 0x1F90.
        let r = FlowSpecRule {
            dst_port: Some(8080),
            ..rule_v4()
        };
        let nlri = encode_flowspec_nlri(&r);
        // find the type-5 component tail
        let idx = nlri
            .windows(4)
            .position(|w| w == [0x05, 0x91, 0x1F, 0x90])
            .expect("2-byte port op");
        assert!(idx > 0);
    }

    #[test]
    fn nlri_v6_dst_has_offset_byte() {
        // v6 dst prefix (RFC 8956): type1, bitlen 0x80, offset 0x00, then 16 octets.
        let r = FlowSpecRule {
            dst: "2001:db8::7/128".parse().unwrap(),
            protocol: Some(17),
            dst_port: Some(53),
            action: FlowAction::TrafficRate(0.0),
        };
        let nlri = encode_flowspec_nlri(&r);
        // after the 1-byte length, component: 01 80 00 20 01 0d b8 ...
        assert_eq!(&nlri[1..5], &[0x01, 0x80, 0x00, 0x20]);
    }

    #[test]
    fn nlri_omits_optional_components() {
        // dst-only rule: just type1.
        let r = FlowSpecRule {
            protocol: None,
            dst_port: None,
            ..rule_v4()
        };
        assert_eq!(
            encode_flowspec_nlri(&r),
            vec![0x06, 0x01, 0x20, 0xCB, 0x00, 0x71, 0x07]
        );
    }

    #[test]
    fn push_numeric_eq_covers_4_and_8_byte_len_fields() {
        // 4-byte value: op 0xA1 (e|len=10|eq), value big-endian in the low 4 octets.
        let mut out = Vec::new();
        push_numeric_eq(&mut out, 0x0102_0304, 4);
        assert_eq!(out, vec![0xA1, 0x01, 0x02, 0x03, 0x04]);

        // any other width (e.g. 8 bytes) falls into the `_ => 0b11` arm.
        let mut out = Vec::new();
        push_numeric_eq(&mut out, 0x0102_0304_0506_0708, 8);
        assert_eq!(
            out,
            vec![0xB1, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
    }

    #[test]
    fn push_two_byte_len_encodes_extended_length_prefix() {
        // RFC 8955 §4: NLRI length >= 240 uses 0xF000 | len as a 2-byte prefix.
        let mut out = Vec::new();
        push_two_byte_len(&mut out, 0x0100);
        assert_eq!(out, vec![0xF1, 0x00]);
    }

    #[test]
    fn traffic_rate_drop_community_is_zero_float() {
        assert_eq!(
            traffic_rate_community(0.0),
            [0x80, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn traffic_rate_limit_community_encodes_be_float() {
        let c = traffic_rate_community(1_000_000.0);
        assert_eq!(&c[0..4], &[0x80, 0x06, 0x00, 0x00]);
        assert_eq!(&c[4..8], &1_000_000.0f32.to_be_bytes());
    }

    #[test]
    fn announce_carries_mp_reach_safi133_nlri_and_action() {
        let msg = build_flowspec_announce(&rule_v4());
        let (ty, total) = crate::message::parse_header(&msg).unwrap();
        assert_eq!(ty, 2); // UPDATE
        assert_eq!(total, msg.len());
        // MP_REACH_NLRI attribute (type 14, optional non-transitive 0x80)
        assert!(msg.windows(2).any(|w| w == [0x80, 14]));
        // AFI 1 (v4), SAFI 133, nexthop_len 0
        assert!(msg.windows(4).any(|w| w == [0x00, 0x01, 0x85, 0x00]));
        // the traffic-rate action community bytes appear
        assert!(msg
            .windows(8)
            .any(|w| w == [0x80, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
        // the NLRI appears verbatim
        let nlri = encode_flowspec_nlri(&rule_v4());
        assert!(msg.windows(nlri.len()).any(|w| w == nlri.as_slice()));
    }

    #[test]
    fn withdraw_uses_mp_unreach_with_identical_nlri() {
        let msg = build_flowspec_withdraw(&rule_v4());
        let (ty, _) = crate::message::parse_header(&msg).unwrap();
        assert_eq!(ty, 2);
        assert!(msg.windows(2).any(|w| w == [0x80, 15])); // MP_UNREACH_NLRI
        let nlri = encode_flowspec_nlri(&rule_v4());
        assert!(msg.windows(nlri.len()).any(|w| w == nlri.as_slice()));
    }

    #[test]
    fn announce_v6_uses_afi2() {
        let r = FlowSpecRule {
            dst: "2001:db8::7/128".parse().unwrap(),
            ..rule_v4()
        };
        let msg = build_flowspec_announce(&r);
        assert!(msg.windows(4).any(|w| w == [0x00, 0x02, 0x85, 0x00])); // AFI 2, SAFI 133, nh 0
    }
}
