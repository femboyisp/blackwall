//! BGP message framing and the control messages (OPEN/KEEPALIVE/NOTIFICATION).

use crate::error::BgpError;

/// The 16-byte all-ones BGP marker.
pub const MARKER: [u8; 16] = [0xFF; 16];
/// The fixed BGP message header length.
pub const HEADER_LEN: usize = 19;

/// Prepend the 19-byte BGP header (marker + total length + type) to `body`.
pub fn encode_header(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let total = HEADER_LEN + body.len();
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&MARKER);
    out.extend_from_slice(&u16::try_from(total).unwrap_or(u16::MAX).to_be_bytes());
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
}
