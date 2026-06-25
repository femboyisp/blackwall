//! A small store of fake service banners keyed by port.

use crate::error::DeceptionError;
use std::collections::HashMap;

/// Fake service banners, selected by destination port.
#[derive(Debug, Clone)]
pub struct BannerStore {
    banners: HashMap<u16, Vec<u8>>,
    fallback: Vec<u8>,
}

impl BannerStore {
    /// Parse a banner file. Each non-empty, non-`#` line is `port = banner` or
    /// `* = banner` (the fallback). Banners may use `\r`, `\n`, `\t` escapes.
    pub fn from_text(input: &str) -> Result<BannerStore, DeceptionError> {
        let mut banners = HashMap::new();
        let mut fallback = b"\r\n".to_vec();
        for (idx, raw) in input.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (key, value) = line.split_once('=').ok_or_else(|| {
                DeceptionError::Protocol(format!("banner line {}: missing '='", idx + 1))
            })?;
            let bytes = unescape(value.trim());
            if key.trim() == "*" {
                fallback = bytes;
            } else {
                let port: u16 = key.trim().parse().map_err(|_| {
                    DeceptionError::Protocol(format!("banner line {}: bad port", idx + 1))
                })?;
                banners.insert(port, bytes);
            }
        }
        Ok(BannerStore { banners, fallback })
    }

    /// The banner bytes for `port`, or the fallback.
    pub fn banner_for(&self, port: u16) -> &[u8] {
        self.banners.get(&port).unwrap_or(&self.fallback)
    }
}

fn unescape(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('r') => out.push(b'\r'),
                Some('n') => out.push(b'\n'),
                Some('t') => out.push(b'\t'),
                Some('\\') => out.push(b'\\'),
                Some(other) => {
                    out.push(b'\\');
                    let mut buf = [0u8; 4];
                    out.extend_from_slice(other.encode_utf8(&mut buf).as_bytes());
                }
                None => out.push(b'\\'),
            }
        } else {
            let mut buf = [0u8; 4];
            out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_port_banner_then_fallback() {
        let store = BannerStore::from_text("# comment\n22 = SSH-2.0-OpenSSH_9.6\\r\\n\n* = \\r\\n")
            .expect("valid");
        assert_eq!(store.banner_for(22), b"SSH-2.0-OpenSSH_9.6\r\n");
        assert_eq!(store.banner_for(9999), b"\r\n");
    }

    #[test]
    fn rejects_line_without_equals() {
        let err = BannerStore::from_text("nonsense").expect_err("should fail");
        assert!(matches!(err, DeceptionError::Protocol(_)));
    }
}
