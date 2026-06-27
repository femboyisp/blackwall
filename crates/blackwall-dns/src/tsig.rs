//! Parse a BIND-format TSIG key file.

use crate::error::DnsError;
use base64::Engine as _;

/// A TSIG HMAC algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TsigAlgorithm {
    /// HMAC-SHA256.
    HmacSha256,
    /// HMAC-SHA512.
    HmacSha512,
    /// HMAC-SHA1.
    HmacSha1,
}

/// A parsed TSIG key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TsigKey {
    /// Key name (the TSIG key id).
    pub name: String,
    /// HMAC algorithm.
    pub algorithm: TsigAlgorithm,
    /// Raw (base64-decoded) shared secret.
    pub secret: Vec<u8>,
}

/// Parse a BIND `key "name" { algorithm <alg>; secret "<base64>"; };` file.
///
/// Returns [`DnsError::Config`] if the key name, algorithm, or secret is
/// missing or the algorithm string is unrecognised.
pub fn parse_tsig_key(text: &str) -> Result<TsigKey, DnsError> {
    let name = between(text, "key", "{")
        .map(|s| s.trim().trim_matches('"').to_owned())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| DnsError::Config("tsig key: missing key name".to_owned()))?;
    let alg_tok = field(text, "algorithm")
        .ok_or_else(|| DnsError::Config("tsig key: missing algorithm".to_owned()))?;
    let algorithm = match alg_tok.as_str() {
        "hmac-sha256" => TsigAlgorithm::HmacSha256,
        "hmac-sha512" => TsigAlgorithm::HmacSha512,
        "hmac-sha1" => TsigAlgorithm::HmacSha1,
        other => {
            return Err(DnsError::Config(format!(
                "tsig key: unsupported algorithm {other}"
            )));
        }
    };
    let secret_b64 = field(text, "secret")
        .map(|s| s.trim_matches('"').to_owned())
        .ok_or_else(|| DnsError::Config("tsig key: missing secret".to_owned()))?;
    let secret = base64::engine::general_purpose::STANDARD
        .decode(secret_b64.as_bytes())
        .map_err(|e| DnsError::Config(format!("tsig key: bad base64 secret: {e}")))?;
    Ok(TsigKey {
        name,
        algorithm,
        secret,
    })
}

/// The text between the first `start` and the next `end`, trimmed.
fn between<'a>(text: &'a str, start: &str, end: &str) -> Option<&'a str> {
    let after = text.find(start)? + start.len();
    let rest = &text[after..];
    let stop = rest.find(end)?;
    Some(&rest[..stop])
}

/// The token following keyword `key_word` up to the next `;`, trimmed.
fn field(text: &str, key_word: &str) -> Option<String> {
    let after = text.find(key_word)? + key_word.len();
    let rest = &text[after..];
    let stop = rest.find(';')?;
    Some(rest[..stop].trim().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
key "bw-key" {
    algorithm hmac-sha256;
    secret "dGVzdC1zZWNyZXQtMTIzNA==";
};
"#;

    #[test]
    fn parses_bind_tsig_key() {
        let k = parse_tsig_key(SAMPLE).unwrap();
        assert_eq!(k.name, "bw-key");
        assert_eq!(k.algorithm, TsigAlgorithm::HmacSha256);
        assert_eq!(k.secret, b"test-secret-1234");
    }

    #[test]
    fn parses_each_supported_algorithm() {
        for (s, alg) in [
            ("hmac-sha256", TsigAlgorithm::HmacSha256),
            ("hmac-sha512", TsigAlgorithm::HmacSha512),
            ("hmac-sha1", TsigAlgorithm::HmacSha1),
        ] {
            let text = format!("key \"k\" {{ algorithm {s}; secret \"AAAA\"; }};");
            assert_eq!(parse_tsig_key(&text).unwrap().algorithm, alg);
        }
    }

    #[test]
    fn rejects_unknown_algorithm() {
        assert!(parse_tsig_key("key \"k\" { algorithm hmac-md5; secret \"AAAA\"; };").is_err());
    }

    #[test]
    fn rejects_malformed() {
        assert!(parse_tsig_key("not a key file").is_err());
        assert!(parse_tsig_key("key \"k\" { algorithm hmac-sha256; };").is_err());
        // no secret
    }
}
