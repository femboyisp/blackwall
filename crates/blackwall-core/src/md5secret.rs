//! A BGP TCP-MD5 shared secret that never prints itself.
use serde::{Deserialize, Serialize};

/// A TCP-MD5 (RFC 2385) shared secret. `Debug` is redacted so the key never
/// lands in a log or a `Debug`-dumped `Policy`; serde is transparent so the
/// config round-trips the raw string.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Md5Secret(String);

impl Md5Secret {
    /// Wrap a secret string.
    #[must_use]
    pub fn new(secret: String) -> Self {
        Self(secret)
    }

    /// Borrow the underlying secret (use only where it must cross an API, e.g.
    /// building the socket option).
    #[must_use]
    pub fn reveal(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Md5Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Md5Secret(***)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_redacted() {
        let s = Md5Secret::new("hunter2".into());
        assert_eq!(format!("{s:?}"), "Md5Secret(***)");
        assert!(!format!("{s:?}").contains("hunter2"));
    }

    #[test]
    fn reveal_returns_the_secret() {
        assert_eq!(Md5Secret::new("k".into()).reveal(), "k");
    }

    #[test]
    fn serde_roundtrips_transparently() {
        let s = Md5Secret::new("pw".into());
        let j = serde_json::to_string(&s).unwrap();
        assert_eq!(j, "\"pw\"");
        assert_eq!(serde_json::from_str::<Md5Secret>(&j).unwrap(), s);
    }
}
