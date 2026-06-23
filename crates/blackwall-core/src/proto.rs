//! Layer-4 transport protocols Blackwall classifies on.

use serde::{Deserialize, Serialize};

/// A layer-4 transport protocol. Blackwall classifies policy per `(IP, proto, port)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum L4Proto {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
}

impl std::fmt::Display for L4Proto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            L4Proto::Tcp => "tcp",
            L4Proto::Udp => "udp",
        };
        f.write_str(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_is_lowercase_keyword() {
        assert_eq!(L4Proto::Tcp.to_string(), "tcp");
        assert_eq!(L4Proto::Udp.to_string(), "udp");
    }
}
