//! Pure parsing helpers for the Ookla (speedtest.net) provider.

use crate::error::SpeedtestError;
use serde::Deserialize;

/// An Ookla server entry.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct OoklaServer {
    /// `host:port` of the test server.
    pub host: String,
    /// Server name.
    pub name: String,
}

/// Parse an Ookla server list (array of objects with `host` and `name`).
pub fn parse_servers(json: &str) -> Result<Vec<OoklaServer>, SpeedtestError> {
    serde_json::from_str(json).map_err(|e| SpeedtestError::Parse(e.to_string()))
}

/// Parse the protocol version from an Ookla `HELLO 2 ...` greeting line.
pub fn parse_hello(line: &str) -> Option<u32> {
    let mut parts = line.split_whitespace();
    if parts.next()? != "HELLO" {
        return None;
    }
    parts.next()?.parse::<u32>().ok()
}

/// The text command requesting a download of `bytes` bytes.
pub fn download_command(bytes: u64) -> String {
    format!("DOWNLOAD {bytes}\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_servers() {
        let json = r#"[{"host":"sp.example.com:8080","name":"Example"}]"#;
        let s = parse_servers(json).unwrap();
        assert_eq!(s[0].host, "sp.example.com:8080");
    }

    #[test]
    fn parses_hello() {
        assert_eq!(parse_hello("HELLO 2 2024 abcdef"), Some(2));
        assert_eq!(parse_hello("WAT"), None);
    }

    #[test]
    fn builds_download_command() {
        assert_eq!(download_command(1000), "DOWNLOAD 1000\n");
    }
}
