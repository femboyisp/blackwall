//! Pure parsing helpers for the LibreSpeed provider.

use crate::error::SpeedtestError;
use serde::Deserialize;

/// One LibreSpeed server entry from a `servers.json`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct LibreServer {
    /// Display name.
    pub name: String,
    /// Base URL (may or may not end in `/`).
    pub server: String,
}

/// Parse a LibreSpeed `servers.json` array.
pub fn parse_server_list(json: &str) -> Result<Vec<LibreServer>, SpeedtestError> {
    serde_json::from_str(json).map_err(|e| SpeedtestError::Parse(e.to_string()))
}

fn base(server: &str) -> &str {
    server.trim_end_matches('/')
}

/// The garbage (download) URL for `server`, requesting ~100 MB worth of chunks.
pub fn download_url(server: &str) -> String {
    format!("{}/backend/garbage.php?ckSize=100", base(server))
}

/// The empty (ping/latency) URL for `server`.
pub fn ping_url(server: &str) -> String {
    format!("{}/backend/empty.php", base(server))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_server_list() {
        let json = r#"[{"name":"Example","server":"https://ls.example.com/"}]"#;
        let servers = parse_server_list(json).unwrap();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].name, "Example");
    }

    #[test]
    fn builds_urls_trimming_slash() {
        assert_eq!(
            download_url("https://ls.example.com/"),
            "https://ls.example.com/backend/garbage.php?ckSize=100"
        );
        assert_eq!(
            ping_url("https://ls.example.com"),
            "https://ls.example.com/backend/empty.php"
        );
    }

    #[test]
    fn rejects_bad_json() {
        assert!(parse_server_list("not json").is_err());
    }
}
