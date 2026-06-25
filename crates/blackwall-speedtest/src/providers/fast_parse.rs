//! Pure parsing helpers for the fast.com (Netflix) provider.

use crate::error::SpeedtestError;
use serde::Deserialize;

/// Extract the `token:"..."` value from fast.com's application JavaScript.
pub fn extract_token(js: &str) -> Option<String> {
    let marker = "token:\"";
    let start = js.find(marker)? + marker.len();
    let rest = &js[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_owned())
}

/// Build the fast.com measurement API URL.
pub fn api_url(token: &str, count: u32) -> String {
    format!("https://api.fast.com/netflix/speedtest/v2?https=true&token={token}&urlCount={count}")
}

/// A download target returned by the fast.com API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FastTarget {
    /// The URL to download from.
    pub url: String,
}

#[derive(Deserialize)]
struct ApiResponse {
    targets: Vec<ApiTarget>,
}

#[derive(Deserialize)]
struct ApiTarget {
    url: String,
}

/// Extract the absolute URL of fast.com's application JS bundle from the page HTML.
///
/// Looks for a `<script src="/app-*.js">` tag and returns the full `https://fast.com/…` URL.
/// Returns `None` if no matching tag is found.
pub fn extract_js_url(html: &str) -> Option<String> {
    // fast.com embeds a script tag like: <script src="/app-abc123.js"></script>
    let marker = "src=\"/app-";
    let start = html.find(marker)? + "src=\"".len();
    let rest = &html[start..];
    let end = rest.find('"')?;
    let path = &rest[..end];
    Some(format!("https://fast.com{path}"))
}

/// Parse the fast.com API response into download targets.
pub fn parse_targets(json: &str) -> Result<Vec<FastTarget>, SpeedtestError> {
    let resp: ApiResponse =
        serde_json::from_str(json).map_err(|e| SpeedtestError::Parse(e.to_string()))?;
    Ok(resp
        .targets
        .into_iter()
        .map(|t| FastTarget { url: t.url })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_token() {
        let js = r#"...,token:"abc123DEF",apiEndpoint:..."#;
        assert_eq!(extract_token(js).as_deref(), Some("abc123DEF"));
        assert_eq!(extract_token("no token here"), None);
        assert_eq!(extract_token(r#"token:"unterminated"#), None);
    }

    #[test]
    fn extracts_js_url() {
        let html = r#"<script src="/app-abc123.js"></script>"#;
        assert_eq!(
            extract_js_url(html).as_deref(),
            Some("https://fast.com/app-abc123.js")
        );
        assert_eq!(extract_js_url("<html>no bundle here</html>"), None);
    }

    #[test]
    fn builds_api_url() {
        assert_eq!(
            api_url("tok", 3),
            "https://api.fast.com/netflix/speedtest/v2?https=true&token=tok&urlCount=3"
        );
    }

    #[test]
    fn parses_targets() {
        let json =
            r#"{"targets":[{"url":"https://cdn.example/a"},{"url":"https://cdn.example/b"}]}"#;
        let t = parse_targets(json).unwrap();
        assert_eq!(t.len(), 2);
        assert_eq!(t[0].url, "https://cdn.example/a");
    }
}
