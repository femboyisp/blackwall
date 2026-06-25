//! Pure parsing helpers for the Cloudflare provider.

/// Build the Cloudflare download URL for `bytes`.
pub fn download_url(bytes: u64) -> String {
    format!("https://speed.cloudflare.com/__down?bytes={bytes}")
}

/// Parse the `dur=` value (milliseconds) from a Cloudflare `Server-Timing`
/// header such as `cfRequestDuration;dur=12.3`.
pub fn server_timing_latency(header: &str) -> Option<f64> {
    for part in header.split(',') {
        for kv in part.split(';') {
            let kv = kv.trim();
            if let Some(v) = kv.strip_prefix("dur=") {
                if let Ok(ms) = v.trim().parse::<f64>() {
                    if ms.is_finite() {
                        return Some(ms);
                    }
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_download_url() {
        assert_eq!(
            download_url(1000),
            "https://speed.cloudflare.com/__down?bytes=1000"
        );
    }

    #[test]
    fn parses_server_timing() {
        assert_eq!(
            server_timing_latency("cfRequestDuration;dur=12.3"),
            Some(12.3)
        );
        assert_eq!(
            server_timing_latency("cfL4;desc=\"x\", cfRequestDuration;dur=8"),
            Some(8.0)
        );
        assert_eq!(server_timing_latency("nothing-here"), None);
        assert_eq!(server_timing_latency("cfRequestDuration;dur=NaN"), None);
    }
}
