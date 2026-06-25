//! A minimal but believable HTTP responder.

use crate::conn::{AsyncStream, DeceptionConn};
use crate::emulator::{EmulatorOutcome, ServiceEmulator};
use crate::error::DeceptionError;
use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MAX_REQUEST: usize = 8192;
const BODY: &str = "<!doctype html><html><head><title>It works</title></head>\
<body><h1>It works!</h1></body></html>";

/// Answers any HTTP request with a complete, well-formed 200 response.
pub struct HttpEmulator {
    server_header: String,
}

impl HttpEmulator {
    /// Create an emulator that advertises `server_header` (e.g. `"nginx/1.24.0"`).
    pub fn new(server_header: impl Into<String>) -> Self {
        Self {
            server_header: server_header.into(),
        }
    }

    /// Build the raw response bytes (pure; unit-tested directly).
    pub fn response(&self) -> Vec<u8> {
        format!(
            "HTTP/1.1 200 OK\r\nServer: {}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            self.server_header,
            BODY.len(),
            BODY
        )
        .into_bytes()
    }
}

#[async_trait]
impl ServiceEmulator for HttpEmulator {
    fn name(&self) -> &str {
        "http"
    }

    async fn handle(
        &self,
        mut conn: DeceptionConn<Box<dyn AsyncStream>>,
    ) -> Result<EmulatorOutcome, DeceptionError> {
        // Read until the header terminator or the cap, whichever comes first.
        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];
        let mut bytes_in: u64 = 0;
        loop {
            let n = conn.stream.read(&mut chunk).await?;
            if n == 0 {
                break;
            }
            bytes_in += u64::try_from(n).unwrap_or(0);
            buf.extend_from_slice(&chunk[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() >= MAX_REQUEST {
                break;
            }
        }
        let request_line = buf
            .split(|&b| b == b'\r' || b == b'\n')
            .next()
            .map(|l| String::from_utf8_lossy(l).into_owned())
            .filter(|l| !l.is_empty());

        let response = self.response();
        conn.stream.write_all(&response).await?;
        conn.stream.flush().await?;

        Ok(EmulatorOutcome {
            bytes_in,
            bytes_out: u64::try_from(response.len()).unwrap_or(u64::MAX),
            note: request_line,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::DeceptionMeta;
    use blackwall_core::L4Proto;
    use tokio::io::AsyncReadExt;

    #[test]
    fn response_is_well_formed() {
        let r = String::from_utf8(HttpEmulator::new("nginx/1.24.0").response()).unwrap();
        assert!(r.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(r.contains("\r\nServer: nginx/1.24.0\r\n"));
        assert!(r.contains(&format!("\r\nContent-Length: {}\r\n", super::BODY.len())));
        // No header line begins with whitespace (would be obs-fold / malformed).
        for line in r.split("\r\n") {
            assert!(
                !line.starts_with(' ') && !line.starts_with('\t'),
                "malformed header line: {line:?}"
            );
        }
        assert!(r.ends_with("</html>"));
    }

    #[tokio::test]
    async fn answers_request_and_captures_request_line() {
        let emu = HttpEmulator::new("nginx/1.24.0");
        let (client, server) = tokio::io::duplex(4096);
        let meta = DeceptionMeta {
            local: "203.0.113.5:80".parse().unwrap(),
            peer: "198.51.100.9:40000".parse().unwrap(),
            proto: L4Proto::Tcp,
        };
        let mut client = client;
        let writer = tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            client
                .write_all(b"GET /admin HTTP/1.1\r\nHost: x\r\n\r\n")
                .await
                .unwrap();
            let mut resp = Vec::new();
            client.read_to_end(&mut resp).await.unwrap();
            resp
        });
        let outcome = emu
            .handle(DeceptionConn {
                stream: Box::new(server),
                meta,
            })
            .await
            .expect("handled");
        let resp = writer.await.unwrap();
        assert!(String::from_utf8_lossy(&resp).starts_with("HTTP/1.1 200 OK"));
        assert_eq!(outcome.note.as_deref(), Some("GET /admin HTTP/1.1"));
    }
}
