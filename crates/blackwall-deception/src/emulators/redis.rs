//! A low-interaction Redis responder speaking enough RESP to answer common
//! probes (PING/INFO) convincingly.

use crate::conn::{AsyncStream, DeceptionConn};
use crate::emulator::{EmulatorOutcome, ServiceEmulator};
use crate::error::DeceptionError;
use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MAX_BYTES: usize = 16 * 1024;

/// Answers Redis probes over RESP.
pub struct RedisEmulator {
    version: String,
}

impl RedisEmulator {
    /// Create an emulator advertising server `version` (e.g. `"7.2.4"`).
    pub fn new(version: impl Into<String>) -> Self {
        Self {
            version: version.into(),
        }
    }

    /// RESP reply for a single (already-parsed) command verb.
    pub fn reply_for(&self, command: &str) -> Vec<u8> {
        match command.to_ascii_uppercase().as_str() {
            "PING" => b"+PONG\r\n".to_vec(),
            "INFO" => {
                let body = format!("# Server\r\nredis_version:{}\r\n", self.version);
                let len = body.len();
                format!("${len}\r\n{body}\r\n").into_bytes()
            }
            "COMMAND" | "CLIENT" | "AUTH" | "SELECT" | "HELLO" => b"+OK\r\n".to_vec(),
            "QUIT" => b"+OK\r\n".to_vec(),
            _ => b"-ERR unknown command\r\n".to_vec(),
        }
    }
}

/// Extract the command verb from a RESP request or an inline command.
fn parse_command(buf: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(buf);
    if let Some(stripped) = text.strip_prefix('*') {
        // RESP array: find the first bulk string's content.
        let mut lines = stripped.split("\r\n");
        let _count = lines.next()?;
        let len_line = lines.next()?; // "$<n>"
        if !len_line.starts_with('$') {
            return None;
        }
        let verb = lines.next()?;
        if verb.is_empty() {
            return None;
        }
        Some(verb.to_owned())
    } else {
        // Inline command.
        text.split_whitespace().next().map(|s| s.to_owned())
    }
}

#[async_trait]
impl ServiceEmulator for RedisEmulator {
    fn name(&self) -> &str {
        "redis"
    }

    async fn handle(
        &self,
        mut conn: DeceptionConn<Box<dyn AsyncStream>>,
    ) -> Result<EmulatorOutcome, DeceptionError> {
        let mut bytes_in: u64 = 0;
        let mut bytes_out: u64 = 0;
        let mut chunk = [0u8; 1024];
        let mut total = Vec::new();
        let mut first_cmd: Option<String> = None;

        loop {
            let n = conn.stream.read(&mut chunk).await?;
            if n == 0 {
                break;
            }
            bytes_in += u64::try_from(n).unwrap_or(0);
            total.extend_from_slice(&chunk[..n]);
            if total.len() > MAX_BYTES {
                break;
            }
            if let Some(verb) = parse_command(&chunk[..n]) {
                if first_cmd.is_none() {
                    first_cmd = Some(verb.clone());
                }
                let reply = self.reply_for(&verb);
                conn.stream.write_all(&reply).await?;
                conn.stream.flush().await?;
                bytes_out += u64::try_from(reply.len()).unwrap_or(0);
                if verb.eq_ignore_ascii_case("QUIT") {
                    break;
                }
            }
        }
        Ok(EmulatorOutcome {
            bytes_in,
            bytes_out,
            note: first_cmd,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::{DeceptionConn, DeceptionMeta};
    use blackwall_core::L4Proto;

    #[test]
    fn ping_and_info_and_unknown() {
        let e = RedisEmulator::new("7.2.4");
        assert_eq!(e.reply_for("PING"), b"+PONG\r\n");
        let info = e.reply_for("INFO");
        let body = "# Server\r\nredis_version:7.2.4\r\n";
        let expected = format!("${}\r\n{}\r\n", body.len(), body);
        assert_eq!(info, expected.as_bytes());
        assert!(e.reply_for("FLOOByARG").starts_with(b"-ERR"));
    }

    #[test]
    fn parses_resp_array_and_inline() {
        assert_eq!(
            parse_command(b"*1\r\n$4\r\nPING\r\n").as_deref(),
            Some("PING")
        );
        assert_eq!(parse_command(b"PING\r\n").as_deref(), Some("PING"));
        assert_eq!(parse_command(b""), None);
        assert_eq!(parse_command(b"*1\r\n"), None); // truncated RESP array
        assert_eq!(parse_command(b"*1\r\nXXXX\r\nPING\r\n"), None); // bad length-prefix line
    }

    #[tokio::test]
    async fn answers_ping() {
        let emu = RedisEmulator::new("7.2.4");
        let (client, server) = tokio::io::duplex(1024);
        let meta = DeceptionMeta {
            local: "203.0.113.5:6379".parse().unwrap(),
            peer: "198.51.100.9:40000".parse().unwrap(),
            proto: L4Proto::Tcp,
        };
        let mut client = client;
        let driver = tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            client.write_all(b"*1\r\n$4\r\nPING\r\n").await.unwrap();
            let mut resp = [0u8; 16];
            let n = client.read(&mut resp).await.unwrap();
            resp[..n].to_vec()
        });
        let outcome = emu
            .handle(DeceptionConn {
                stream: Box::new(server),
                meta,
            })
            .await
            .expect("handled");
        let resp = driver.await.unwrap();
        assert_eq!(resp, b"+PONG\r\n");
        assert_eq!(outcome.note.as_deref(), Some("PING"));
    }
}
