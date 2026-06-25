//! A low-interaction SMTP responder that speaks enough of the protocol to
//! satisfy scanners and capture envelope addresses.

use crate::conn::{AsyncStream, DeceptionConn};
use crate::emulator::{EmulatorOutcome, ServiceEmulator};
use crate::error::DeceptionError;
use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MAX_BYTES: usize = 16 * 1024;
const MAX_COMMANDS: usize = 64;

/// Answers SMTP with correct numeric reply codes through a basic envelope.
pub struct SmtpEmulator {
    hostname: String,
}

impl SmtpEmulator {
    /// Create an emulator greeting as `hostname` (e.g. `"mail.example.com"`).
    pub fn new(hostname: impl Into<String>) -> Self {
        Self {
            hostname: hostname.into(),
        }
    }

    /// The reply for a single command line (without CRLF). Returns the reply
    /// bytes and whether the session should close after sending it.
    pub fn reply_for(&self, line: &str) -> (Vec<u8>, bool) {
        let verb = line
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_ascii_uppercase();
        match verb.as_str() {
            "EHLO" | "HELO" => (format!("250 {}\r\n", self.hostname).into_bytes(), false),
            "MAIL" | "RCPT" => (b"250 OK\r\n".to_vec(), false),
            "DATA" => (b"354 End data with <CR><LF>.<CR><LF>\r\n".to_vec(), false),
            "RSET" | "NOOP" => (b"250 OK\r\n".to_vec(), false),
            "QUIT" => (b"221 Bye\r\n".to_vec(), true),
            "" => (b"500 Error\r\n".to_vec(), false),
            _ => (b"502 Command not implemented\r\n".to_vec(), false),
        }
    }
}

#[async_trait]
impl ServiceEmulator for SmtpEmulator {
    fn name(&self) -> &str {
        "smtp"
    }

    async fn handle(
        &self,
        mut conn: DeceptionConn<Box<dyn AsyncStream>>,
    ) -> Result<EmulatorOutcome, DeceptionError> {
        let greeting = format!("220 {} ESMTP ready\r\n", self.hostname).into_bytes();
        conn.stream.write_all(&greeting).await?;
        conn.stream.flush().await?;

        let mut bytes_in: u64 = 0;
        let mut bytes_out = u64::try_from(greeting.len()).unwrap_or(0);
        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];
        let mut commands = 0usize;
        let mut first_cmd: Option<String> = None;
        let mut in_data = false;

        'outer: loop {
            let n = conn.stream.read(&mut chunk).await?;
            if n == 0 {
                break;
            }
            bytes_in += u64::try_from(n).unwrap_or(0);
            buf.extend_from_slice(&chunk[..n]);
            if bytes_in > u64::try_from(MAX_BYTES).unwrap_or(u64::MAX) {
                break;
            }
            // Process complete CRLF-terminated lines.
            while let Some(pos) = buf.windows(2).position(|w| w == b"\r\n") {
                let line_bytes: Vec<u8> = buf.drain(..pos + 2).collect();
                let line =
                    String::from_utf8_lossy(&line_bytes[..line_bytes.len() - 2]).into_owned();
                if in_data {
                    if line == "." {
                        in_data = false;
                        conn.stream.write_all(b"250 OK\r\n").await?;
                        conn.stream.flush().await?;
                        bytes_out += 8;
                    }
                    continue;
                }
                if first_cmd.is_none() {
                    first_cmd = Some(line.clone());
                }
                let (reply, close) = self.reply_for(&line);
                if line
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .eq_ignore_ascii_case("DATA")
                {
                    in_data = true;
                }
                conn.stream.write_all(&reply).await?;
                bytes_out += u64::try_from(reply.len()).unwrap_or(0);
                commands += 1;
                if close || commands >= MAX_COMMANDS {
                    break 'outer;
                }
            }
        }
        conn.stream.flush().await?;
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
    fn reply_codes_are_correct() {
        let e = SmtpEmulator::new("mail.example.com");
        assert!(e.reply_for("EHLO x").0.starts_with(b"250 "));
        assert!(e.reply_for("MAIL FROM:<a@b>").0.starts_with(b"250 "));
        assert!(e.reply_for("DATA").0.starts_with(b"354 "));
        let (q, close) = e.reply_for("QUIT");
        assert!(q.starts_with(b"221 "));
        assert!(close);
        assert!(e.reply_for("WizardFizzle").0.starts_with(b"502 "));
    }

    #[tokio::test]
    async fn greets_and_handles_quit() {
        let emu = SmtpEmulator::new("mail.example.com");
        let (client, server) = tokio::io::duplex(4096);
        let meta = DeceptionMeta {
            local: "203.0.113.5:25".parse().unwrap(),
            peer: "198.51.100.9:40000".parse().unwrap(),
            proto: L4Proto::Tcp,
        };
        let mut client = client;
        let driver = tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut greet = [0u8; 64];
            let n = client.read(&mut greet).await.unwrap();
            client.write_all(b"EHLO test\r\n").await.unwrap();
            let mut resp = [0u8; 64];
            let _ = client.read(&mut resp).await.unwrap();
            client.write_all(b"QUIT\r\n").await.unwrap();
            let mut bye = Vec::new();
            client.read_to_end(&mut bye).await.unwrap();
            (greet[..n].to_vec(), bye)
        });
        let outcome = emu
            .handle(DeceptionConn {
                stream: Box::new(server),
                meta,
            })
            .await
            .expect("handled");
        let (greet, bye) = driver.await.unwrap();
        assert!(greet.starts_with(b"220 mail.example.com ESMTP"));
        assert!(String::from_utf8_lossy(&bye).contains("221 "));
        assert_eq!(outcome.note.as_deref(), Some("EHLO test"));
    }
}
