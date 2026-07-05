//! A low-interaction SSH responder: real version banner + a static KEXINIT,
//! then capture the client's banner and disconnect. No cryptography.

use crate::conn::{AsyncStream, DeceptionConn};
use crate::emulator::{EmulatorOutcome, ServiceEmulator};
use crate::error::DeceptionError;
use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MAX_BANNER: usize = 512;

/// Answers an SSH connection with a version banner and a KEXINIT, then closes.
pub struct SshEmulator {
    version: String,
}

impl SshEmulator {
    /// Create an emulator that advertises `version` (e.g. `"SSH-2.0-OpenSSH_9.6"`).
    pub fn new(version: impl Into<String>) -> Self {
        Self {
            version: version.into(),
        }
    }

    /// Build a valid SSH binary KEXINIT packet (RFC 4253 §7.1, msg type 20).
    /// Cookie bytes are fixed (deterministic output); algorithm name-lists are
    /// plausible OpenSSH defaults.
    pub fn kexinit_packet() -> Vec<u8> {
        let mut payload = Vec::new();
        payload.push(20u8); // SSH_MSG_KEXINIT
        payload.extend_from_slice(&[0u8; 16]); // cookie
        let lists = [
            "curve25519-sha256",
            "ssh-ed25519",
            "chacha20-poly1305@openssh.com",
            "chacha20-poly1305@openssh.com",
            "hmac-sha2-256",
            "hmac-sha2-256",
            "none",
            "none",
            "",
            "",
        ];
        for list in lists {
            let bytes = list.as_bytes();
            let len = u32::try_from(bytes.len()).unwrap_or(0);
            payload.extend_from_slice(&len.to_be_bytes());
            payload.extend_from_slice(bytes);
        }
        payload.push(0u8); // first_kex_packet_follows
        payload.extend_from_slice(&[0u8; 4]); // reserved

        // Frame: uint32 packet_length, byte padding_length, payload, padding.
        let block = 8usize;
        let min_pad = 4usize;
        let unpadded = 1 + payload.len(); // padding_length byte + payload
        let mut pad = block - (unpadded % block);
        if pad < min_pad {
            pad += block;
        }
        let packet_length = u32::try_from(1 + payload.len() + pad).unwrap_or(0);
        let pad_len = u8::try_from(pad).unwrap_or(0);

        let mut out = Vec::new();
        out.extend_from_slice(&packet_length.to_be_bytes());
        out.push(pad_len);
        out.extend_from_slice(&payload);
        out.extend(std::iter::repeat_n(0u8, pad));
        out
    }
}

#[async_trait]
impl ServiceEmulator for SshEmulator {
    fn name(&self) -> &str {
        "ssh"
    }

    async fn handle(
        &self,
        mut conn: DeceptionConn<Box<dyn AsyncStream>>,
    ) -> Result<EmulatorOutcome, DeceptionError> {
        let mut banner = self.version.clone().into_bytes();
        banner.extend_from_slice(b"\r\n");
        conn.stream.write_all(&banner).await?;
        let kex = Self::kexinit_packet();
        conn.stream.write_all(&kex).await?;
        conn.stream.flush().await?;

        // Read the client's version line (up to CRLF or a cap).
        let mut buf = Vec::new();
        let mut chunk = [0u8; 256];
        let mut bytes_in: u64 = 0;
        loop {
            let n = conn.stream.read(&mut chunk).await?;
            if n == 0 {
                break;
            }
            bytes_in += u64::try_from(n).unwrap_or(0);
            buf.extend_from_slice(&chunk[..n]);
            if buf.contains(&b'\n') || buf.len() >= MAX_BANNER {
                break;
            }
        }
        let client_banner = buf
            .split(|&b| b == b'\r' || b == b'\n')
            .next()
            .map(|l| String::from_utf8_lossy(l).into_owned())
            .filter(|l| !l.is_empty());

        let bytes_out = u64::try_from(banner.len() + kex.len()).unwrap_or(u64::MAX);
        Ok(EmulatorOutcome {
            bytes_in,
            bytes_out,
            note: client_banner,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::{DeceptionConn, DeceptionMeta};
    use blackwall_core::L4Proto;

    #[test]
    fn kexinit_is_well_framed() {
        let pkt = SshEmulator::kexinit_packet();
        // packet_length field equals the rest of the packet.
        let plen = u32::from_be_bytes([pkt[0], pkt[1], pkt[2], pkt[3]]);
        assert_eq!(usize::try_from(plen).unwrap(), pkt.len() - 4);
        assert_eq!(pkt[5], 20u8); // first payload byte is SSH_MSG_KEXINIT
    }

    #[tokio::test]
    async fn sends_banner_then_kexinit_on_the_wire_and_captures_client_version() {
        let emu = SshEmulator::new("SSH-2.0-OpenSSH_9.6");
        let (client, server) = tokio::io::duplex(2048);
        let meta = DeceptionMeta {
            local: "203.0.113.5:22".parse().unwrap(),
            peer: "198.51.100.9:40000".parse().unwrap(),
            proto: L4Proto::Tcp,
        };
        let expected_kex = SshEmulator::kexinit_packet();
        let kex_len = expected_kex.len();
        let mut client = client;
        let driver = tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            // 1. Version banner.
            let mut head = [0u8; 21]; // "SSH-2.0-OpenSSH_9.6\r\n"
            client.read_exact(&mut head).await.unwrap();
            // 2. The binary KEXINIT that a real SSH server sends right after.
            let mut kex = vec![0u8; kex_len];
            client.read_exact(&mut kex).await.unwrap();
            client.write_all(b"SSH-2.0-libssh_0.10\r\n").await.unwrap();
            (head, kex)
        });
        let outcome = emu
            .handle(DeceptionConn {
                stream: Box::new(server),
                meta,
            })
            .await
            .expect("handled");
        let (head, kex) = driver.await.unwrap();
        assert!(head.starts_with(b"SSH-2.0-OpenSSH_9.6"));
        // Assert the KEXINIT is really on the wire and well-formed (not just
        // that the builder can produce one): the packet_length field matches the
        // trailing bytes and the first payload byte is SSH_MSG_KEXINIT (20).
        assert_eq!(kex, expected_kex, "server must send its KEXINIT verbatim");
        let plen = u32::from_be_bytes([kex[0], kex[1], kex[2], kex[3]]);
        assert_eq!(usize::try_from(plen).unwrap(), kex.len() - 4);
        assert_eq!(kex[5], 20u8, "first payload byte is SSH_MSG_KEXINIT");
        assert_eq!(outcome.note.as_deref(), Some("SSH-2.0-libssh_0.10"));
    }
}
