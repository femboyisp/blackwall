//! Render a wg-quick-style WireGuard configuration.

/// A WireGuard peer stanza.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WgPeer {
    /// Peer public key.
    pub public_key: String,
    /// Comma-free `AllowedIPs` value.
    pub allowed_ips: String,
    /// Optional `Endpoint` (`host:port`).
    pub endpoint: Option<String>,
}

/// Render an `[Interface]` plus one `[Peer]` block per entry in `peers`.
#[must_use]
pub fn render_wireguard(
    private_key: &str,
    address: &str,
    listen_port: Option<u16>,
    peers: &[WgPeer],
) -> String {
    let mut out = String::new();
    out.push_str("[Interface]\n");
    out.push_str(&format!("PrivateKey = {private_key}\n"));
    out.push_str(&format!("Address = {address}\n"));
    if let Some(port) = listen_port {
        out.push_str(&format!("ListenPort = {port}\n"));
    }
    for peer in peers {
        out.push_str("\n[Peer]\n");
        out.push_str(&format!("PublicKey = {}\n", peer.public_key));
        out.push_str(&format!("AllowedIPs = {}\n", peer.allowed_ips));
        if let Some(ep) = &peer.endpoint {
            out.push_str(&format!("Endpoint = {ep}\n"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_interface_and_one_peer() {
        let peers = vec![WgPeer {
            public_key: "PUBKEYB".to_owned(),
            allowed_ips: "10.222.1.1/32".to_owned(),
            endpoint: Some("198.51.100.2:55555".to_owned()),
        }];
        let out = render_wireguard("PRIVKEYA", "10.222.1.0/30", Some(55555), &peers);
        let expected = "[Interface]\n\
PrivateKey = PRIVKEYA\n\
Address = 10.222.1.0/30\n\
ListenPort = 55555\n\
\n\
[Peer]\n\
PublicKey = PUBKEYB\n\
AllowedIPs = 10.222.1.1/32\n\
Endpoint = 198.51.100.2:55555\n";
        assert_eq!(out, expected);
    }

    #[test]
    fn omits_listenport_and_endpoint_when_absent() {
        let peers = vec![WgPeer { public_key: "PK".to_owned(), allowed_ips: "10.0.0.2/32".to_owned(), endpoint: None }];
        let out = render_wireguard("PRIV", "10.0.0.1/30", None, &peers);
        let expected = "[Interface]\n\
PrivateKey = PRIV\n\
Address = 10.0.0.1/30\n\
\n\
[Peer]\n\
PublicKey = PK\n\
AllowedIPs = 10.0.0.2/32\n";
        assert_eq!(out, expected);
    }
}
