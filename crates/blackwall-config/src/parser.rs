//! Turns lexed lines into a [`Policy`]. Hand-written recursive-descent over a
//! flat line list; the only nesting is the `tenant { ... }` block.

use crate::error::ConfigError;
use crate::lexer::Line;
use blackwall_core::{
    AllowRule, L4Proto, Policy, PortState, ServiceTarget, ShapeBandwidth, ShapeRule, Tenant,
};
use std::net::{IpAddr, SocketAddr};

/// Parse pre-lexed lines into a [`Policy`].
pub fn parse(lines: &[Line]) -> Result<Policy, ConfigError> {
    let mut interface: Option<String> = None;
    let mut prefixes = Vec::new();
    let mut default_state = PortState::Deception;
    let mut tenants = Vec::new();
    let mut shaping = Vec::new();

    let mut i = 0;
    while i < lines.len() {
        let line = &lines[i];
        let directive = line.words[0].as_str();
        match directive {
            "interface" => {
                expect_len(line, 3, "interface <name> <iface>")?;
                interface = Some(line.words[2].clone());
            }
            "ipv4" | "ipv6" => {
                expect_len(line, 2, "<family> <cidr>")?;
                prefixes.push(parse_cidr(line, &line.words[1])?);
            }
            "default" => {
                expect_len(line, 2, "default deception|drop")?;
                default_state = match line.words[1].as_str() {
                    "deception" => PortState::Deception,
                    "drop" => PortState::Closed,
                    other => {
                        return Err(ConfigError::BadValue {
                            line: line.number,
                            what: "default state",
                            value: other.to_owned(),
                        })
                    }
                };
            }
            "tenant" => {
                let (tenant, next) = parse_tenant(lines, i)?;
                tenants.push(tenant);
                i = next;
                continue;
            }
            "shape" => {
                shaping.push(parse_shape(line)?);
            }
            other => {
                return Err(ConfigError::UnknownDirective {
                    line: line.number,
                    word: other.to_owned(),
                })
            }
        }
        i += 1;
    }

    let eof_line = lines.last().map_or(1, |l| l.number);
    let interface = interface.ok_or(ConfigError::UnexpectedToken {
        line: eof_line,
        found: "<eof>".to_owned(),
        expected: "an `interface` directive",
    })?;

    Ok(Policy {
        interface,
        prefixes,
        default_state,
        tenants,
        shaping,
    })
}

fn parse_tenant(lines: &[Line], start: usize) -> Result<(Tenant, usize), ConfigError> {
    let header = &lines[start];
    // `tenant <name> {`
    if header.words.len() != 3 || header.words[2] != "{" {
        return Err(ConfigError::UnexpectedToken {
            line: header.number,
            found: header.words.join(" "),
            expected: "tenant <name> {",
        });
    }
    let name = header.words[1].clone();
    let mut owned: Vec<IpAddr> = Vec::new();
    let mut allows: Vec<AllowRule> = Vec::new();

    let mut i = start + 1;
    while i < lines.len() {
        let line = &lines[i];
        if line.words[0] == "}" {
            return Ok((
                Tenant {
                    name,
                    owned,
                    allows,
                },
                i + 1,
            ));
        }
        match line.words[0].as_str() {
            "owns" => {
                if line.words.len() < 2 {
                    return Err(ConfigError::UnexpectedToken {
                        line: line.number,
                        found: line.words.join(" "),
                        expected: "owns <ip>[, <ip>...]",
                    });
                }
                for token in &line.words[1..] {
                    let cleaned = token.trim_end_matches(',');
                    let addr: IpAddr = cleaned.parse().map_err(|_| ConfigError::BadValue {
                        line: line.number,
                        what: "ip address",
                        value: cleaned.to_owned(),
                    })?;
                    owned.push(addr);
                }
            }
            "allow" => allows.push(parse_allow(line)?),
            other => {
                return Err(ConfigError::UnknownDirective {
                    line: line.number,
                    word: other.to_owned(),
                })
            }
        }
        i += 1;
    }

    Err(ConfigError::UnexpectedToken {
        line: header.number,
        found: "<eof>".to_owned(),
        expected: "a closing `}` for the tenant block",
    })
}

fn parse_allow(line: &Line) -> Result<AllowRule, ConfigError> {
    // `allow <tcp|udp> <port> <target>`
    expect_len(line, 4, "allow <tcp|udp> <port> <target>")?;
    let proto = match line.words[1].as_str() {
        "tcp" => L4Proto::Tcp,
        "udp" => L4Proto::Udp,
        other => {
            return Err(ConfigError::BadValue {
                line: line.number,
                what: "protocol",
                value: other.to_owned(),
            })
        }
    };
    let port: u16 = line.words[2].parse().map_err(|_| ConfigError::BadValue {
        line: line.number,
        what: "port",
        value: line.words[2].clone(),
    })?;
    let target = parse_target(line, &line.words[3])?;
    Ok(AllowRule {
        proto,
        port,
        target,
    })
}

fn parse_target(line: &Line, raw: &str) -> Result<ServiceTarget, ConfigError> {
    if raw == "host" {
        return Ok(ServiceTarget::Host);
    }
    if let Some(name) = raw.strip_prefix("incus:") {
        return Ok(ServiceTarget::Incus(name.to_owned()));
    }
    if let Some(sockaddr) = raw.strip_prefix("nat:") {
        let parsed: SocketAddr = sockaddr.parse().map_err(|_| ConfigError::BadValue {
            line: line.number,
            what: "nat target",
            value: raw.to_owned(),
        })?;
        return Ok(ServiceTarget::Nat(parsed));
    }
    Err(ConfigError::BadValue {
        line: line.number,
        what: "target",
        value: raw.to_owned(),
    })
}

fn parse_cidr(line: &Line, raw: &str) -> Result<ipnet::IpNet, ConfigError> {
    raw.parse().map_err(|_| ConfigError::BadValue {
        line: line.number,
        what: "cidr",
        value: raw.to_owned(),
    })
}

fn parse_mbit(line: &Line, token: &str) -> Result<u32, ConfigError> {
    token
        .strip_suffix("mbit")
        .and_then(|n| n.parse::<u32>().ok())
        .ok_or_else(|| ConfigError::BadValue {
            line: line.number,
            what: "bandwidth",
            value: token.to_owned(),
        })
}

fn parse_ms(line: &Line, token: &str) -> Result<u32, ConfigError> {
    token
        .strip_suffix("ms")
        .and_then(|n| n.parse::<u32>().ok())
        .ok_or_else(|| ConfigError::BadValue {
            line: line.number,
            what: "rtt",
            value: token.to_owned(),
        })
}

/// Parse `shape <iface> (auto | bandwidth <N>mbit) [up (auto | <N>mbit)] [rtt <N>ms]`.
fn parse_shape(line: &Line) -> Result<ShapeRule, ConfigError> {
    // words[0] = "shape", words[1] = iface, words[2] = "auto"|"bandwidth"
    if line.words.len() < 3 {
        return Err(ConfigError::UnexpectedToken {
            line: line.number,
            found: line.words.join(" "),
            expected: "shape <iface> (auto | bandwidth <N>mbit) [up (auto | <N>mbit)] [rtt <N>ms]",
        });
    }
    let iface = line.words[1].clone();

    let (download, mut idx) = match line.words[2].as_str() {
        "auto" => (ShapeBandwidth::Auto, 3),
        "bandwidth" => {
            if line.words.len() < 4 {
                return Err(ConfigError::UnexpectedToken {
                    line: line.number,
                    found: line.words.join(" "),
                    expected: "bandwidth <N>mbit",
                });
            }
            let bw = parse_mbit(line, &line.words[3])?;
            (ShapeBandwidth::Fixed(bw), 4)
        }
        other => {
            return Err(ConfigError::BadValue {
                line: line.number,
                what: "bandwidth mode",
                value: other.to_owned(),
            })
        }
    };

    let mut upload: Option<ShapeBandwidth> = None;
    let mut rtt_ms: Option<u32> = None;

    while idx < line.words.len() {
        match line.words[idx].as_str() {
            "up" => {
                idx += 1;
                if idx >= line.words.len() {
                    return Err(ConfigError::UnexpectedToken {
                        line: line.number,
                        found: line.words.join(" "),
                        expected: "up (auto | <N>mbit)",
                    });
                }
                upload = Some(match line.words[idx].as_str() {
                    "auto" => ShapeBandwidth::Auto,
                    token => ShapeBandwidth::Fixed(parse_mbit(line, token)?),
                });
                idx += 1;
            }
            "rtt" => {
                idx += 1;
                if idx >= line.words.len() {
                    return Err(ConfigError::UnexpectedToken {
                        line: line.number,
                        found: line.words.join(" "),
                        expected: "rtt <N>ms",
                    });
                }
                rtt_ms = Some(parse_ms(line, &line.words[idx])?);
                idx += 1;
            }
            other => {
                return Err(ConfigError::UnexpectedToken {
                    line: line.number,
                    found: other.to_owned(),
                    expected: "up | rtt",
                });
            }
        }
    }

    Ok(ShapeRule {
        iface,
        download,
        upload: upload.unwrap_or(download),
        rtt_ms,
    })
}

fn expect_len(line: &Line, n: usize, expected: &'static str) -> Result<(), ConfigError> {
    if line.words.len() == n {
        Ok(())
    } else {
        Err(ConfigError::UnexpectedToken {
            line: line.number,
            found: line.words.join(" "),
            expected,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer::lex;

    fn parse_text(s: &str) -> Result<Policy, ConfigError> {
        parse(&lex(s))
    }

    const SAMPLE: &str = "\
interface wan eth0
ipv4 203.0.113.0/24
ipv6 2001:db8::/48
default deception
tenant acme {
    owns 203.0.113.5, 2001:db8::5
    allow tcp 443 incus:web01
    allow udp 53 nat:203.0.113.5:5353
}
";

    #[test]
    fn parses_full_sample() {
        let policy = parse_text(SAMPLE).expect("valid config");
        assert_eq!(policy.interface, "eth0");
        assert_eq!(policy.prefixes.len(), 2);
        assert_eq!(policy.default_state, PortState::Deception);
        assert_eq!(policy.tenants.len(), 1);
        let acme = &policy.tenants[0];
        assert_eq!(acme.owned.len(), 2);
        assert_eq!(acme.allows.len(), 2);
        assert_eq!(
            acme.allows[0].target,
            ServiceTarget::Incus("web01".to_owned())
        );
    }

    #[test]
    fn rejects_unknown_directive() {
        let err = parse_text("frobnicate yes\n").expect_err("should fail");
        assert!(matches!(err, ConfigError::UnknownDirective { .. }));
    }

    #[test]
    fn rejects_bad_port() {
        let bad = "interface wan eth0\ntenant t {\n owns 203.0.113.5\n allow tcp 99999 host\n}\n";
        let err = parse_text(bad).expect_err("should fail");
        assert!(matches!(err, ConfigError::BadValue { what: "port", .. }));
    }

    #[test]
    fn requires_interface() {
        let err = parse_text("ipv4 203.0.113.0/24\n").expect_err("should fail");
        assert!(
            matches!(err, ConfigError::UnexpectedToken { line, .. } if line >= 1),
            "expected UnexpectedToken with 1-based line, got {err:?}"
        );
    }

    #[test]
    fn parses_default_drop() {
        let input = "interface wan eth0\ndefault drop\n";
        let policy = parse_text(input).expect("valid config");
        assert_eq!(policy.default_state, PortState::Closed);
    }

    #[test]
    fn rejects_bad_default_state() {
        let err = parse_text("interface wan eth0\ndefault bogus\n").expect_err("should fail");
        assert!(
            matches!(
                err,
                ConfigError::BadValue {
                    what: "default state",
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_bad_cidr() {
        let err = parse_text("interface wan eth0\nipv4 notacidr\n").expect_err("should fail");
        assert!(
            matches!(err, ConfigError::BadValue { what: "cidr", .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn parses_nat_target() {
        let input = "\
interface wan eth0
ipv4 203.0.113.0/24
tenant t {
    owns 203.0.113.5
    allow tcp 8080 nat:203.0.113.5:9090
}
";
        let policy = parse_text(input).expect("valid config");
        let rule = &policy.tenants[0].allows[0];
        assert!(matches!(rule.target, ServiceTarget::Nat(_)));
    }

    #[test]
    fn parses_host_target() {
        let input = "\
interface wan eth0
ipv4 203.0.113.0/24
tenant t {
    owns 203.0.113.5
    allow tcp 22 host
}
";
        let policy = parse_text(input).expect("valid config");
        let rule = &policy.tenants[0].allows[0];
        assert_eq!(rule.target, ServiceTarget::Host);
    }

    #[test]
    fn rejects_bad_target() {
        let input = "interface wan eth0\nipv4 203.0.113.0/24\ntenant t {\n owns 203.0.113.5\n allow tcp 80 badtarget\n}\n";
        let err = parse_text(input).expect_err("should fail");
        assert!(
            matches!(err, ConfigError::BadValue { what: "target", .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_bad_nat_sockaddr() {
        let input = "interface wan eth0\nipv4 203.0.113.0/24\ntenant t {\n owns 203.0.113.5\n allow tcp 80 nat:notanaddr\n}\n";
        let err = parse_text(input).expect_err("should fail");
        assert!(
            matches!(
                err,
                ConfigError::BadValue {
                    what: "nat target",
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_malformed_tenant_header() {
        let input = "interface wan eth0\ntenant missing_brace\n";
        let err = parse_text(input).expect_err("should fail");
        assert!(
            matches!(err, ConfigError::UnexpectedToken { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_unclosed_tenant_block() {
        let input = "interface wan eth0\nipv4 203.0.113.0/24\ntenant t {\n  owns 203.0.113.5\n";
        let err = parse_text(input).expect_err("should fail");
        assert!(
            matches!(err, ConfigError::UnexpectedToken { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_unknown_directive_in_tenant() {
        let input = "interface wan eth0\nipv4 203.0.113.0/24\ntenant t {\n  bogus directive\n}\n";
        let err = parse_text(input).expect_err("should fail");
        assert!(
            matches!(err, ConfigError::UnknownDirective { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_bad_protocol_in_allow() {
        let input = "interface wan eth0\nipv4 203.0.113.0/24\ntenant t {\n  owns 203.0.113.5\n  allow sctp 80 host\n}\n";
        let err = parse_text(input).expect_err("should fail");
        assert!(
            matches!(
                err,
                ConfigError::BadValue {
                    what: "protocol",
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_bad_ip_in_owns() {
        let input = "interface wan eth0\nipv4 203.0.113.0/24\ntenant t {\n  owns notanip\n}\n";
        let err = parse_text(input).expect_err("should fail");
        assert!(
            matches!(
                err,
                ConfigError::BadValue {
                    what: "ip address",
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn parses_shape_auto() {
        let p = parse_text("interface wan eth0\nshape eth0 auto\n").unwrap();
        assert_eq!(p.shaping.len(), 1);
        let s = &p.shaping[0];
        assert_eq!(s.iface, "eth0");
        assert_eq!(s.download, blackwall_core::ShapeBandwidth::Auto);
        assert_eq!(s.upload, blackwall_core::ShapeBandwidth::Auto);
    }

    #[test]
    fn parses_shape_fixed_with_up_and_rtt() {
        let p = parse_text("interface wan eth0\nshape eth0 auto up 50mbit rtt 50ms\n").unwrap();
        let s = &p.shaping[0];
        assert_eq!(s.download, blackwall_core::ShapeBandwidth::Auto);
        assert_eq!(s.upload, blackwall_core::ShapeBandwidth::Fixed(50));
        assert_eq!(s.rtt_ms, Some(50));
    }

    #[test]
    fn parses_shape_bandwidth_symmetric() {
        let p = parse_text("interface wan eth0\nshape eth0 bandwidth 1000mbit\n").unwrap();
        let s = &p.shaping[0];
        assert_eq!(s.download, blackwall_core::ShapeBandwidth::Fixed(1000));
        assert_eq!(s.upload, blackwall_core::ShapeBandwidth::Fixed(1000));
    }

    #[test]
    fn rejects_bad_shape_bandwidth() {
        let err = parse_text("interface wan eth0\nshape eth0 bandwidth lots\n").unwrap_err();
        assert!(matches!(
            err,
            ConfigError::BadValue {
                what: "bandwidth",
                ..
            }
        ));
    }

    #[test]
    fn rejects_wrong_token_count_for_directive() {
        // `interface` expects exactly 3 words
        let err = parse_text("interface eth0\n").expect_err("should fail");
        assert!(
            matches!(err, ConfigError::UnexpectedToken { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn error_display_unexpected_token() {
        let e = ConfigError::UnexpectedToken {
            line: 5,
            found: "foo".to_owned(),
            expected: "bar",
        };
        assert!(e.to_string().contains("line 5"));
        assert!(e.to_string().contains("foo"));
    }

    #[test]
    fn error_display_unknown_directive() {
        let e = ConfigError::UnknownDirective {
            line: 3,
            word: "baz".to_owned(),
        };
        assert!(e.to_string().contains("line 3"));
        assert!(e.to_string().contains("baz"));
    }

    #[test]
    fn error_display_bad_value() {
        let e = ConfigError::BadValue {
            line: 7,
            what: "port",
            value: "xyz".to_owned(),
        };
        assert!(e.to_string().contains("line 7"));
        assert!(e.to_string().contains("xyz"));
    }
}
