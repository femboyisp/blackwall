//! Turns lexed lines into a [`Policy`]. Hand-written recursive-descent over a
//! flat line list; the only nesting is the `tenant { ... }` block.

use crate::error::ConfigError;
use crate::lexer::Line;
use blackwall_core::{
    AllowRule, BannerFluxConfig, DnsFluxConfig, EngineConfig, FlowSpecPolicy, FlowTableConfig,
    L4Proto, Policy, PortState, RtbhPolicy, ServiceTarget, ShapeBandwidth, ShapeRule, Tenant,
    XdpConfig, XdpMode,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Parse pre-lexed lines into a [`Policy`].
pub fn parse(lines: &[Line]) -> Result<Policy, ConfigError> {
    let mut interface: Option<String> = None;
    let mut prefixes = Vec::new();
    let mut default_state = PortState::Deception;
    let mut tenants = Vec::new();
    let mut shaping = Vec::new();
    let mut banner_flux: Option<BannerFluxConfig> = None;
    let mut dns_flux: Option<DnsFluxConfig> = None;
    let mut rtbh: Option<RtbhPolicy> = None;
    let mut flowspec: Option<FlowSpecPolicy> = None;
    let mut metrics_listen: Option<SocketAddr> = None;
    let mut engine = EngineConfig::default();
    let mut flowtable: Option<FlowTableConfig> = None;
    let mut xdp: Option<XdpConfig> = None;
    let mut stateless_tcp_ports: Vec<u16> = Vec::new();

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
            "banner-flux" => {
                if banner_flux.is_some() {
                    return Err(ConfigError::BadValue {
                        line: line.number,
                        what: "banner-flux",
                        value: "duplicate".to_owned(),
                    });
                }
                let dir = line.words.get(1).ok_or_else(|| ConfigError::BadValue {
                    line: line.number,
                    what: "banner-flux",
                    value: "missing dir".to_owned(),
                })?;
                let period = match line.words.get(2) {
                    Some(tok) => parse_duration(line, tok)?,
                    None => std::time::Duration::from_secs(6 * 3600),
                };
                banner_flux = Some(BannerFluxConfig {
                    dir: std::path::PathBuf::from(dir.as_str()),
                    period,
                });
            }
            "dns-flux" => {
                if dns_flux.is_some() {
                    return Err(ConfigError::BadValue {
                        line: line.number,
                        what: "dns-flux",
                        value: "duplicate".to_owned(),
                    });
                }
                let mut kv: std::collections::HashMap<&str, &str> =
                    std::collections::HashMap::new();
                for tok in &line.words[1..] {
                    let (k, v) = tok.split_once('=').ok_or_else(|| ConfigError::BadValue {
                        line: line.number,
                        what: "dns-flux",
                        value: tok.as_str().to_owned(),
                    })?;
                    if !matches!(
                        k,
                        "server"
                            | "zone"
                            | "name"
                            | "from"
                            | "count"
                            | "set"
                            | "period"
                            | "ttl"
                            | "tsig"
                    ) {
                        return Err(ConfigError::BadValue {
                            line: line.number,
                            what: "dns-flux key",
                            value: k.to_owned(),
                        });
                    }
                    if kv.insert(k, v).is_some() {
                        return Err(ConfigError::BadValue {
                            line: line.number,
                            what: "dns-flux duplicate key",
                            value: k.to_owned(),
                        });
                    }
                }
                let get = |k: &str| -> Result<&str, ConfigError> {
                    kv.get(k).copied().ok_or_else(|| ConfigError::BadValue {
                        line: line.number,
                        what: "dns-flux missing key",
                        value: k.to_owned(),
                    })
                };
                let bad = |what: &'static str, v: &str| ConfigError::BadValue {
                    line: line.number,
                    what,
                    value: v.to_owned(),
                };

                let server_tok = get("server")?;
                let server: SocketAddr = server_tok
                    .parse::<SocketAddr>()
                    .or_else(|_| {
                        server_tok
                            .parse::<IpAddr>()
                            .map(|ip| SocketAddr::new(ip, 53))
                    })
                    .map_err(|_| bad("server", server_tok))?;
                let prefix: ipnet::IpNet = {
                    let v = get("from")?;
                    v.parse().map_err(|_| bad("from", v))?
                };
                let count: usize = {
                    let v = get("count")?;
                    v.parse().map_err(|_| bad("count", v))?
                };
                let set: usize = {
                    let v = get("set")?;
                    v.parse().map_err(|_| bad("set", v))?
                };
                if set < 1 || count < set {
                    return Err(bad(
                        "dns-flux set/count",
                        &format!("set={set} count={count}"),
                    ));
                }
                let period = match kv.get("period") {
                    Some(t) => parse_duration(line, t)?,
                    None => std::time::Duration::from_secs(300),
                };
                let ttl: u32 = match kv.get("ttl") {
                    Some(t) => u32::try_from(parse_duration(line, t)?.as_secs())
                        .map_err(|_| bad("ttl", t))?,
                    None => 30,
                };
                dns_flux = Some(DnsFluxConfig {
                    server,
                    zone: get("zone")?.to_owned(),
                    name: get("name")?.to_owned(),
                    prefix,
                    count,
                    set,
                    period,
                    ttl,
                    tsig_path: std::path::PathBuf::from(get("tsig")?),
                });
            }
            "rtbh" => {
                if rtbh.is_some() {
                    return Err(ConfigError::BadValue {
                        line: line.number,
                        what: "rtbh",
                        value: "duplicate".to_owned(),
                    });
                }
                let mut kv: std::collections::HashMap<&str, &str> =
                    std::collections::HashMap::new();
                for tok in &line.words[1..] {
                    let (k, v) = tok.split_once('=').ok_or_else(|| ConfigError::BadValue {
                        line: line.number,
                        what: "rtbh",
                        value: tok.as_str().to_owned(),
                    })?;
                    if !matches!(
                        k,
                        "peer"
                            | "local-as"
                            | "peer-as"
                            | "router-id"
                            | "next-hop-v4"
                            | "next-hop-v6"
                            | "max"
                            | "hold-down"
                            | "ttl"
                            | "community"
                            | "md5"
                            | "gtsm-hops"
                    ) {
                        return Err(ConfigError::BadValue {
                            line: line.number,
                            what: "rtbh key",
                            value: k.to_owned(),
                        });
                    }
                    if kv.insert(k, v).is_some() {
                        return Err(ConfigError::BadValue {
                            line: line.number,
                            what: "rtbh duplicate key",
                            value: k.to_owned(),
                        });
                    }
                }
                let bad = |what: &'static str, v: &str| ConfigError::BadValue {
                    line: line.number,
                    what,
                    value: v.to_owned(),
                };
                let get = |k: &str| -> Result<&str, ConfigError> {
                    kv.get(k).copied().ok_or_else(|| ConfigError::BadValue {
                        line: line.number,
                        what: "rtbh missing key",
                        value: k.to_owned(),
                    })
                };
                let peer_tok = get("peer")?;
                let peer_addr: SocketAddr = peer_tok
                    .parse::<SocketAddr>()
                    .or_else(|_| {
                        peer_tok
                            .parse::<IpAddr>()
                            .map(|ip| SocketAddr::new(ip, 179))
                    })
                    .map_err(|_| bad("peer", peer_tok))?;
                let local_asn: u32 = get("local-as")?
                    .parse()
                    .map_err(|_| bad("local-as", get("local-as").unwrap_or("")))?;
                let peer_asn: u32 = get("peer-as")?
                    .parse()
                    .map_err(|_| bad("peer-as", get("peer-as").unwrap_or("")))?;
                if local_asn != peer_asn {
                    return Err(bad("rtbh local-as/peer-as", "must match (iBGP only)"));
                }
                let router_id: Ipv4Addr = get("router-id")?
                    .parse()
                    .map_err(|_| bad("router-id", get("router-id").unwrap_or("")))?;
                let next_hop_v4: Option<Ipv4Addr> = kv
                    .get("next-hop-v4")
                    .map(|v| v.parse().map_err(|_| bad("next-hop-v4", v)))
                    .transpose()?;
                let next_hop_v6: Option<Ipv6Addr> = kv
                    .get("next-hop-v6")
                    .map(|v| v.parse().map_err(|_| bad("next-hop-v6", v)))
                    .transpose()?;
                if next_hop_v4.is_none() && next_hop_v6.is_none() {
                    return Err(bad(
                        "rtbh",
                        "at least one of next-hop-v4/next-hop-v6 required",
                    ));
                }
                let max_blackholes: usize = get("max")?
                    .parse()
                    .map_err(|_| bad("max", get("max").unwrap_or("")))?;
                let hold_down = parse_duration(line, get("hold-down")?)?;
                let max_ttl = match kv.get("ttl") {
                    Some(t) => Some(parse_duration(line, t)?),
                    None => None,
                };
                if let Some(ttl) = max_ttl {
                    if ttl < hold_down {
                        return Err(bad("rtbh ttl", "must be >= hold-down"));
                    }
                }
                let blackhole_communities = match kv.get("community") {
                    Some(spec) => {
                        let mut out = Vec::new();
                        for pair in spec.split(',') {
                            let (a, v) =
                                pair.split_once(':').ok_or_else(|| bad("community", pair))?;
                            let asn: u16 = a.parse().map_err(|_| bad("community", pair))?;
                            let val: u16 = v.parse().map_err(|_| bad("community", pair))?;
                            out.push((asn, val));
                        }
                        out
                    }
                    None => vec![(65535, 666)],
                };
                let gtsm_hops: Option<u8> = match kv.get("gtsm-hops") {
                    Some(v) => {
                        let hops: u8 = v.parse().map_err(|_| bad("rtbh gtsm-hops", v))?;
                        if hops == 0 {
                            return Err(bad("rtbh gtsm-hops", "must be >= 1"));
                        }
                        Some(hops)
                    }
                    None => None,
                };
                rtbh = Some(RtbhPolicy {
                    local_asn,
                    peer_asn,
                    peer_addr,
                    router_id,
                    blackhole_communities,
                    next_hop_v4,
                    next_hop_v6,
                    max_blackholes,
                    hold_down,
                    max_ttl,
                    md5: kv
                        .get("md5")
                        .map(|s| blackwall_core::Md5Secret::new((*s).to_owned())),
                    gtsm_hops,
                });
            }
            "flowspec" => {
                if flowspec.is_some() {
                    return Err(ConfigError::BadValue {
                        line: line.number,
                        what: "flowspec",
                        value: "duplicate".to_owned(),
                    });
                }
                let mut kv: std::collections::HashMap<&str, &str> =
                    std::collections::HashMap::new();
                for tok in &line.words[1..] {
                    let (k, v) = tok.split_once('=').ok_or_else(|| ConfigError::BadValue {
                        line: line.number,
                        what: "flowspec",
                        value: tok.as_str().to_owned(),
                    })?;
                    if !matches!(
                        k,
                        "concentration" | "max-flows" | "rate" | "max-rules" | "hold-down" | "ttl"
                    ) {
                        return Err(ConfigError::BadValue {
                            line: line.number,
                            what: "flowspec key",
                            value: k.to_owned(),
                        });
                    }
                    if kv.insert(k, v).is_some() {
                        return Err(ConfigError::BadValue {
                            line: line.number,
                            what: "flowspec duplicate key",
                            value: k.to_owned(),
                        });
                    }
                }
                let bad = |what: &'static str, v: &str| ConfigError::BadValue {
                    line: line.number,
                    what,
                    value: v.to_owned(),
                };
                let get = |k: &str| -> Result<&str, ConfigError> {
                    kv.get(k).copied().ok_or_else(|| ConfigError::BadValue {
                        line: line.number,
                        what: "flowspec missing key",
                        value: k.to_owned(),
                    })
                };
                let concentration: f64 = get("concentration")?
                    .parse()
                    .map_err(|_| bad("concentration", get("concentration").unwrap_or("")))?;
                let max_flows: usize = get("max-flows")?
                    .parse()
                    .map_err(|_| bad("max-flows", get("max-flows").unwrap_or("")))?;
                let rate: f32 = get("rate")?
                    .parse()
                    .map_err(|_| bad("rate", get("rate").unwrap_or("")))?;
                let max_rules: usize = get("max-rules")?
                    .parse()
                    .map_err(|_| bad("max-rules", get("max-rules").unwrap_or("")))?;
                let hold_down = parse_duration(line, get("hold-down")?)?;
                let max_ttl = match kv.get("ttl") {
                    Some(t) => Some(parse_duration(line, t)?),
                    None => None,
                };
                if let Some(ttl) = max_ttl {
                    if ttl < hold_down {
                        return Err(bad("flowspec ttl", "must be >= hold-down"));
                    }
                }
                // Reject misconfigurations that silently break selection: a NaN
                // or out-of-range `concentration` (NaN makes `cumulative >= c`
                // always false → FlowSpec never chosen), `max-flows` of 0 (loop
                // never selects), or a negative `rate` (nonsensical traffic-rate).
                if !(0.0..=1.0).contains(&concentration) {
                    return Err(bad("flowspec concentration", "must be in 0.0..=1.0"));
                }
                if max_flows == 0 {
                    return Err(bad("flowspec max-flows", "must be >= 1"));
                }
                if rate.is_nan() || rate < 0.0 {
                    return Err(bad("flowspec rate", "must be >= 0"));
                }
                flowspec = Some(FlowSpecPolicy {
                    concentration,
                    max_flows,
                    rate,
                    max_rules,
                    hold_down,
                    max_ttl,
                });
            }
            "metrics" => {
                for tok in &line.words[1..] {
                    let (k, v) = tok.split_once('=').ok_or_else(|| ConfigError::BadValue {
                        line: line.number,
                        what: "metrics",
                        value: tok.as_str().to_owned(),
                    })?;
                    if k != "listen" {
                        return Err(ConfigError::BadValue {
                            line: line.number,
                            what: "metrics key",
                            value: k.to_owned(),
                        });
                    }
                    metrics_listen =
                        Some(v.parse::<SocketAddr>().map_err(|_| ConfigError::BadValue {
                            line: line.number,
                            what: "metrics listen",
                            value: v.to_owned(),
                        })?);
                }
            }
            "engine" => {
                let bad = |what: &'static str, v: &str| ConfigError::BadValue {
                    line: line.number,
                    what,
                    value: v.to_owned(),
                };
                for tok in &line.words[1..] {
                    let (k, v) = tok.split_once('=').ok_or_else(|| ConfigError::BadValue {
                        line: line.number,
                        what: "engine",
                        value: tok.as_str().to_owned(),
                    })?;
                    match k {
                        "max-concurrent" => {
                            let n = v.parse::<usize>().map_err(|_| ConfigError::BadValue {
                                line: line.number,
                                what: "engine max-concurrent",
                                value: v.to_owned(),
                            })?;
                            if n == 0 {
                                return Err(bad("engine max-concurrent", "must be >= 1"));
                            }
                            engine.max_concurrent = n;
                        }
                        "session-timeout" => {
                            let n = v.parse::<u64>().map_err(|_| ConfigError::BadValue {
                                line: line.number,
                                what: "engine session-timeout",
                                value: v.to_owned(),
                            })?;
                            if n == 0 {
                                return Err(bad(
                                    "engine session-timeout",
                                    "must be >= 1 (seconds)",
                                ));
                            }
                            engine.session_timeout_secs = n;
                        }
                        "tproxy-port" => {
                            let n = v.parse::<u16>().map_err(|_| ConfigError::BadValue {
                                line: line.number,
                                what: "engine tproxy-port",
                                value: v.to_owned(),
                            })?;
                            if n == 0 {
                                return Err(bad("engine tproxy-port", "must be 1..=65535"));
                            }
                            engine.tproxy_port = n;
                        }
                        "nfqueue" => {
                            engine.nfqueue_num =
                                v.parse::<u16>().map_err(|_| ConfigError::BadValue {
                                    line: line.number,
                                    what: "engine nfqueue",
                                    value: v.to_owned(),
                                })?;
                        }
                        other => {
                            return Err(ConfigError::BadValue {
                                line: line.number,
                                what: "engine key",
                                value: other.to_owned(),
                            })
                        }
                    }
                }
            }
            "flowtable" => {
                if flowtable.is_some() {
                    return Err(ConfigError::BadValue {
                        line: line.number,
                        what: "flowtable",
                        value: "duplicate".to_owned(),
                    });
                }
                let mut devices: Vec<String> = Vec::new();
                for tok in &line.words[1..] {
                    let (k, v) = tok.split_once('=').ok_or_else(|| ConfigError::BadValue {
                        line: line.number,
                        what: "flowtable",
                        value: tok.as_str().to_owned(),
                    })?;
                    if k != "devices" {
                        return Err(ConfigError::BadValue {
                            line: line.number,
                            what: "flowtable key",
                            value: k.to_owned(),
                        });
                    }
                    for dev in v.split(',') {
                        let dev = dev.trim();
                        if !dev.is_empty() {
                            devices.push(dev.to_owned());
                        }
                    }
                }
                if devices.is_empty() {
                    return Err(ConfigError::BadValue {
                        line: line.number,
                        what: "flowtable devices",
                        value: "must list at least one interface".to_owned(),
                    });
                }
                flowtable = Some(FlowTableConfig { devices });
            }
            "xdp" => {
                let bad = |what: &'static str, v: &str| ConfigError::BadValue {
                    line: line.number,
                    what,
                    value: v.to_owned(),
                };
                let mut cfg = XdpConfig {
                    interface: None,
                    mode: XdpMode::default(),
                    default_rate_limit_pps: None,
                    cookie_ports: Vec::new(),
                };
                for tok in &line.words[1..] {
                    let (k, v) = tok
                        .split_once('=')
                        .ok_or_else(|| bad("xdp", tok.as_str()))?;
                    match k {
                        "interface" => cfg.interface = Some(v.to_owned()),
                        "mode" => {
                            cfg.mode = match v {
                                "auto" => XdpMode::Auto,
                                "native" => XdpMode::Native,
                                "generic" => XdpMode::Generic,
                                _ => return Err(bad("xdp mode", v)),
                            }
                        }
                        "default-rate-limit" => {
                            let n = v
                                .parse::<u64>()
                                .map_err(|_| bad("xdp default-rate-limit", v))?;
                            if n == 0 {
                                return Err(bad("xdp default-rate-limit", "must be >= 1"));
                            }
                            cfg.default_rate_limit_pps = Some(n);
                        }
                        "cookie-ports" => {
                            for port_tok in v.split(',') {
                                let port_tok = port_tok.trim();
                                let n: u16 = port_tok
                                    .parse()
                                    .map_err(|_| bad("xdp cookie-ports", port_tok))?;
                                if n == 0 {
                                    return Err(bad("xdp cookie-ports", port_tok));
                                }
                                cfg.cookie_ports.push(n);
                            }
                        }
                        other => return Err(bad("xdp key", other)),
                    }
                }
                xdp = Some(cfg);
            }
            "stateless-tcp" => {
                let bad = |what: &'static str, v: &str| ConfigError::BadValue {
                    line: line.number,
                    what,
                    value: v.to_owned(),
                };
                for tok in &line.words[1..] {
                    let (k, v) = tok
                        .split_once('=')
                        .ok_or_else(|| bad("stateless-tcp", tok.as_str()))?;
                    if k != "ports" {
                        return Err(bad("stateless-tcp key", k));
                    }
                    for port_tok in v.split(',') {
                        let port_tok = port_tok.trim();
                        let n: u16 = port_tok
                            .parse()
                            .map_err(|_| bad("stateless-tcp ports", port_tok))?;
                        if n == 0 {
                            return Err(bad("stateless-tcp ports", port_tok));
                        }
                        stateless_tcp_ports.push(n);
                    }
                }
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

    // FlowSpec reuses the `rtbh` block's BGP peer (single shared iBGP session),
    // so a `flowspec` directive is meaningless without an `rtbh` block.
    if flowspec.is_some() && rtbh.is_none() {
        return Err(ConfigError::BadValue {
            line: eof_line,
            what: "flowspec",
            value: "requires an rtbh block (shared BGP session)".to_owned(),
        });
    }

    Ok(Policy {
        interface,
        prefixes,
        default_state,
        tenants,
        shaping,
        banner_flux,
        dns_flux,
        rtbh,
        flowspec,
        metrics_listen,
        engine,
        flowtable,
        xdp,
        stateless_tcp_ports,
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
        // Config-file allows apply to all of the tenant's owned addresses.
        scope: None,
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

fn parse_duration(line: &Line, token: &str) -> Result<std::time::Duration, ConfigError> {
    let (digits, mult) = if let Some(d) = token.strip_suffix('h') {
        (d, 3600_u64)
    } else if let Some(d) = token.strip_suffix('m') {
        (d, 60_u64)
    } else if let Some(d) = token.strip_suffix('s') {
        (d, 1_u64)
    } else {
        return Err(ConfigError::BadValue {
            line: line.number,
            what: "duration",
            value: token.to_owned(),
        });
    };
    let n: u64 = digits.parse().map_err(|_| ConfigError::BadValue {
        line: line.number,
        what: "duration",
        value: token.to_owned(),
    })?;
    Ok(std::time::Duration::from_secs(n * mult))
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
    fn parses_banner_flux_dir_only_defaults_period() {
        let p = parse_text("interface wan eth0\nbanner-flux /etc/bw/banners.d\n").unwrap();
        let f = p.banner_flux.unwrap();
        assert_eq!(f.dir, std::path::PathBuf::from("/etc/bw/banners.d"));
        assert_eq!(f.period, std::time::Duration::from_secs(6 * 3600));
    }

    #[test]
    fn parses_banner_flux_with_period() {
        let p = parse_text("interface wan eth0\nbanner-flux /var/b 30m\n").unwrap();
        let f = p.banner_flux.unwrap();
        assert_eq!(f.dir, std::path::PathBuf::from("/var/b"));
        assert_eq!(f.period, std::time::Duration::from_secs(1800));
    }

    #[test]
    fn rejects_bad_banner_flux_period() {
        assert!(parse_text("interface wan eth0\nbanner-flux /var/b 5x\n").is_err());
    }

    #[test]
    fn rejects_duplicate_banner_flux() {
        assert!(parse_text("interface wan eth0\nbanner-flux /a\nbanner-flux /b\n").is_err());
    }

    #[test]
    fn parses_dns_flux_full_with_defaults() {
        let p = parse_text(
            "interface wan eth0\n\
             dns-flux server=192.0.2.53 zone=example.com name=www.example.com from=203.0.113.0/24 count=8 set=3 tsig=/etc/bw/knot.tsig\n",
        )
        .unwrap();
        let d = p.dns_flux.unwrap();
        assert_eq!(d.server, "192.0.2.53:53".parse().unwrap());
        assert_eq!(d.zone, "example.com");
        assert_eq!(d.name, "www.example.com");
        assert_eq!(d.prefix, "203.0.113.0/24".parse().unwrap());
        assert_eq!(d.count, 8);
        assert_eq!(d.set, 3);
        assert_eq!(d.period, std::time::Duration::from_secs(300));
        assert_eq!(d.ttl, 30);
        assert_eq!(d.tsig_path, std::path::PathBuf::from("/etc/bw/knot.tsig"));
    }

    #[test]
    fn parses_dns_flux_with_explicit_port_period_ttl() {
        let p = parse_text(
            "interface wan eth0\n\
             dns-flux server=192.0.2.53:5353 zone=z name=n from=2001:db8::/64 count=4 set=2 period=1m ttl=10s tsig=/k\n",
        )
        .unwrap();
        let d = p.dns_flux.unwrap();
        assert_eq!(d.server, "192.0.2.53:5353".parse().unwrap());
        assert_eq!(d.period, std::time::Duration::from_secs(60));
        assert_eq!(d.ttl, 10);
        assert_eq!(d.prefix, "2001:db8::/64".parse().unwrap());
    }

    #[test]
    fn rejects_dns_flux_set_gt_count() {
        assert!(parse_text("interface wan eth0\ndns-flux server=192.0.2.53 zone=z name=n from=203.0.113.0/24 count=2 set=5 tsig=/k\n").is_err());
    }

    #[test]
    fn rejects_dns_flux_unknown_key() {
        assert!(parse_text("interface wan eth0\ndns-flux server=192.0.2.53 zone=z name=n from=203.0.113.0/24 count=2 set=1 tsig=/k bogus=1\n").is_err());
    }

    #[test]
    fn rejects_dns_flux_duplicate_key() {
        let err = parse_text("interface wan eth0\ndns-flux server=192.0.2.53 zone=z name=n from=203.0.113.0/24 count=8 count=2 set=1 tsig=/k\n").unwrap_err();
        assert!(
            matches!(
                err,
                ConfigError::BadValue {
                    what: "dns-flux duplicate key",
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_rtbh_duplicate_key() {
        let err = parse_text("interface wan eth0\nrtbh peer=10.0.0.2 peer=10.0.0.3 local-as=1 peer-as=1 router-id=10.0.0.1 next-hop-v4=10.0.0.9 max=8 hold-down=30s\n").unwrap_err();
        assert!(
            matches!(
                err,
                ConfigError::BadValue {
                    what: "rtbh duplicate key",
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_dns_flux_missing_required() {
        assert!(parse_text("interface wan eth0\ndns-flux server=192.0.2.53 zone=z\n").is_err());
    }

    #[test]
    fn rejects_duplicate_dns_flux() {
        assert!(parse_text("interface wan eth0\ndns-flux server=192.0.2.53 zone=z name=n from=203.0.113.0/24 count=2 set=1 tsig=/k\ndns-flux server=192.0.2.53 zone=z name=n from=203.0.113.0/24 count=2 set=1 tsig=/k\n").is_err());
    }

    #[test]
    fn parses_rtbh_full() {
        let p = parse_text(
            "interface wan eth0\nipv4 203.0.113.0/24\n\
             rtbh peer=10.0.0.2:179 local-as=214806 peer-as=214806 router-id=10.222.255.1 next-hop-v4=10.222.255.99 max=256 hold-down=60s ttl=2h\n",
        ).unwrap();
        let r = p.rtbh.unwrap();
        assert_eq!(r.peer_addr, "10.0.0.2:179".parse().unwrap());
        assert_eq!(r.local_asn, 214806);
        assert_eq!(r.peer_asn, 214806);
        assert_eq!(
            r.router_id,
            "10.222.255.1".parse::<std::net::Ipv4Addr>().unwrap()
        );
        assert_eq!(
            r.next_hop_v4,
            Some("10.222.255.99".parse::<std::net::Ipv4Addr>().unwrap())
        );
        assert_eq!(r.max_blackholes, 256);
        assert_eq!(r.hold_down, std::time::Duration::from_secs(60));
        assert_eq!(r.max_ttl, Some(std::time::Duration::from_secs(7200)));
        assert_eq!(r.blackhole_communities, vec![(65535, 666)]); // default
        assert_eq!(r.gtsm_hops, None); // absent by default
    }

    #[test]
    fn parses_rtbh_gtsm_hops() {
        let p = parse_text(
            "interface wan eth0\nrtbh peer=10.0.0.2 local-as=1 peer-as=1 router-id=10.0.0.1 next-hop-v4=10.0.0.9 max=8 hold-down=30s gtsm-hops=1\n",
        )
        .unwrap();
        assert_eq!(p.rtbh.unwrap().gtsm_hops, Some(1));
    }

    #[test]
    fn rejects_rtbh_zero_gtsm_hops() {
        let err = parse_text(
            "interface wan eth0\nrtbh peer=10.0.0.2 local-as=1 peer-as=1 router-id=10.0.0.1 next-hop-v4=10.0.0.9 max=8 hold-down=30s gtsm-hops=0\n",
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                ConfigError::BadValue {
                    what: "rtbh gtsm-hops",
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn rtbh_peer_bare_ip_defaults_179() {
        let p = parse_text("interface wan eth0\nrtbh peer=10.0.0.2 local-as=1 peer-as=1 router-id=10.0.0.1 next-hop-v6=2001:db8::1 max=8 hold-down=30s\n").unwrap();
        assert_eq!(p.rtbh.unwrap().peer_addr, "10.0.0.2:179".parse().unwrap());
    }

    #[test]
    fn rtbh_parses_custom_communities() {
        let p = parse_text("interface wan eth0\nrtbh peer=10.0.0.2 local-as=1 peer-as=1 router-id=10.0.0.1 next-hop-v4=10.0.0.9 max=8 hold-down=30s community=65535:666,65535:667\n").unwrap();
        assert_eq!(
            p.rtbh.unwrap().blackhole_communities,
            vec![(65535, 666), (65535, 667)]
        );
    }

    #[test]
    fn rtbh_rejects_ebgp() {
        assert!(parse_text("interface wan eth0\nrtbh peer=10.0.0.2 local-as=1 peer-as=2 router-id=10.0.0.1 next-hop-v4=10.0.0.9 max=8 hold-down=30s\n").is_err());
    }

    #[test]
    fn rtbh_requires_a_next_hop() {
        assert!(parse_text("interface wan eth0\nrtbh peer=10.0.0.2 local-as=1 peer-as=1 router-id=10.0.0.1 max=8 hold-down=30s\n").is_err());
    }

    #[test]
    fn rtbh_rejects_ttl_below_hold_down() {
        assert!(parse_text("interface wan eth0\nrtbh peer=10.0.0.2 local-as=1 peer-as=1 router-id=10.0.0.1 next-hop-v4=10.0.0.9 max=8 hold-down=60s ttl=30s\n").is_err());
    }

    #[test]
    fn rtbh_rejects_unknown_key() {
        assert!(parse_text("interface wan eth0\nrtbh peer=10.0.0.2 local-as=1 peer-as=1 router-id=10.0.0.1 next-hop-v4=10.0.0.9 max=8 hold-down=30s bogus=1\n").is_err());
    }

    #[test]
    fn rtbh_rejects_duplicate() {
        let dup = "interface wan eth0\nrtbh peer=10.0.0.2 local-as=1 peer-as=1 router-id=10.0.0.1 next-hop-v4=10.0.0.9 max=8 hold-down=30s\nrtbh peer=10.0.0.3 local-as=1 peer-as=1 router-id=10.0.0.1 next-hop-v4=10.0.0.9 max=8 hold-down=30s\n";
        assert!(parse_text(dup).is_err());
    }

    #[test]
    fn rtbh_parses_optional_md5() {
        let src = "interface wan eth0\nrtbh peer=10.0.0.2:179 local-as=65000 peer-as=65000 router-id=10.0.0.1 next-hop-v4=192.0.2.1 max=8 hold-down=60s md5=s3cret\n";
        let p = parse_text(src).unwrap();
        assert_eq!(p.rtbh.unwrap().md5.unwrap().reveal(), "s3cret");
    }

    #[test]
    fn rtbh_md5_absent_is_none() {
        let src = "interface wan eth0\nrtbh peer=10.0.0.2:179 local-as=65000 peer-as=65000 router-id=10.0.0.1 next-hop-v4=192.0.2.1 max=8 hold-down=60s\n";
        assert!(parse_text(src).unwrap().rtbh.unwrap().md5.is_none());
    }

    #[test]
    fn parses_flowspec_directive() {
        let src = "\
interface wan eth0
ipv4 203.0.113.0/24
rtbh peer=10.0.0.2:179 local-as=214806 peer-as=214806 router-id=10.222.255.1 next-hop-v4=10.222.255.99 max=256 hold-down=60s ttl=2h
flowspec concentration=0.8 max-flows=4 rate=0 max-rules=256 hold-down=60s ttl=2h
";
        let policy = parse_text(src).unwrap();
        let fs = policy.flowspec.expect("flowspec present");
        assert_eq!(fs.concentration, 0.8);
        assert_eq!(fs.max_flows, 4);
        assert_eq!(fs.rate, 0.0);
        assert_eq!(fs.max_rules, 256);
        assert_eq!(fs.hold_down, std::time::Duration::from_secs(60));
        assert_eq!(fs.max_ttl, Some(std::time::Duration::from_secs(7200)));
    }

    #[test]
    fn flowspec_without_rtbh_is_rejected() {
        let src = "\
interface wan eth0
ipv4 203.0.113.0/24
flowspec concentration=0.8 max-flows=4 rate=0 max-rules=256 hold-down=60s ttl=2h
";
        let err = parse_text(src).unwrap_err();
        assert!(format!("{err}").contains("flowspec"));
    }

    #[test]
    fn flowspec_rejects_invalid_selection_tunables() {
        let base = "interface wan eth0\nrtbh peer=10.0.0.2:179 local-as=214806 peer-as=214806 router-id=10.222.255.1 next-hop-v4=10.222.255.99 max=256 hold-down=60s ttl=2h\n";
        for fs in [
            "flowspec concentration=1.5 max-flows=4 rate=0 max-rules=256 hold-down=60s",
            "flowspec concentration=nan max-flows=4 rate=0 max-rules=256 hold-down=60s",
            "flowspec concentration=0.8 max-flows=0 rate=0 max-rules=256 hold-down=60s",
            "flowspec concentration=0.8 max-flows=4 rate=-1 max-rules=256 hold-down=60s",
        ] {
            let src = format!("{base}{fs}\n");
            assert!(parse_text(&src).is_err(), "should reject: {fs}");
        }
    }

    #[test]
    fn duplicate_flowspec_is_rejected() {
        let src = "\
interface wan eth0
rtbh peer=10.0.0.2:179 local-as=214806 peer-as=214806 router-id=10.222.255.1 next-hop-v4=10.222.255.99 max=256 hold-down=60s ttl=2h
flowspec concentration=0.8 max-flows=4 rate=0 max-rules=256 hold-down=60s ttl=2h
flowspec concentration=0.9 max-flows=2 rate=0 max-rules=8 hold-down=30s ttl=1h
";
        assert!(parse_text(src).is_err());
    }

    #[test]
    fn flowspec_rejects_ttl_below_hold_down() {
        let src = "\
interface wan eth0
rtbh peer=10.0.0.2:179 local-as=1 peer-as=1 router-id=10.0.0.1 next-hop-v4=10.0.0.9 max=8 hold-down=60s
flowspec concentration=0.8 max-flows=4 rate=0 max-rules=256 hold-down=60s ttl=30s
";
        assert!(parse_text(src).is_err());
    }

    #[test]
    fn flowspec_rejects_unknown_key() {
        let src = "\
interface wan eth0
rtbh peer=10.0.0.2:179 local-as=1 peer-as=1 router-id=10.0.0.1 next-hop-v4=10.0.0.9 max=8 hold-down=60s
flowspec concentration=0.8 max-flows=4 rate=0 max-rules=256 hold-down=60s bogus=1
";
        assert!(parse_text(src).is_err());
    }

    #[test]
    fn parses_metrics_listen() {
        let p = parse_text("interface wan eth0\nmetrics listen=127.0.0.1:9100\n").unwrap();
        assert_eq!(
            p.metrics_listen,
            Some("127.0.0.1:9100".parse::<SocketAddr>().unwrap())
        );
    }

    #[test]
    fn metrics_listen_absent_is_none() {
        let p = parse_text("interface wan eth0\n").unwrap();
        assert_eq!(p.metrics_listen, None);
    }

    #[test]
    fn rejects_bad_metrics_addr() {
        let err = parse_text("interface wan eth0\nmetrics listen=not-an-addr\n").unwrap_err();
        assert!(
            matches!(
                err,
                ConfigError::BadValue {
                    what: "metrics listen",
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_metrics_unknown_key() {
        let err = parse_text("interface wan eth0\nmetrics bogus=1\n").unwrap_err();
        assert!(
            matches!(
                err,
                ConfigError::BadValue {
                    what: "metrics key",
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn engine_absent_uses_defaults() {
        let p = parse_text("interface wan eth0\n").unwrap();
        assert_eq!(p.engine, EngineConfig::default());
    }

    #[test]
    fn parses_engine_directive() {
        let p = parse_text(
            "interface wan eth0\n\
             engine max-concurrent=4096 session-timeout=120 tproxy-port=62000 nfqueue=3\n",
        )
        .unwrap();
        assert_eq!(p.engine.max_concurrent, 4096);
        assert_eq!(p.engine.session_timeout_secs, 120);
        assert_eq!(p.engine.tproxy_port, 62000);
        assert_eq!(p.engine.nfqueue_num, 3);
    }

    #[test]
    fn engine_partial_overrides_only_named_keys() {
        let p = parse_text("interface wan eth0\nengine tproxy-port=62000\n").unwrap();
        assert_eq!(p.engine.tproxy_port, 62000);
        // Untouched knobs keep their defaults.
        assert_eq!(
            p.engine.max_concurrent,
            EngineConfig::default().max_concurrent
        );
        assert_eq!(p.engine.nfqueue_num, EngineConfig::default().nfqueue_num);
    }

    #[test]
    fn rejects_zero_engine_max_concurrent() {
        let err = parse_text("interface wan eth0\nengine max-concurrent=0\n").unwrap_err();
        assert!(
            matches!(
                err,
                ConfigError::BadValue {
                    what: "engine max-concurrent",
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_zero_engine_tproxy_port() {
        let err = parse_text("interface wan eth0\nengine tproxy-port=0\n").unwrap_err();
        assert!(
            matches!(
                err,
                ConfigError::BadValue {
                    what: "engine tproxy-port",
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_engine_unknown_key() {
        let err = parse_text("interface wan eth0\nengine bogus=1\n").unwrap_err();
        assert!(
            matches!(
                err,
                ConfigError::BadValue {
                    what: "engine key",
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn flowtable_absent_is_none() {
        let p = parse_text("interface wan eth0\n").unwrap();
        assert!(p.flowtable.is_none());
    }

    #[test]
    fn parses_flowtable_devices() {
        let p = parse_text("interface wan eth0\nflowtable devices=eth0,incusbr0\n").unwrap();
        let ft = p.flowtable.expect("flowtable set");
        assert_eq!(ft.devices, vec!["eth0".to_owned(), "incusbr0".to_owned()]);
    }

    #[test]
    fn rejects_empty_flowtable_devices() {
        let err = parse_text("interface wan eth0\nflowtable devices=\n").unwrap_err();
        assert!(
            matches!(
                err,
                ConfigError::BadValue {
                    what: "flowtable devices",
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_flowtable_unknown_key() {
        let err = parse_text("interface wan eth0\nflowtable bogus=eth0\n").unwrap_err();
        assert!(
            matches!(
                err,
                ConfigError::BadValue {
                    what: "flowtable key",
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_duplicate_flowtable() {
        let err =
            parse_text("interface wan eth0\nflowtable devices=eth0\nflowtable devices=eth1\n")
                .unwrap_err();
        assert!(
            matches!(
                err,
                ConfigError::BadValue {
                    what: "flowtable",
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn parses_xdp_directive() {
        let p = parse_text(
            "interface wan eth0\nxdp interface=eth0 mode=native default-rate-limit=1000\n",
        )
        .unwrap();
        let x = p.xdp.expect("xdp set");
        assert_eq!(x.interface.as_deref(), Some("eth0"));
        assert_eq!(x.mode, blackwall_core::XdpMode::Native);
        assert_eq!(x.default_rate_limit_pps, Some(1000));
        assert!(x.cookie_ports.is_empty());
    }

    #[test]
    fn parses_xdp_cookie_ports() {
        let p =
            parse_text("interface wan eth0\nxdp interface=eth0 cookie-ports=8080,443\n").unwrap();
        let x = p.xdp.expect("xdp set");
        assert_eq!(x.cookie_ports, vec![8080, 443]);
    }

    #[test]
    fn rejects_xdp_cookie_ports_bad() {
        let err = parse_text("interface wan eth0\nxdp cookie-ports=8080,0\n").unwrap_err();
        assert!(
            matches!(
                err,
                ConfigError::BadValue {
                    what: "xdp cookie-ports",
                    ..
                }
            ),
            "got {err:?}"
        );

        let err = parse_text("interface wan eth0\nxdp cookie-ports=notaport\n").unwrap_err();
        assert!(
            matches!(
                err,
                ConfigError::BadValue {
                    what: "xdp cookie-ports",
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn xdp_absent_is_none() {
        assert!(parse_text("interface wan eth0\n").unwrap().xdp.is_none());
    }

    #[test]
    fn rejects_xdp_unknown_key() {
        let err = parse_text("interface wan eth0\nxdp bogus=1\n").unwrap_err();
        assert!(
            matches!(
                err,
                ConfigError::BadValue {
                    what: "xdp key",
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_xdp_bad_mode() {
        let err = parse_text("interface wan eth0\nxdp mode=turbo\n").unwrap_err();
        assert!(
            matches!(
                err,
                ConfigError::BadValue {
                    what: "xdp mode",
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn parses_stateless_tcp() {
        let p = parse_text("interface wan eth0\nstateless-tcp ports=22,80,443\n").unwrap();
        assert_eq!(p.stateless_tcp_ports, vec![22, 80, 443]);
    }

    #[test]
    fn stateless_tcp_absent_is_empty() {
        let p = parse_text("interface wan eth0\n").unwrap();
        assert!(p.stateless_tcp_ports.is_empty());
    }

    #[test]
    fn rejects_stateless_tcp_bad_port() {
        let err = parse_text("interface wan eth0\nstateless-tcp ports=22,0,443\n").unwrap_err();
        assert!(
            matches!(
                err,
                ConfigError::BadValue {
                    what: "stateless-tcp ports",
                    ..
                }
            ),
            "got {err:?}"
        );

        let err = parse_text("interface wan eth0\nstateless-tcp ports=notaport\n").unwrap_err();
        assert!(
            matches!(
                err,
                ConfigError::BadValue {
                    what: "stateless-tcp ports",
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_stateless_tcp_unknown_key() {
        let err = parse_text("interface wan eth0\nstateless-tcp bogus=1\n").unwrap_err();
        assert!(
            matches!(
                err,
                ConfigError::BadValue {
                    what: "stateless-tcp key",
                    ..
                }
            ),
            "got {err:?}"
        );
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
