//! Render a [`Policy`] into an nftables `inet blackwall` table.
//!
//! Layout:
//! * Named set `real_v4` — open `(ipv4_addr, inet_proto, inet_service)`
//!   tuples for every Open IPv4 service in the policy.
//! * Named set `real_v6` — open `(ipv6_addr, inet_proto, inet_service)`
//!   tuples for every Open IPv6 service in the policy.
//! * Chain `prerouting` — base chain with classifier rules scoped to the
//!   managed interface via an `iifname` match:
//!   1. Real-service membership → accept (host/incus reach the backend directly;
//!      `nat:` targets are DNAT'd in a separate `nat` chain).
//!   2. Deception TCP on a configured stateless port (`stateless-tcp ports=`)
//!      on a managed prefix → queue to the configured NFQUEUE (the same queue
//!      the ICMP/UDP responder uses; the stateless SYN-cookie responder
//!      handles TCP on that queue). Emitted before rule 3 so a stateless-tier
//!      port is queued and never falls through to tproxy.
//!   3. Deception TCP on managed prefix (all other ports) → tproxy to the
//!      configured engine port.
//!   4. Deception ICMP/UDP on managed prefix → queue to the configured NFQUEUE.
//!   5. If default_state == Closed → an interface-scoped terminal `drop` rule
//!      (the chain runs for every interface, so the closed posture must be
//!      enforced by a rule matched on `iifname`, not a chain-wide drop policy).
//!
//! This module is pure: it builds the schema only. Applying it is handled by
//! the `apply` function in the crate root.

use blackwall_core::{Policy, PolicyError, PortState, ServiceTarget};
use nftables::{
    expr::{
        Expression, Meta, MetaKey, NamedExpression, Payload, PayloadField, Prefix, SetItem, CT,
    },
    schema::{
        Chain, FlowTable, FlushObject, NfCmd, NfListObject, NfObject, Nftables, Rule, Set, SetType,
        SetTypeValue, Table,
    },
    stmt::{Flow, Mangle, Match, NATFamily, Operator, Queue, SetOp, Statement, TProxy, NAT},
    types::{NfChainPolicy, NfChainType, NfFamily, NfHook},
};

/// Build an `iifname == <iface>` match statement.
///
/// Used to scope each classifier rule to the managed interface without binding
/// the prerouting chain to a device (which nft rejects for non-ingress/egress
/// chains).
fn iifname_match(iface: &str) -> Statement<'static> {
    Statement::Match(Match {
        left: Expression::Named(NamedExpression::Meta(Meta {
            key: MetaKey::Iifname,
        })),
        right: Expression::String(iface.to_owned().into()),
        op: Operator::EQ,
    })
}

/// The nftables family Blackwall uses (dual-stack).
const FAMILY: NfFamily = NfFamily::INet;
/// The table name Blackwall owns.
const TABLE: &str = "blackwall";

/// Firewall mark set on deception-TCP packets by the tproxy rule.
///
/// TPROXY only delivers a packet to the local transparent socket if the routing
/// decision keeps it local; for a *forwarded* managed prefix (the dst is not a
/// local address) it would otherwise be routed onward. Marking the packet lets
/// a policy route (`ip rule fwmark <mark> lookup <table>` + a `local default`
/// route in that table — installed by [`crate::apply`]) send it to the local
/// input path instead. Must match [`TPROXY_ROUTE_TABLE`] in `apply`.
pub(crate) const TPROXY_MARK: u32 = 0x1;

/// Routing table holding the `local default` route for TPROXY-marked packets.
pub(crate) const TPROXY_ROUTE_TABLE: u32 = 100;

/// Build the full nftables ruleset for `policy`.
///
/// Emits objects in order:
/// 1. `add table inet blackwall`   — ensure the table exists
/// 2. `flush table inet blackwall` — atomically empty it (stale state removed)
/// 3. `add set inet blackwall real_v4 { type ipv4_addr . inet_proto . inet_service; ... }`
/// 4. `add set inet blackwall real_v6 { type ipv6_addr . inet_proto . inet_service; ... }`
/// 5. `add chain inet blackwall prerouting { type filter hook prerouting priority -300; }`
///    (no device binding — device binding is rejected by nft for prerouting chains;
///    the managed interface is scoped per-rule via `iifname == policy.interface`)
/// 6. Rule: `iifname` match + real-service membership → accept (nat: targets DNAT'd in the nat chain)
/// 7. Rule: `iifname` match + deception TCP on a configured stateless port → queue to the
///    configured NFQUEUE (only when `policy.stateless_tcp_ports` is non-empty; emitted before
///    rule 8 so these ports never fall through to tproxy)
/// 8. Rule: `iifname` match + deception TCP on managed prefix (all other ports) → tproxy to the
///    configured engine port
/// 9. Rule: `iifname` match + deception ICMP/UDP on managed prefix → queue to the configured NFQUEUE
///
/// The idiomatic nft atomic full-replace pattern is: `add table` (creates if
/// absent), `flush table` (empties existing content), then re-add sets and
/// chains. This guarantees that services removed from the policy are never left
/// behind in `real_v4`/`real_v6`.
///
/// When `policy.default_state == Closed` the chain's default policy is `drop`.
pub fn render(policy: &Policy) -> Result<Nftables<'static>, PolicyError> {
    let resolved = policy.resolve()?;

    let mut objects: Vec<NfObject<'static>> = Vec::new();

    // 1. Table — create if absent.
    objects.push(NfObject::CmdObject(NfCmd::Add(NfListObject::Table(
        Table {
            family: FAMILY,
            name: TABLE.into(),
            handle: None,
        },
    ))));

    // 2. Flush table — atomically empty stale sets/chains so that a service
    //    removed from the policy is never left behind in real_v4/real_v6.
    objects.push(NfObject::CmdObject(NfCmd::Flush(FlushObject::Table(
        Table {
            family: FAMILY,
            name: TABLE.into(),
            handle: None,
        },
    ))));

    // 3. Named set of open (addr, proto, port) tuples — IPv4 addresses only.
    let v4_elements = set_elements_for(&resolved, |s| s.addr.is_ipv4());
    objects.push(NfObject::CmdObject(NfCmd::Add(NfListObject::Set(
        Box::new(Set {
            family: FAMILY,
            table: TABLE.into(),
            name: "real_v4".into(),
            handle: None,
            set_type: SetTypeValue::Concatenated(
                vec![SetType::Ipv4Addr, SetType::InetProto, SetType::InetService].into(),
            ),
            policy: None,
            flags: None,
            // Omit `elem` entirely when empty: nft rejects `"elem": []` on a
            // typed set ("Invalid set elem expression"), which breaks any
            // single-family policy (e.g. IPv4-only, or a family with no real
            // services). An absent `elem` declares an empty set correctly.
            elem: if v4_elements.is_empty() {
                None
            } else {
                Some(v4_elements.into())
            },
            timeout: None,
            gc_interval: None,
            size: None,
            comment: None,
        }),
    ))));

    // 4. Named set of open (addr, proto, port) tuples — IPv6 addresses only.
    //    Uses SetType::Ipv6Addr for the address field.
    let v6_elements = set_elements_for(&resolved, |s| s.addr.is_ipv6());
    objects.push(NfObject::CmdObject(NfCmd::Add(NfListObject::Set(
        Box::new(Set {
            family: FAMILY,
            table: TABLE.into(),
            name: "real_v6".into(),
            handle: None,
            set_type: SetTypeValue::Concatenated(
                vec![SetType::Ipv6Addr, SetType::InetProto, SetType::InetService].into(),
            ),
            policy: None,
            flags: None,
            elem: if v6_elements.is_empty() {
                None
            } else {
                Some(v6_elements.into())
            },
            timeout: None,
            gc_interval: None,
            size: None,
            comment: None,
        }),
    ))));

    // 5. Prerouting base chain.
    //
    // The chain is NOT bound to a device (nft rejects a device-bound filter
    // prerouting chain), so it runs for packets ingressing on *every* interface.
    // Its policy is therefore always Accept: a chain-wide `drop` policy would
    // black-hole unrelated host traffic (loopback, other NICs). The Closed
    // posture is instead enforced by an explicit interface-scoped drop rule
    // appended below (rule 9), preserving the original "drop only on the managed
    // interface" semantics the device binding used to provide.
    objects.push(NfObject::CmdObject(NfCmd::Add(NfListObject::Chain(
        Chain {
            family: FAMILY,
            table: TABLE.into(),
            name: "prerouting".into(),
            newname: None,
            handle: None,
            _type: Some(NfChainType::Filter),
            hook: Some(NfHook::Prerouting),
            prio: Some(-300),
            dev: None,
            policy: Some(NfChainPolicy::Accept),
        },
    ))));

    // 6. Rule: real-service membership check — accept.
    //    daddr . l4proto . dport in @real_v4 → accept
    //    (host:/incus: targets pass to the host stack / instance address; a
    //    fixed `nat:` backend is rewritten by the DNAT chain built below.)
    //
    //    Note: we emit one rule per address family so the concat type matches.
    //    IPv4: meta nfproto ipv4 ip daddr . meta l4proto . th dport @real_v4 accept
    //    IPv6: meta nfproto ipv6 ip6 daddr . meta l4proto . th dport @real_v6 accept
    for (set_name, nfproto) in [("real_v4", "ipv4"), ("real_v6", "ipv6")] {
        let daddr_field = if set_name == "real_v4" { "ip" } else { "ip6" };
        let accept_rule = Rule {
            family: FAMILY,
            table: TABLE.into(),
            chain: "prerouting".into(),
            expr: vec![
                // iifname == managed interface — scope rule to policy interface
                iifname_match(&policy.interface),
                // meta nfproto == ipv4/ipv6
                Statement::Match(Match {
                    left: Expression::Named(NamedExpression::Meta(Meta {
                        key: MetaKey::Nfproto,
                    })),
                    right: Expression::String(nfproto.into()),
                    op: Operator::EQ,
                }),
                // daddr . l4proto . dport in @real_vN
                Statement::Match(Match {
                    left: Expression::Named(NamedExpression::Concat(vec![
                        Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                            PayloadField {
                                protocol: daddr_field.into(),
                                field: "daddr".into(),
                            },
                        ))),
                        Expression::Named(NamedExpression::Meta(Meta {
                            key: MetaKey::L4proto,
                        })),
                        Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                            PayloadField {
                                protocol: "th".into(),
                                field: "dport".into(),
                            },
                        ))),
                    ])),
                    right: Expression::String(format!("@{set_name}").into()),
                    op: Operator::IN,
                }),
                // accept — host/incus reach the backend directly; nat: is DNAT'd in the nat chain
                Statement::Accept(None),
            ]
            .into(),
            handle: None,
            index: None,
            comment: Some("real service: accept (nat: targets DNAT'd in the nat chain)".into()),
        };
        objects.push(NfObject::CmdObject(NfCmd::Add(NfListObject::Rule(
            accept_rule,
        ))));
    }

    // 7. Rule: deception TCP on a configured stateless port → queue to the
    //    configured NFQUEUE — the SAME NFQUEUE the ICMP/UDP responder uses
    //    (rule 9 below); the stateless SYN-cookie responder handles TCP on
    //    that queue. Only emitted when `policy.stateless_tcp_ports` is
    //    non-empty. This rule MUST precede the tproxy rule (rule 8) so that
    //    deception TCP on these ports is queued and never falls through to
    //    the interactive tier.
    if !policy.stateless_tcp_ports.is_empty() {
        let port_set: Vec<SetItem<'static>> = policy
            .stateless_tcp_ports
            .iter()
            .map(|&port| SetItem::Element(Expression::Number(u32::from(port))))
            .collect();
        for prefix in &policy.prefixes {
            let proto_name: &'static str = if prefix.addr().is_ipv4() { "ip" } else { "ip6" };
            let prefix_str = prefix.addr().to_string();
            let prefix_len = prefix.prefix_len();
            let stateless_tcp_rule = Rule {
                family: FAMILY,
                table: TABLE.into(),
                chain: "prerouting".into(),
                expr: vec![
                    // iifname == managed interface — scope rule to policy interface
                    iifname_match(&policy.interface),
                    // meta l4proto tcp
                    Statement::Match(Match {
                        left: Expression::Named(NamedExpression::Meta(Meta {
                            key: MetaKey::L4proto,
                        })),
                        right: Expression::String("tcp".into()),
                        op: Operator::EQ,
                    }),
                    // daddr in managed prefix
                    Statement::Match(Match {
                        left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                            PayloadField {
                                protocol: proto_name.into(),
                                field: "daddr".into(),
                            },
                        ))),
                        right: Expression::Named(NamedExpression::Prefix(Prefix {
                            addr: Box::new(Expression::String(prefix_str.into())),
                            len: u32::from(prefix_len),
                        })),
                        op: Operator::EQ,
                    }),
                    // th dport in { the configured stateless ports }
                    Statement::Match(Match {
                        left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                            PayloadField {
                                protocol: "th".into(),
                                field: "dport".into(),
                            },
                        ))),
                        right: Expression::Named(NamedExpression::Set(port_set.clone())),
                        op: Operator::IN,
                    }),
                    // queue num — the configured NFQUEUE number (same as ICMP/UDP)
                    Statement::Queue(Queue {
                        num: Expression::Number(u32::from(policy.engine.nfqueue_num)),
                        flags: None,
                    }),
                ]
                .into(),
                handle: None,
                index: None,
                comment: Some(
                    format!(
                        "deception TCP (stateless ports): queue to nfqueue {}",
                        policy.engine.nfqueue_num
                    )
                    .into(),
                ),
            };
            objects.push(NfObject::CmdObject(NfCmd::Add(NfListObject::Rule(
                stateless_tcp_rule,
            ))));
        }
    }

    // 8. Rule: deception TCP on managed prefix → tproxy to the configured engine port.
    //
    //    nftables-0.6 provides a typed `Statement::TProxy` variant that
    //    serializes as `{"tproxy": {"family": "<f>", "port": <n>}}`.
    for prefix in &policy.prefixes {
        let (addr_family, proto_name): (&'static str, &'static str) = if prefix.addr().is_ipv4() {
            ("ip", "ip")
        } else {
            ("ip6", "ip6")
        };
        let prefix_str = prefix.addr().to_string();
        let prefix_len = prefix.prefix_len();
        let tproxy_rule = Rule {
            family: FAMILY,
            table: TABLE.into(),
            chain: "prerouting".into(),
            expr: vec![
                // iifname == managed interface — scope rule to policy interface
                iifname_match(&policy.interface),
                // meta l4proto tcp
                Statement::Match(Match {
                    left: Expression::Named(NamedExpression::Meta(Meta {
                        key: MetaKey::L4proto,
                    })),
                    right: Expression::String("tcp".into()),
                    op: Operator::EQ,
                }),
                // daddr in managed prefix
                Statement::Match(Match {
                    left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                        PayloadField {
                            protocol: proto_name.into(),
                            field: "daddr".into(),
                        },
                    ))),
                    right: Expression::Named(NamedExpression::Prefix(Prefix {
                        addr: Box::new(Expression::String(prefix_str.into())),
                        len: u32::from(prefix_len),
                    })),
                    op: Operator::EQ,
                }),
                // meta mark set TPROXY_MARK — so the policy route installed by
                // `apply` delivers this (possibly forwarded) packet to the local
                // transparent socket instead of routing it onward.
                Statement::Mangle(Mangle {
                    key: Expression::Named(NamedExpression::Meta(Meta { key: MetaKey::Mark })),
                    value: Expression::Number(TPROXY_MARK),
                }),
                Statement::TProxy(TProxy {
                    family: Some(addr_family.into()),
                    port: policy.engine.tproxy_port,
                    addr: None,
                }),
                Statement::Accept(None),
            ]
            .into(),
            handle: None,
            index: None,
            comment: Some(
                format!(
                    "deception TCP: tproxy to engine port {}",
                    policy.engine.tproxy_port
                )
                .into(),
            ),
        };
        objects.push(NfObject::CmdObject(NfCmd::Add(NfListObject::Rule(
            tproxy_rule,
        ))));
    }

    // 9. Rule: deception ICMP/UDP on managed prefix → queue to the configured NFQUEUE.
    //
    //    `Statement::Queue` is a typed variant; it serializes as
    //    `{"queue": {"num": <n>}}`.
    for prefix in &policy.prefixes {
        let proto_name: &'static str = if prefix.addr().is_ipv4() { "ip" } else { "ip6" };
        let prefix_str = prefix.addr().to_string();
        let prefix_len = prefix.prefix_len();
        let queue_rule = Rule {
            family: FAMILY,
            table: TABLE.into(),
            chain: "prerouting".into(),
            expr: vec![
                // iifname == managed interface — scope rule to policy interface
                iifname_match(&policy.interface),
                // meta l4proto != tcp  (i.e. ICMP and UDP)
                Statement::Match(Match {
                    left: Expression::Named(NamedExpression::Meta(Meta {
                        key: MetaKey::L4proto,
                    })),
                    right: Expression::String("tcp".into()),
                    op: Operator::NEQ,
                }),
                // daddr in managed prefix
                Statement::Match(Match {
                    left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                        PayloadField {
                            protocol: proto_name.into(),
                            field: "daddr".into(),
                        },
                    ))),
                    right: Expression::Named(NamedExpression::Prefix(Prefix {
                        addr: Box::new(Expression::String(prefix_str.into())),
                        len: u32::from(prefix_len),
                    })),
                    op: Operator::EQ,
                }),
                // queue num — the configured NFQUEUE number
                Statement::Queue(Queue {
                    num: Expression::Number(u32::from(policy.engine.nfqueue_num)),
                    flags: None,
                }),
            ]
            .into(),
            handle: None,
            index: None,
            comment: Some(
                format!(
                    "deception ICMP/UDP: queue to nfqueue {}",
                    policy.engine.nfqueue_num
                )
                .into(),
            ),
        };
        objects.push(NfObject::CmdObject(NfCmd::Add(NfListObject::Rule(
            queue_rule,
        ))));
    }

    // 10. Closed posture: drop unmatched traffic on the managed interface.
    //
    //    The chain is unbound (rule 5) and its policy is Accept, so the Closed
    //    default_state is enforced with this interface-scoped terminal drop
    //    rather than a chain-wide drop policy. Only managed-interface traffic
    //    that fell through the classifier rules above is dropped — never
    //    loopback or other-interface host traffic, which the old device-bound
    //    chain's drop policy also never touched.
    if policy.default_state == PortState::Closed {
        let drop_rule = Rule {
            family: FAMILY,
            table: TABLE.into(),
            chain: "prerouting".into(),
            expr: vec![iifname_match(&policy.interface), Statement::Drop(None)].into(),
            handle: None,
            index: None,
            comment: Some("closed posture: drop unmatched traffic on the managed interface".into()),
        };
        objects.push(NfObject::CmdObject(NfCmd::Add(NfListObject::Rule(
            drop_rule,
        ))));
    }

    // 6b. Real-service DNAT for `nat:<ip>:<port>` targets. A `filter` chain can
    //     not DNAT, so this needs a separate `nat` chain at `dstnat` priority
    //     (-100). `host:`/`incus:` targets keep the plain accept above (the
    //     packet reaches the host stack / the instance address directly); only
    //     an explicit fixed backend is rewritten here. Cross-family targets
    //     (v4 frontend → v6 backend) are skipped (nft can't dnat across
    //     families in one rule).
    objects.push(NfObject::CmdObject(NfCmd::Add(NfListObject::Chain(
        Chain {
            family: FAMILY,
            table: TABLE.into(),
            name: "dnat".into(),
            newname: None,
            handle: None,
            _type: Some(NfChainType::NAT),
            hook: Some(NfHook::Prerouting),
            prio: Some(-100),
            dev: None,
            policy: Some(NfChainPolicy::Accept),
        },
    ))));
    for svc in &resolved {
        let ServiceTarget::Nat(backend) = svc.target else {
            continue;
        };
        if svc.addr.is_ipv4() != backend.is_ipv4() {
            continue; // cross-family DNAT unsupported in a single rule
        }
        let (daddr_field, nat_family) = if svc.addr.is_ipv4() {
            ("ip", NATFamily::IP)
        } else {
            ("ip6", NATFamily::IP6)
        };
        let dnat_rule = Rule {
            family: FAMILY,
            table: TABLE.into(),
            chain: "dnat".into(),
            expr: vec![
                iifname_match(&policy.interface),
                // <ip|ip6> daddr == frontend address
                Statement::Match(Match {
                    left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                        PayloadField {
                            protocol: daddr_field.into(),
                            field: "daddr".into(),
                        },
                    ))),
                    right: Expression::String(svc.addr.to_string().into()),
                    op: Operator::EQ,
                }),
                // meta l4proto == tcp|udp
                Statement::Match(Match {
                    left: Expression::Named(NamedExpression::Meta(Meta {
                        key: MetaKey::L4proto,
                    })),
                    right: Expression::String(svc.proto.to_string().into()),
                    op: Operator::EQ,
                }),
                // th dport == frontend port
                Statement::Match(Match {
                    left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                        PayloadField {
                            protocol: "th".into(),
                            field: "dport".into(),
                        },
                    ))),
                    right: Expression::Number(u32::from(svc.port)),
                    op: Operator::EQ,
                }),
                // dnat <ip|ip6> to <backend-ip>:<backend-port>
                Statement::DNAT(Some(NAT {
                    addr: Some(Expression::String(backend.ip().to_string().into())),
                    family: Some(nat_family),
                    port: Some(Expression::Number(u32::from(backend.port()))),
                    flags: None,
                })),
            ]
            .into(),
            handle: None,
            index: None,
            comment: Some(format!("real service DNAT → {backend}").into()),
        };
        objects.push(NfObject::CmdObject(NfCmd::Add(NfListObject::Rule(
            dnat_rule,
        ))));
    }

    // 11. Optional flowtable fast path for real-service (forwarded) traffic.
    //
    //     A flowtable offloads *established forwarded* flows to the kernel's
    //     conntrack fast path, bypassing the per-packet forwarding path.
    //     Deception traffic is TPROXY-diverted to the local engine and is never
    //     forwarded, so it is never offloaded. Emitted only when the operator
    //     opts in with an explicit device list (`flowtable devices=...`); the
    //     kernel engages offload only once both directions' devices are members.
    if let Some(ft) = &policy.flowtable {
        // Flowtable object bound to the operator's forwarding devices.
        let devices: Vec<std::borrow::Cow<'static, str>> = ft
            .devices
            .iter()
            .map(|d| std::borrow::Cow::Owned(d.clone()))
            .collect();
        objects.push(NfObject::CmdObject(NfCmd::Add(NfListObject::FlowTable(
            FlowTable {
                family: FAMILY,
                table: TABLE.into(),
                name: "ft".into(),
                handle: None,
                hook: Some(NfHook::Ingress),
                // `filter` priority == 0.
                prio: Some(0),
                dev: Some(devices.into()),
            },
        ))));

        // Forward filter chain — policy accept, so it never changes the
        // forwarding decision; it only tags established flows for offload.
        objects.push(NfObject::CmdObject(NfCmd::Add(NfListObject::Chain(
            Chain {
                family: FAMILY,
                table: TABLE.into(),
                name: "forward".into(),
                newname: None,
                handle: None,
                _type: Some(NfChainType::Filter),
                hook: Some(NfHook::Forward),
                prio: Some(0),
                dev: None,
                policy: Some(NfChainPolicy::Accept),
            },
        ))));

        // Offload rule: scope to traffic ingressing on the managed uplink (so
        // unrelated transit flows on the box are not offloaded), match only
        // established conntrack flows, then hand the flow to the flowtable.
        let offload_rule = Rule {
            family: FAMILY,
            table: TABLE.into(),
            chain: "forward".into(),
            expr: vec![
                iifname_match(&policy.interface),
                Statement::Match(Match {
                    left: Expression::Named(NamedExpression::CT(CT {
                        key: "state".into(),
                        family: None,
                        dir: None,
                    })),
                    right: Expression::String("established".into()),
                    op: Operator::IN,
                }),
                Statement::Flow(Flow {
                    op: SetOp::Add,
                    flowtable: "@ft".into(),
                }),
            ]
            .into(),
            handle: None,
            index: None,
            comment: Some("real-service fast path: offload established flows".into()),
        };
        objects.push(NfObject::CmdObject(NfCmd::Add(NfListObject::Rule(
            offload_rule,
        ))));
    }

    Ok(Nftables {
        objects: objects.into(),
    })
}

/// Build set elements for services matching `predicate`.
fn set_elements_for(
    resolved: &[blackwall_core::ResolvedService],
    predicate: impl Fn(&blackwall_core::ResolvedService) -> bool,
) -> Vec<Expression<'static>> {
    resolved
        .iter()
        .filter(|s| predicate(s))
        .map(|s| {
            Expression::Named(NamedExpression::Concat(vec![
                Expression::String(s.addr.to_string().into()),
                Expression::String(s.proto.to_string().into()),
                Expression::Number(u32::from(s.port)),
            ]))
        })
        .collect()
}

/// Render `policy` to the nft JSON the kernel / `nft` binary accepts.
///
/// # Errors
///
/// Returns [`PolicyError`] when policy resolution fails (e.g. unresolvable
/// service targets). The `serde_json` serialization is infallible for this
/// closed schema type — the `expect` below can never fire in practice.
pub fn ruleset_json(policy: &Policy) -> Result<String, PolicyError> {
    let ruleset = render(policy)?;
    Ok(serde_json::to_string_pretty(&ruleset).expect("nftables schema serializes"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use blackwall_core::{AllowRule, L4Proto, PortState, ServiceTarget, Tenant};

    fn sample() -> Policy {
        Policy {
            interface: "eth0".to_owned(),
            prefixes: vec!["203.0.113.0/24".parse().expect("prefix")],
            default_state: PortState::Deception,
            tenants: vec![Tenant {
                name: "acme".to_owned(),
                owned: vec!["203.0.113.5".parse().expect("ip")],
                allows: vec![AllowRule {
                    proto: L4Proto::Tcp,
                    port: 443,
                    target: ServiceTarget::Incus("web01".to_owned()),
                    scope: None,
                }],
            }],
            shaping: Vec::new(),
            banner_flux: None,
            dns_flux: None,
            rtbh: None,
            flowspec: None,
            metrics_listen: None,
            engine: blackwall_core::EngineConfig::default(),
            flowtable: None,
            xdp: None,
            stateless_tcp_ports: Vec::new(),
        }
    }

    fn sample_v6() -> Policy {
        Policy {
            interface: "eth0".to_owned(),
            prefixes: vec!["2001:db8::/32".parse().expect("prefix")],
            default_state: PortState::Deception,
            tenants: vec![Tenant {
                name: "v6tenant".to_owned(),
                owned: vec!["2001:db8::1".parse().expect("ip")],
                allows: vec![AllowRule {
                    proto: L4Proto::Tcp,
                    port: 80,
                    target: ServiceTarget::Incus("web-v6".to_owned()),
                    scope: None,
                }],
            }],
            shaping: Vec::new(),
            banner_flux: None,
            dns_flux: None,
            rtbh: None,
            flowspec: None,
            metrics_listen: None,
            engine: blackwall_core::EngineConfig::default(),
            flowtable: None,
            xdp: None,
            stateless_tcp_ports: Vec::new(),
        }
    }

    #[test]
    fn renders_table_set_and_chain() {
        let ruleset = render(&sample()).expect("render");
        // sample() has 1 prefix → 2 accept rules (v4+v6) + 1 tproxy rule + 1 queue rule = 4 rules
        // Objects: add-table, flush-table, real_v4, real_v6, prerouting chain, 4 rules, + dnat chain = 10
        assert_eq!(ruleset.objects.len(), 10);

        // Assert structural order and types.
        assert!(
            matches!(
                &ruleset.objects[0],
                NfObject::CmdObject(NfCmd::Add(NfListObject::Table(_)))
            ),
            "objects[0] must be add table"
        );
        assert!(
            matches!(
                &ruleset.objects[1],
                NfObject::CmdObject(NfCmd::Flush(FlushObject::Table(_)))
            ),
            "objects[1] must be flush table"
        );
        assert!(
            matches!(
                &ruleset.objects[2],
                NfObject::CmdObject(NfCmd::Add(NfListObject::Set(s))) if s.name == "real_v4"
            ),
            "objects[2] must be the real_v4 set"
        );
        assert!(
            matches!(
                &ruleset.objects[3],
                NfObject::CmdObject(NfCmd::Add(NfListObject::Set(s))) if s.name == "real_v6"
            ),
            "objects[3] must be the real_v6 set"
        );
        assert!(
            matches!(
                &ruleset.objects[4],
                NfObject::CmdObject(NfCmd::Add(NfListObject::Chain(_)))
            ),
            "objects[4] must be a chain"
        );
        // objects[5..6]: real-service accept rules (v4 + v6)
        assert!(
            matches!(
                &ruleset.objects[5],
                NfObject::CmdObject(NfCmd::Add(NfListObject::Rule(_)))
            ),
            "objects[5] must be the real_v4 accept rule"
        );
        assert!(
            matches!(
                &ruleset.objects[6],
                NfObject::CmdObject(NfCmd::Add(NfListObject::Rule(_)))
            ),
            "objects[6] must be the real_v6 accept rule"
        );
        // objects[7]: tproxy rule for 203.0.113.0/24
        assert!(
            matches!(
                &ruleset.objects[7],
                NfObject::CmdObject(NfCmd::Add(NfListObject::Rule(_)))
            ),
            "objects[7] must be the tproxy rule"
        );
        // objects[8]: queue rule for 203.0.113.0/24
        assert!(
            matches!(
                &ruleset.objects[8],
                NfObject::CmdObject(NfCmd::Add(NfListObject::Rule(_)))
            ),
            "objects[8] must be the queue rule"
        );
    }

    #[test]
    fn ruleset_json_contains_tproxy_and_queue() {
        let json = ruleset_json(&sample()).expect("render json");
        assert!(json.contains("tproxy"), "rendered JSON must contain tproxy");
        assert!(json.contains("queue"), "rendered JSON must contain queue");
        assert!(
            !json.contains("\"xt\""),
            "rendered JSON must NOT contain xt"
        );
    }

    #[test]
    fn renders_ipv6_service_into_v6_set() {
        let ruleset = render(&sample_v6()).expect("render v6");

        // real_v6 set (objects[3]) must contain the service.
        let v6_set = match &ruleset.objects[3] {
            NfObject::CmdObject(NfCmd::Add(NfListObject::Set(s))) => s,
            other => panic!("expected real_v6 set, got {other:?}"),
        };
        assert_eq!(v6_set.name, "real_v6");
        let elems = v6_set.elem.as_ref().expect("real_v6 has elements");
        assert_eq!(elems.len(), 1, "one IPv6 service expected");

        // real_v4 set (objects[2]) must be empty.
        let v4_set = match &ruleset.objects[2] {
            NfObject::CmdObject(NfCmd::Add(NfListObject::Set(s))) => s,
            other => panic!("expected real_v4 set, got {other:?}"),
        };
        assert_eq!(v4_set.name, "real_v4");
        // No v4 services → the v4 set omits `elem` entirely (an empty `elem: []`
        // is invalid nft JSON).
        assert!(
            v4_set.elem.is_none(),
            "v4 set must omit elem for an IPv6-only policy"
        );
    }

    #[test]
    fn renders_dnat_rule_for_nat_target() {
        let mut policy = sample();
        policy.tenants[0].allows[0].target = ServiceTarget::Nat("10.0.0.9:8443".parse().unwrap());
        let ruleset = render(&policy).expect("render");
        let has_nat_chain = ruleset.objects.iter().any(|o| {
            matches!(o, NfObject::CmdObject(NfCmd::Add(NfListObject::Chain(c)))
                if c.name == "dnat" && c._type == Some(NfChainType::NAT))
        });
        assert!(has_nat_chain, "a nat chain must be emitted");
        let has_dnat_rule = ruleset.objects.iter().any(|o| {
            matches!(o, NfObject::CmdObject(NfCmd::Add(NfListObject::Rule(r)))
                if r.chain == "dnat" && r.expr.iter().any(|s| matches!(s, Statement::DNAT(_))))
        });
        assert!(
            has_dnat_rule,
            "a DNAT rule must be emitted for a nat: target"
        );
    }

    #[test]
    fn no_dnat_rule_for_incus_or_host_target() {
        // sample() uses an Incus target: the nat chain exists but carries no rule.
        let ruleset = render(&sample()).expect("render");
        let has_dnat_rule = ruleset.objects.iter().any(|o| {
            matches!(o, NfObject::CmdObject(NfCmd::Add(NfListObject::Rule(r))) if r.chain == "dnat")
        });
        assert!(
            !has_dnat_rule,
            "incus/host targets must not emit a DNAT rule"
        );
    }

    #[test]
    fn ruleset_json_snapshot() {
        let json = ruleset_json(&sample()).expect("render json");
        insta::assert_snapshot!(json);
    }

    #[test]
    fn closed_default_state_emits_interface_scoped_drop_rule() {
        let mut policy = sample();
        policy.default_state = PortState::Closed;
        let ruleset = render(&policy).expect("render");

        // The chain policy stays Accept: the chain is unbound and runs for every
        // interface, so a drop *policy* would black-hole unrelated host traffic.
        let chain = match &ruleset.objects[4] {
            NfObject::CmdObject(NfCmd::Add(NfListObject::Chain(c))) => c,
            other => panic!("expected chain, got {other:?}"),
        };
        assert_eq!(chain.policy, Some(NfChainPolicy::Accept));

        // The Closed posture is enforced by a terminal drop rule appended after
        // the classifier rules, scoped to the managed interface by `iifname`.
        // Find the closed-posture drop rule by content (the dnat chain is
        // emitted after it, so it is no longer the last object).
        let drop_rule = ruleset
            .objects
            .iter()
            .find_map(|o| match o {
                NfObject::CmdObject(NfCmd::Add(NfListObject::Rule(r)))
                    if r.expr.iter().any(|s| matches!(s, Statement::Drop(None))) =>
                {
                    Some(r)
                }
                _ => None,
            })
            .expect("a terminal drop rule");
        assert!(
            matches!(
                drop_rule.expr.first(),
                Some(Statement::Match(Match {
                    left: Expression::Named(NamedExpression::Meta(Meta {
                        key: MetaKey::Iifname
                    })),
                    ..
                }))
            ),
            "the closed-posture drop must be scoped to the managed interface"
        );
        assert!(
            drop_rule
                .expr
                .iter()
                .any(|s| matches!(s, Statement::Drop(None))),
            "the closed-posture rule must drop"
        );
    }

    #[test]
    fn non_closed_default_state_emits_no_drop_rule() {
        // Deception/Open postures must NOT append a terminal drop rule (the
        // chain policy carries the accept fall-through).
        for state in [PortState::Deception, PortState::Open] {
            let mut policy = sample();
            policy.default_state = state;
            let ruleset = render(&policy).expect("render");
            let has_drop = ruleset.objects.iter().any(|o| {
                matches!(
                    o,
                    NfObject::CmdObject(NfCmd::Add(NfListObject::Rule(r)))
                        if r.expr.iter().any(|s| matches!(s, Statement::Drop(None)))
                )
            });
            assert!(!has_drop, "{state:?} must not emit a drop rule");
        }
    }

    #[test]
    fn renders_ipv6_deception_tproxy() {
        let json = ruleset_json(&sample_v6()).expect("render ipv6 json");
        assert!(json.contains("\"ip6\""), "rendered JSON must contain ip6");
        assert!(json.contains("tproxy"), "rendered JSON must contain tproxy");
        assert!(json.contains("queue"), "rendered JSON must contain queue");
        assert!(
            !json.contains("\"xt\""),
            "rendered JSON must NOT contain xt"
        );
    }

    #[test]
    fn ruleset_json_is_valid_json() {
        let json = ruleset_json(&sample()).expect("render json");
        let v: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert!(v.is_object(), "top-level nftables json should be an object");
    }

    #[test]
    fn nft_error_display() {
        use crate::NftError;
        let e = NftError::Apply("permission denied".to_owned());
        assert!(e.to_string().contains("permission denied"));
    }

    #[test]
    fn open_default_state_sets_chain_policy_to_accept() {
        let mut policy = sample();
        policy.default_state = PortState::Open;
        let ruleset = render(&policy).expect("render");
        let chain = match &ruleset.objects[4] {
            NfObject::CmdObject(NfCmd::Add(NfListObject::Chain(c))) => c,
            other => panic!("expected chain, got {other:?}"),
        };
        assert_eq!(chain.policy, Some(NfChainPolicy::Accept));
    }

    #[test]
    fn renders_multiple_prefixes_produces_tproxy_and_queue_per_prefix() {
        let mut policy = sample();
        policy.prefixes = vec![
            "203.0.113.0/24".parse().unwrap(),
            "198.51.100.0/24".parse().unwrap(),
        ];
        let ruleset = render(&policy).expect("render");
        // 2 accept rules (real_v4, real_v6) + 2 tproxy rules + 2 queue rules = 6 rules
        // plus table, flush, real_v4, real_v6, prerouting chain, dnat chain = 6 structural → 12 total
        assert_eq!(ruleset.objects.len(), 12);
    }

    #[test]
    fn tproxy_and_queue_rules_follow_configured_engine_port_and_nfqueue() {
        let mut policy = sample();
        policy.engine.tproxy_port = 62000;
        policy.engine.nfqueue_num = 7;
        let ruleset = render(&policy).expect("render");

        let tproxy_port = ruleset.objects.iter().find_map(|o| {
            let NfObject::CmdObject(NfCmd::Add(NfListObject::Rule(r))) = o else {
                return None;
            };
            r.expr.iter().find_map(|s| match s {
                Statement::TProxy(t) => Some(t.port),
                _ => None,
            })
        });
        assert_eq!(
            tproxy_port,
            Some(62000),
            "tproxy rule must use configured port"
        );

        let queue_num = ruleset.objects.iter().find_map(|o| {
            let NfObject::CmdObject(NfCmd::Add(NfListObject::Rule(r))) = o else {
                return None;
            };
            r.expr.iter().find_map(|s| match s {
                Statement::Queue(q) => Some(q.num.clone()),
                _ => None,
            })
        });
        assert_eq!(
            queue_num,
            Some(Expression::Number(7)),
            "queue rule must use configured nfqueue number"
        );
    }

    #[test]
    fn renders_stateless_tcp_queue_rule_before_tproxy() {
        let mut policy = sample();
        policy.stateless_tcp_ports = vec![22];
        let ruleset = render(&policy).expect("render");

        // Find the stateless-tcp queue rule: a rule with both a Queue
        // statement and a `th dport` set-membership match (distinguishes it
        // from the ICMP/UDP queue rule, which matches `meta l4proto != tcp`
        // and has no dport match).
        let stateless_idx = ruleset.objects.iter().position(|o| {
            let NfObject::CmdObject(NfCmd::Add(NfListObject::Rule(r))) = o else {
                return false;
            };
            let has_queue = r.expr.iter().any(|s| matches!(s, Statement::Queue(_)));
            let has_dport_set = r.expr.iter().any(|s| {
                matches!(
                    s,
                    Statement::Match(Match {
                        left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                            PayloadField { field, .. }
                        ))),
                        right: Expression::Named(NamedExpression::Set(_)),
                        ..
                    }) if field == "dport"
                )
            });
            has_queue && has_dport_set
        });
        let stateless_idx = stateless_idx.expect("stateless-tcp queue rule present");

        // Confirm the dport set contains port 22, and the rule queues to the
        // configured NFQUEUE number.
        let stateless_rule = match &ruleset.objects[stateless_idx] {
            NfObject::CmdObject(NfCmd::Add(NfListObject::Rule(r))) => r,
            _ => unreachable!(),
        };
        let queue_num = stateless_rule.expr.iter().find_map(|s| match s {
            Statement::Queue(q) => Some(q.num.clone()),
            _ => None,
        });
        assert_eq!(
            queue_num,
            Some(Expression::Number(u32::from(
                blackwall_core::EngineConfig::default().nfqueue_num
            ))),
            "stateless-tcp rule must queue to the configured NFQUEUE"
        );
        let has_port_22 = stateless_rule.expr.iter().any(|s| {
            matches!(
                s,
                Statement::Match(Match {
                    right: Expression::Named(NamedExpression::Set(items)),
                    ..
                }) if items.iter().any(|i| matches!(i, SetItem::Element(Expression::Number(22))))
            )
        });
        assert!(has_port_22, "dport set must contain port 22");

        // The tproxy rule must appear AFTER the stateless-tcp rule (lower
        // object index), so stateless-port TCP is queued and never falls
        // through to tproxy.
        let tproxy_idx = ruleset
            .objects
            .iter()
            .position(|o| {
                let NfObject::CmdObject(NfCmd::Add(NfListObject::Rule(r))) = o else {
                    return false;
                };
                r.expr.iter().any(|s| matches!(s, Statement::TProxy(_)))
            })
            .expect("tproxy rule present");
        assert!(
            stateless_idx < tproxy_idx,
            "stateless-tcp queue rule (index {stateless_idx}) must precede the tproxy rule (index {tproxy_idx})"
        );
    }

    #[test]
    fn no_stateless_rule_when_empty() {
        // sample() has stateless_tcp_ports empty (the default).
        let ruleset = render(&sample()).expect("render");
        let has_dport_set_match = ruleset.objects.iter().any(|o| {
            let NfObject::CmdObject(NfCmd::Add(NfListObject::Rule(r))) = o else {
                return false;
            };
            r.expr.iter().any(|s| {
                matches!(
                    s,
                    Statement::Match(Match {
                        right: Expression::Named(NamedExpression::Set(_)),
                        ..
                    })
                )
            })
        });
        assert!(
            !has_dport_set_match,
            "no stateless-tcp queue rule must be emitted when stateless_tcp_ports is empty"
        );
        // Unchanged object count vs. the pre-existing baseline (table, flush,
        // real_v4, real_v6, chain, 2 accept, 1 tproxy, 1 queue, dnat chain).
        assert_eq!(ruleset.objects.len(), 10);
    }

    #[test]
    fn no_flowtable_objects_without_directive() {
        let ruleset = render(&sample()).expect("render");
        let has_ft = ruleset.objects.iter().any(|o| {
            matches!(
                o,
                NfObject::CmdObject(NfCmd::Add(NfListObject::FlowTable(_)))
            )
        });
        let has_forward_chain = ruleset.objects.iter().any(|o| {
            matches!(o, NfObject::CmdObject(NfCmd::Add(NfListObject::Chain(c))) if c.name == "forward")
        });
        assert!(!has_ft, "no flowtable object without the directive");
        assert!(!has_forward_chain, "no forward chain without the directive");
    }

    #[test]
    fn renders_flowtable_object_forward_chain_and_offload_rule() {
        let mut policy = sample();
        policy.flowtable = Some(blackwall_core::FlowTableConfig {
            devices: vec!["eth0".to_owned(), "incusbr0".to_owned()],
        });
        let ruleset = render(&policy).expect("render");

        // Flowtable object with hook ingress and the configured devices.
        let ft = ruleset
            .objects
            .iter()
            .find_map(|o| match o {
                NfObject::CmdObject(NfCmd::Add(NfListObject::FlowTable(ft))) => Some(ft),
                _ => None,
            })
            .expect("flowtable object present");
        assert_eq!(ft.name, "ft");
        assert_eq!(ft.hook, Some(NfHook::Ingress));
        let devs = ft.dev.as_ref().expect("devices set");
        assert_eq!(devs.as_ref(), &["eth0", "incusbr0"]);

        // Forward filter chain, accept policy.
        let fwd = ruleset
            .objects
            .iter()
            .find_map(|o| match o {
                NfObject::CmdObject(NfCmd::Add(NfListObject::Chain(c))) if c.name == "forward" => {
                    Some(c)
                }
                _ => None,
            })
            .expect("forward chain present");
        assert_eq!(fwd.hook, Some(NfHook::Forward));
        assert_eq!(fwd.policy, Some(NfChainPolicy::Accept));

        // Offload rule references the flowtable via `@ft`.
        let flow = ruleset.objects.iter().find_map(|o| {
            let NfObject::CmdObject(NfCmd::Add(NfListObject::Rule(r))) = o else {
                return None;
            };
            r.expr.iter().find_map(|s| match s {
                Statement::Flow(f) => Some(f.clone()),
                _ => None,
            })
        });
        let flow = flow.expect("offload rule present");
        assert_eq!(flow.op, SetOp::Add);
        assert_eq!(flow.flowtable, "@ft");
    }

    #[test]
    fn empty_tenant_list_produces_empty_sets() {
        let policy = Policy {
            interface: "eth0".to_owned(),
            prefixes: vec!["203.0.113.0/24".parse().expect("prefix")],
            default_state: PortState::Deception,
            tenants: vec![],
            shaping: Vec::new(),
            banner_flux: None,
            dns_flux: None,
            rtbh: None,
            flowspec: None,
            metrics_listen: None,
            engine: blackwall_core::EngineConfig::default(),
            flowtable: None,
            xdp: None,
            stateless_tcp_ports: Vec::new(),
        };
        let ruleset = render(&policy).expect("render empty");
        // No resolved services, so real_v4 and real_v6 sets are empty.
        // Objects: table + flush + real_v4 + real_v6 + prerouting chain + 2 accept + 1 tproxy + 1 queue + dnat chain = 10
        assert_eq!(ruleset.objects.len(), 10);
    }
}
