//! Render a [`Policy`] into an nftables `inet blackwall` table.
//!
//! Layout:
//! * Named set `real_v4` — open `(ipv4_addr, inet_proto, inet_service)`
//!   tuples for every Open IPv4 service in the policy.
//! * Named set `real_v6` — open `(ipv6_addr, inet_proto, inet_service)`
//!   tuples for every Open IPv6 service in the policy.
//! * Chain `prerouting` — base chain capturing the managed interface with
//!   classifier rules:
//!   1. Real-service membership → accept (DNAT to backend deferred to M3).
//!   2. Deception TCP on managed prefix → tproxy to ENGINE_TPROXY_PORT.
//!   3. Deception ICMP/UDP on managed prefix → queue to DECEPTION_QUEUE.
//!   4. If default_state == Closed → drop (chain policy).
//!
//! This module is pure: it builds the schema only. Applying it is handled by
//! the `apply` function in the crate root.

use blackwall_core::{Policy, PolicyError, PortState};
use nftables::{
    expr::{Expression, Meta, MetaKey, NamedExpression, Payload, PayloadField, Prefix},
    schema::{
        Chain, FlushObject, NfCmd, NfListObject, NfObject, Nftables, Rule, Set, SetType,
        SetTypeValue, Table,
    },
    stmt::{Match, Operator, Queue, Statement, TProxy},
    types::{NfChainPolicy, NfChainType, NfFamily, NfHook},
};

/// The nftables family Blackwall uses (dual-stack).
const FAMILY: NfFamily = NfFamily::INet;
/// The table name Blackwall owns.
const TABLE: &str = "blackwall";

/// TCP port the deception engine's tproxy listener binds to.
///
/// Traffic classified as deception TCP is redirected here so the engine can
/// respond with honeypot content. The engine itself is wired in Task 9.
const ENGINE_TPROXY_PORT: u16 = 61000;

/// NFQUEUE number used for deception ICMP/UDP packets.
///
/// The deception engine receives these packets via the kernel's userspace
/// queue mechanism and generates appropriate honeypot responses. The engine
/// is wired in Task 9.
const DECEPTION_QUEUE: u16 = 0;

/// Build the full nftables ruleset for `policy`.
///
/// Emits objects in order:
/// 1. `add table inet blackwall`   — ensure the table exists
/// 2. `flush table inet blackwall` — atomically empty it (stale state removed)
/// 3. `add set inet blackwall real_v4 { type ipv4_addr . inet_proto . inet_service; ... }`
/// 4. `add set inet blackwall real_v6 { type ipv6_addr . inet_proto . inet_service; ... }`
/// 5. `add chain inet blackwall prerouting { type filter hook prerouting priority -300; }`
/// 6. Rule: real-service membership → accept (DNAT to backend deferred to M3)
/// 7. Rule: deception TCP on managed prefix → tproxy to ENGINE_TPROXY_PORT
/// 8. Rule: deception ICMP/UDP on managed prefix → queue to DECEPTION_QUEUE
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
            elem: Some(v4_elements.into()),
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
            elem: Some(v6_elements.into()),
            timeout: None,
            gc_interval: None,
            size: None,
            comment: None,
        }),
    ))));

    // 5. Prerouting base chain.
    //
    // Chain policy: Closed → Drop (enforce closed posture); otherwise Accept
    // (the explicit classifier rules above handle deception/real traffic).
    let chain_policy = match policy.default_state {
        PortState::Closed => NfChainPolicy::Drop,
        PortState::Deception | PortState::Open => NfChainPolicy::Accept,
    };
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
            dev: Some(policy.interface.clone().into()),
            policy: Some(chain_policy),
        },
    ))));

    // 6. Rule: real-service membership check — accept.
    //    daddr . l4proto . dport in @real_v4 → accept
    //    (DNAT to Incus backend is deferred to M3; for now, accept passes the
    //    packet to the host stack which will reach the real service.)
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
                // accept — DNAT to backend deferred to M3
                Statement::Accept(None),
            ]
            .into(),
            handle: None,
            index: None,
            comment: Some("real service: accept (DNAT to backend deferred to M3)".into()),
        };
        objects.push(NfObject::CmdObject(NfCmd::Add(NfListObject::Rule(
            accept_rule,
        ))));
    }

    // 7. Rule: deception TCP on managed prefix → tproxy to ENGINE_TPROXY_PORT.
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
                // tproxy to ENGINE_TPROXY_PORT — typed variant, serializes as
                // {"tproxy": {"family": "<f>", "port": <n>}}
                Statement::TProxy(TProxy {
                    family: Some(addr_family.into()),
                    port: ENGINE_TPROXY_PORT,
                    addr: None,
                }),
            ]
            .into(),
            handle: None,
            index: None,
            comment: Some(
                format!("deception TCP: tproxy to engine port {ENGINE_TPROXY_PORT}").into(),
            ),
        };
        objects.push(NfObject::CmdObject(NfCmd::Add(NfListObject::Rule(
            tproxy_rule,
        ))));
    }

    // 8. Rule: deception ICMP/UDP on managed prefix → queue to DECEPTION_QUEUE.
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
                // queue num DECEPTION_QUEUE
                Statement::Queue(Queue {
                    num: Expression::Number(u32::from(DECEPTION_QUEUE)),
                    flags: None,
                }),
            ]
            .into(),
            handle: None,
            index: None,
            comment: Some(format!("deception ICMP/UDP: queue to nfqueue {DECEPTION_QUEUE}").into()),
        };
        objects.push(NfObject::CmdObject(NfCmd::Add(NfListObject::Rule(
            queue_rule,
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
                }],
            }],
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
                }],
            }],
        }
    }

    #[test]
    fn renders_table_set_and_chain() {
        let ruleset = render(&sample()).expect("render");
        // sample() has 1 prefix → 2 accept rules (v4+v6) + 1 tproxy rule + 1 queue rule = 4 rules
        // Total objects: add-table, flush-table, real_v4, real_v6, chain, + 4 rules = 9
        assert_eq!(ruleset.objects.len(), 9);

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
        let v4_elems = v4_set.elem.as_ref().expect("real_v4 elem vec present");
        assert!(
            v4_elems.is_empty(),
            "v4 set must be empty for IPv6-only policy"
        );
    }

    #[test]
    fn ruleset_json_snapshot() {
        let json = ruleset_json(&sample()).expect("render json");
        insta::assert_snapshot!(json);
    }

    #[test]
    fn drop_default_state_sets_chain_policy_to_drop() {
        let mut policy = sample();
        policy.default_state = PortState::Closed;
        let ruleset = render(&policy).expect("render");
        let chain = match &ruleset.objects[4] {
            NfObject::CmdObject(NfCmd::Add(NfListObject::Chain(c))) => c,
            other => panic!("expected chain, got {other:?}"),
        };
        assert_eq!(chain.policy, Some(NfChainPolicy::Drop));
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
}
