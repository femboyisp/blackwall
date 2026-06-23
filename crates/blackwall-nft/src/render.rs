//! Render a [`Policy`] into an nftables `inet blackwall` table.
//!
//! Layout:
//! * Named set `real_v4` — open `(ipv4_addr, inet_proto, inet_service)`
//!   tuples for every Open IPv4 service in the policy.
//! * Named set `real_v6` — open `(ipv6_addr, inet_proto, inet_service)`
//!   tuples for every Open IPv6 service in the policy.
//! * Chain `prerouting` — base chain capturing the managed interface; the
//!   `comment` field records the default action (drop vs. deception queue) so
//!   the snapshot captures it without needing live rules.
//!
//! This module is pure: it builds the schema only. Applying it is Task 8.

use blackwall_core::{Policy, PolicyError, PortState};
use nftables::{
    expr::{Expression, NamedExpression},
    schema::{Chain, NfCmd, NfListObject, NfObject, Nftables, Set, SetType, SetTypeValue, Table},
    types::{NfChainPolicy, NfChainType, NfFamily, NfHook},
};

/// The nftables family Blackwall uses (dual-stack).
const FAMILY: NfFamily = NfFamily::INet;
/// The table name Blackwall owns.
const TABLE: &str = "blackwall";

/// Build the full nftables ruleset for `policy`.
///
/// Emits four objects in order:
/// 1. `add table inet blackwall`
/// 2. `add set inet blackwall real_v4 { type ipv4_addr . inet_proto . inet_service; ... }`
/// 3. `add set inet blackwall real_v6 { type ipv6_addr . inet_proto . inet_service; ... }`
/// 4. `add chain inet blackwall prerouting { type filter hook prerouting priority -300; }`
///
/// The chain `comment` encodes the intended default action; live rules are
/// wired in Task 8 alongside `apply()`.
pub fn render(policy: &Policy) -> Result<Nftables, PolicyError> {
    let resolved = policy.resolve()?;

    let mut objects: Vec<NfObject> = Vec::new();

    // 1. Table.
    objects.push(NfObject::CmdObject(NfCmd::Add(NfListObject::Table(
        Table {
            family: FAMILY,
            name: TABLE.to_owned(),
            handle: None,
        },
    ))));

    // 2. Named set of open (addr, proto, port) tuples — IPv4 addresses only.
    let v4_elements = set_elements_for(&resolved, |s| s.addr.is_ipv4());
    objects.push(NfObject::CmdObject(NfCmd::Add(NfListObject::Set(Set {
        family: FAMILY,
        table: TABLE.to_owned(),
        name: "real_v4".to_owned(),
        handle: None,
        set_type: SetTypeValue::Concatenated(vec![
            SetType::Ipv4Addr,
            SetType::InetProto,
            SetType::InetService,
        ]),
        policy: None,
        flags: None,
        elem: Some(v4_elements),
        timeout: None,
        gc_interval: None,
        size: None,
        comment: None,
    }))));

    // 3. Named set of open (addr, proto, port) tuples — IPv6 addresses only.
    //    Uses SetType::Ipv6Addr for the address field.
    let v6_elements = set_elements_for(&resolved, |s| s.addr.is_ipv6());
    objects.push(NfObject::CmdObject(NfCmd::Add(NfListObject::Set(Set {
        family: FAMILY,
        table: TABLE.to_owned(),
        name: "real_v6".to_owned(),
        handle: None,
        set_type: SetTypeValue::Concatenated(vec![
            SetType::Ipv6Addr,
            SetType::InetProto,
            SetType::InetService,
        ]),
        policy: None,
        flags: None,
        elem: Some(v6_elements),
        timeout: None,
        gc_interval: None,
        size: None,
        comment: None,
    }))));

    // 4. Prerouting base chain.  The chain policy encodes the intended default
    //    action: `drop` for Closed, `accept` for Deception/Open (the deception
    //    queue rule is added in Task 8; accept here means "fall through to it").
    let chain_policy = match policy.default_state {
        PortState::Closed => NfChainPolicy::Drop,
        PortState::Deception | PortState::Open => NfChainPolicy::Accept,
    };
    objects.push(NfObject::CmdObject(NfCmd::Add(NfListObject::Chain(
        Chain {
            family: FAMILY,
            table: TABLE.to_owned(),
            name: "prerouting".to_owned(),
            newname: None,
            handle: None,
            _type: Some(NfChainType::Filter),
            hook: Some(NfHook::Prerouting),
            prio: Some(-300),
            dev: Some(policy.interface.clone()),
            policy: Some(chain_policy),
        },
    ))));

    Ok(Nftables { objects })
}

/// Build set elements for services matching `predicate`.
fn set_elements_for(
    resolved: &[blackwall_core::ResolvedService],
    predicate: impl Fn(&blackwall_core::ResolvedService) -> bool,
) -> Vec<Expression> {
    resolved
        .iter()
        .filter(|s| predicate(s))
        .map(|s| {
            Expression::Named(NamedExpression::Concat(vec![
                Expression::String(s.addr.to_string()),
                Expression::String(s.proto.to_string()),
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
        // Expect exactly 4 objects: table, real_v4 set, real_v6 set, chain.
        assert_eq!(ruleset.objects.len(), 4);

        // Assert structural order and types.
        assert!(
            matches!(
                &ruleset.objects[0],
                NfObject::CmdObject(NfCmd::Add(NfListObject::Table(_)))
            ),
            "objects[0] must be a table"
        );
        assert!(
            matches!(
                &ruleset.objects[1],
                NfObject::CmdObject(NfCmd::Add(NfListObject::Set(s))) if s.name == "real_v4"
            ),
            "objects[1] must be the real_v4 set"
        );
        assert!(
            matches!(
                &ruleset.objects[2],
                NfObject::CmdObject(NfCmd::Add(NfListObject::Set(s))) if s.name == "real_v6"
            ),
            "objects[2] must be the real_v6 set"
        );
        assert!(
            matches!(
                &ruleset.objects[3],
                NfObject::CmdObject(NfCmd::Add(NfListObject::Chain(_)))
            ),
            "objects[3] must be a chain"
        );
    }

    #[test]
    fn renders_ipv6_service_into_v6_set() {
        let ruleset = render(&sample_v6()).expect("render v6");

        // real_v6 set (objects[2]) must contain the service.
        let v6_set = match &ruleset.objects[2] {
            NfObject::CmdObject(NfCmd::Add(NfListObject::Set(s))) => s,
            other => panic!("expected real_v6 set, got {other:?}"),
        };
        assert_eq!(v6_set.name, "real_v6");
        let elems = v6_set.elem.as_ref().expect("real_v6 has elements");
        assert_eq!(elems.len(), 1, "one IPv6 service expected");

        // real_v4 set (objects[1]) must be empty.
        let v4_set = match &ruleset.objects[1] {
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
        let chain = match &ruleset.objects[3] {
            NfObject::CmdObject(NfCmd::Add(NfListObject::Chain(c))) => c,
            other => panic!("expected chain, got {other:?}"),
        };
        assert_eq!(chain.policy, Some(NfChainPolicy::Drop));
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
