# Blackwall

**A Rust deception firewall and DDoS-mitigation platform for operators running their own IP space.**

By default, every address and port across your IPv4/IPv6 prefixes *appears* open and running a
service — scanners and attackers can't tell which ports are real. A port only becomes a genuine,
forwarded service when you explicitly open it (via a declarative config file, the API, or Incus
auto-discovery); everything else is answered by an interactive honeypot engine that behaves like
the real thing. Blackwall is built for high packet rates and multi-tenant hosting, with a fast
nftables data plane today and an XDP/eBPF fast path, BGP scrubbing, and DNS fast-flux on the
roadmap.

> ⚠️ **Status:** early development. Milestone 1 (the core foundation) is complete; the deception
> engine and later layers are in progress — see [Roadmap](#roadmap). The current nftables ruleset
> classifies policy structure but does **not** yet enforce deception/forwarding (that lands in
> Milestone 2).

## How it works

Every `(IP, protocol, port)` across your prefixes is in exactly one of three states:

| State | Behaviour |
|-------|-----------|
| **Open** | A real service — traffic is forwarded (NAT'd) to the backing host, VM, or container and rides an nftables flowtable fast path. The deception engine never touches it, so real traffic stays at near line rate. |
| **Deception** *(default)* | Looks open and alive. Closed ports answer a real TCP handshake and carry on a believable, protocol-aware conversation (SSH, HTTP, SMTP, databases, …) like an interactive honeypot — but nothing real is ever reached, and every probe is logged. |
| **Closed** | Silently dropped (e.g. management ports). |

A scan of one of your hosts therefore shows *lots* of open ports, with your one or two real
services hidden in the noise — and the fake fingerprints rotate over time (moving-target
deception) while real services stay stable.

## Features

- **All-ports-open deception** across whole IPv4 + IPv6 prefixes.
- **Interactive honeypot engine** *(Milestone 2)* — stateless SYN-cookie answers for scan/flood
  volume, plus per-protocol emulators that hold real multi-turn conversations and capture
  attacker activity.
- **Declarative config DSL** — high-level, readable rules compiled down to nftables.
- **Fast nftables data plane** — real traffic accepted/DNAT'd on a flowtable fast path; deception
  traffic handed to userspace; designed so an XDP/AF_XDP fast path slots in later.
- **Multi-tenant** — per-tenant IP/prefix ownership; tenants manage ports only on their own
  addresses, via config or API.
- **PostgreSQL-backed state** with a full audit log of every policy change.
- **Incus auto-discovery** *(Milestone 3)* — instances declare ports and Blackwall opens/closes
  them automatically.
- **Moving-target & DNS fast-flux, automatic CAKE traffic shaping, REST API + Prometheus
  metrics** *(later milestones)*.
- **DDoS mitigation** *(sub-projects)* — XDP/eBPF fast drop, SYNPROXY, and ISP-level BGP scrubbing
  (RTBH, FlowSpec) for operators announcing their own ASN.

## Configuration

Policy is written in a small, readable DSL that compiles to nftables:

```
interface wan eth0
ipv4 203.0.113.0/24
ipv6 2001:db8::/48

default deception                 # everything not listed below looks open but is fake

tenant acme {
    owns 203.0.113.5, 2001:db8::5
    allow tcp 443 incus:web01     # real service -> forwarded to a container
    allow udp 53  incus:dns01
}
```

## Build & run

Requires a recent stable Rust toolchain and (for the state layer) PostgreSQL.

```bash
# Start the dev database (host port is overridable via BW_PG_PORT; defaults to 5432)
docker compose up -d postgres

# Parse a config and print the nftables ruleset it would apply (no DB, no root)
cargo run -p blackwalld -- render --config path/to/blackwall.conf

# Persist the policy and apply the ruleset to the kernel (needs CAP_NET_ADMIN)
export DATABASE_URL=postgres://blackwall:blackwall@localhost:5432/blackwall
sudo -E cargo run -p blackwalld -- apply --config path/to/blackwall.conf
```

## Development

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- --deny warnings
DATABASE_URL=postgres://blackwall:blackwall@localhost:5432/blackwall cargo test --workspace
cargo llvm-cov --workspace --fail-under-lines 90     # ≥90% line coverage is enforced
```

The repo follows strict coding guidelines (deny-warnings lints, exact dependency pins, rustdoc on
public items) and ships a pre-commit config (`pre-commit install`).

### Workspace layout

| Crate | Responsibility |
|-------|----------------|
| `blackwall-core` | Domain types, the per-port state machine, policy resolution and validation. |
| `blackwall-config` | The configuration DSL: lexer + parser → policy model. |
| `blackwall-state` | PostgreSQL persistence (migrations, tenants, services, audit log). |
| `blackwall-nft` | Renders the policy to an nftables ruleset and applies it atomically. |
| `blackwalld` | The daemon/CLI that wires it together (`render`, `apply`). |

## Roadmap

Blackwall is built as four independent sub-projects, each delivered in milestones:

**A — Deception firewall + orchestrator** *(in progress)*
- ✅ **M1 — Core foundation:** workspace, domain/policy model, config DSL, PostgreSQL state,
  nftables render + atomic apply, CLI.
- ⏳ **M2 — Deception engine:** two-tier stateless + interactive honeypot with protocol emulators.
- ⏳ **M3 — Discovery, shaping, flux:** host/Incus discovery, automatic CAKE shaping + speedtests,
  signature rotation, DNS fast-flux (Knot DNS).
- ⏳ **M4 — API & ops:** tenant-scoped REST API, Prometheus metrics, daemon supervision.

**B — DDoS data plane** — XDP/eBPF + AF_XDP fast drop, SYNPROXY, conntrack, rate limiting.
**C — ISP/BGP control plane** — own-ASN prefix announcement, RTBH, FlowSpec, scrubbing, dn42.
**D — Detection & telemetry** — sFlow/NetFlow/IPFIX ingest driving B and C.

## License

Licensed under the [GNU General Public License v3.0](LICENSE).
