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
public items) and ships a pre-commit config (`pre-commit install`) that runs fmt, clippy, and tests.

### Integration lab (`blackwall-lab`)

Beyond unit tests, Blackwall ships a **reproducible network-namespace lab** that exercises each
component against the real peer software it talks to, with one command that runs identically
locally and in CI. A scenario is a small [KDL](https://kdl.dev) file declaring a topology (nodes,
veth links, daemons, processes) and assertions; the `lab` binary realizes it in per-run network
namespaces (`bw-<id>-…`), runs the assertions with timeout-polling, emits JUnit + TAP, and
self-cleans on any exit.

```bash
cargo build -p blackwall-lab
sudo ./target/debug/lab test crates/blackwall-lab/scenarios/bgp-bird.kdl   # one scenario
sudo ./target/debug/lab up   crates/blackwall-lab/scenarios/dns-knot.kdl   # leave it standing
sudo ./target/debug/lab shell crates/blackwall-lab/scenarios/dns-knot.kdl ns   # poke at a node
sudo ./target/debug/lab down                                              # tear everything down
```

Current scenarios (each a CI gate):

| Scenario | What it proves |
|----------|----------------|
| `bgp-bird` | The native BGP speaker peers with real **BIRD2**; an announced `/32` lands in BIRD's RIB. |
| `dns-knot` | The DNS fast-flux path pushes an RFC 2136 + TSIG update to real **Knot DNS**; `kdig` serves the rotated record. |
| `shaper-cake` | The shaper installs **CAKE** on an interface; `tc qdisc show` reports it. |
| `flow-sflow` | Crafted **sFlow v5** datagrams drive the collector + detector to fire a volumetric detection (fast, dependency-free decoder test). |
| `flow-sflow-live` | A trafficgen flood is sampled by **real hsflowd** (`mod_pcap`) into real sFlow v5; the production collector + detector must fire — proving the decoder handles real-agent (expanded) flow samples, which the crafted gate cannot. |
| `deception-nft` | The real nftables ruleset classifies a scanner's TCP connection to a non-real port, **TPROXY**-redirects it to the deception engine, and the SSH emulator answers an `SSH-2.0` banner — the full data path end to end. |
| `trafficgen-foundation` | A Rust generator floods the victim with the full DDoS pattern set (UDP/SYN/reflection/malformed + benign) over **AF_PACKET**; the victim's per-flow sink + `/proc/net/dev` counters classify delivery and gate fidelity, benign-survival, and measurement-consistency. |
| `deception-resilience` | A connection flood past the deception engine's `max_concurrent` cap proves its DDoS-defense is correct — drop-at-cap is enforced, legit deception still gets `SSH-2.0`, and the engine survives. A **resilience/correctness** gate, not a throughput benchmark (realistic-scale stress needs kernel-bypass, tracked separately). |

The architecture is pure-core / thin-IO: the topology compiler, address allocator, config
renderers, and report serializers are unit-tested to the 90% gate; the netns/process executor is
the only coverage-excluded part, validated end-to-end by the scenarios above. The roadmap adds
per-component scenarios for the remaining crates, then a multi-host POP simulation (home + POPs
over a WireGuard mesh with OSPF/BFD + iBGP + anycast), and eventually DDoS attack-traffic
generation to exercise the XDP/eBPF data plane.

### Workspace layout

| Crate | Responsibility |
|-------|----------------|
| `blackwall-core` | Domain types, the per-port state machine, policy resolution and validation. |
| `blackwall-config` | The configuration DSL: lexer + parser → policy model. |
| `blackwall-state` | PostgreSQL persistence (migrations, tenants, services, audit log). |
| `blackwall-nft` | Renders the policy to an nftables ruleset and applies it atomically. |
| `blackwall-deception` | Two-tier deception engine: service emulators, banner store + fast-flux, TPROXY/NFQUEUE transports. |
| `blackwall-discovery` | Host-socket + Incus instance discovery feeding effective policy. |
| `blackwall-speedtest` | Multi-provider speedtest with source/interface binding. |
| `blackwall-shaper` | CAKE traffic shaping (egress + IFB ingress) computed from measured bandwidth. |
| `blackwall-dns` | RFC 2136 + TSIG DNS fast-flux against a Knot primary. |
| `blackwall-flow` | sFlow v5 decode + sliding-window volumetric attack detection (sub-project D). |
| `blackwall-bgp` | Byte-exact BGP codec + injection-only iBGP speaker (sub-project C). |
| `blackwall-lab` | netns integration-test lab harness (`lab` CLI) — see below. |
| `blackwalld` | The daemon/CLI that wires it together (`render`, `apply`, `run`, `flow`, …). |

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
