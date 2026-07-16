# Blackwall

**A Rust deception firewall and DDoS-mitigation platform for operators running their own IP space.**

By default, every address and port across your IPv4/IPv6 prefixes *appears* open and running a
service — scanners and attackers can't tell which ports are real. A port only becomes a genuine,
forwarded service when you explicitly open it (via a declarative config file, the API, or Incus
auto-discovery); everything else is answered by an interactive honeypot engine that behaves like
the real thing. Blackwall is built for high packet rates and multi-tenant hosting, with a fast
nftables data plane, an on-box XDP/eBPF fast-drop + in-kernel SYN-cookie path with a zero-copy
AF_XDP responder, ISP-level BGP mitigation (RTBH + FlowSpec), and DNS fast-flux.

> ⚠️ **Status:** active development, approaching a first live deployment. Sub-project **A**
> (deception firewall) is feature-complete through M3 — the nftables data plane enforces deception
> (TPROXY/NFQUEUE → honeypot engine) and real-service forwarding, with protocol emulators, Incus
> discovery, CAKE shaping, and DNS/banner fast-flux — plus a stateless SYN-cookie deception tier
> (keyed SipHash cookies + a reflection-safe UDP responder). Sub-project **B** (the XDP/eBPF DDoS
> data plane) is **complete**: on-box source-drop + per-source rate-limit, in-kernel `XDP_TX` SYN
> cookies (dual-stack), a zero-copy **AF_XDP** UDP responder, and xdpcap observability with a
> DDoS-lab XDP gate. Sub-project **C** (BGP control plane) ships RTBH + FlowSpec auto-mitigation
> end to end; **D** (detection) ships sFlow volumetric detection plus anycast-aware telemetry
> ingest (per-POP identity, liveness, sampling sanity). **A·M4** (API & ops) has shipped its
> Phase 1 read-only control API (axum + OpenAPI). Remaining: C scrubbing/deaggregation/dn42, D2
> adaptive/L7 detection, A·M4 mutation/supervision, and the AS214806 deployment integration. See
> the [Roadmap](#roadmap).

## How it works

Every `(IP, protocol, port)` across your prefixes is in exactly one of three states:

| State | Behaviour |
|-------|-----------|
| **Open** | A real service — traffic is accepted (and DNAT'd to the backing host, VM, or container for `nat:` targets) by the nftables data plane. The deception engine never touches it. An optional nftables **flowtable** offloads established forwarded flows to the kernel conntrack fast path (`flowtable devices=…`), and an optional **XDP** fast path (`xdp` directive) drops/rate-limits attack sources at the driver level, with a zero-copy AF_XDP responder for the stateless UDP tier. |
| **Deception** *(default)* | Looks open and alive. Closed ports answer a real TCP handshake and carry on a believable, protocol-aware conversation (SSH, HTTP, SMTP, databases, …) like an interactive honeypot — but nothing real is ever reached, and every probe is logged. Ports opted into the **stateless tier** (`stateless-tcp ports=…`) are instead answered with a keyed SYN-cookie handshake carrying no per-connection state, optionally fronted by an in-kernel XDP fast path (`xdp cookie-ports=…`) that answers the same cookie ahead of nftables. |
| **Closed** | Silently dropped (e.g. management ports). |

A scan of one of your hosts therefore shows *lots* of open ports, with your one or two real
services hidden in the noise — and the fake fingerprints rotate over time (moving-target
deception) while real services stay stable.

## Features

- **All-ports-open deception** across whole IPv4 + IPv6 prefixes.
- **Interactive honeypot engine** *(Milestone 2)* — per-protocol emulators (SSH, HTTP, SMTP, Redis,
  MySQL, PostgreSQL) that hold real multi-turn conversations and capture attacker activity.
- **Stateless SYN-cookie deception tier** — a keyed SipHash-2-4 SYN-cookie responder answers scan/
  flood volume on configured ports (`stateless-tcp ports=…`) with no per-connection state, plus a
  reflection-safe UDP responder (reply length ≤ request, so it can never be an amplifier); dual-stack
  IPv4/IPv6. An in-kernel XDP fast path (`xdp cookie-ports=…`) answers the same cookie via `XDP_TX`
  ahead of nftables, sharing its key with the userspace tier over Postgres.
- **Declarative config DSL** — high-level, readable rules compiled down to nftables.
- **nftables data plane** — real traffic accepted/DNAT'd (`nat:` targets) with an optional flowtable
  fast path for established forwarded flows; deception traffic handed to userspace via TPROXY
  (interactive) or NFQUEUE (stateless SYN-cookie tier); an on-box XDP fast path (drop/rate-limit +
  SYN cookies) already slots in ahead of it, plus a zero-copy AF_XDP responder for the UDP tier.
- **Multi-tenant** — per-tenant IP/prefix ownership; tenants manage ports only on their own
  addresses, via config or API.
- **PostgreSQL-backed state** with a full audit log of every policy change.
- **Incus auto-discovery** *(Milestone 3)* — instances declare ports and Blackwall opens/closes
  them automatically.
- **Moving-target & DNS fast-flux, automatic CAKE traffic shaping, REST API + Prometheus
  metrics** *(later milestones)*.
- **DDoS mitigation** — on-box **XDP/eBPF fast drop + per-source rate-limit** (source-keyed, driven
  by the detection loop; `xdp` directive), a **stateless SYN-cookie tier** (userspace
  `stateless-tcp ports=…` + in-kernel `xdp cookie-ports=…` fast path sharing one SipHash key via
  Postgres) with a zero-copy **AF_XDP** UDP responder, and ISP-level BGP mitigation (RTBH, FlowSpec)
  for operators announcing their own ASN.

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

# RTBH: announce /32 (/128) blackholes for detected/operator-flagged attacks over iBGP.
# Eligibility reuses the prefixes above (only your own space is ever blackholed).
rtbh peer=10.0.0.2:179 local-as=214806 peer-as=214806 router-id=10.222.255.1 \
     next-hop-v4=192.0.2.1 max=256 hold-down=60s ttl=2h \
     md5=optional-tcp-md5-secret gtsm-hops=1   # gtsm-hops: TTL-security, 1 = directly connected

# Optional Prometheus metrics endpoint (bind to localhost or a trusted mgmt net — no auth/TLS).
metrics listen=127.0.0.1:9100

# Optional deception-engine tuning (all keys optional; shown with their defaults).
# tproxy-port / nfqueue are a single source of truth — the nft rules follow them.
engine max-concurrent=1024 session-timeout=60 tproxy-port=61000 nfqueue=0

# Optional stateless SYN-cookie deception tier: routes these deception TCP ports
# to a keyed SipHash SYN-cookie responder (NFQUEUE) instead of the interactive
# TPROXY honeypot, so a spoofed-source SYN flood against them creates no state.
stateless-tcp ports=22,80,443

# Optional flowtable fast path for real-service traffic. List every device a
# forwarded flow traverses (uplink + backend); offload engages only when both
# directions' devices are present. Omit the directive to keep the nft slow path.
flowtable devices=eth0,incusbr0

# Optional on-box XDP fast drop / per-source rate-limit (source-keyed: drops the
# attacker, not the victim). Driven by the detection loop on `blackwalld flow`;
# operator control via `blackwalld xdp block|unblock|rate-limit|list|stats`.
# mode auto = native XDP with a generic (skb) fallback. cookie-ports= additionally
# answers SYNs to those ports in-kernel with the same keyed cookie as the
# userspace stateless-tcp tier above (shared via Postgres). Omit to disable XDP.
xdp interface=eth0 mode=auto default-rate-limit=1000 cookie-ports=8080,443
```

With a `metrics` block, `blackwalld flow` serves `GET /metrics` (Prometheus text) exposing BGP
session state + reconnects, sFlow datagrams/decode-errors, active RTBH/FlowSpec rule counts,
pending operator-intent queue depths, and detection/session/audit totals.

### RTBH operator commands

With an `rtbh` block configured, `blackwalld flow` auto-blackholes detected volumetric
attacks through the BGP speaker and persists them (re-announced on restart). An operator can
also drive blackholes manually — these are recorded to Postgres and applied by the running
daemon (a one-shot CLI can't hold an iBGP route itself):

```bash
blackwalld rtbh add 203.0.113.7        # queue a manual blackhole (rejected if outside your prefixes)
blackwalld rtbh remove 203.0.113.7     # release it
blackwalld rtbh list                   # active blackholes (target, origin, age)
blackwalld rtbh list --requests        # the operator-intent log with per-request status
```

> **Ops note:** Postgres is the RTBH authorization boundary — anyone who can write
> `rtbh_requests` can null-route any IP in your prefixes. Give the CLI a least-privilege DB role
> (INSERT on `rtbh_requests`, SELECT on the RTBH tables) distinct from the daemon's role, and set
> `--operator` (or rely on `$USER@host`) so `created_by` attributes each request. Optional
> **TCP-MD5** (RFC 2385) authentication is available via `md5=<password>` on the `rtbh` directive
> (the secret is redacted from logs); GTSM/TTL-security is not yet implemented. The session logs a
> WARN whenever it leaves the Established state.

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
scripts/build-lab-tests.sh                                                # build the interop drivers the gates run
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
| `rtbh-bird` | The `RtbhManager` announces both an auto-detected and an operator-manual `/32` blackhole (community `65535:666`, RFC 7999) via the native BGP speaker; real **BIRD2** must show both routes carrying that community — the detection→mitigation (D→C) loop, auto and manual, end to end. |
| `flowspec-bird` | The native speaker injects a BGP **FlowSpec** rule (RFC 8955, SAFI 133) — *drop UDP dport 53 → 203.0.113.7/32* — over iBGP; real **BIRD2** must validate and install it into its `flow4` table with the full match (`dst 203.0.113.7/32; proto 17; dport 53`) — finer-grained mitigation than a whole-IP blackhole. |
| `flowspec-auto-bird` | The concentration-based selector routes a synthetic detection to the right mitigation: a *concentrated* attack (one dominant port) auto-installs a FlowSpec drop rule in real **BIRD2**'s `flow4tab`, while a *diffuse* attack auto-installs an RTBH `/32` blackhole — the auto-mitigation decision (`FlowSpec` vs `RTBH`) proven end to end. |

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
| `blackwall-bgp` | Byte-exact BGP codec (unicast RTBH routes + FlowSpec rules, RFC 8955/8956) + injection-only iBGP speaker (sub-project C). |
| `blackwall-rtbh` | RTBH + FlowSpec controllers and single-owner managers — detected/operator attacks → BGP blackhole/FlowSpec announcements, persisted and re-announced on restart (sub-project C). |
| `blackwall-xdp` / `blackwall-xdp-ebpf` / `blackwall-xdp-common` | On-box XDP/eBPF data plane (sub-project B): userspace loader/control/sink + the aya eBPF program (source-drop, rate-limit, in-kernel SYN cookies, AF_XDP redirect). |
| `blackwall-cookie` | `no_std` SipHash SYN-cookie core shared byte-for-byte between the userspace and eBPF tiers. |
| `blackwall-api` | Tenant-aware, bearer-authenticated read-only control API (axum + OpenAPI), mounted in `blackwalld run` (A·M4). |
| `blackwall-trafficgen` | DDoS-lab traffic generator (AF_PACKET) for the netns XDP/flood gates. |
| `blackwall-lab` | netns integration-test lab harness (`lab` CLI) — see below. |
| `blackwalld` | The daemon/CLI that wires it together (`render`, `apply`, `run`, `flow`, …). |

## Roadmap

Blackwall is built as four independent sub-projects, each delivered in milestones.

**A — Deception firewall + orchestrator**
- ✅ **M1 — Core foundation:** workspace, domain/policy model, config DSL, PostgreSQL state,
  nftables render + atomic apply, CLI.
- ✅ **M2 — Deception engine:** two-tier stateless + interactive honeypot; SSH/HTTP/SMTP/Redis/
  MySQL/PostgreSQL emulators; TPROXY/NFQUEUE transports; connection cap + session timeout.
- ✅ **M3 — Discovery, shaping, flux:** host/Incus discovery + reconciler, automatic CAKE shaping
  from multi-provider speedtests, banner fast-flux, DNS fast-flux (RFC 2136 + TSIG to Knot).
- 🟡 **M4 — API & ops:** **Phase 1 shipped** — a tenant-aware, bearer-authenticated **read-only
  control API** (axum) with a generated OpenAPI document, mounted in `blackwalld run`. Remaining:
  mutation endpoints, daemon supervision, load/bench harness.

**B — DDoS data plane** ✅ *(complete)* — on-box XDP/eBPF fast drop, in-kernel SYN cookies, zero-copy
AF_XDP, rate limiting.
- ✅ **B1 — On-box XDP fast drop:** in-kernel, source-keyed drop + per-source rate-limiting on the
  uplink, driven by the detection loop; `xdp` directive; non-fatal attach with a generic-mode
  fallback.
- ✅ **B2 — Stateless SYN cookies:** a keyed SipHash-2-4 responder (userspace, NFQUEUE;
  `stateless-tcp ports=…`) plus a reflection-safe UDP responder for the deception tier, and an
  in-kernel `XDP_TX` SYN-cookie fast path (`xdp cookie-ports=…`, dual-stack IPv4/IPv6) sharing the
  same key with the userspace tier via Postgres — the two tiers interoperate on a single handshake.
- ✅ **B3 — AF_XDP:** a zero-copy userspace fast path (`xdpilone`) with a reflection-safe UDP
  responder, including binary/hex-configurable banners.
- ✅ **B4 — xdpcap + DDoS-lab XDP gate:** `xdpcap`-style pcap capture plus the netns lab gates for
  the XDP data plane (`BPF_PROG_TEST_RUN`, AF_XDP redirect, DDoS flood-drop). Multi-queue AF_XDP
  scaling is deferred (needs multi-queue-NIC hardware).

**C — ISP/BGP control plane** *(in progress)* — a native injection-only iBGP speaker to BIRD.
- ✅ **C1 — RTBH:** byte-exact BGP codec + speaker (C1a); pure blackhole controller (C1b);
  the full control plane — Postgres persistence, detector auto-trigger, operator CLI (C1c).
- ✅ **C2a — FlowSpec codec:** RFC 8955/8956 (SAFI 133) rule encoding + speaker inject path.
- ✅ **C2b-1 — Auto-mitigation core:** concentration-based selection routes a detection to a
  flow-scoped FlowSpec drop (concentrated) or an RTBH blackhole (diffuse).
- ✅ **C2b-2 — FlowSpec control plane:** persistence (`flowspec_rules`, re-announced on restart),
  `flowspec` config directive, `blackwalld flowspec` operator CLI, and daemon wiring — the FlowSpec
  manager runs alongside RTBH off the shared iBGP session, driven by the selector.
- ⏳ **C3 — Looking-glass, C4 — auto-peering, scrubbing, dn42** *(later).*

**D — Detection & telemetry** *(in progress)*
- ✅ **D1 — Volumetric detection:** sFlow v5 ingest + sliding-window threshold detector driving C.
- ✅ **Anycast telemetry ingest:** per-POP identity from the sFlow agent address, per-POP tagging on
  detections, per-agent liveness + sampling-sanity, and top-N attacker source-block attribution —
  so feeds from many anycast POPs read as one logical view.
- ⏳ **D2+ — NetFlow/IPFIX, adaptive baseline detection, L7 (HTTP/DNS-flood)** *(later).*

**Deployment — Blackwall on an anycast network** *(next)* — turning the platform into a live
deployment on an anycast ISP (centralized BGP brain + multi-POP telemetry). Staged, not flag-day:
- 🟡 **M0 — detection-only (shadow):** telemetry ingest ✅ (above), a POP-sensor deploy contract
  (hsflowd) ✅, a **BIRD iBGP-snippet generator** ✅ (`blackwalld bird-config` emits BIRD's side of
  the session from blackwall's config — `OWN_V4/V6` defines opt-in via `--with-defines`, off by
  default so they don't collide with the operator's own — validated against real BIRD2), and
  **network-wide shadow mode** ✅ (a `shadow` directive logs+records every RTBH/FlowSpec/XDP
  mitigation the daemon *would* apply, via `/v1/audit` + `blackwall_shadow_would_mitigate_total`,
  without executing it). Remaining: Incus/metrics deploy glue. Run live, watch, tune — act on nothing.
- ⏳ **M1 — arm with safety:** per-upstream blackhole communities, RPKI/ROA cross-check, a single
  audited disarm + blast-radius caps, and anycast self-protection (don't blackhole yourself).
- ⏳ **M2 — deception + intel loop:** deception at home (tenant space only), coherent per-IP personas,
  a tarpit tier, and a deception→mitigation intel loop.
- ⏳ **M3 — harden & scale:** HA/brain-loss survival, public looking-glass, tenant self-service,
  multi-source correlation, scrubbing redirect, prefix steering.

**Integration lab** *(cross-cutting)* — a reproducible netns harness (`blackwall-lab`) with one
`lab` command that runs identically locally and in CI. Every component is gated against the real
peer software (BIRD, Knot, CAKE, hsflowd, nftables) — see [Integration lab](#integration-lab-blackwall-lab).

## License

Licensed under the [GNU General Public License v3.0](LICENSE).
