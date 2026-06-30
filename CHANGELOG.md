# Changelog

All notable changes to this project are documented here, following
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Changed
- Speedtest now runs providers sequentially, measures each download over the full window, and reports the fastest clean provider — fixing wildly variable, under-reporting results on fast links.

### Added
- Integration lab harness (`blackwall-lab` crate + `lab` CLI): a reproducible network-namespace lab that exercises components against the real peer software, with one command that runs identically locally and in CI. Scenarios are KDL topology+assertion files; the harness realizes them in per-run namespaces, emits JUnit + TAP, and self-cleans. Pure-core/thin-IO: topology compiler, address allocator, config renderers, and reporters are unit-tested; the netns executor is validated end-to-end by the scenarios. Ships gates for BGP↔BIRD (native speaker peers real BIRD2, a `/32` lands in the RIB), DNS↔Knot (RFC 2136 + TSIG fast-flux against real Knot, served via `kdig`), shaper↔CAKE (CAKE installed on an interface, asserted via `tc qdisc`), and flow↔sFlow (real sFlow v5 drives the detector to fire a volumetric detection). A new CI `lab` job runs every gate downstream of the unit/coverage job.
- Native BGP speaker (sub-project C, M1a): a `blackwall-bgp` crate with a byte-exact BGP codec (OPEN/KEEPALIVE/UPDATE/NOTIFICATION, IPv4 + IPv6 MP-BGP, communities) and a thin injection-only iBGP session that announces/withdraws routes — the foundation for RTBH (C1b) and FlowSpec (C2).
- Flow detection (sub-project D, M1): a `blackwalld flow` subcommand ingests sFlow v5, estimates per-destination pps/bps over a sliding window, and records volumetric attacks against the operator's prefixes to a `detections` table (new `blackwall-flow` crate).
- Workspace scaffold, CI, and lint configuration (`Cargo.toml` resolver v2, `rustfmt.toml`, workspace-level Clippy lints).
- Core domain types: `Policy`, `Tenant`, `AllowRule`, `PortState`, `L4Proto`, `ServiceTarget`, `ResolvedService`, and `PolicyError` (`blackwall-core`).
- Policy resolution: validates prefix containment, duplicate ownership, and duplicate services (`blackwall-core::resolve`).
- Config DSL parser: hand-written lexer + recursive-descent parser for the Blackwall config language (`blackwall-config`).
- PostgreSQL state persistence: ACID `apply_policy` transaction, `list_services`, `audit_count`, and SQLx migrations (`blackwall-state`).
- nftables ruleset rendering: pure `render()` / `ruleset_json()` producing `inet blackwall` table, `real_v4`/`real_v6` sets, and `prerouting` chain (`blackwall-nft`).
- nftables kernel application via the `nftables` crate (`blackwall-nft::apply`).
- `blackwalld` CLI with `render` and `apply` subcommands wiring config, state, and nftables.
- Coverage gate: ≥ 90% line coverage enforced via `cargo llvm-cov --fail-under-lines 90`.
- Deception engine (`blackwall-deception`): `ServiceEmulator` framework + `EmulatorRegistry` dispatch.
- HTTP emulator: captures request line, returns configurable fake response.
- Generic/tarpit emulator: sends port-appropriate banner from `BannerStore`, optional tarpit delay.
- Banner store: `BannerStore::from_text`, `SharedBanners` (loaded at startup); inotify-backed `watch_banners` hot-reload infrastructure exists and is unit-tested but is not yet wired into `blackwalld run` (runtime reload is forthcoming).
- TPROXY transport: `TproxyListener::bind` + `serve` loop terminating real TCP connections transparently.
- NFQUEUE transport + ICMP responders: `run_nfqueue` loop; ICMPv4/v6 echo-reply packet builders.
- Session persistence: `SessionRow` + `Store::record_session` audit table in `blackwall-state`.
- nftables enforcement: real TPROXY and NFQUEUE redirect rules replace M1 placeholder (`blackwall-nft::render`).
- `blackwalld run` subcommand: wires IPv4 and IPv6 TPROXY listeners (port 61000), NFQUEUE loop, banners loaded at startup, and session drain.
- Deception engine hardening: connection cap and session timeout via `EngineLimits`; supervised transports with `JoinSet`/`select!` and non-zero exit on transport death.
- Live banner hot-reload: `BannerSource::Live` read-through with inotify-backed `SharedBanners::reload` wired into `blackwalld run`.
- SSH emulator: believable KEXINIT + banner exchange capturing client version string.
- SMTP emulator: ESMTP greeting, `EHLO`/`MAIL`/`RCPT`/`DATA`/`QUIT` handling capturing sender and recipient.
- Redis emulator: RESP array and inline command parsing; handles `PING`, `INFO`, and unknown commands.
- MySQL emulator: static handshake packet + error response capturing client login attempt.
- PostgreSQL emulator: `ErrorResponse` framing capturing startup message.
- Emulator port registration: SSH (22), SMTP (25), Redis (6379), MySQL (3306), PostgreSQL (5432) registered in `default_registry`.
- Service discovery crate (`blackwall-discovery`): host-socket scanner parsing `/proc/net/{tcp,tcp6,udp,udp6}` into `ListeningSocket` entries.
- Incus instance model: `IncusInstance` + `instance_services` producing `ResolvedService` from Incus API JSON (addresses × ports cartesian product).
- Incus event stream parser: lifecycle events (`started`, `stopped`, `deleted`) mapped to `IncusLifecycleEvent`.
- Incus unix-socket client (`IncusClient`): `list_instances` + `stream_events` over the Incus unix socket with a `MockIncusClient` for unit tests.
- Policy reconciler (`reconcile_incus_instances`): auto-opens Incus-opted ports by merging discovered services into the active `Policy`, respecting tenant prefix ownership and synthesizing a catch-all tenant for unowned-but-in-prefix addresses.
- `blackwalld run` integration: service discovery reconciler invoked at startup to populate dynamic allow-rules from live Incus instances.
- Multi-source speedtest aggregator (`blackwall-speedtest`): Cloudflare/LibreSpeed/fast.com/Ookla providers run concurrently with trimmed-mean aggregation, plus a `blackwalld speedtest` subcommand.
- CAKE traffic shaping (`blackwall-shaper`): a `shape` config directive, egress + ingress (IFB) CAKE qdiscs applied via tc/ip, auto-tuned from the speedtest aggregate (Cloudflare/LibreSpeed now also measure upload), wired into `blackwalld run`.
- Speedtest source binding (`--source-ip`/`--interface`; `shape <iface> auto` measures bound to that interface) and upload measurement for the fast.com and Ookla providers (all four providers now report upload).
- Banner fast-flux: a `banner-flux <dir> [period]` directive rotates the deception honeypot's banner persona among a pool of files on a deterministic, time-bucketed schedule (stable within each period, identical across restarts).
- DNS fast-flux: a `dns-flux` directive rotates a name's A/AAAA records among a deterministically-selected window of prefix addresses via TSIG-authenticated RFC-2136 dynamic updates (new `blackwall-dns` crate, `domain`-backed send).
