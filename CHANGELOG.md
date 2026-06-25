# Changelog

All notable changes to this project are documented here, following
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added
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
