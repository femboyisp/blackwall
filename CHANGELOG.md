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
- Banner store + hot-reload: `BannerStore::from_text`, `SharedBanners`, inotify-backed `watch_banners` hot-reload.
- TPROXY transport: `TproxyListener::bind` + `serve` loop terminating real TCP connections transparently.
- NFQUEUE transport + ICMP responders: `run_nfqueue` loop; ICMPv4/v6 echo-reply packet builders.
- Session persistence: `SessionRow` + `Store::record_session` audit table in `blackwall-state`.
- nftables enforcement: real TPROXY and NFQUEUE redirect rules replace M1 placeholder (`blackwall-nft::render`).
- `blackwalld run` subcommand: wires TPROXY listener, NFQUEUE loop, banner hot-reload, and session drain.
