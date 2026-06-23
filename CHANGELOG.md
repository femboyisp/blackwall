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
