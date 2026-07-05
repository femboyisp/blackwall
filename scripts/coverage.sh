#!/usr/bin/env bash
# Canonical coverage gate for Blackwall — the single source of truth shared by
# CI and local runs, so the two cannot drift apart.
#
# The excluded files require CAP_NET_ADMIN / a live kernel / a live network and
# therefore cannot be exercised in CI:
#   - transport/{tproxy,nfqueue}.rs   TPROXY transparent sockets, NFQUEUE + raw sockets
#   - blackwall-nft/src/apply.rs      nftables kernel apply
#   - blackwalld/src/main.rs          daemon process/runtime glue
#   - discovery/src/{incus_client,proc_io}.rs   Incus unix-socket + /proc readers
#   - speedtest/src/providers/*_net.rs          live HTTP/TCP speedtest fetchers
#   - blackwall-lab/src/{exec/*,cli,bin/lab}.rs   netns/process orchestration (needs CAP_NET_ADMIN)
#   - blackwall-trafficgen/src/{io/*,bin/*}.rs    AF_PACKET send/recv sockets (needs CAP_NET_RAW + netns)
# Every one of these is a thin adapter; all of its non-trivial pure logic lives
# in unit-tested helpers (e.g. transport/packet.rs, render.rs, *_parse.rs).
#
# When a milestone adds a new thin I/O adapter, extend EXCLUDE here only — CI
# picks it up automatically.
#
# blackwall-xdp-ebpf is not listed above: it's excluded from the workspace
# entirely (targets bpfel-unknown-none), so it never participates in
# `--workspace` llvm-cov, and it's exempt from the no-`as`-casts guideline
# (verifier idioms require `as` for register-width/pointer casts).
#
# Extra args are forwarded to cargo llvm-cov (e.g. --html, --summary-only).
set -euo pipefail

EXCLUDE='(transport/(tproxy|nfqueue)\.rs|blackwall-nft/src/apply\.rs|blackwalld/src/(main|metrics)\.rs|discovery/src/incus_client\.rs|discovery/src/proc_io\.rs|speedtest/src/providers/.*_net\.rs|shaper/src/apply\.rs|dns/src/send_net\.rs|flow/src/collector_net\.rs|bgp/src/session_net\.rs|blackwall-lab/src/exec/.*\.rs|blackwall-lab/src/cli\.rs|blackwall-lab/src/bin/lab\.rs|blackwall-trafficgen/src/io/.*\.rs|blackwall-trafficgen/src/bin/.*\.rs)'

exec cargo llvm-cov --workspace --fail-under-lines 90 --ignore-filename-regex "$EXCLUDE" "$@"
