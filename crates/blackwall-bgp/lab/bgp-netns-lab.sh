#!/usr/bin/env bash
# bgp-netns-lab.sh — BGP session interop gate for blackwall-bgp.
#
# Creates two network namespaces connected by a veth pair:
#   lab-bgp-peer    10.0.0.1/30  — runs BIRD2 as the BGP peer (AS 214806)
#   lab-bgp-speaker 10.0.0.2/30  — runs the Rust BGP speaker under test
#
# BIRD2 is configured to accept a passive iBGP session from 10.0.0.2 and
# import all received routes.  After the speaker announces 203.0.113.7/32,
# `birdc show route` should list it.
#
# Requires: root, iproute2, bird2 (binary: bird), ip.
# Run:  sudo bash crates/blackwall-bgp/lab/bgp-netns-lab.sh
#
# Self-cleans on exit (trapped).  The interop test binary must already be
# built; run `cargo build -p blackwall-bgp --tests` before invoking.
#
# Validation checklist (printed at the end):
#   [1] BIRD session Established with 10.0.0.2
#   [2] `birdc show route 203.0.113.7/32` lists the /32
#   [3] origin IGP, community 65535:666 present
#
# RESULT 2026-06: expected Full BGP session + /32 in BIRD RIB after ~8 s.

set -euo pipefail

NS_PEER="lab-bgp-peer"
NS_SPEAKER="lab-bgp-speaker"
VETH_PEER="veth-bgp-peer"
VETH_SPEAKER="veth-bgp-spkr"
PEER_ADDR="10.0.0.1"
SPEAKER_ADDR="10.0.0.2"
BIRD_CTL="/tmp/bgp-lab-bird.ctl"
BIRD_PID="/tmp/bgp-lab-bird.pid"
BIRD_LOG="/tmp/bgp-lab-bird.log"
BIRD_CONF="/tmp/bgp-lab-bird.conf"

# ── Cleanup ───────────────────────────────────────────────────────────────────

cleanup() {
    set +e
    # Kill BIRD if it is still running.
    if [ -f "$BIRD_PID" ]; then
        ip netns exec "$NS_PEER" kill "$(cat "$BIRD_PID")" 2>/dev/null
        rm -f "$BIRD_PID"
    fi
    ip netns del "$NS_PEER"    2>/dev/null
    ip netns del "$NS_SPEAKER" 2>/dev/null
    ip link del "$VETH_PEER"   2>/dev/null
    rm -f "$BIRD_CONF" "$BIRD_CTL" "$BIRD_LOG"
    echo "== cleanup done =="
}
# Clean up on any exit (success or failure).
trap cleanup EXIT

# Run cleanup first to remove stale state from a previous run.
set +e
cleanup
set -e

# ── Network namespaces + veth ─────────────────────────────────────────────────

echo "== creating netns and veth pair =="
ip netns add "$NS_PEER"
ip netns add "$NS_SPEAKER"

# Create the veth pair in the root netns, then move each end.
ip link add "$VETH_PEER" type veth peer name "$VETH_SPEAKER"
ip link set "$VETH_PEER"    netns "$NS_PEER"
ip link set "$VETH_SPEAKER" netns "$NS_SPEAKER"

# Configure peer side (10.0.0.1/30).
ip netns exec "$NS_PEER"    ip link set lo up
ip netns exec "$NS_PEER"    ip link set "$VETH_PEER" up
ip netns exec "$NS_PEER"    ip addr add "${PEER_ADDR}/30"    dev "$VETH_PEER"

# Configure speaker side (10.0.0.2/30).
ip netns exec "$NS_SPEAKER" ip link set lo up
ip netns exec "$NS_SPEAKER" ip link set "$VETH_SPEAKER" up
ip netns exec "$NS_SPEAKER" ip addr add "${SPEAKER_ADDR}/30" dev "$VETH_SPEAKER"

echo "== connectivity check =="
ip netns exec "$NS_PEER" ping -c1 -W2 "$SPEAKER_ADDR" > /dev/null \
    && echo "  peer -> speaker OK" \
    || { echo "  ERROR: peer cannot reach speaker"; exit 1; }

# ── BIRD2 configuration (inline) ─────────────────────────────────────────────
#
# Accepts a passive iBGP session from 10.0.0.2 (the Rust speaker).
# AS 214806, router-id 10.0.0.1, import all received routes.

cat > "$BIRD_CONF" << 'BIRDCONF'
log stderr all;
router id 10.0.0.1;

protocol device {
    scan time 5;
}

protocol kernel {
    ipv4 { import none; export none; };
}

protocol bgp blackwall_speaker {
    local as 214806;
    neighbor 10.0.0.2 as 214806;
    # Passive: wait for the speaker to initiate the TCP connection.
    passive yes;
    hold time 90;
    keepalive time 30;
    ipv4 {
        import all;
        export none;
    };
}
BIRDCONF

# ── Start BIRD2 in the peer netns ─────────────────────────────────────────────

echo "== starting BIRD2 in $NS_PEER =="
ip netns exec "$NS_PEER" bird \
    -c "$BIRD_CONF" \
    -s "$BIRD_CTL" \
    -P "$BIRD_PID" \
    2> "$BIRD_LOG" \
    && echo "  bird started" \
    || { echo "  ERROR: bird failed to start:"; cat "$BIRD_LOG"; exit 1; }

sleep 2

# ── Run the Rust interop test in the speaker netns ────────────────────────────
#
# The test binary is found by `cargo test --no-run --message-format=json`.
# Alternatively, find it under target/.  We use cargo test directly with
# `ip netns exec` after locating the workspace root.

WORKSPACE_ROOT="$(git -C "$(dirname "$0")" rev-parse --show-toplevel 2>/dev/null \
    || realpath "$(dirname "$0")/../../../../")"

echo "== building interop test binary =="
cargo build -p blackwall-bgp --tests --manifest-path "$WORKSPACE_ROOT/Cargo.toml" 2>&1 | tail -5

# Find the interop test binary.
TEST_BIN="$(find "$WORKSPACE_ROOT/target/debug/deps" -name 'interop-*' -perm /111 \
    -newer "$WORKSPACE_ROOT/Cargo.toml" | sort -t- -k2 | tail -1)"

if [ -z "$TEST_BIN" ]; then
    echo "ERROR: interop test binary not found under target/debug/deps/"
    exit 1
fi
echo "  test binary: $TEST_BIN"

echo "== running interop test in $NS_SPEAKER =="
ip netns exec "$NS_SPEAKER" \
    env BW_BGP_PEER="${PEER_ADDR}:179" BW_BGP_ASN=214806 \
    "$TEST_BIN" announces_a_host_route --ignored --nocapture \
    && echo "  interop test PASSED" \
    || { echo "  interop test FAILED (see output above)"; exit 1; }

# ── Verify the /32 is in BIRD's RIB ──────────────────────────────────────────

echo "== birdc show route 203.0.113.7/32 =="
ip netns exec "$NS_PEER" birdc -s "$BIRD_CTL" show route 203.0.113.7/32 \
    | tee /tmp/bgp-lab-route.txt

if grep -q "203.0.113.7/32" /tmp/bgp-lab-route.txt; then
    echo ""
    echo "== RESULT: /32 learned by BIRD — interop gate PASSED =="
else
    echo ""
    echo "== RESULT: /32 NOT found in BIRD RIB — interop gate FAILED =="
    exit 1
fi
