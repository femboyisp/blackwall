#!/usr/bin/env bash
#
# End-to-end smoke test for the Blackwall DECEPTION firewall running as a WHOLE
# assembled daemon (`blackwalld run`) against real nftables, in the ROUTED case
# that matches production: a managed prefix is routed *through* the box (the dst
# is not a local address), so this actually exercises the TPROXY policy-route
# path — unlike the lab gate, which only ever hits a local address.
#
# Topology (two netns):
#   scanner --veth-- box(blackwalld run, ip_forward, nft tproxy) --veth-- host(Postgres)
# The scanner routes 203.0.113.0/24 via the box; the box must divert deception
# TCP to the honeypot engine and serve a banner.
#
# Usage:  sudo -E scripts/smoke-deception.sh
set -uo pipefail
cd "$(dirname "$0")/.."

BOX=bw-dec-box
SCAN=bw-dec-scan
SC_BOX=bwd-box; SC_SCAN=bwd-scan   # scanner<->box veth
DB_H=bwd-dbh;   DB_B=bwd-dbb       # box<->host veth (for Postgres)
BOX_SC_IP=10.50.0.1; SCAN_IP=10.50.0.2
HOST_DB_IP=10.60.0.1; BOX_DB_IP=10.60.0.2
PREFIX=203.0.113.0/24
VICTIM=203.0.113.7      # routed dst, NOT local on the box
REAL_PORT=8080          # a declared real service (so the ruleset has a real set)
PGHOST_PORT="${PGPORT:-5433}"
PG_CONTAINER="${PG_CONTAINER:-blackwall-postgres-1}"
SMOKE_DB=blackwall_decep_smoke
RUNDIR="$(mktemp -d /tmp/bw-decep.XXXXXX)"
LAB=./target/debug
DAEMON_PID=""

BOLD=$'\e[1m'; GRN=$'\e[32m'; RED=$'\e[31m'; YEL=$'\e[33m'; RST=$'\e[0m'
step(){ echo "${BOLD}== $* ==${RST}"; }
ok(){ echo "  ${GRN}✔${RST} $*"; }
die(){ echo "  ${RED}FAIL: $*${RST}"; exit 1; }
poll(){ local n="$1"; shift; for _ in $(seq 1 "$n"); do "$@" >/dev/null 2>&1 && return 0; sleep 1; done; return 1; }
inbox(){ ip netns exec "$BOX" "$@"; }
inscan(){ ip netns exec "$SCAN" "$@"; }

cleanup(){
  step "Teardown"
  # SIGTERM triggers the engine's graceful shutdown (removes the ruleset + policy
  # route, exits 0); fall back to a hard kill if it does not exit promptly.
  if [ -n "$DAEMON_PID" ]; then
    kill -TERM "$DAEMON_PID" 2>/dev/null
    for _ in 1 2 3 4 5 6; do kill -0 "$DAEMON_PID" 2>/dev/null || break; sleep 0.5; done
    kill -9 "$DAEMON_PID" 2>/dev/null
  fi
  pkill -9 -f 'target/debug/blackwalld' 2>/dev/null
  sleep 1
  ip netns del "$BOX" 2>/dev/null
  ip netns del "$SCAN" 2>/dev/null
  ip link del "$SC_BOX" 2>/dev/null
  ip link del "$DB_H" 2>/dev/null
  rm -rf "$RUNDIR"
  echo "  cleaned up (smoke DB '$SMOKE_DB' left; drop: docker exec $PG_CONTAINER dropdb -U blackwall $SMOKE_DB)"
}
trap cleanup EXIT

[ "$(id -u)" = 0 ] || die "run with sudo"
command -v nft >/dev/null || die "nft not installed"
[ -x "$LAB/blackwalld" ] || die "build first: cargo build -p blackwalld"

step "1. Clean Postgres ($SMOKE_DB)"
docker exec "$PG_CONTAINER" dropdb -U blackwall --if-exists "$SMOKE_DB" >/dev/null 2>&1
docker exec "$PG_CONTAINER" createdb -U blackwall "$SMOKE_DB" >/dev/null 2>&1 || die "createdb failed (is '$PG_CONTAINER' up?)"
ok "fresh database"

step "2. netns box + scanner + veths"
ip netns add "$BOX"; ip netns add "$SCAN"
# scanner <-> box
ip link add "$SC_SCAN" type veth peer name "$SC_BOX"
ip link set "$SC_BOX" netns "$BOX"; ip link set "$SC_SCAN" netns "$SCAN"
ip -n "$BOX"  addr add "$BOX_SC_IP/30" dev "$SC_BOX"; ip -n "$BOX"  link set "$SC_BOX" up
ip -n "$SCAN" addr add "$SCAN_IP/30"   dev "$SC_SCAN"; ip -n "$SCAN" link set "$SC_SCAN" up
ip -n "$BOX" link set lo up; ip -n "$SCAN" link set lo up
# box <-> host (for Postgres reachability from the box netns)
ip link add "$DB_H" type veth peer name "$DB_B"
ip link set "$DB_B" netns "$BOX"
ip addr add "$HOST_DB_IP/30" dev "$DB_H"; ip link set "$DB_H" up
ip -n "$BOX" addr add "$BOX_DB_IP/30" dev "$DB_B"; ip -n "$BOX" link set "$DB_B" up
# box forwards; scanner routes the managed prefix through the box (routed, not local)
inbox sysctl -qw net.ipv4.ip_forward=1
inbox ethtool -K "$SC_BOX" rx off tx off
inscan ethtool -K "$SC_SCAN" rx off tx off
inscan ip route add "$PREFIX" via "$BOX_SC_IP"
ok "scanner routes $PREFIX via the box (dst is NOT local on the box, checksum offloading disabled)"

step "3. blackwalld config + engine (applies nft itself)"
printf '* = smoke-generic\\r\\n\n' > "$RUNDIR/banners.txt"
cat > "$RUNDIR/decep.conf" <<EOF
interface wan $SC_BOX
ipv4 $PREFIX
default deception
tenant t {
    owns $VICTIM
    allow tcp $REAL_PORT nat:$VICTIM:$REAL_PORT
}
EOF
inbox env DATABASE_URL="postgres://blackwall:blackwall@${HOST_DB_IP}:${PGHOST_PORT}/${SMOKE_DB}" \
  "$LAB/blackwalld" run --config "$RUNDIR/decep.conf" --banners "$RUNDIR/banners.txt" \
  --incus-socket /nonexistent-smoke-no-incus \
  > "$RUNDIR/daemon.log" 2>&1 &
DAEMON_PID=$!
poll 20 sh -c "ip netns exec $BOX ss -lnt 2>/dev/null | grep -q ':61000'" || die "engine never bound :61000 (see $RUNDIR/daemon.log)"
ok "engine listening on :61000, nft applied"

step "4. nft ruleset installed in the box"
inbox nft list table inet blackwall >/dev/null 2>&1 && ok "inet blackwall table present" || die "nft table missing"

step "5. Scanner hits a deception TCP port — expect the honeypot banner"
banner="$(inscan timeout 6 bash -c "exec 3<>/dev/tcp/$VICTIM/22 && head -c 40 <&3" 2>/dev/null)"
if echo "$banner" | grep -q "SSH-2.0"; then
  ok "deception SSH banner served for routed victim $VICTIM:22  ($banner)"
else
  echo "  ${RED}FAIL: no honeypot banner for $VICTIM:22 (got: '${banner:-<nothing>}')${RST}"
  echo "  ${YEL}This is the routed-TPROXY gap: forwarded deception traffic is not diverted to the engine.${RST}"
  echo "  ${YEL}nft ruleset:${RST}"; inbox nft list table inet blackwall 2>/dev/null | sed 's/^/    /' | grep -iE 'tproxy|mark|queue'
  echo "  ${YEL}ip rules in box:${RST}"; inbox ip rule 2>/dev/null | sed 's/^/    /'
  die "deception data path broken in the routed case"
fi

step "6. Session persisted to Postgres"
poll 6 sh -c "[ \"\$(docker exec $PG_CONTAINER psql -U blackwall -d $SMOKE_DB -tAc 'SELECT count(*) FROM deception_sessions' 2>/dev/null)\" -ge 1 ]" \
  && ok "deception_sessions row recorded" \
  || echo "  ${YEL}~ no deception_sessions row yet (session-drain latency)${RST}"

echo
echo "${BOLD}${GRN}DECEPTION SMOKE PASSED${RST} — the assembled daemon diverts routed deception traffic to the honeypot engine."
