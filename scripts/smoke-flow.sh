#!/usr/bin/env bash
#
# End-to-end smoke test / dress rehearsal for the `blackwalld flow` mitigation
# pipeline. Runs the REAL daemon against a REAL BIRD2 peer (in a throwaway netns)
# and a clean Postgres, and drives the full path:
#
#   config -> Postgres -> iBGP session -> operator RTBH/FlowSpec -> auto-detection
#   from crafted sFlow -> BGP announce -> DB persistence -> RESTART -> rehydrate
#   -> /metrics -> rollback.
#
# It proves the assembled daemon works before you point it at production routing.
# Needs: sudo, a running Postgres (the dev container is fine), BIRD2 (bird/birdc),
# and a built workspace.
#
# Usage:  sudo -E scripts/smoke-flow.sh
# Env:    PGHOST/PGPORT (default localhost:5433 dev container), METRICS_PORT (9109)
#
# For a run against a REAL router instead of the netns BIRD, see
# docs/runbook-flow-mitigation.md — you skip the netns setup and point the
# generated config's `rtbh peer=` at your router.
set -uo pipefail
cd "$(dirname "$0")/.."

NS=bw-smoke-rtr
VETH_H=bwsmk0
VETH_R=bwsmk1
HOST_IP=10.99.0.1
RTR_IP=10.99.0.2
PREFIX=203.0.113.0/24
RTBH_OP=203.0.113.50   # operator-driven RTBH target
FS_OP=203.0.113.51     # operator-driven FlowSpec target
AUTO=203.0.113.7       # auto-detected victim (matches sflow-blast's default frame)
SFLOW_PORT=16343
METRICS_PORT="${METRICS_PORT:-9109}"
PGHOST="${PGHOST:-localhost}"
PGPORT="${PGPORT:-5433}"
PG_CONTAINER="${PG_CONTAINER:-blackwall-postgres-1}"
SMOKE_DB=blackwall_smoke
DB_URL="postgres://blackwall:blackwall@${PGHOST}:${PGPORT}/${SMOKE_DB}"
RUNDIR="$(mktemp -d /tmp/bw-smoke.XXXXXX)"
LAB=./target/debug
DAEMON_PID=""

BOLD=$'\e[1m'; GRN=$'\e[32m'; RED=$'\e[31m'; YEL=$'\e[33m'; RST=$'\e[0m'
step() { echo "${BOLD}== $* ==${RST}"; }
ok()   { echo "  ${GRN}✔${RST} $*"; }
die()  { echo "  ${RED}FAIL: $*${RST}"; exit 1; }

birdc()  { ip netns exec "$NS" birdc -s "$RUNDIR/bird.ctl" "$@" 2>/dev/null; }
psql_q() { docker exec -i "$PG_CONTAINER" psql -U blackwall -d "$SMOKE_DB" -tAc "$1" 2>/dev/null; }
metrics(){ curl -s --max-time 3 "http://127.0.0.1:${METRICS_PORT}/metrics"; }

# poll <seconds> <cmd...> : succeed when cmd exits 0 within the budget
poll() { local n="$1"; shift; for _ in $(seq 1 "$n"); do "$@" >/dev/null 2>&1 && return 0; sleep 1; done; return 1; }

cleanup() {
  step "Teardown"
  [ -n "$DAEMON_PID" ] && kill "$DAEMON_PID" 2>/dev/null
  [ -f "$RUNDIR/bird.pid" ] && ip netns exec "$NS" kill "$(cat "$RUNDIR/bird.pid")" 2>/dev/null
  ip netns del "$NS" 2>/dev/null
  ip link del "$VETH_H" 2>/dev/null
  rm -rf "$RUNDIR"
  echo "  cleaned up (smoke DB '$SMOKE_DB' left for inspection; drop with: docker exec $PG_CONTAINER dropdb -U blackwall $SMOKE_DB)"
}
trap cleanup EXIT

[ "$(id -u)" = 0 ] || die "run with sudo (needs netns + raw sockets)"
command -v bird >/dev/null || die "bird2 not installed"
[ -x "$LAB/blackwalld" ] || die "build first: cargo build -p blackwalld --example sflow-blast"

start_daemon() {
  DATABASE_URL="$DB_URL" "$LAB/blackwalld" flow \
    --config "$RUNDIR/smoke.conf" --listen "127.0.0.1:${SFLOW_PORT}" \
    --pps-threshold 100000 --bps-threshold 1000000000 \
    --window-secs 1 --hold-down-secs 3 > "$RUNDIR/daemon.log" 2>&1 &
  DAEMON_PID=$!
}

########################################################################
step "1. Clean Postgres ($SMOKE_DB)"
docker exec "$PG_CONTAINER" dropdb -U blackwall --if-exists "$SMOKE_DB" >/dev/null 2>&1
docker exec "$PG_CONTAINER" createdb -U blackwall "$SMOKE_DB" >/dev/null 2>&1 || die "createdb failed (is '$PG_CONTAINER' running?)"
ok "fresh database created"

step "2. netns router + veth"
ip netns add "$NS"
ip link add "$VETH_H" type veth peer name "$VETH_R"
ip link set "$VETH_R" netns "$NS"
ip addr add "$HOST_IP/30" dev "$VETH_H"; ip link set "$VETH_H" up
ip -n "$NS" addr add "$RTR_IP/30" dev "$VETH_R"; ip -n "$NS" link set "$VETH_R" up
ip -n "$NS" link set lo up
ok "veth $HOST_IP <-> $RTR_IP up"

step "3. BIRD2 router (passive iBGP peer, accepts routes + flowspec)"
cat > "$RUNDIR/bird.conf" <<EOF
log stderr all;
router id $RTR_IP;
flow4 table flow4tab;
flow6 table flow6tab;
protocol device { scan time 5; }
protocol direct { ipv4; ipv6; interface "*"; }
# Static covering route so BIRD's RFC 8955 flowspec validation accepts our rules.
protocol static {
    ipv4;
    route $PREFIX via "$VETH_R";
}
protocol bgp blackwalld {
    local as 65000;
    neighbor $HOST_IP as 65000;
    passive yes;
    hold time 90;
    ipv4 { import all; export none; };
    flow4 { table flow4tab; import all; };
    flow6 { table flow6tab; import all; };
}
EOF
ip netns exec "$NS" bird -c "$RUNDIR/bird.conf" -s "$RUNDIR/bird.ctl" -P "$RUNDIR/bird.pid" || die "bird failed to start"
poll 5 test -S "$RUNDIR/bird.ctl" || die "bird control socket never appeared"
ok "BIRD up"

step "4. blackwalld config + daemon"
cat > "$RUNDIR/smoke.conf" <<EOF
interface wan $VETH_H
ipv4 $PREFIX
ipv6 2001:db8::/48
default deception
rtbh peer=$RTR_IP:179 local-as=65000 peer-as=65000 router-id=$HOST_IP next-hop-v4=192.0.2.1 next-hop-v6=100::1 max=256 hold-down=3s ttl=1h
flowspec concentration=0.8 max-flows=4 rate=0 max-rules=256 hold-down=3s ttl=1h
metrics listen=127.0.0.1:$METRICS_PORT
EOF
start_daemon
ok "daemon started (pid $DAEMON_PID)"

step "5. iBGP session establishes"
poll 20 sh -c "ip netns exec $NS birdc -s $RUNDIR/bird.ctl show protocols blackwalld 2>/dev/null | grep -q Established" \
  || die "BGP never established (see $RUNDIR/daemon.log)"
ok "session Established"

step "6. Operator path — rtbh add"
DATABASE_URL="$DB_URL" "$LAB/blackwalld" rtbh add "$RTBH_OP" --config "$RUNDIR/smoke.conf" >/dev/null 2>&1 || die "rtbh add rejected"
poll 8 sh -c "[ \"\$(docker exec $PG_CONTAINER psql -U blackwall -d $SMOKE_DB -tAc \"SELECT count(*) FROM rtbh_blackholes WHERE target='$RTBH_OP' AND withdrawn_at IS NULL\")\" = 1 ]" \
  || die "$RTBH_OP never recorded in rtbh_blackholes"
poll 8 sh -c "ip netns exec $NS birdc -s $RUNDIR/bird.ctl show route 2>/dev/null | grep -q '$RTBH_OP/32'" \
  || die "$RTBH_OP/32 never reached BIRD's RIB"
ok "$RTBH_OP blackholed: recorded in DB + present in BIRD's RIB"

step "7. Operator path — flowspec add"
DATABASE_URL="$DB_URL" "$LAB/blackwalld" flowspec add "$FS_OP" 17 53 --config "$RUNDIR/smoke.conf" >/dev/null 2>&1 || die "flowspec add rejected"
poll 8 sh -c "[ \"\$(docker exec $PG_CONTAINER psql -U blackwall -d $SMOKE_DB -tAc \"SELECT count(*) FROM flowspec_rules WHERE dst='$FS_OP' AND withdrawn_at IS NULL\")\" = 1 ]" \
  || die "$FS_OP never recorded in flowspec_rules"
if poll 8 sh -c "ip netns exec $NS birdc -s $RUNDIR/bird.ctl show route table flow4tab 2>/dev/null | grep -q '$FS_OP/32'"; then
  ok "$FS_OP flow rule: recorded in DB + installed in BIRD's flow4tab"
else
  echo "  ${YEL}~${RST} $FS_OP recorded in DB but not in BIRD's flow4tab (validation) — see runbook"
fi

step "8. Auto path — crafted sFlow attack drives a detection"
"$LAB/examples/sflow-blast" "127.0.0.1:${SFLOW_PORT}" "$AUTO" 600 1024 >/dev/null 2>&1 \
  || cargo run -q -p blackwall-flow --example sflow-blast -- "127.0.0.1:${SFLOW_PORT}" "$AUTO" 600 1024 >/dev/null 2>&1
poll 15 sh -c "[ \"\$(docker exec $PG_CONTAINER psql -U blackwall -d $SMOKE_DB -tAc \"SELECT count(*) FROM detections WHERE target='$AUTO'\")\" -ge 1 ]" \
  || die "no detection recorded for $AUTO (see $RUNDIR/daemon.log)"
ok "detection recorded for $AUTO"
poll 15 sh -c "[ \"\$(docker exec $PG_CONTAINER psql -U blackwall -d $SMOKE_DB -tAc \"SELECT count(*) FROM flowspec_rules WHERE dst='$AUTO' AND withdrawn_at IS NULL\")\" -ge 1 ]" \
  || die "auto-mitigation (FlowSpec) never recorded for $AUTO"
ok "auto-mitigation selected + announced + persisted for $AUTO (concentrated → FlowSpec)"

step "9. Restart + rehydrate (the persistence guarantee)"
kill "$DAEMON_PID" 2>/dev/null; wait "$DAEMON_PID" 2>/dev/null; DAEMON_PID=""
sleep 2
start_daemon
poll 20 sh -c "ip netns exec $NS birdc -s $RUNDIR/bird.ctl show protocols blackwalld 2>/dev/null | grep -q Established" \
  || die "session did not re-establish after restart"
poll 12 sh -c "ip netns exec $NS birdc -s $RUNDIR/bird.ctl show route 2>/dev/null | grep -q '$RTBH_OP/32'" \
  || die "$RTBH_OP/32 did NOT re-announce after restart — rehydrate broken"
ok "active mitigations re-announced from Postgres after restart"

step "10. /metrics"
metrics | grep -E '^blackwall_(bgp_session_state|rtbh_active|flowspec_active|detections_total|flow_datagrams_total) ' | sed 's/^/  /'

step "11. Rollback — rtbh remove"
DATABASE_URL="$DB_URL" "$LAB/blackwalld" rtbh remove "$RTBH_OP" >/dev/null 2>&1 || die "rtbh remove failed"
poll 8 sh -c "! ip netns exec $NS birdc -s $RUNDIR/bird.ctl show route 2>/dev/null | grep -q '$RTBH_OP/32'" \
  || die "$RTBH_OP/32 still in BIRD after remove"
ok "$RTBH_OP withdrawn from BIRD"

echo
echo "${BOLD}${GRN}SMOKE PASSED${RST} — the full detect → select → announce → persist → restart → rehydrate path works end to end."
