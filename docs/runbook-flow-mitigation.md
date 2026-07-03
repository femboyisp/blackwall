# Runbook — `blackwalld flow` mitigation dress rehearsal & first real run

This is the pre-deployment checklist and dress rehearsal for the DDoS-mitigation
pipeline (`blackwalld flow`): sFlow in → detector → FlowSpec/RTBH selection →
iBGP announce to your router → Postgres persistence → restart/rehydrate.

The whole assembled pipeline is exercised by **`scripts/smoke-flow.sh`**, which
runs the *real* daemon against a *real* BIRD2 peer (in a throwaway netns) and a
clean Postgres. Run it first; then follow the "First real run" section to point
the same daemon at your dev-net router.

---

## 1. Automated smoke (self-contained)

Proves — deterministically, in ~30s — that the assembled daemon works:

```bash
cargo build -p blackwalld
cargo build -p blackwall-flow --example sflow-blast
sudo -E env PGPORT=5433 scripts/smoke-flow.sh
```

It walks 11 steps and prints `SMOKE PASSED` on success:

1. Creates a clean `blackwall_smoke` Postgres database (leaves it for inspection).
2/3. Spins up a netns with a passive-iBGP **BIRD2** peer (accepts unicast + FlowSpec).
4/5. Starts `blackwalld flow` and waits for the iBGP session to reach `Established`.
6. **Operator RTBH:** `blackwalld rtbh add` → asserts the `/32` reaches both Postgres (`rtbh_blackholes`) and BIRD's RIB.
7. **Operator FlowSpec:** `blackwalld flowspec add` → asserts the flow rule reaches Postgres (`flowspec_rules`) and BIRD's `flow4tab`.
8. **Auto path:** blasts a crafted volumetric sFlow stream at the collector (`sflow-blast`) → asserts a `detections` row is recorded and the auto-selected FlowSpec mitigation is announced + persisted.
9. **Restart + rehydrate:** kills and restarts the daemon → asserts the active mitigations re-announce from Postgres (a crash never drops protection).
10. Prints `/metrics`.
11. **Rollback:** `blackwalld rtbh remove` → asserts the route is withdrawn from BIRD.

Requirements: `sudo`, a running Postgres (the dev `docker compose` container on
`:5433` is fine), `bird2` (`bird`/`birdc`), and a built workspace.

> **Note:** counters like `blackwall_flow_datagrams_total` reset to 0 on the
> restart in step 9, so the `/metrics` dump in step 10 shows the post-restart
> daemon's fresh collector counters — the DB-backed gauges (`rtbh_active`,
> `flowspec_active`, `detections_total`) reflect the persisted state.

---

## 2. First real run (dev-net router)

Do this **deliberately and hands-on** — it is the first time the full pipeline
runs against real routing. Have a second terminal open on `/metrics` and `birdc`.

### 2.0 Before you start — safety checklist
- [ ] **Clean, dedicated Postgres.** Point `DATABASE_URL` at a *fresh* production
      database, **not** the dev one — on startup the daemon **rehydrates and
      re-announces every active row** in `rtbh_blackholes`/`flowspec_rules`, so
      stale dev rows would immediately null-route/flow-drop real IPs.
- [ ] **iBGP peer is local/trusted**, or set `md5=<secret>` on the `rtbh`
      directive (and the matching `password` on the router) — see the config below.
- [ ] **Thresholds tuned** to the net's real baseline (`--pps-threshold` /
      `--bps-threshold`), so a legitimate high-bandwidth flow doesn't trip a
      null-route. Start conservative (high) and lower toward reality.
- [ ] You know the **manual override**: `blackwalld rtbh remove <ip>` /
      `blackwalld flowspec remove <ip> <proto> <port>` to pull a mitigation, and
      the `ttl=` backstop auto-clears an auto-mitigation after its window.

### 2.1 Config
Same directives as the smoke, pointed at your router (see
`scripts/smoke-flow.sh`'s generated `smoke.conf` for a working template):

```
interface wan <iface>
ipv4 <your-v4-prefix>
ipv6 <your-v6-prefix>
default deception
rtbh peer=<router-ip>:179 local-as=<asn> peer-as=<asn> router-id=<id> \
     next-hop-v4=<blackhole-nh> max=256 hold-down=60s ttl=2h \
     md5=<optional-tcp-md5-secret>
flowspec concentration=0.8 max-flows=4 rate=0 max-rules=256 hold-down=60s ttl=2h
metrics listen=127.0.0.1:9100
```

On the router, configure the neighbour to accept the session (and `password
"<secret>"` if you set `md5=`), import the blackhole community into a null-route
policy, and enable a FlowSpec (`flow4`/`flow6`) channel.

### 2.2 Start + verify the session
```bash
DATABASE_URL=postgres://…/<clean-db> ./target/debug/blackwalld flow \
  --config prod.conf --listen 0.0.0.0:6343 \
  --pps-threshold <tuned> --bps-threshold <tuned>
```
- `curl -s localhost:9100/metrics | grep bgp_session_state` → **`2`** (Established).
- The daemon logs a **loud WARN** whenever the session leaves Established — watch
  for it; a down session means mitigations aren't reaching the router.

### 2.3 Prove the control plane before trusting auto
1. `blackwalld rtbh add <test-ip> --config prod.conf` → confirm on the router:
   the `/32` appears with the blackhole community and is null-routed. Then
   `blackwalld rtbh remove <test-ip>` and confirm it's gone.
2. `blackwalld flowspec add <test-ip> 17 53 --config prod.conf` → confirm the
   router **validates and installs** the flow rule (FlowSpec needs a covering
   route toward the origin — the smoke adds a static one; your router's config
   must resolve it too). `blackwalld flowspec remove <test-ip> 17 53` to clear.

### 2.4 Prove auto-mitigation (controlled)
Against a victim IP *you* own and can afford to disrupt on the dev net, generate
a controlled flood so real sFlow drives a detection:
```bash
# real path: your sFlow agent (hsflowd etc.) samples a trafficgen flood
cargo run -p blackwall-trafficgen -- send --dst <victim> --spec full-set --duration 10
# or, to drive the collector directly without an agent:
cargo run -p blackwall-flow --example sflow-blast -- <collector-ip>:6343 <victim> 600 1024
```
Watch: a `detections` row for `<victim>`; `blackwall_flow_datagrams_total`
climbing; `rtbh_active`/`flowspec_active` going up; and the corresponding rule on
the router. A *concentrated* attack (one dominant port) becomes a FlowSpec
drop; a *diffuse* one becomes an RTBH `/32`.

### 2.5 Prove persistence
Kill and restart `blackwalld flow`. The active mitigations must **re-announce**
(rehydrated from Postgres) and the session return to Established. If a rule
vanishes, stop and investigate before relying on it.

### 2.6 Dashboard (until the full metrics/API land)
- `/metrics` — session state, reconnects, sFlow datagrams/decode-errors, active
  RTBH/FlowSpec counts, pending queue depths, detection/session/audit totals.
- Postgres — `detections`, `rtbh_blackholes`, `flowspec_rules`, and the
  `*_requests` intent logs (with `created_by`).
- The router — `show route` / the FlowSpec table, and the BGP session state.

---

## 3. Known limits (as of this runbook)
- No auth/TLS on `/metrics` — bind to localhost or a trusted management net.
- No GTSM/TTL-security on BGP (TCP-MD5 only).
- Mitigation kind is chosen at detection open; it isn't re-evaluated if the
  attack's fingerprint shifts mid-attack.
- The high-rate XDP/eBPF data plane (sub-project B) is not built — this path
  mitigates via BGP to your router, not by dropping packets on the box at line
  rate.
