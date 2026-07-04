# Deploying Blackwall

Blackwall deploys as two independent `blackwalld` services against a shared
PostgreSQL. Deploy either or both.

| Service | Binary | What it does |
|---------|--------|--------------|
| `blackwalld-deception` | `blackwalld run` | The all-ports-open honeypot + nft dataplane (in the packet path). |
| `blackwalld-flow` | `blackwalld flow` | sFlow detection + BGP RTBH/FlowSpec auto-mitigation (announces to your router). |

The operator CLIs (`blackwalld rtbh …`, `blackwalld flowspec …`) only queue intent
to Postgres; the running `flow` daemon is the sole applier.

## Prerequisites
- Linux with `nftables` (userspace `nft`), `nft_tproxy`/`nfnetlink_queue`
  kernel modules, and `iproute2`.
- PostgreSQL (a dedicated database). **Use a fresh production DB** — on startup
  both services migrate it, and `flow` re-announces every active `rtbh_blackholes`
  / `flowspec_rules` row, so stale rows would immediately act on real IPs.
- For deception: `net.ipv4.ip_forward=1` (and v6) and the managed prefix routed
  *through* the box.
- For BGP: a local/trusted iBGP peer, or set `md5=` (TCP-MD5) on the `rtbh` block.

## Install
```bash
cargo build --release -p blackwalld
sudo install -m0755 target/release/blackwalld /usr/local/bin/
sudo install -d /etc/blackwall
sudo install -m0644 your-blackwall.conf /etc/blackwall/blackwall.conf
sudo install -m0644 your-banners.txt    /etc/blackwall/banners.txt   # deception only
# DB creds (0600, least-privilege roles — see the security note below)
printf 'DATABASE_URL=postgres://bw_daemon:...@db/blackwall\n' | sudo tee /etc/blackwall/deception.env >/dev/null
sudo cp /etc/blackwall/deception.env /etc/blackwall/flow.env
sudo chmod 600 /etc/blackwall/*.env
sudo cp deploy/blackwalld-*.service /etc/systemd/system/
sudo systemctl daemon-reload
```

## Dress-rehearse first (do not skip)
Both data paths have dress rehearsals that run the real daemon against real
peers. Run them before enabling the services:
```bash
scripts/build-lab-tests.sh
sudo -E scripts/smoke-flow.sh        # BGP mitigation end to end
sudo -E scripts/smoke-deception.sh   # routed deception → honeypot
```

## Enable (staged)
Bring the services up **deliberately**, watching `/metrics` and Postgres:
```bash
sudo systemctl enable --now blackwalld-flow        # start in detection-only mode (no rtbh/flowspec blocks)
sudo systemctl enable --now blackwalld-deception
```
Then follow the two runbooks for the hands-on first-run procedure:
- `docs/runbook-flow-mitigation.md` — observe-only → tune → arm auto-mitigation.
- `docs/runbook-deception.md` — verify the routed diversion + a real service.

## Observe
Set `metrics listen=127.0.0.1:9100` in the config and scrape `GET /metrics`:
- `flow`: BGP session state + reconnects, sFlow datagrams/decode-errors, active
  RTBH/FlowSpec counts, pending queue depths, detection/session/audit totals.
- `run`: `blackwall_deception_sessions_active` (live in-flight) + session/audit
  totals.
Also: Postgres tables (`detections`, `rtbh_blackholes`, `flowspec_rules`, the
`*_requests` intent logs) and `birdc`/your router.

## Stop / emergency
- `systemctl stop blackwalld-deception` — graceful: removes the nft ruleset +
  policy route, exits 0 (traffic stops being diverted). **Do not SIGKILL** — that
  leaves the box black-holing deception traffic; if you must, clean up with
  `nft delete table inet blackwall`, `ip rule del fwmark 0x1 lookup 100`,
  `ip route flush table 100`.
- `systemctl stop blackwalld-flow` — the BGP session drops, so your router
  withdraws all Blackwall-announced routes: all mitigations clear. This is the
  BGP kill switch.

## Security
- Postgres is the authorization boundary — anyone who can write `rtbh_requests`
  can null-route any IP in your prefixes. Give the operator CLI a least-privilege
  role (INSERT on the `*_requests` tables) distinct from the daemon's role.
- `/metrics` has no auth/TLS — bind it to localhost or a trusted management net.
- The config's `interface` must be the real ingress device (the daemon now
  refuses to start if it doesn't exist).

## Not yet implemented (know before you rely on it)
- **No flowtable / XDP fast path.** Traffic is handled on the nft slow path;
  there is no kernel-bypass offload yet (sub-project B). Fine for moderate rates,
  not for line-rate volumetric attack traffic *on the box* (BGP mitigation pushes
  that to your router instead).
- `run` engine limits (concurrency 1024, session timeout 60s) and the TPROXY
  port (61000) / NFQUEUE (0) are not configurable.
- No GTSM/TTL-security on BGP (TCP-MD5 only).
