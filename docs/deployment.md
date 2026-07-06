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
- For BGP: a local/trusted iBGP peer. Harden the session with `md5=` (TCP-MD5)
  and/or `gtsm-hops=` (RFC 5082 TTL-security; `1` for a directly-connected peer)
  on the `rtbh` block.

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
```

Then install the service units for your init system.

**systemd:**
```bash
sudo cp deploy/blackwalld-*.service /etc/systemd/system/
sudo systemctl daemon-reload
```

**runit** (Void, Artix, …):
```bash
sudo cp -r deploy/runit/blackwalld-deception deploy/runit/blackwalld-flow /etc/sv/
# activate by symlinking into the supervision dir (/var/service on Void, /etc/service elsewhere)
sudo ln -s /etc/sv/blackwalld-flow       /var/service/
sudo ln -s /etc/sv/blackwalld-deception  /var/service/
# `sv stop <svc>` sends SIGTERM = graceful shutdown; `sv status <svc>` to check.
```
The `run` scripts load DB creds from the same `/etc/blackwall/*.env` files, run
as root (the daemons need `CAP_NET_ADMIN`/`CAP_NET_RAW`), and log via `svlogd`
under `/var/log/blackwalld-*`. The deception service ships a `finish` backstop
that clears the nft table + policy route if the process is ever SIGKILLed.

## Dress-rehearse first (do not skip)
Both data paths have dress rehearsals that run the real daemon against real
peers. Run them before enabling the services:
```bash
scripts/build-lab-tests.sh
sudo -E scripts/smoke-flow.sh        # BGP mitigation end to end
sudo -E scripts/smoke-deception.sh   # routed deception → honeypot
```

## Enable (staged)
Bring the services up **deliberately**, watching `/metrics` and Postgres. Start
`flow` in detection-only mode (no rtbh/flowspec blocks in the config) first:
```bash
# systemd
sudo systemctl enable --now blackwalld-flow
sudo systemctl enable --now blackwalld-deception
# runit — the symlink from the install step already starts it; to hold one down
# until you're ready, `touch /etc/sv/<svc>/down` before symlinking, then `sv up <svc>`.
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
- `systemctl stop blackwalld-deception` (or `sv stop blackwalld-deception`) —
  graceful: removes the nft ruleset + policy route, exits 0 (traffic stops being
  diverted). **Do not SIGKILL** — that leaves the box black-holing deception
  traffic; if you must, clean up with `nft delete table inet blackwall`,
  `ip rule del fwmark 0x1 lookup 100`, `ip route flush table 100`. (The runit
  service's `finish` script runs exactly this cleanup as a backstop.)
- `systemctl stop blackwalld-flow` (or `sv stop blackwalld-flow`) — the BGP
  session drops, so your router withdraws all Blackwall-announced routes: all
  mitigations clear. This is the BGP kill switch.

## Security
- Postgres is the authorization boundary — anyone who can write `rtbh_requests`
  can null-route any IP in your prefixes. Give the operator CLI a least-privilege
  role (INSERT on the `*_requests` tables) distinct from the daemon's role.
- `/metrics` has no auth/TLS — bind it to localhost or a trusted management net.
- The config's `interface` must be the real ingress device (the daemon now
  refuses to start if it doesn't exist).

## On-box XDP fast drop (optional)
An `xdp` config directive turns on an in-kernel XDP program on the uplink that
drops and per-source rate-limits attack traffic at the driver level, ahead of
the nftables classify path:
```
xdp interface=eth0 mode=auto default-rate-limit=1000
```
- **Source-keyed:** it drops/limits the *attacker source*, not the victim —
  preserving the victim's other traffic (the on-box complement to whole-IP BGP
  RTBH). Detections drive per-source rate-limits automatically; `blackwalld xdp
  block|unblock|rate-limit|list|stats` is the operator control plane (intent is
  written to Postgres and applied by the running `flow` daemon, like `rtbh`).
- **Prerequisites:** a kernel with XDP (any modern Linux) and, for `mode=native`,
  a NIC driver with native XDP support. `mode=auto` (the default) tries native
  and falls back to generic (skb) mode with a warning, so it works on veth/less
  capable NICs too. Attach is **non-fatal** — if XDP can't load, the daemon logs
  a warning and continues on the nft slow path.
- **Metrics:** `blackwall_xdp_packets_dropped_total{reason}`, `_passed_total`,
  `_blocked_entries`, `_ratelimit_entries` on `/metrics`.

## Not yet implemented (know before you rely on it)
- **No SYN-cookie / AF_XDP acceleration yet.** B1 ships XDP source-drop +
  rate-limit; in-XDP SYN cookies and a zero-copy AF_XDP userspace path are
  B2–B3 (sub-project B). The nftables flowtable (`flowtable devices=…`) offloads
  established forwarded real-service flows, but there is no kernel-bypass offload
  for the deception/inspection path yet. Fine for moderate rates and on-box
  source-drop; line-rate volumetric attack traffic is still best pushed to your
  router via BGP mitigation.
