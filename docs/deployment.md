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

## Shadow mode (run detection-only, act on nothing)
For a first deployment on a live network, run the mitigation plane in **shadow
mode** before arming it. Add a bare `shadow` line to the config:
```
shadow            # log + record + meter every RTBH/FlowSpec/XDP mitigation, apply none
```
With `shadow` set, `blackwalld flow` starts with a loud `WARN: SHADOW MODE —
mitigations are LOGGED, NOT APPLIED` banner. Detection, selection, and the
RTBH/FlowSpec/XDP controllers all run normally, but every mitigation the daemon
*would* apply is instead:
- logged at INFO (`shadow: would announce 203.0.113.7/32 …`),
- counted in `blackwall_shadow_would_mitigate_total{plane,action}` (Prometheus), and
- written to the audit log (visible via the read API's `/v1/audit` endpoint).

No BGP session is opened, nothing is announced, and no XDP map is written — the
persistent mirror stays empty, so a later restart can't rehydrate never-vetted
entries. Run it for a day or a week, review the intended mitigations, and **arm
by removing the `shadow` line and re-applying**. Shadow is the mitigation-plane
interlock; the deception engine is unaffected.

## Enable (staged)
Bring the services up **deliberately**, watching `/metrics` and Postgres. Start
`flow` in detection-only mode (no rtbh/flowspec blocks in the config, or with
`shadow` set — see above) first:
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
  RTBH/FlowSpec counts, pending queue depths, detection/session/audit totals,
  and (with `cookie-ports=` set) `blackwall_xdp_syn_cookies_sent_total`.
- `run`: `blackwall_deception_sessions_active` (live in-flight) + session/audit
  totals, and (with `stateless-tcp ports=` set) `blackwall_stateless_syn_cookies_sent_total`,
  `blackwall_stateless_acks_validated_total`, `blackwall_stateless_acks_rejected_total`,
  and `blackwall_stateless_udp_responses_total`.
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
- **Cookie fast path:** add `cookie-ports=` to the same `xdp` directive (see
  below) to also answer SYNs in-kernel, ahead of the drop/rate-limit path.
- **Metrics:** `blackwall_xdp_packets_dropped_total{reason}`, `_passed_total`,
  `_blocked_entries`, `_ratelimit_entries` on `/metrics`.

## Stateless SYN-cookie tier (optional)
Two independent, interoperating opt-ins turn on stateless deception: a
userspace responder on the deception (`run`) side and an in-kernel fast path
on the `flow` side. Both use the same keyed **SipHash-2-4** cookie construction
and **the same secret**, shared via Postgres (get-or-create in a singleton
`cookie_secret` row) — so a connection that gets its cookie SYN-ACK from the
in-XDP fast path still validates when its ACK reaches the userspace responder.
**Both daemons must point at the same Postgres DB** (they already do per the
install steps above) for this to work.

- **Userspace stateless TCP responder** — add `stateless-tcp ports=…` to the
  deception (`run`) config to route those ports to the NFQUEUE stateless
  responder instead of the interactive TPROXY tier:
  ```
  stateless-tcp ports=22,80,443
  ```
  A SYN to one of these ports gets a keyed SYN-ACK cookie carrying no
  connection state; a client that completes the handshake gets the port's
  banner (PSH|ACK|FIN) and the connection closes immediately — a spoofed-source
  SYN flood against these ports creates no state on the box. Dual-stack (IPv4 +
  IPv6, v6 replies go via a raw socket + `IPV6_PKTINFO`). Because a managed
  prefix is *routed to* the box (not assigned to an interface), replies come
  from a non-local source; the responder sets `IP_FREEBIND`/`IPV6_FREEBIND` on
  its raw sockets so this works out of the box — you do **not** need to set the
  `net.ipv{4,6}.ip_nonlocal_bind` sysctl. Deception UDP on
  these paths is answered by a reflection-safe responder whose reply is never
  longer than the request (amplification factor ≤ 1 — it can't be used as a
  UDP reflector).
- **In-XDP SYN-cookie fast path** — add `cookie-ports=` to the `xdp` directive
  in the `flow` config:
  ```
  xdp interface=eth0 mode=auto default-rate-limit=1000 cookie-ports=8080,443
  ```
  A SYN to a configured cookie-port is answered **in-kernel** via `XDP_TX`,
  driver-level and ahead of nftables — the flood never reaches userspace. It's
  gated fail-closed: only SYNs to the box's own deception prefixes *and* a
  configured cookie-port are answered; everything else (including real
  services) passes through untouched. A legitimate client's follow-up ACK falls
  through (`XDP_PASS`) to the userspace stateless responder above, which
  validates the byte-identical cookie and serves the banner.
- **Metrics:** `blackwall_stateless_syn_cookies_sent_total`,
  `blackwall_stateless_acks_validated_total`,
  `blackwall_stateless_acks_rejected_total`, and
  `blackwall_stateless_udp_responses_total` on the `run` daemon's `/metrics`;
  `blackwall_xdp_syn_cookies_sent_total` on the `flow` daemon's `/metrics`.

## POP sensor (sFlow)
Anycast POPs are not `blackwalld` hosts: each POP runs `hsflowd` (host-sflow)
to sample its uplink and export sFlow v5/UDP to the home `flow` daemon, which
does the actual detection. The flow config is the single source of truth for
which POPs exist and how they sample — a `pop` directive per POP:
```
pop ord agent=10.222.3.8 sampling=1000
pop fra agent=10.222.4.8 sampling=500
```
`agent=` is the POP's mesh IP (the address hsflowd stamps as the sFlow agent
on every datagram — this is how the collector attributes traffic back to a
POP); `sampling=` is that POP's configured 1-in-N packet sampling rate. The
`flow` daemon builds its `AgentRegistry` from these entries: every
`FlowObservation` is tagged with the originating POP, and an agent sending at
a rate wildly different from its configured `sampling` trips the
sampling-sanity clamp.

Generate each POP's `hsflowd.conf` from the same config, so the POP-map and
the deployed sensors never drift apart:
```bash
blackwalld sensor render-hsflowd \
  --config /etc/blackwall/blackwall.conf \
  --collector <home-flow-mesh-ip>:6343 \
  --iface eth0
```
This prints one commented block per `pop` entry:
```
# --- POP ord (agent 10.222.3.8) ---
sflow {
  sampling = 1000
  polling = 0
  collector { ip = <home-flow-mesh-ip>  udpport = 6343 }
  pcap { dev = eth0 }
}
```
Split the output and install the right block as `/etc/hsflowd.conf` on each
POP (`--iface` is the device to sample there — usually the uplink NIC, not
necessarily the same name on every POP host). `--collector` must match the
`flow --listen` address of the home daemon and be reachable from every POP —
in practice this means sFlow v5/UDP traverses the WireGuard mesh, so the
POP's firewall/routes must permit outbound UDP to the collector over the WG
interface, and the home box's config must accept it (`flow --listen
0.0.0.0:6343` or scoped to the mesh interface).

## Generate BIRD's side of the session (`bird-config`)
Blackwall's native speaker peers *into* your BIRD; the BIRD side of that iBGP
session (the `protocol bgp` stanza + the `OWN_V4/OWN_V6` prefix defines its
export filters reference) is generated from the same `blackwall.conf`, so you
don't hand-maintain the prefix/session lists twice:
```bash
blackwalld bird-config --config /etc/blackwall/blackwall.conf > /etc/bird/blackwall.conf
```
Add `include "blackwall.conf";` to your `bird.conf` and `birdc configure`. This
requires `local-addr=<ip>` on the `rtbh` directive — blackwall's own BGP source
address, which the generator emits as BIRD's `neighbor` and the speaker binds as
its source so the session matches by construction (its family must match the
`peer=` address). If the `rtbh` block sets `md5=`, the generated file references
`include "blackwall-secret.conf";` instead of embedding the secret — keep that
one-line `password "…";` file `0600` alongside your other BIRD secrets. The
generated file is otherwise non-sensitive and safe to commit. BIRD remains the
fan-out point: blackwall injects a blackhole/FlowSpec once, and BIRD
re-advertises it to every upstream via your existing per-peer export filters —
so adding or retuning upstreams stays a pure BIRD-side operation.

## Not yet implemented (know before you rely on it)
- **XDP data plane is complete but its scale ceiling is real.** Sub-project B is
  shipped end to end: B1 (XDP source-drop + rate-limit), B2 (stateless SYN
  cookies — userspace tier + in-XDP fast path), B3 (zero-copy AF_XDP UDP
  responder), and B4 (xdpcap capture + the DDoS-lab XDP gates). Multi-queue
  AF_XDP scaling is deferred (needs multi-queue-NIC hardware), and realistic
  DDoS-scale stress testing is tracked separately (issue #67). The nftables
  flowtable (`flowtable devices=…`) offloads established forwarded real-service
  flows. Fine for moderate rates and on-box source-drop/SYN-cookie absorption;
  line-rate volumetric attack traffic is still best pushed to your router via
  BGP mitigation.
