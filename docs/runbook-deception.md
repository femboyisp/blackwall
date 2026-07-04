# Runbook — deception firewall (`blackwalld run`) dress rehearsal

Companion to `runbook-flow-mitigation.md`, for the **deception data plane**: the
all-ports-open honeypot. It runs *in the packet path*, so a bug drops real
traffic — higher stakes than the BGP mitigation path. Dress-rehearse it before a
real deployment.

## What `blackwalld run` does

One self-contained daemon: parses the config, persists policy to Postgres,
**applies the nft ruleset itself** (there is no separate `apply` step for the
running daemon — `apply` is only for a standalone push), installs the TPROXY
policy route, and runs the honeypot engine. Deception TCP on a managed prefix is
`tproxy`'d to the engine on **port 61000** and marked so a policy route delivers
it locally; deception ICMP/UDP goes to **NFQUEUE 0**; real services are accepted
to the host stack (real-service DNAT is not yet implemented).

## The routed requirement (this is the load-bearing fix)

TPROXY only diverts a packet to the local engine if the routing decision keeps it
local. For a **routed managed prefix** — the production case, where traffic to
your prefix is routed *through* the box — the packet's destination is not a local
address, so it would be forwarded onward. Blackwall now handles this: the nft
tproxy rule sets `meta mark`, and `apply`/`run` install
`ip rule fwmark 0x1 lookup 100` + a `local default` route in table 100 (v4 + v6),
so marked packets are delivered to the transparent engine socket.

You must have `net.ipv4.ip_forward=1` (and `net.ipv6.conf.all.forwarding=1`) and
the prefix actually routed to the box.

## Automated smoke

`scripts/smoke-deception.sh` runs the real `blackwalld run` daemon against real
nftables in a **routed** two-netns topology (a scanner routes a managed prefix
through the box) and asserts a scanner hitting a deception port gets a honeypot
banner — the case the lab gate never covers (it only uses a local address):

```bash
cargo build -p blackwalld
sudo -E env PGPORT=5433 scripts/smoke-deception.sh
```

It: creates a clean DB → netns box (forwarding) + scanner → starts `blackwalld
run` (which applies nft + the policy route + binds the engine) → the scanner
connects to a routed victim and must receive `SSH-2.0` → checks a
`deception_sessions` row landed in Postgres.

> **Stopping the engine:** send **SIGTERM** (or Ctrl-C / `systemctl stop`). The
> engine catches it, **removes the nft ruleset + TPROXY policy route** (so the box
> stops diverting deception traffic to a now-dead socket), and exits 0. This is
> important: if the ruleset were left in place while the engine is down, the box
> would black-hole most of the managed address space. If a run is force-killed
> (`kill -9`) instead, clean up the leftover dataplane manually:
> `sudo nft delete table inet blackwall`, `sudo ip rule del fwmark 0x1 lookup 100`,
> `sudo ip route flush table 100`.

## First real run

1. **Config** in the `interface <label> <device>` grammar; declare your prefixes,
   `default deception`, and a `tenant` block with each real service
   (`allow tcp <port> nat:<ip>:<port>` or `incus:<instance>`). Declare at least
   the families you route — an IPv4-only policy is fine now (the empty-family set
   bug is fixed).
2. **Enable forwarding** and route the managed prefix to the box.
3. `sudo -E blackwalld run --config prod.conf --banners banners.txt` (with
   `DATABASE_URL` set; pass `--incus-socket /nonexistent` to skip Incus
   discovery if you don't want it). Confirm the engine bound `:61000`
   (`ss -lnt | grep 61000`) and the nft table + `ip rule fwmark` + `ip route
   show table 100` are present.
4. From another host on the prefix, connect to a non-real port on a managed
   address — you should get a protocol-appropriate honeypot banner (SSH/HTTP/…),
   and a `deception_sessions` row should appear in Postgres. A **real** service
   port should reach the actual service.

## Known limits
- The honeypot engine, its concurrency cap (1024) and session timeout (60s), and
  the TPROXY port (61000) / NFQUEUE (0) are not configurable.
- Real-service DNAT is not implemented — declared real services are accepted to
  the host stack, not forwarded to a separate backend.
- `run` does not expose `/metrics` (only `blackwalld flow` does).
