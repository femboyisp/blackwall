# B3.2 — Zero-copy stateless UDP responder over AF_XDP

## Directive

Implement increment B3.2 of Blackwall sub-project B: the flow daemon redirects
configured deception UDP ports to a userspace AF_XDP socket (B3.1's XSKMAP) and
answers them at line rate with the reflection-safe `udp_response` builder,
bypassing the kernel stack + NFQUEUE — symmetric with how B2 gave the TCP SYN
tier an in-kernel fast path. Scope: IPv4 UDP only, queue 0 only, copy-mode.
Work in the isolated worktree `blackwall-b32-wt` (branch `sp-b3-2-afxdp-udp`),
one clean commit on top of B3.1.

## What shipped

1. **`XdpConfig.afxdp_udp_ports: Vec<u16>`** (`blackwall-core/src/xdp.rs`) +
   `xdp afxdp-udp-ports=53,123` parser directive (mirrors `cookie-ports=`,
   rejects bad/zero port), with parser tests (`parses_xdp_afxdp_udp_ports`,
   `rejects_xdp_afxdp_udp_ports_bad`). Empty = responder disabled. The single
   `XdpConfig` literal (the parser) was updated.

2. **AF_XDP TX path — REAL zero-copy TX (no raw-socket fallback needed).**
   `AfXdpReceiver` renamed to `AfXdpSocket` (RX+TX), keeping `bind`/`raw_fd`/
   `recv_one`/`queue_id`. The socket now maps a TX ring (`tx_size` set,
   `user.map_tx()`) and reaps the completion ring. New
   `AfXdpSocket::send(&[u8])` copies the reply frame into a free TX chunk of the
   **same UMEM**, enqueues an `XdpDesc`, and wakes the kernel — a genuine
   zero-copy AF_XDP transmit. TX chunks are the disjoint high half of the UMEM
   (`RING_SIZE..FRAME_COUNT`); the RX fill ring keeps the low half, so a reply
   in flight never aliases a chunk the kernel may overwrite. A `tx_free`
   free-list is refilled from the completion ring on each `send`. Every
   `unsafe` (the `copy_nonoverlapping` into the UMEM) carries a SAFETY comment.
   New `AfXdpError::Transmit`. `xdpilone` reused (no new deps for the socket).

3. **Responder loop** (`blackwalld/src/main.rs`, `Command::Flow`). When
   `afxdp_udp_ports` is non-empty, after XDP attach a **dedicated blocking
   `std::thread`** (`afxdp-udp-responder`) runs `afxdp_udp_responder_loop`:
   binds `AfXdpSocket` on the XDP interface **queue 0** (multi-queue noted as a
   follow-up), `register_xsk(...)`, then `set_redirect_ports(...)` (installed
   *after* registration so no UDP is diverted to an empty XSKS slot during
   startup), then loops `recv_one(200ms)` → `udp_l2_response(frame, banner)` →
   `sock.send(reply)` → counter++. Frames that aren't IPv4 UDP or that the
   reflection guard declines (`None`) are dropped. Non-fatal throughout (any
   setup failure logs a warning and leaves the fast path inert). Graceful
   teardown: an `AtomicBool` stop flag is set on shutdown and the thread joined
   (it wakes from its bounded poll within ~200 ms). Does not block the async
   runtime.

   **L2 framing helper.** AF_XDP delivers whole L2 frames (Ethernet header
   included). Rather than reimplement anything, a pure, unit-tested
   `packet::udp_l2_response(frame, payload)` was added to `blackwall-deception`
   (sibling of `udp_response`): it strips the 14-byte Ethernet header, delegates
   the IPv4 reply + reflection guard to the existing `udp_response`, and
   prepends a reply Ethernet header with the MACs swapped. IPv4-only (rejects
   non-`0x0800` EtherType). This keeps the reflection safety in one place and is
   the tested pure helper (the socket I/O and daemon loop are coverage-excluded).

4. **Metric** `blackwall_xdp_udp_responses_total` (counter, "AF_XDP UDP
   responder replies sent") rendered via the flow daemon's `/metrics` from a
   shared `Arc<AtomicU64>` incremented by the responder thread (like the
   stateless counters); `MetricsSources.afxdp_udp_responses`.

## Banner source

Minimal, as the directive permits. The flow daemon (`Command::Flow`) runs no
deception engine and holds no live banner store (unlike `Command::Run`), so
B3.2 ships **one static default banner** (`const AFXDP_UDP_BANNER = b"blackwall\n"`)
reflected to every redirected port. The reflection-amplification guard truncates
it to ≤ the request payload, so it can never amplify. **Concern / follow-up:**
per-port banners (wiring the deception banner store into the flow daemon) are
deferred; the current banner is a placeholder that proves the path, not a
convincing per-service honeypot response.

## Round-trip test + local result

Extended `crates/blackwall-xdp/tests/afxdp_redirect.rs` with
`redirected_udp_gets_a_reflection_safe_reply_over_afxdp` (`#[ignore]`, root). It
attaches `xdp_filter` to a veth, binds `AfXdpSocket`, registers XSKS, installs
the redirect port, injects a UDP request (16-byte payload) from the peer, drives
the **exact responder pipeline** (`recv_one` → `udp_l2_response` → `send`), and
captures the reply egressing the veth via an `AF_PACKET` socket — asserting the
reply is IPv4 UDP with addresses/ports swapped and payload truncated to the
request length (banner prefix). This proves the **real zero-copy round trip**.

Ran locally under `sudo -n`: **both AF_XDP tests pass** (B3.1 RX + B3.2 round
trip), 2 passed / 0 failed. It stays in the CI AF_XDP gate (same
`afxdp_redirect` binary), which runs before the prog-test-run gate (unchanged
last).

## Verification

- `cargo build --workspace` — clean.
- `cargo clippy --workspace --all-targets -- --deny warnings` — clean.
- `cargo fmt --all -- --check` — clean.
- `scripts/coverage.sh` (≥90 gate) — **exit 0, TOTAL 95.42% lines** (AF_XDP
  socket I/O + daemon loop coverage-excluded; parser + `udp_l2_response` tested).
- AF_XDP veth gate under root — 2/2 pass.

## Concerns

- **Banner source** (above): static placeholder; per-port banners deferred.
- **Queue 0 only**: multi-queue NICs deliver on other RX queues; those are not
  answered until the multi-queue follow-up (noted in code).
- **Supervision**: the responder is a detached `std::thread` with a stop flag +
  best-effort join at shutdown; if the socket hits a receive error it logs and
  exits (leaving the fast path inert) rather than re-binding. Acceptable for
  B3.2; auto-restart is a possible hardening follow-up.
- **Copy-mode**: veth (and the current bind flags) are copy-mode; true
  zero-copy NIC binding is the documented follow-up.
