# Task B4.1 — xdpcap-style packet capture for the XDP data plane

## Summary
An operator can now capture the packets the XDP program acted on — with the
verdict and reason — to a pcap file that opens directly in tcpdump/wireshark,
via `blackwalld xdp capture`. Capture is off by default and costs a single map
lookup per packet when disabled; it is turned on only while a reader holds the
ring.

## Ring + flag design, zero-overhead-when-off proof
- **eBPF maps** (`crates/blackwall-xdp-ebpf/src/main.rs`):
  - `CAPTURE: RingBuf` sized 256 KiB (power-of-2 page multiple).
  - `CAPTURE_ENABLED: HashMap<u32,u8>` single entry (key 0), mirroring the
    `COOKIE_KEY` single-flag pattern: absent/0 = disabled, 1 = enabled. A
    `HashMap` (not `Array`) so *absence* is the natural disabled state.
- **Decision path**: `capture(ctx, reason, verdict, frame_len)` is called next
  to each `count(...)` at every verdict (blocklist/ratelimit/redirect/syncookie/
  pass, v4 and v6). Its **first** action is `capture_enabled()` — one
  `CAPTURE_ENABLED.get()` lookup — and it returns immediately when unset, before
  any `reserve`/snapshot/submit. **Zero ring work when disabled.** Proven live by
  the `disabled_capture_pushes_nothing` gate test: four frames run with the flag
  absent leave the ring empty.
- **Robustness**: if `reserve()` returns `None` (ring full) the sample is dropped
  silently; if the snapshot fails the reserved slot is `discard`ed. Capture never
  changes the verdict.

## CaptureRecord layout (blackwall-xdp-common, `#![no_std]`, `#[repr(C)]`)
`CaptureRecord` = `{ timestamp_ns:u64, reason:u32, verdict:u32, pkt_len:u32,
cap_len:u32 }` — exactly **24 bytes**, 8-byte aligned, no interior/trailing
padding (asserted by a unit test). `CaptureFrame` = `{ header:CaptureRecord,
data:[u8;CAP_SNAP_LEN] }` = **120 bytes**, 8-byte aligned, so the eBPF side can
`RingBuf::reserve::<CaptureFrame>()` in one shot (`8 % align == 0` holds). Fields
are host-native byte order (same machine), like the existing `RateBucket`/
`CookieKeyValue` PODs. `CAP_SNAP_LEN = 96` (Ethernet + IPv4/IPv6 + TCP/UDP
headers). `timestamp_ns` is `bpf_ktime_get_ns()` — monotonic since-boot, not
wall-clock.

## Snapshot mechanism (verifier note)
The snapshot copies from **offset 0 (Ethernet L2)** using `bpf_xdp_load_bytes`
called with **compile-time-constant** lengths in descending tiers
(96/64/32/20/14) — the largest the frame satisfies wins. This was necessary:
- a runtime `min(frame_len, CAP_SNAP_LEN)` length is rejected as an "invalid
  zero-sized read" (the helper's size arg must be a provably-nonzero const), and
  the optimizer folds `clamp`/`if len==0` guards into branchless selects the
  verifier can't narrow;
- a per-byte `load_u8` copy loop trips the documented bpf-linker `data_end`
  guard-coalescing issue (same one `ipv4_checksum` calls out).
Short frames are truncated to the next-lower tier (fine for header inspection).
`cap_len` records the tier actually captured.

## pcap link-type + encoder
- **Link-type = ETHERNET (1)** because the eBPF snapshots from L2. Documented in
  `pcap.rs`.
- Encoder `to_pcap(&[CapturedPacket]) -> Vec<u8>` and parser `parse_record(&[u8])
  -> Option<CapturedPacket>` are **pure** (`crates/blackwall-xdp/src/pcap.rs`).
  Classic format: 24-byte global header (magic 0xa1b2c3d4 LE, v2.4, snaplen 96,
  linktype 1) + per-packet 16-byte header (ts_sec/ts_usec from the boot-time ns,
  incl_len=cap_len, orig_len=pkt_len) + snapshot bytes. All fields little-endian.
  Hand-rolled — no new deps.

## Userspace reader + CLI
- `XdpCapture` (`crates/blackwall-xdp/src/capture.rs`, I/O, coverage-excluded)
  opens the pinned `CAPTURE` ring + `CAPTURE_ENABLED` flag via `MapData::from_pin`,
  sets the flag on, `drain()`s records (parsed with the pure `parse_record`), and
  clears the flag on `stop()`/`Drop`.
- The `flow` daemon pins both maps to bpffs (`/sys/fs/bpf/blackwall/`) in
  `XdpDataplane::attach` — **best-effort**: a pin failure only makes `xdp capture`
  unavailable, it never aborts the attach. Stale pins from a prior instance are
  removed first.
- CLI: `blackwalld xdp capture [--count N | --duration Ns] [--out FILE]
  [--pin-dir DIR]` (default stdout; default 10 s window when neither bound is
  given). Enables capture on open, poll-drains to the limit, writes pcap,
  disables capture on exit (handle drop). Rustdoc + `--help` description added.

## Tests + coverage
- **Pure (required, coverage-counted)**: 7 tests in `pcap.rs` — exact-bytes pcap
  encoding (magic/version/snaplen/linktype, per-packet header, payload), empty →
  global-header-only, header parse round-trip, oversized/past-end `cap_len`
  rejection, encode↔parse round-trip. `pcap.rs` = 97.89% region / 100% line;
  `blackwall-xdp-common` = 100%.
- **Live (optional, done)**: two root `BPF_PROG_TEST_RUN` tests in
  `prog_test_run.rs` — `enabled_capture_pushes_a_record_for_the_acted_packet`
  (verifies verdict/reason/pkt_len/cap_len/snapshot bytes/timestamp of a real
  captured record) and `disabled_capture_pushes_nothing`. Both pass; the whole
  prog-test-run gate (10 tests) is green under `sudo`. No CI change needed — the
  gate auto-discovers them and already runs last, after the AF_XDP gate.
- Coverage gate (`scripts/coverage.sh`, `capture.rs` added to EXCLUDE): **exit 0**,
  TOTAL 96.11% line / 95.46% region (≥90%).
- `cargo build --workspace`, `cargo clippy --workspace --all-targets --
  --deny warnings`, `cargo fmt --all -- --check`, and host rustfmt on the eBPF
  file: all clean.

## Concerns / follow-ups
- **bpffs requirement**: capture needs `/sys/fs/bpf` mounted; pinning is
  best-effort so a missing bpffs only disables capture (daemon still runs).
- **Snapshot truncation to tiers**: a 90-byte frame captures 64 bytes. Enough for
  header/flow inspection; finer tiers or a single `bpf_xdp_load_bytes` with a
  verifier-friendly length are a follow-up.
- **Timestamps are boot-relative** (monotonic ns), not wall-clock — deltas are
  accurate, absolute date is not. Wall-clock correlation is a follow-up.
- **Out of scope (noted as follow-ups)**: no filter expression language, no pcap
  rotation, no per-record verdict/reason surfaced *inside* the pcap (they live in
  the `/metrics` totals and the `CaptureRecord`); single ring shared across CPUs.
