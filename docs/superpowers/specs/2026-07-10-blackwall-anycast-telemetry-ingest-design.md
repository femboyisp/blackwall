# Blackwall Anycast Telemetry Ingest Design

**Status:** Approved (brainstorming) — 2026-07-10
**Deployment tracking:** AS214806 backlog #1 (POP sensor) + #2 (anycast-aware aggregation); milestone
**M0** critical-path long pole in `blackwall-internal-docs/blackwall-on-as214806-deployment-plan.md`.
**Depends on:** `blackwall-flow` (sFlow collector + `ThresholdDetector`), the flow policy config, the
`blackwalld flow` daemon.

## Goal

Let the central `flow` daemon at home treat the sFlow feeds from the 8 anycast POPs as **one logical
view**: every sampled flow carries its POP identity, per-victim volume aggregates correctly across
POPs, and per-agent robustness (liveness + sampling sanity) guards the feed. This is the telemetry
foundation the whole mitigation plane waits on.

## Key realization (why this is smaller than "rebuild the detector")

`ThresholdDetector.state` is already keyed **per-destination (victim)**, and `observe()` scales every
sample by its own `sampling_rate` (`est_bytes = sampling_rate × frame_len`). Therefore, with 8
hsflowd feeds pointed at one collector:
- One victim under attack across N POPs yields **one** detection (per-victim keying), not N.
- Per-victim volume **sums across POPs** with automatic per-sample sampling normalization.

Two of the backlog's stated #2 fears ("looks like 8 detections", "thresholds mis-fire") are thus
already handled by the existing design. The genuine net-new work is the **agent/POP identity
dimension** (currently parsed-then-discarded in `sflow.rs`) and the **per-agent bookkeeping** built on
it. The aggregation *logic* stands; the plumbing and robustness are new.

## Scope

**In scope (this spec):**
- #1 as a **thin deploy contract**: the POPs run hsflowd exporting sFlow v5 over the WG mesh; the
  blackwall side ships a config-generation helper (promote the lab's `render_hsflowd_conf`) so the
  hsflowd config is derived from the same POP-map that names the agents. The actual POP install is
  deploy-repo glue, tracked separately — **not built here**.
- #2 as code: agent-identity plumbing, per-POP tagging on detections, per-agent liveness, per-agent
  sampling sanity, and a minimal source-level attribution rollup.

**Out of scope (deferred):**
- Native Rust packet sampler on the POPs (hsflowd is proven in the lab; YAGNI).
- Reliable/buffered transport for sFlow (statistical sampling tolerates UDP loss).
- Source-level *detection* (a new threshold axis) — overlaps [D2] adaptive detection; only a top-N
  attacker-block **attribution** rollup ships here.
- Consuming liveness for auto-withdraw (#17) or HA (#24) — this spec only *emits* the signal.

## Global constraints

- **No `as` casts** — `TryFrom`/`try_from`, `to_be_bytes`.
- **`#[expect(lint, reason = "…")]`, never bare `#[allow]`.**
- **Exact version pins** for any new dependency (none expected).
- **Rustdoc on all public items.**
- **≥90% line coverage** on the pure modules (`sflow.rs`, `detector.rs`, config); the collector
  accept loop + `blackwalld` glue stay coverage-excluded like today (`scripts/coverage.sh`).
- **clippy `--workspace --all-targets --deny warnings` clean; `cargo fmt` clean.**
- `DATABASE_URL=postgres://blackwall:blackwall@localhost:5433/blackwall`.
- Each increment: isolated worktree off `origin/main` → branch → PR → board 4 → merge on check-green.

## Architecture

```
  POP (×8): hsflowd mod_pcap ──sFlow v5/UDP over WG mesh──┐
    agent = <POP mesh IP>, sampling = N                   │
                                                          ▼
  home: blackwalld flow ──▶ run_collector (collector_net.rs, glue)
                              │ decode_datagram (sflow.rs) — NOW stamps obs.agent
                              ▼
                          ThresholdDetector (detector.rs)
                            • per-dst volume  (unchanged)
                            • per-agent tally within window  (new)
                            • liveness: per-agent last_seen  (new)
                            • sampling sanity vs expected     (new)
                            • top-N source /24 rollup         (new)
                              │
                              ▼
                          DetectionEvent { Detection.pops, .top_sources } ──▶ sink
```

### Component 1 — Agent-identity plumbing

**Files:** `crates/blackwall-flow/src/observation.rs`, `sflow.rs`; `crates/blackwall-core` +
`blackwall-config` (POP-map); `bin/blackwalld/src/main.rs` (wire it).

- `FlowObservation` gains `pub agent: IpAddr` — the sFlow **agent address** of the datagram the sample
  came from.
- `sflow.rs::decode_datagram` currently reads the agent-address type at line ~70 and **skips** the
  bytes (`cur.take(agent_addr_len)`, line ~80). Change: decode the agent address (v4 → 4 bytes →
  `Ipv4Addr`; v6 → 16 bytes → `Ipv6Addr`) into an `IpAddr`, and stamp it onto every `FlowObservation`
  produced from that datagram. Signature stays `decode_datagram(bytes) -> Result<Vec<FlowObservation>,
  FlowError>` (the agent is internal to the datagram, applied to all its observations).
- **POP-map** in the flow policy config (same file `blackwalld flow --config` reads):
  ```
  pop ord  agent=10.222.3.8  sampling=1000
  pop fra  agent=10.222.4.8  sampling=1000
  ```
  Parses into `AgentRegistry` (new): `agent: IpAddr → AgentInfo { name: String, expected_sampling: u32 }`.
  Lookup by agent IP yields the POP name + expected rate. An agent absent from the map is **unknown**
  (processed, tagged `"unknown"`, counted).

### Component 2 — Per-POP aggregation + tagging

**Files:** `crates/blackwall-flow/src/detector.rs`.

- `Sample` gains `agent: IpAddr` (carried from the observation).
- `DstState` gains a per-agent tally over the retained window (derivable from `samples`, or an
  incremental `HashMap<IpAddr, AgentTally>` for O(1) — implementation detail).
- `Detection` gains `pub pops: Vec<PopContribution>` where
  `PopContribution { pop: String, est_pps: f64, est_bps: f64 }` (pop = registry name or `"unknown"`),
  computed from the window at event time. Emitted on `Opened`/`Updated`. `Cleared` is unchanged
  (target + at_ms).
- Per-victim keying, volume sum, and threshold logic are **unchanged** — this is enrichment.

### Component 3 — Per-agent robustness

**Files:** `detector.rs` (or a new `agents.rs` in `blackwall-flow`), `metrics.rs`.

- **Liveness:** `AgentRegistry`/detector tracks `last_seen_ms` per agent, updated on every datagram.
  A configurable `pop_silence_secs` (default 60): an agent that was active then goes silent past the
  timeout raises `blackwall_flow_pop_last_seen_seconds` (gauge, per pop label) + a `warn!` log. M0 =
  signal only; #17/#24 consume later.
- **Sampling sanity:** on each sample, compare `obs.sampling_rate` to the agent's `expected_sampling`.
  If it deviates beyond a tolerance (default: not within [expected/4, expected×4]), **clamp the
  sample's effective rate to `expected_sampling`** for the volume math and increment
  `blackwall_flow_agent_sampling_mismatch_total{pop}` + `warn!`. Unknown agents (no expected rate)
  are trusted as-is but counted under `unknown`.

### Component 4 — Source-level attribution rollup

**Files:** `detector.rs`.

- On `Opened`/`Updated`, roll up attacker **sources** in the victim's window into **/24 (v4) / /48
  (v6)** blocks by `est_bytes`, attach the **top-N (default 5)** as
  `Detection.top_sources: Vec<SourceBlock>` where `SourceBlock { block: IpNet, est_bps: f64 }`.
  Attribution metadata only — no threshold, no new detection axis. Reuses the samples already in
  `DstState`.

### Component 5 — #1 deploy contract + config helper

**Files:** promote `crates/blackwall-lab/src/render/hsflowd.rs::render_hsflowd_conf` into a shipped
location callable from `blackwalld` (e.g. `blackwall sensor render-hsflowd --config <flow.conf>`
emitting one hsflowd.conf per POP from the POP-map) — single source of truth for agent IP + sampling.

The contract each POP satisfies (documented, deploy-repo executes):
- hsflowd `mod_pcap` on the ingress interface, `sampling = N`, `polling = 0`,
  `collector { ip = <home flow IP> udpport = <port> }`, agent address = the POP's mesh IP.
- sFlow v5/UDP reaches the home collector over the WG mesh (firewall/route allows it).

## Data flow (end to end)

hsflowd@POP → sFlow v5/UDP over mesh → `run_collector` → `decode_datagram` (stamps `agent`) →
`detector.observe` (per-dst bucket; per-agent tally; liveness `last_seen`; sampling-sanity clamp) →
`detector.tick` → `DetectionEvent::{Opened,Updated}(Detection{ …, pops, top_sources })` /
`Cleared` → `MitigationSink` (RTBH/FlowSpec, or shadow later). Metrics updated per datagram/sample.

## Error handling

| Condition | Behavior |
|---|---|
| Datagram from an agent not in the POP-map | processed, tagged `"unknown"`, `blackwall_flow_unknown_agent_datagrams_total`++ |
| Unparseable / unknown agent-addr type | falls into the existing decode-skip path (`decode_errors`++) |
| UDP loss over the mesh | tolerated (statistical); lowers sample count, never corrupts detection |
| Agent reports an implausible sampling rate | clamp to `expected_sampling`, `…sampling_mismatch_total`++ |
| Agent feed goes silent | `pop_last_seen` gauge + warn; not a hard error |
| Duplicate/malformed `pop` config line | config parse error at load (fail fast) |

## Testing

Pure modules unit-tested; collector loop + `blackwalld` glue coverage-excluded.

- **`sflow.rs`:** agent address extracted for a **v4** agent and a **v6** agent; every observation
  from a datagram carries that agent; an unknown addr-type datagram is skipped (existing behavior
  preserved).
- **`detector.rs`:**
  - two agents (POPs) feeding the same victim → a single `Opened` whose `pops` lists both with
    proportional shares; total volume equals the sum.
  - `top_sources` picks the correct top /24 by volume; v6 rolls to /48.
  - liveness: an agent silent past the timeout is reflected in the last-seen gauge input.
  - sampling sanity: an agent reporting 1-in-1 against an expected 1-in-1000 is **clamped** (volume
    matches the expected-rate computation, mismatch counter increments).
- **config:** `pop <name> agent=<ip> sampling=<n>` parses into `AgentRegistry`; missing keys and
  duplicate agents are rejected.
- **Non-breaking:** with no `pop` block, behavior equals today except `FlowObservation.agent` is
  populated and all traffic tags as `unknown`.
- Coverage ≥90% on `sflow.rs`, `detector.rs`, and the config additions.

## Non-goals / compatibility

Non-breaking: a single-collector / no-POP-map deployment behaves exactly as today (per-victim
threshold detection), with the `agent` field populated and everything tagged `unknown`. The
mitigation controllers (`rtbh`/`flowspec`) are untouched — they consume `DetectionEvent` as before;
the new `pops`/`top_sources` fields are additive metadata they may ignore.
