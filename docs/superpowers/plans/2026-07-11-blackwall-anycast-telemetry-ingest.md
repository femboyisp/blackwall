# Blackwall Anycast Telemetry Ingest Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give every sampled flow its POP identity (from the sFlow agent address, currently discarded) and build the per-POP tagging, liveness, sampling-sanity, and source-attribution that lets the central `flow` daemon treat the 8 anycast POP feeds as one logical view.

**Architecture:** All code is in `blackwall-flow` plus a `pop` config directive (`blackwall-core`/`blackwall-config`) and thin `blackwalld` glue. The detector's per-victim aggregation is unchanged; we thread a new `agent` dimension through it. hsflowd on the POPs is a deploy contract, not code — we only ship a config-generation helper.

**Tech Stack:** Rust 2021, sFlow v5 decoding (existing hand-rolled `sflow.rs`), `ipnet`, sqlx-free (this is the detection path).

## Global Constraints

Copied verbatim from `docs/superpowers/specs/2026-07-10-blackwall-anycast-telemetry-ingest-design.md`:

- **No `as` casts** — use `TryFrom`/`try_from`, `to_be_bytes`. (Existing `as` casts in `detector.rs` carry `#[expect(clippy::cast_precision_loss, reason=…)]`; match that pattern if you add a numeric cast, never a bare `as`.)
- **`#[expect(lint, reason = "…")]`, never bare `#[allow]`.**
- **Exact version pins** for any new dependency (none expected — `ipnet` is already a workspace dep).
- **Rustdoc on all public items.**
- **≥90% line coverage** on `sflow.rs`, `detector.rs`, and the config additions; the collector accept loop + `blackwalld` glue stay coverage-excluded (`scripts/coverage.sh`).
- **clippy `--workspace --all-targets --deny warnings` clean; `cargo fmt` clean.**
- `DATABASE_URL=postgres://blackwall:blackwall@localhost:5433/blackwall`.
- Work in worktree `/home/zoa/projects/femboy/blackwall/blackwall-telemetry-wt`, branch `sp-telemetry-spec`.

## File Structure

```
crates/blackwall-flow/src/observation.rs   — MODIFY: add FlowObservation.agent
crates/blackwall-flow/src/sflow.rs         — MODIFY: decode agent addr, thread to observations
crates/blackwall-flow/src/agents.rs        — CREATE: AgentRegistry (name + expected sampling per agent)
crates/blackwall-flow/src/detector.rs      — MODIFY: Sample.agent, liveness, sampling sanity, Detection.pops + top_source_blocks
crates/blackwall-flow/src/lib.rs           — MODIFY: `mod agents;` + re-export
crates/blackwall-core/src/pop.rs           — CREATE: PopEntry
crates/blackwall-core/src/lib.rs           — MODIFY: re-export PopEntry
crates/blackwall-core/src/policy.rs        — MODIFY: Policy.pops field
crates/blackwall-core/src/resolve.rs       — MODIFY: default pops at Policy construction sites
crates/blackwall-config/src/parser.rs      — MODIFY: parse `pop` directive
bin/blackwalld/src/main.rs                 — MODIFY: build AgentRegistry, pass to detector (flow path)
bin/blackwalld/src/metrics.rs OR flow glue — MODIFY: per-agent metrics
bin/blackwalld/src/sensor.rs               — CREATE: render-hsflowd helper (or in an existing module)
docs/deployment.md                         — MODIFY: POP sensor / hsflowd deploy contract section
```

---

### Task 1: sFlow agent-address extraction → `FlowObservation.agent`

**Files:**
- Modify: `crates/blackwall-flow/src/observation.rs`
- Modify: `crates/blackwall-flow/src/sflow.rs`

**Interfaces:**
- Produces: `FlowObservation` gains `pub agent: IpAddr` (the datagram's sFlow agent address). `decode_datagram(bytes) -> Result<Vec<FlowObservation>, FlowError>` signature unchanged; every observation it returns now carries the agent.

- [ ] **Step 1: Add the field to `FlowObservation` and update the RED test**

In `crates/blackwall-flow/src/observation.rs`, add to the struct (after `tcp_flags`):
```rust
    /// The sFlow agent (POP) address the sampled datagram came from.
    pub agent: IpAddr,
```
Ensure `use std::net::IpAddr;` is present (it is — `src`/`dst` use it).

- [ ] **Step 2: Write the failing test for agent extraction (v4 and v6 agents)**

In `crates/blackwall-flow/src/sflow.rs` `#[cfg(test)] mod tests`, add. Reuse the existing test datagram builder in that module (find the helper that assembles a v5 datagram with a flow sample; it currently writes agent-addr-type=1 + 4 bytes). Add a test that asserts the decoded observations carry the agent:
```rust
    #[test]
    fn decodes_agent_address_v4() {
        // Build a datagram with agent 10.222.3.8 (addr type 1) containing one
        // raw-header flow sample (reuse the existing sample-building helper).
        let dg = build_test_datagram_v4_agent([10, 222, 3, 8]);
        let obs = decode_datagram(&dg).unwrap();
        assert!(!obs.is_empty());
        assert!(obs.iter().all(|o| o.agent == IpAddr::V4(Ipv4Addr::new(10, 222, 3, 8))));
    }

    #[test]
    fn decodes_agent_address_v6() {
        let dg = build_test_datagram_v6_agent([0x2a, 0x12, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8]);
        let obs = decode_datagram(&dg).unwrap();
        assert!(!obs.is_empty());
        assert!(obs.iter().all(|o| matches!(o.agent, IpAddr::V6(_))));
    }
```
If the existing test datagram builder is inline in a single test, refactor it into `build_test_datagram_v4_agent(agent: [u8;4]) -> Vec<u8>` (and a v6 variant) so it's reusable. `use std::net::Ipv4Addr;` in the test module.

- [ ] **Step 3: Run to verify it fails**

```bash
cd /home/zoa/projects/femboy/blackwall/blackwall-telemetry-wt
cargo test -p blackwall-flow decodes_agent 2>&1 | grep -E "test result|error\[|cannot find|missing field"
```
Expected: FAIL (`missing field agent` in `FlowObservation` literals, and/or the new asserts fail).

- [ ] **Step 4: Decode the agent address in `decode_datagram` and thread it**

In `sflow.rs::decode_datagram`, replace the skip at lines ~70–80:
```rust
    let agent_addr_type = cur.read_u32()?;
    let agent: IpAddr = match agent_addr_type {
        1 => {
            let b = cur.take(4)?;
            IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3]))
        }
        2 => {
            let b = cur.take(16)?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(b);
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        t => {
            return Err(FlowError::Decode(format!(
                "unknown sFlow agent address type {t}"
            )))
        }
    };
```
Add `use std::net::{Ipv4Addr, Ipv6Addr};` to the file imports (IpAddr is already used).

Thread `agent` to the sample decoders: change
`decode_flow_sample(sample_body, &mut observations)?` → `decode_flow_sample(sample_body, agent, &mut observations)?`
and likewise `decode_expanded_flow_sample(sample_body, agent, &mut observations)?`.

Update both fn signatures to take `agent: IpAddr` and pass it to `decode_raw_header_record(record_body, sampling_rate, agent)`. Update `decode_raw_header_record` to take `agent: IpAddr` and set it in the `FlowObservation { … }` literal (add `agent,`).

- [ ] **Step 5: Fix any other `FlowObservation { … }` literals**

Grep for construction sites that now miss the field:
```bash
grep -rn "FlowObservation {" crates/blackwall-flow/src | grep -v "pub struct"
```
Add `agent: <IpAddr>` to each (in tests use e.g. `agent: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))`). The detector's tests construct `FlowObservation` — update those too (Task 3 will rely on `agent`).

- [ ] **Step 6: Run tests + commit**

```bash
cargo test -p blackwall-flow 2>&1 | grep -E "test result|error\["
cargo clippy -p blackwall-flow --all-targets -- --deny warnings 2>&1 | grep -E "warning|error" | head
cargo fmt --all
git add crates/blackwall-flow
git commit -m "feat(flow): extract sFlow agent address into FlowObservation.agent"
```
Expected: all pass, agent tests green.

---

### Task 2: `pop` config directive + `AgentRegistry`

**Files:**
- Create: `crates/blackwall-core/src/pop.rs`
- Modify: `crates/blackwall-core/src/lib.rs`, `crates/blackwall-core/src/policy.rs`, `crates/blackwall-core/src/resolve.rs`
- Modify: `crates/blackwall-config/src/parser.rs`
- Create: `crates/blackwall-flow/src/agents.rs`
- Modify: `crates/blackwall-flow/src/lib.rs`

**Interfaces:**
- Produces:
  - `blackwall_core::PopEntry { pub name: String, pub agent: IpAddr, pub sampling: u32 }`.
  - `Policy.pops: Vec<PopEntry>` (empty default).
  - `blackwall_flow::AgentRegistry` with `pub fn from_entries(entries: &[blackwall_core::PopEntry]) -> Self`, `pub fn name(&self, agent: IpAddr) -> &str` (returns `"unknown"` if absent), `pub fn expected_sampling(&self, agent: IpAddr) -> Option<u32>`.

- [ ] **Step 1: Define `PopEntry` in `blackwall-core`**

Create `crates/blackwall-core/src/pop.rs`:
```rust
//! POP-map entries (`pop` directive): map an sFlow agent address to a human POP
//! name and its expected sampling rate.

use std::net::IpAddr;

/// One POP: its sFlow agent address, display name, and configured 1-in-N
/// sampling rate (used to name detections' contributing POPs and to sanity-check
/// the rate each agent reports).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PopEntry {
    /// Human POP name, e.g. `"ord"`.
    pub name: String,
    /// The sFlow agent address the POP's hsflowd stamps on its datagrams.
    pub agent: IpAddr,
    /// Configured 1-in-N sampling rate for this POP.
    pub sampling: u32,
}
```
In `crates/blackwall-core/src/lib.rs`, add `mod pop;` and `pub use pop::PopEntry;` (match how other types are re-exported).

- [ ] **Step 2: Add `Policy.pops` and default it**

In `policy.rs`, after `pub api: Option<crate::ApiConfig>,` (or near the other optional config fields) add:
```rust
    /// POP-map for anycast telemetry (`pop` directives); empty disables POP
    /// naming/sanity (all agents tag as `"unknown"`).
    pub pops: Vec<crate::PopEntry>,
```
In `resolve.rs`, at each `Policy { … }` construction site (grep `metrics_listen:` to find them), add `pops: Vec::new(),`.

- [ ] **Step 3: Write the failing parser test**

In `crates/blackwall-config/src/parser.rs` `mod tests`:
```rust
    #[test]
    fn parses_pop_directive() {
        let p = parse_text(
            "interface wan eth0\npop ord agent=10.222.3.8 sampling=1000\npop fra agent=10.222.4.8 sampling=500\n",
        )
        .unwrap();
        assert_eq!(p.pops.len(), 2);
        assert_eq!(p.pops[0].name, "ord");
        assert_eq!(p.pops[0].agent, "10.222.3.8".parse::<std::net::IpAddr>().unwrap());
        assert_eq!(p.pops[0].sampling, 1000);
        assert_eq!(p.pops[1].name, "fra");
    }

    #[test]
    fn pop_requires_agent_and_sampling() {
        assert!(parse_text("interface wan eth0\npop ord agent=10.222.3.8\n").is_err());
        assert!(parse_text("interface wan eth0\npop ord sampling=1000\n").is_err());
    }
```

- [ ] **Step 4: Run to verify it fails**

```bash
cargo test -p blackwall-config parses_pop_directive 2>&1 | grep -E "test result|error\[|no field"
```
Expected: FAIL (field `pops` missing / arm not handled).

- [ ] **Step 5: Implement the `pop` parser arm**

Near the top of the parse fn add `let mut pops: Vec<blackwall_core::PopEntry> = Vec::new();`. Add the directive arm (mirror the `metrics`/`api` arms; the first word after `pop` is the NAME, then `key=value` tokens):
```rust
            "pop" => {
                let name = line.words.get(1).ok_or(ConfigError::BadValue {
                    line: line.number,
                    what: "pop name",
                    value: String::new(),
                })?;
                let mut agent: Option<std::net::IpAddr> = None;
                let mut sampling: Option<u32> = None;
                for tok in &line.words[2..] {
                    let (k, v) = tok.split_once('=').ok_or_else(|| ConfigError::BadValue {
                        line: line.number,
                        what: "pop",
                        value: tok.as_str().to_owned(),
                    })?;
                    match k {
                        "agent" => {
                            agent = Some(v.parse().map_err(|_| ConfigError::BadValue {
                                line: line.number,
                                what: "pop agent",
                                value: v.to_owned(),
                            })?);
                        }
                        "sampling" => {
                            sampling = Some(v.parse().map_err(|_| ConfigError::BadValue {
                                line: line.number,
                                what: "pop sampling",
                                value: v.to_owned(),
                            })?);
                        }
                        _ => {
                            return Err(ConfigError::BadValue {
                                line: line.number,
                                what: "pop key",
                                value: k.to_owned(),
                            });
                        }
                    }
                }
                let agent = agent.ok_or(ConfigError::BadValue {
                    line: line.number,
                    what: "pop missing agent",
                    value: name.as_str().to_owned(),
                })?;
                let sampling = sampling.ok_or(ConfigError::BadValue {
                    line: line.number,
                    what: "pop missing sampling",
                    value: name.as_str().to_owned(),
                })?;
                pops.push(blackwall_core::PopEntry { name: name.as_str().to_owned(), agent, sampling });
            }
```
(Confirm `ConfigError::BadValue { line, what, value }` is the right variant — check `blackwall-config/src/error.rs`; it is the same one the `metrics`/`api` arms use.) Add `pops,` to the returned `Policy { … }` literal.

- [ ] **Step 6: Create `AgentRegistry` in `blackwall-flow`**

Create `crates/blackwall-flow/src/agents.rs`:
```rust
//! Maps sFlow agent addresses to POP names + expected sampling rates, built
//! from the `pop` config directives.

use std::collections::HashMap;
use std::net::IpAddr;

/// What the collector knows about one POP agent.
#[derive(Debug, Clone)]
struct AgentInfo {
    name: String,
    expected_sampling: u32,
}

/// Registry of known POP agents. Absent agents are `"unknown"` with no expected
/// rate (trusted as-is, counted separately).
#[derive(Debug, Clone, Default)]
pub struct AgentRegistry {
    by_addr: HashMap<IpAddr, AgentInfo>,
}

impl AgentRegistry {
    /// Build from the policy's `pop` entries.
    pub fn from_entries(entries: &[blackwall_core::PopEntry]) -> Self {
        let mut by_addr = HashMap::new();
        for e in entries {
            by_addr.insert(
                e.agent,
                AgentInfo { name: e.name.clone(), expected_sampling: e.sampling },
            );
        }
        Self { by_addr }
    }

    /// The POP name for an agent, or `"unknown"`.
    pub fn name(&self, agent: IpAddr) -> &str {
        self.by_addr.get(&agent).map_or("unknown", |i| i.name.as_str())
    }

    /// The configured expected sampling rate for an agent, if known.
    pub fn expected_sampling(&self, agent: IpAddr) -> Option<u32> {
        self.by_addr.get(&agent).map(|i| i.expected_sampling)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn a(o: u8) -> IpAddr { IpAddr::V4(Ipv4Addr::new(10, 0, 0, o)) }

    #[test]
    fn names_known_and_unknown_agents() {
        let reg = AgentRegistry::from_entries(&[blackwall_core::PopEntry {
            name: "ord".into(),
            agent: a(8),
            sampling: 1000,
        }]);
        assert_eq!(reg.name(a(8)), "ord");
        assert_eq!(reg.expected_sampling(a(8)), Some(1000));
        assert_eq!(reg.name(a(9)), "unknown");
        assert_eq!(reg.expected_sampling(a(9)), None);
    }
}
```
Add `pub mod agents;` + `pub use agents::AgentRegistry;` to `crates/blackwall-flow/src/lib.rs`. Add `blackwall-core = { path = "../blackwall-core" }` to `blackwall-flow/Cargo.toml` if not already a dep (check first — it likely is).

- [ ] **Step 7: Fix Policy literals across the workspace + run**

```bash
grep -rn "Policy {" crates bin | grep -v "RtbhPolicy\|FlowSpecPolicy\|struct Policy"
```
Add `pops: Vec::new(),` to each literal that spells fields explicitly (mirrors how `api: None` was added for A·M4). Then:
```bash
cargo test -p blackwall-core -p blackwall-config -p blackwall-flow 2>&1 | grep -E "test result|error\["
cargo build --workspace 2>&1 | grep -E "error\[|Finished" | tail -1
cargo fmt --all
git add crates
git commit -m "feat(config): pop directive + AgentRegistry (agent→POP name + sampling)"
```
Expected: workspace builds, new tests pass.

---

### Task 3: Detector — `Sample.agent`, per-agent liveness, sampling sanity

**Files:**
- Modify: `crates/blackwall-flow/src/detector.rs`

**Interfaces:**
- Consumes: `FlowObservation.agent` (Task 1), `AgentRegistry` (Task 2).
- Produces:
  - `ThresholdDetector::new(...)` gains a trailing `agents: AgentRegistry` parameter.
  - `pub fn agent_last_seen(&self) -> &std::collections::HashMap<IpAddr, u64>` (for liveness metrics).
  - `Sample` gains `agent: IpAddr` (private).

- [ ] **Step 1: Write failing tests for sampling-sanity clamp + liveness**

In `detector.rs` `mod tests`:
```rust
    #[test]
    fn clamps_rogue_agent_sampling_to_expected() {
        // A rogue agent reporting 1-in-1 (expected 1-in-1000) must be clamped to
        // 1000, so its observed volume equals what a correctly-configured agent
        // reporting 1-in-1000 would produce — NOT the ~1000x-inflated rogue value.
        // Assert equality against a control detector fed the honest rate.
        let window_ms = 1_000; // 1s window so bps math is a clean divisor.
        let mk = || ThresholdDetector::new(
            vec!["203.0.113.0/24".parse().unwrap()],
            1.0, 1.0, window_ms, 30_000,
            AgentRegistry::from_entries(&[blackwall_core::PopEntry {
                name: "ord".into(), agent: agent_ip(8), sampling: 1000,
            }]),
        );
        // Rogue: claims sampling_rate=1; honest control: claims 1000.
        let mut rogue = mk();
        rogue.observe(&obs(agent_ip(8), "198.51.100.5", "203.0.113.9", 1, 100), 500);
        let rogue_d = rogue.tick(1_000).into_iter().find_map(|e| match e {
            DetectionEvent::Opened(d) => Some(d), _ => None }).expect("rogue opened");

        let mut honest = mk();
        honest.observe(&obs(agent_ip(8), "198.51.100.5", "203.0.113.9", 1000, 100), 500);
        let honest_d = honest.tick(1_000).into_iter().find_map(|e| match e {
            DetectionEvent::Opened(d) => Some(d), _ => None }).expect("honest opened");

        // Clamp makes the rogue volume identical to the honest-rate volume.
        assert_eq!(rogue_d.observed_bps, honest_d.observed_bps);
        assert_eq!(rogue_d.observed_pps, honest_d.observed_pps);
    }

    #[test]
    fn tracks_agent_last_seen() {
        let reg = AgentRegistry::from_entries(&[blackwall_core::PopEntry{
            name:"ord".into(), agent: agent_ip(8), sampling: 1000}]);
        let mut det = ThresholdDetector::new(
            vec!["203.0.113.0/24".parse().unwrap()], 1.0, 1.0, 10_000, 30_000, reg);
        det.observe(&obs(agent_ip(8), "198.51.100.5", "203.0.113.9", 1000, 100), 5_000);
        assert_eq!(det.agent_last_seen().get(&agent_ip(8)), Some(&5_000));
    }
```
Add helpers to the test module if absent:
```rust
    fn agent_ip(o: u8) -> std::net::IpAddr { std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 222, 0, o)) }
    fn obs(agent: std::net::IpAddr, src: &str, dst: &str, rate: u32, frame: u32) -> FlowObservation {
        FlowObservation {
            src: src.parse().unwrap(), dst: dst.parse().unwrap(), proto: 17,
            src_port: 1234, dst_port: 53, frame_len: frame, sampling_rate: rate,
            tcp_flags: 0, agent,
        }
    }
```
`use blackwall_core::PopEntry;` / `use crate::agents::AgentRegistry;` in the test module.

- [ ] **Step 2: Run to verify it fails**

```bash
cargo test -p blackwall-flow tracks_agent_last_seen 2>&1 | grep -E "test result|error\[|arguments"
```
Expected: FAIL (`ThresholdDetector::new` arity / no `agent_last_seen`).

- [ ] **Step 3: Add the fields + constructor param + observe logic**

In `detector.rs`: add `agent: IpAddr` to `struct Sample`. Add to `ThresholdDetector`:
```rust
    agents: crate::agents::AgentRegistry,
    agent_last_seen: HashMap<IpAddr, u64>,
```
Extend `ThresholdDetector::new(prefixes, pps_threshold, bps_threshold, window_ms, hold_down_ms, agents: AgentRegistry)` — set `agents`, `agent_last_seen: HashMap::new()`. Add the accessor:
```rust
    /// Last-seen timestamp (ms) per agent, for liveness monitoring.
    pub fn agent_last_seen(&self) -> &HashMap<IpAddr, u64> {
        &self.agent_last_seen
    }
```
In `observe`, before computing `est_*`, record liveness and apply sampling sanity:
```rust
        self.agent_last_seen.insert(obs.agent, now_ms);

        // Sampling sanity: clamp an agent whose reported rate deviates far from
        // its configured expected rate (guards volume math + collector against a
        // misconfigured POP). Unknown agents are trusted as-is.
        let effective_rate = match self.agents.expected_sampling(obs.agent) {
            Some(expected) => {
                let lo = expected / 4;
                let hi = expected.saturating_mul(4);
                if obs.sampling_rate < lo || obs.sampling_rate > hi {
                    expected
                } else {
                    obs.sampling_rate
                }
            }
            None => obs.sampling_rate,
        };
        let est_packets = u64::from(effective_rate);
        let est_bytes = u64::from(effective_rate) * u64::from(obs.frame_len);
```
Add `agent: obs.agent,` to the `Sample { … }` literal in `observe`.

- [ ] **Step 4: Run tests to verify they pass**

```bash
cargo test -p blackwall-flow 2>&1 | grep -E "test result|error\["
```
Expected: liveness + clamp tests pass. (Existing detector tests that call `ThresholdDetector::new` now need the extra `AgentRegistry::default()` arg — update them; grep `ThresholdDetector::new` in tests.)

- [ ] **Step 5: Commit**

```bash
cargo clippy -p blackwall-flow --all-targets -- --deny warnings 2>&1 | grep -E "warning|error" | head
cargo fmt --all
git add crates/blackwall-flow
git commit -m "feat(flow): per-agent liveness + sampling-sanity clamp in detector"
```

---

### Task 4: Detector — `Detection.pops` (per-POP tagging) + `top_source_blocks` (/24-/48 rollup)

**Files:**
- Modify: `crates/blackwall-flow/src/detector.rs`

**Interfaces:**
- Consumes: `Sample.agent` (Task 3), `AgentRegistry` (Task 2), `build_detection`/`DetectionParams`.
- Produces: `Detection` gains `pub pops: Vec<PopContribution>` and `pub top_source_blocks: Vec<(ipnet::IpNet, f64)>`; new public `PopContribution { pub pop: String, pub est_pps: f64, pub est_bps: f64 }`.

- [ ] **Step 1: Write the failing test — two POPs on one victim, and /24 rollup**

```rust
    #[test]
    fn detection_tags_contributing_pops_and_source_blocks() {
        let reg = AgentRegistry::from_entries(&[
            blackwall_core::PopEntry { name: "ord".into(), agent: agent_ip(8), sampling: 1 },
            blackwall_core::PopEntry { name: "fra".into(), agent: agent_ip(9), sampling: 1 },
        ]);
        let mut det = ThresholdDetector::new(
            vec!["203.0.113.0/24".parse().unwrap()], 1.0, 1.0, 10_000, 30_000, reg);
        // Two POPs each see traffic to the same victim from the same /24.
        det.observe(&obs(agent_ip(8), "198.51.100.5", "203.0.113.9", 1, 100), 1_000);
        det.observe(&obs(agent_ip(9), "198.51.100.6", "203.0.113.9", 1, 100), 1_000);
        let ev = det.tick(1_000);
        let d = ev.iter().find_map(|e| match e {
            DetectionEvent::Opened(d) => Some(d), _ => None }).expect("opened");
        let names: Vec<&str> = d.pops.iter().map(|p| p.pop.as_str()).collect();
        assert!(names.contains(&"ord") && names.contains(&"fra"));
        // Both sources are in 198.51.100.0/24 → one rolled-up block.
        assert_eq!(d.top_source_blocks[0].0, "198.51.100.0/24".parse::<ipnet::IpNet>().unwrap());
    }
```

- [ ] **Step 2: Run to verify it fails**

```bash
cargo test -p blackwall-flow detection_tags_contributing_pops 2>&1 | grep -E "test result|error\[|no field"
```
Expected: FAIL (no `pops` / `top_source_blocks` field).

- [ ] **Step 3: Add the `Detection` fields + `PopContribution` type**

In `detector.rs` add:
```rust
/// One POP's contribution to a detection within the window.
#[derive(Debug, Clone, PartialEq)]
pub struct PopContribution {
    /// POP name (or `"unknown"`).
    pub pop: String,
    /// Estimated packets/s this POP contributed.
    pub est_pps: f64,
    /// Estimated bits/s this POP contributed.
    pub est_bps: f64,
}
```
Add to `Detection` (after `top_ports`):
```rust
    /// Per-POP contribution to this detection, by contributed PPS descending.
    pub pops: Vec<PopContribution>,
    /// Top attacker source blocks (/24 v4, /48 v6) by estimated PPS, descending.
    pub top_source_blocks: Vec<(ipnet::IpNet, f64)>,
```

- [ ] **Step 4: Compute them in `build_detection`**

`DetectionParams` needs the registry — add `agents: &'a crate::agents::AgentRegistry,` to the struct and pass `agents: &self.agents` at both `build_detection(DetectionParams { … })` call sites in `tick`.

In `build_detection`, after computing `top_sources`/`top_ports`, add (mirror their fold-then-sort style):
```rust
    // Per-POP contribution: sum est per agent, name via the registry.
    let mut pop_pkts: HashMap<IpAddr, (u128, u128)> = HashMap::new();
    for s in p.samples {
        let e = pop_pkts.entry(s.agent).or_insert((0, 0));
        e.0 = e.0.saturating_add(u128::from(s.est_packets));
        e.1 = e.1.saturating_add(u128::from(s.est_bytes));
    }
    let mut pops: Vec<PopContribution> = pop_pkts
        .into_iter()
        .map(|(agent, (pkts, bytes))| {
            #[expect(clippy::cast_precision_loss, reason = "u128 sums to f64 rate estimate")]
            let est_pps = pkts as f64 / p.window_secs;
            #[expect(clippy::cast_precision_loss, reason = "u128 sums to f64 rate estimate")]
            let est_bps = (bytes as f64) * 8.0 / p.window_secs;
            PopContribution { pop: p.agents.name(agent).to_owned(), est_pps, est_bps }
        })
        .collect();
    pops.sort_by(|a, b| b.est_pps.partial_cmp(&a.est_pps).unwrap_or(std::cmp::Ordering::Equal));

    // Source-block rollup: /24 for v4, /48 for v6.
    let mut block_pkts: HashMap<ipnet::IpNet, u128> = HashMap::new();
    for s in p.samples {
        let block = source_block(s.src);
        *block_pkts.entry(block).or_insert(0) = block_pkts
            .get(&block).copied().unwrap_or(0)
            .saturating_add(u128::from(s.est_packets));
    }
    let mut top_source_blocks: Vec<(ipnet::IpNet, f64)> = block_pkts
        .into_iter()
        .map(|(net, pkts)| {
            #[expect(clippy::cast_precision_loss, reason = "u128 sum to f64 rate estimate")]
            let pps = pkts as f64 / p.window_secs;
            (net, pps)
        })
        .collect();
    top_source_blocks.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    top_source_blocks.truncate(5);
```
Add `pops,` and `top_source_blocks,` to the returned `Detection { … }` literal. Add the helper:
```rust
/// The attacker source block for attribution: /24 for IPv4, /48 for IPv6.
fn source_block(src: IpAddr) -> ipnet::IpNet {
    match src {
        IpAddr::V4(v4) => ipnet::Ipv4Net::new(v4, 24)
            .map(|n| ipnet::IpNet::V4(n.trunc()))
            .unwrap_or_else(|_| ipnet::IpNet::V4(ipnet::Ipv4Net::new(v4, 32).unwrap())),
        IpAddr::V6(v6) => ipnet::Ipv6Net::new(v6, 48)
            .map(|n| ipnet::IpNet::V6(n.trunc()))
            .unwrap_or_else(|_| ipnet::IpNet::V6(ipnet::Ipv6Net::new(v6, 128).unwrap())),
    }
}
```
Ensure `ipnet` is imported (`use ipnet::IpNet;` or fully-qualified as above). Fix any `Detection { … }` literals in tests to include the two new fields.

- [ ] **Step 5: Run + commit**

```bash
cargo test -p blackwall-flow 2>&1 | grep -E "test result|error\["
cargo clippy -p blackwall-flow --all-targets -- --deny warnings 2>&1 | grep -E "warning|error" | head
cargo fmt --all
git add crates/blackwall-flow
git commit -m "feat(flow): tag detections with contributing POPs + top source blocks"
```

---

### Task 5: Wire `AgentRegistry` into `blackwalld flow` + per-agent metrics

**Files:**
- Modify: `bin/blackwalld/src/main.rs` (the `Command::Flow` path)
- Modify: `bin/blackwalld/src/metrics.rs` (or the flow metrics glue)

**Interfaces:**
- Consumes: `Policy.pops` (Task 2), `AgentRegistry::from_entries` (Task 2), `ThresholdDetector::new(..., agents)` (Task 3), `agent_last_seen()` (Task 3).

- [ ] **Step 1: Build the registry from config and pass to the detector**

In `main.rs` `Command::Flow`, after the policy is parsed (grep for where `ThresholdDetector::new` is constructed for the flow daemon), build the registry and pass it:
```rust
        let agents = blackwall_flow::AgentRegistry::from_entries(&policy.pops);
        let detector = ThresholdDetector::new(
            prefixes,
            pps_threshold,
            bps_threshold,
            window_secs.saturating_mul(1000),
            hold_down_secs.saturating_mul(1000),
            agents,
        );
```
(Match the exact existing argument expressions for prefixes/thresholds/window/hold-down at that call site.)

- [ ] **Step 2: Add per-agent metrics (coverage-excluded glue)**

Expose three metrics on the flow `/metrics` (follow the existing `blackwall-metrics` Metric pattern used by the flow daemon):
- `blackwall_flow_pop_last_seen_seconds{pop}` — gauge, from `detector.agent_last_seen()` (seconds since the ms timestamp, per POP name via the registry).
- `blackwall_flow_agent_sampling_mismatch_total{pop}` — counter; increment where the clamp fires. (Add a counter to `ThresholdDetector` incremented in `observe` when clamping, plus an accessor `pub fn sampling_mismatches(&self) -> &HashMap<IpAddr, u64>`; render it here. This is a small addition to Task 3's clamp branch — if not already added, add the counter now and a focused test that the counter increments on clamp.)
- `blackwall_flow_unknown_agent_datagrams_total` — counter; increment in the collector glue when `registry.name(agent) == "unknown"`, or track in the detector keyed on unknown agents.

Because this is I/O/glue, it stays coverage-excluded; the *counters* live in `detector.rs` (covered by a focused unit test), the *rendering* lives in glue.

- [ ] **Step 3: Build + manual check + commit**

```bash
cargo build -p blackwalld 2>&1 | grep -E "error\[|Finished" | tail -1
cargo test -p blackwall-flow sampling_mismatch 2>&1 | grep -E "test result|error\[" || true
cargo clippy --workspace --all-targets -- --deny warnings 2>&1 | grep -E "warning|error" | head
cargo fmt --all
git add bin/blackwalld crates/blackwall-flow
git commit -m "feat(flow): wire POP registry into flow daemon + per-agent metrics"
```

---

### Task 6: hsflowd config helper + deploy-contract docs

**Files:**
- Create/modify: a `blackwalld` subcommand or lib helper that renders hsflowd.conf from `Policy.pops`
- Modify: `docs/deployment.md`

**Interfaces:**
- Consumes: `Policy.pops` (Task 2), the lab's `render_hsflowd_conf(iface, collector_ip, collector_port, sampling)` pattern (promote/duplicate into a shipped location — do NOT depend `blackwalld` on `blackwall-lab`).

- [ ] **Step 1: Add a `render_hsflowd_conf` helper to a shipped crate**

Copy the byte-exact renderer (from `crates/blackwall-lab/src/render/hsflowd.rs`) into `blackwall-core` (or `blackwall-flow`) as `pub fn render_hsflowd_conf(iface: &str, collector_ip: &str, collector_port: u16, sampling: u32) -> String`, with the same unit test asserting the known-good output. (Keep the lab's copy; this is the shipped one — a small, deliberate duplication of a 6-line format string, justified by not coupling the daemon to the lab crate.)

- [ ] **Step 2: Add a CLI subcommand to emit per-POP configs**

Add `blackwalld sensor render-hsflowd --config <flow.conf> --collector <ip:port> --iface <dev>` that parses the config and prints, for each `PopEntry`, a commented block:
```rust
// for each pop: println!("# --- POP {name} (agent {agent}) ---");
//               println!("{}", render_hsflowd_conf(iface, collector_ip, collector_port, pop.sampling));
```
This is glue (coverage-excluded); the renderer it calls is unit-tested.

- [ ] **Step 3: Document the deploy contract**

In `docs/deployment.md`, add a "POP sensor (sFlow)" section: each POP runs hsflowd (`mod_pcap`) with `sampling=N`, `polling=0`, `collector { ip=<home flow IP> udpport=<port> }`, agent = the POP's mesh IP; sFlow v5/UDP reaches the home collector over the WG mesh; the `pop` directives in the flow config must list each agent IP + sampling; generate the per-POP hsflowd.conf with `blackwalld sensor render-hsflowd`.

- [ ] **Step 4: Run + commit**

```bash
cargo test -p blackwall-core render_hsflowd 2>&1 | grep -E "test result|error\[" || cargo test -p blackwall-flow render_hsflowd 2>&1 | grep -E "test result"
cargo clippy --workspace --all-targets -- --deny warnings 2>&1 | grep -E "warning|error" | head
cargo fmt --all
git add crates bin/blackwalld docs/deployment.md
git commit -m "feat(sensor): render hsflowd.conf from pop-map + document deploy contract"
```

---

## Final gate

```bash
cargo clippy --workspace --all-targets -- --deny warnings 2>&1 | grep -E "warning|error" | head
cargo fmt --all -- --check && echo FMT_OK
DATABASE_URL=postgres://blackwall:blackwall@localhost:5433/blackwall bash scripts/coverage.sh 2>&1 | tail -6
```
Expected: clippy clean, fmt ok, coverage ≥90% on `blackwall-flow` (`sflow.rs`/`detector.rs`/`agents.rs`) and the config additions.

## Definition of Done

- Every `FlowObservation` carries its POP `agent`; `pop` directives parse into `Policy.pops` → `AgentRegistry`.
- Detections tagged with contributing POPs + top source /24-/48 blocks.
- Per-agent liveness (`agent_last_seen`) + sampling-sanity clamp + the three metrics.
- `blackwalld sensor render-hsflowd` generates POP configs; deploy contract documented.
- Non-breaking: no `pop` block ⇒ behaves as today with `agent` populated, everything tagged `unknown`.
- clippy/fmt clean; coverage ≥90%; PR from `sp-telemetry-spec` merged on check-green.
