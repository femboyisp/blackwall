//! Validates `blackwall_bgp::render_bird_ibgp`'s output against **real BIRD2**
//! via `bird -p -c <file>` — a parse + config-check pass that does not start a
//! daemon or need root/netns. This is the renderer's #1 risk check: catching
//! syntactically- or semantically-invalid BIRD2 config before it ever reaches
//! a lab or production node.
//!
//! Skips cleanly (prints a message, does not fail) when `bird` isn't on
//! `PATH`, so it doesn't break `cargo test` on dev boxes without BIRD
//! installed. CI has `/usr/bin/bird` (BIRD 2.17.1), so it runs there.

use blackwall_bgp::render_bird_ibgp;
use blackwall_core::Policy;
use std::path::Path;
use std::process::Command;

/// `true` if a `bird` binary answers `--version` on `PATH`.
fn bird_on_path() -> bool {
    Command::new("bird")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Build a `Policy` by parsing a real config string, exercising the same
/// parse-to-render path the `render.rs` unit tests use.
fn policy_from(cfg: &str) -> Policy {
    blackwall_config::parse_str(cfg).expect("parse")
}

fn base_cfg() -> String {
    "interface wan eth0\n\
     ipv4 203.0.113.0/24\n\
     ipv6 2001:db8::/48\n\
     rtbh peer=10.0.0.2:179 local-as=65000 peer-as=65000 router-id=10.0.0.1 \
     next-hop-v4=192.0.2.1 next-hop-v6=2001:db8::1 max=256 hold-down=60s \
     local-addr=10.0.0.3\n"
        .to_string()
}

/// The minimal top-level `bird.conf` BIRD needs to parse-check a generated
/// include:
/// - a `router id` (BIRD wants one even for `-p`);
/// - at least one `protocol` block — BIRD refuses a config with none
///   (`"No protocol is specified in the config file"`), so a no-op
///   `protocol device {}` is added unconditionally;
/// - `flow4`/`flow6 table` declarations, only when the include uses those
///   channels — unlike `ipv4`/`ipv6` (which fall back to the built-in
///   `master4`/`master6` tables), BIRD has no default table for flowspec
///   AFIs and errors with `"Routing table not specified"` without one.
fn wrapper(snippet_path: &Path, needs_flow4: bool, needs_flow6: bool) -> String {
    let mut w = String::new();
    w.push_str("router id 10.0.0.1;\n");
    w.push_str("protocol device {}\n");
    if needs_flow4 {
        w.push_str("flow4 table flow4tab;\n");
    }
    if needs_flow6 {
        w.push_str("flow6 table flow6tab;\n");
    }
    w.push_str(&format!("include \"{}\";\n", snippet_path.display()));
    w
}

/// Write `snippet` (and any `extra_files` alongside it, e.g. a stub
/// `blackwall-secret.conf`) to a scratch dir, wrap it per [`wrapper`], and
/// assert `bird -p -c <wrapper>` exits `0` — i.e. real BIRD2 accepts the
/// generated config as valid. Prints BIRD's stderr on failure so a syntax
/// regression is easy to diagnose from `cargo test` output.
fn assert_bird_accepts(
    case: &str,
    snippet: &str,
    needs_flow4: bool,
    needs_flow6: bool,
    extra_files: &[(&str, &str)],
) {
    let dir = std::env::temp_dir().join(format!(
        "blackwall-bird-validate-{}-{case}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("mkdir scratch dir");

    let snippet_path = dir.join("blackwall.conf");
    std::fs::write(&snippet_path, snippet).expect("write snippet");
    for (name, contents) in extra_files {
        std::fs::write(dir.join(name), contents).expect("write extra file");
    }
    let wrapper_path = dir.join("bird.conf");
    std::fs::write(
        &wrapper_path,
        wrapper(&snippet_path, needs_flow4, needs_flow6),
    )
    .expect("write wrapper");

    let out = Command::new("bird")
        .args(["-p", "-c"])
        .arg(&wrapper_path)
        .output()
        .expect("run `bird -p`");

    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        out.status.success(),
        "bird -p rejected the generated config for `{case}`:\n{}\n--- generated include ---\n{snippet}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn full_session_v4_v6_no_auth_parses_under_real_bird() {
    if !bird_on_path() {
        eprintln!("`bird` not on PATH; skipping bird -p validation");
        return;
    }
    let out = render_bird_ibgp(&policy_from(&base_cfg())).expect("render");
    assert_bird_accepts("full-v4-v6", &out, true, true, &[]);
}

#[test]
fn v4_only_parses_under_real_bird() {
    if !bird_on_path() {
        eprintln!("`bird` not on PATH; skipping bird -p validation");
        return;
    }
    let cfg = "interface wan eth0\n\
         ipv4 203.0.113.0/24\n\
         rtbh peer=10.0.0.2:179 local-as=65000 peer-as=65000 router-id=10.0.0.1 \
         next-hop-v4=192.0.2.1 max=256 hold-down=60s local-addr=10.0.0.3\n";
    let out = render_bird_ibgp(&policy_from(cfg)).expect("render");
    assert_bird_accepts("v4-only", &out, true, false, &[]);
}

#[test]
fn v6_only_parses_under_real_bird() {
    if !bird_on_path() {
        eprintln!("`bird` not on PATH; skipping bird -p validation");
        return;
    }
    let cfg = "interface wan eth0\n\
         ipv6 2001:db8::/48\n\
         rtbh peer=[2001:db8::2]:179 local-as=65000 peer-as=65000 router-id=10.0.0.1 \
         next-hop-v6=2001:db8::1 max=256 hold-down=60s local-addr=2001:db8::9\n";
    let out = render_bird_ibgp(&policy_from(cfg)).expect("render");
    assert_bird_accepts("v6-only", &out, false, true, &[]);
}

#[test]
fn gtsm_session_parses_under_real_bird() {
    if !bird_on_path() {
        eprintln!("`bird` not on PATH; skipping bird -p validation");
        return;
    }
    let cfg = format!("{} gtsm-hops=1\n", base_cfg().trim_end());
    let out = render_bird_ibgp(&policy_from(&cfg)).expect("render");
    assert!(out.contains("ttl security on;"));
    assert_bird_accepts("gtsm", &out, true, true, &[]);
}

#[test]
fn md5_session_parses_under_real_bird_with_stub_secret() {
    if !bird_on_path() {
        eprintln!("`bird` not on PATH; skipping bird -p validation");
        return;
    }
    let cfg = format!("{} md5=s3cret\n", base_cfg().trim_end());
    let out = render_bird_ibgp(&policy_from(&cfg)).expect("render");
    assert!(out.contains("include \"blackwall-secret.conf\";"));
    // The real secret is never in the generated output (checked in
    // render.rs's own tests); here it only matters that BIRD accepts a
    // `password "...";` sourced from that include, at the point the
    // generated snippet places it inside `protocol bgp blackwall { ... }`.
    assert_bird_accepts(
        "md5",
        &out,
        true,
        true,
        &[(
            "blackwall-secret.conf",
            "password \"stub-not-the-real-secret\";\n",
        )],
    );
}

#[test]
fn defines_only_no_rtbh_parses_under_real_bird() {
    if !bird_on_path() {
        eprintln!("`bird` not on PATH; skipping bird -p validation");
        return;
    }
    let cfg = "interface wan eth0\nipv4 203.0.113.0/24\nipv6 2001:db8::/48\n";
    let out = render_bird_ibgp(&policy_from(cfg)).expect("render");
    assert!(!out.contains("protocol bgp blackwall"));
    assert_bird_accepts("defines-only", &out, false, false, &[]);
}
