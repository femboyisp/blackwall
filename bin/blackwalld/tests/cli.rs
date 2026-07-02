//! Exercises `blackwalld render` end-to-end without a DB or root.

use std::io::Write;
use std::process::Command;

#[test]
fn render_prints_nft_json() {
    let mut cfg = tempfile_config();
    let path = cfg.0.clone();
    cfg.1
        .write_all(
            b"interface wan eth0\nipv4 203.0.113.0/24\ndefault deception\n\
              tenant acme {\n owns 203.0.113.5\n allow tcp 443 host\n}\n",
        )
        .expect("write config");
    cfg.1.flush().expect("flush");

    let bin = env!("CARGO_BIN_EXE_blackwalld");
    let out = Command::new(bin)
        .args(["render", "--config"])
        .arg(&path)
        .output()
        .expect("run blackwalld");

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("blackwall"), "missing table name: {stdout}");
    assert!(
        stdout.contains("\"table\""),
        "missing nftables JSON structure: {stdout}"
    );

    // Clean up the temp file now that assertions have passed.
    let _ = std::fs::remove_file(&path);
}

/// Create a temp file path + handle without an external crate: use the process
/// temp dir, the PID, and a monotonic counter to guarantee a unique name even
/// across multiple calls within the same test binary run concurrently (tests
/// run in parallel by default; a shared PID + a fixed `line!()` from inside
/// this helper is NOT enough — every caller would collide on the same path).
fn tempfile_config() -> (std::path::PathBuf, std::fs::File) {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut path = std::env::temp_dir();
    path.push(format!(
        "blackwall-cli-{}-{}.conf",
        std::process::id(),
        n
    ));
    let file = std::fs::File::create(&path).expect("create temp config");
    (path, file)
}

/// `rtbh add` on an IP outside the config's eligible prefixes must exit
/// non-zero *without* ever touching a database — no `DATABASE_URL` is set
/// for this test, so a DB-connect attempt would itself fail differently
/// (and prove the ordering: rejection first, connect second).
#[test]
fn rtbh_add_rejects_out_of_prefix() {
    let mut cfg = tempfile_config();
    let path = cfg.0.clone();
    cfg.1
        .write_all(
            b"interface wan eth0\nipv4 203.0.113.0/24\n\
              rtbh peer=10.0.0.2:179 local-as=214806 peer-as=214806 \
              router-id=10.222.255.1 next-hop-v4=10.222.255.99 max=8 hold-down=30s\n",
        )
        .expect("write config");
    cfg.1.flush().expect("flush");

    let bin = env!("CARGO_BIN_EXE_blackwalld");
    let out = Command::new(bin)
        .args(["rtbh", "add", "198.51.100.5", "--config"])
        .arg(&path)
        .env_remove("DATABASE_URL")
        .output()
        .expect("run blackwalld");

    assert!(
        !out.status.success(),
        "expected non-zero exit for an out-of-prefix rtbh add; stdout: {} stderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("outside") || stderr.contains("prefixes"),
        "expected an eligibility rejection message; stderr: {stderr}"
    );

    let _ = std::fs::remove_file(&path);
}

/// `rtbh --help` must succeed and list the `add`/`remove`/`list` subcommands
/// (a DB-free, config-free smoke test of the nested clap wiring).
#[test]
fn rtbh_help_lists_subcommands() {
    let bin = env!("CARGO_BIN_EXE_blackwalld");
    let out = Command::new(bin)
        .args(["rtbh", "--help"])
        .output()
        .expect("run blackwalld");

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("add"), "missing `add` subcommand: {stdout}");
    assert!(
        stdout.contains("remove"),
        "missing `remove` subcommand: {stdout}"
    );
    assert!(
        stdout.contains("list"),
        "missing `list` subcommand: {stdout}"
    );
}
