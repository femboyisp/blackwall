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
/// temp dir, the PID, and the source line number to guarantee a unique name
/// even when multiple test processes share the same PID namespace.
fn tempfile_config() -> (std::path::PathBuf, std::fs::File) {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "blackwall-cli-{}-{}.conf",
        std::process::id(),
        line!()
    ));
    let file = std::fs::File::create(&path).expect("create temp config");
    (path, file)
}
