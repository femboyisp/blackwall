//! Build script: compile the `blackwall-xdp-ebpf` crate to a
//! `bpfel-unknown-none` object and stage it at `$OUT_DIR/blackwall-xdp` so
//! `lib.rs` can embed it with `aya::include_bytes_aligned!`.
//!
//! This deliberately does **not** use `aya_build::build_ebpf`: that helper
//! resolves the eBPF crate with `cargo build --package <name>` from the parent
//! workspace context, which triggers a cargo feature-resolver panic when the
//! target package is an excluded path build-dependency of a large workspace.
//! Instead we invoke the pinned nightly toolchain directly against the eBPF
//! crate's own manifest (it is its own standalone workspace), mirroring the
//! flags `aya-build` would pass (`-Z build-std=core`, BTF/debuginfo, and the
//! `bpf_target_arch` cfg).

use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

const EBPF_PACKAGE: &str = "blackwall-xdp-ebpf";
const EBPF_MANIFEST: &str = "../blackwall-xdp-ebpf/Cargo.toml";
const EBPF_SRC: &str = "../blackwall-xdp-ebpf/src";
const COMMON_SRC: &str = "../blackwall-xdp-common/src";
const COMMON_MANIFEST: &str = "../blackwall-xdp-common/Cargo.toml";
const BIN_NAME: &str = "blackwall-xdp";
const BPF_TARGET: &str = "bpfel-unknown-none";
const TOOLCHAIN: &str = "nightly-2026-06-29";

fn main() {
    println!("cargo:rerun-if-changed={EBPF_SRC}");
    println!("cargo:rerun-if-changed={EBPF_MANIFEST}");
    // The eBPF program depends on blackwall-xdp-common for the shared map POD
    // types; without this, editing those types wouldn't re-run this build
    // script and would silently embed a stale object with a mismatched map ABI.
    println!("cargo:rerun-if-changed={COMMON_SRC}");
    println!("cargo:rerun-if-changed={COMMON_MANIFEST}");

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set by cargo"));
    let ebpf_target_dir = out_dir.join(EBPF_PACKAGE);

    // Under coverage instrumentation (`cargo llvm-cov`), `-C instrument-coverage`
    // propagates into the nested `-Z build-std` compile of the `bpfel-unknown-none`
    // eBPF crate, which then fails: the bpf target has no `profiler_builtins`.
    // The eBPF object is never *executed* under llvm-cov — the only code that
    // loads it (`dataplane.rs`) is coverage-excluded, and the root
    // `BPF_PROG_TEST_RUN` test is `#[ignore]` — so we skip the real eBPF build and
    // stage an empty placeholder purely so `include_bytes_aligned!` resolves.
    let rustflags_instrumented = ["CARGO_ENCODED_RUSTFLAGS", "RUSTFLAGS"].iter().any(|k| {
        env::var(k)
            .map(|v| v.contains("instrument-coverage"))
            .unwrap_or(false)
    });
    // `cargo llvm-cov` builds under `target/llvm-cov-target/...` and sets
    // `LLVM_PROFILE_FILE`; either is a reliable signal even when the coverage
    // rustflag reaches the child by a path we don't see here.
    let instrumented = rustflags_instrumented
        || env::var_os("LLVM_PROFILE_FILE").is_some()
        || out_dir.to_string_lossy().contains("llvm-cov-target");
    if instrumented {
        fs::write(out_dir.join(BIN_NAME), [])
            .expect("stage placeholder eBPF object under coverage");
        return;
    }

    let bpf_target_arch =
        env::var("CARGO_CFG_TARGET_ARCH").expect("CARGO_CFG_TARGET_ARCH is set by cargo");

    // Mirror the rustflags aya-build would set, unit-separated as cargo expects.
    let mut rustflags = OsString::new();
    for part in [
        format!("--cfg=bpf_target_arch=\"{bpf_target_arch}\""),
        "\u{1f}".to_owned(),
        "-Cdebuginfo=2".to_owned(),
        "\u{1f}".to_owned(),
        "-Clink-arg=--btf".to_owned(),
    ] {
        rustflags.push(part);
    }

    let mut cmd = Command::new("rustup");
    cmd.args(["run", TOOLCHAIN, "cargo", "build"])
        .args(["--manifest-path", EBPF_MANIFEST])
        .args(["-Z", "build-std=core"])
        .arg("--bins")
        .arg("--release")
        .args(["--target", BPF_TARGET])
        .arg("--target-dir")
        .arg(&ebpf_target_dir)
        .env("CARGO_ENCODED_RUSTFLAGS", rustflags)
        .env("CARGO_CFG_BPF_TARGET_ARCH", &bpf_target_arch);
    // The parent build sets these to route rustc through its own wrapper; the
    // nested nightly build must use its own rustc.
    cmd.env_remove("RUSTC");
    cmd.env_remove("RUSTC_WORKSPACE_WRAPPER");

    let status = cmd
        .status()
        .expect("failed to spawn nightly cargo for the eBPF build");
    assert!(status.success(), "eBPF build failed: {status}");

    let produced = ebpf_target_dir
        .join(BPF_TARGET)
        .join("release")
        .join(BIN_NAME);
    let embedded = out_dir.join(BIN_NAME);
    let _: u64 = fs::copy(&produced, &embedded).unwrap_or_else(|err| {
        panic!(
            "failed to stage eBPF object {} -> {}: {err}",
            produced.display(),
            embedded.display()
        )
    });
}
