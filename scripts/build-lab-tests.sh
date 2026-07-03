#!/usr/bin/env bash
#
# Build the lab interop-test binaries and expose each at a stable path
# (target/debug/lab-tests/<pkg>-<test>) so lab scenarios can run the pre-built
# binary DIRECTLY instead of `cargo test` inside the netns.
#
# Running `cargo test` as a scenario driver spawns a long-lived cargo process
# that holds the Cargo build-directory lock and a subprocess tree; in CI this
# intermittently wedged a gate until the job cap (blackwall#88). The lab only
# ever needs to *run* these already-built binaries, so we resolve their paths
# once (via `--no-run --message-format=json`) and symlink them under a stable
# directory the scenarios reference.
#
# Run this before running any lab gate locally, and it is invoked by the CI
# "Build the lab" step. Re-run it after changing an interop test (the symlink
# target is hash-suffixed and moves on rebuild).
set -euo pipefail
cd "$(dirname "$0")/.."

# (package, test-target) pairs used as lab scenario drivers. Keep in sync with
# the `target/debug/lab-tests/<pkg>-<test>` paths referenced by scenarios/*.kdl.
pairs=(
  "blackwall-bgp interop"
  "blackwall-bgp flowspec_interop"
  "blackwall-rtbh interop"
  "blackwall-flow interop"
  "blackwall-dns interop"
  "blackwall-shaper interop"
  "blackwall-deception interop"
)
# The C2b-1 FlowSpec auto gate ships its driver in blackwall-rtbh; include it
# only when present so this script works on branches before/after that lands.
if grep -rqs flowspec_auto_interop crates/blackwall-rtbh/tests/ 2>/dev/null; then
  pairs+=("blackwall-rtbh flowspec_auto_interop")
fi

mkdir -p target/debug/lab-tests
for pair in "${pairs[@]}"; do
  # shellcheck disable=SC2086
  set -- $pair
  pkg="$1"
  test="$2"
  bin=$(cargo test -p "$pkg" --test "$test" --no-run --message-format=json 2>/dev/null \
    | jq -r 'select(.executable != null and .target.name == "'"$test"'" and (.target.kind[]? == "test")) | .executable' \
    | tail -1)
  if [ -z "$bin" ] || [ ! -x "$bin" ]; then
    echo "error: could not resolve a built test binary for '$pkg --test $test'" >&2
    echo "       (is jq installed and the crate/test present?)" >&2
    exit 1
  fi
  ln -sfn "$bin" "target/debug/lab-tests/$pkg-$test"
  echo "lab-test: $pkg-$test -> $bin"
done
