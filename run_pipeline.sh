#!/usr/bin/env bash
#
# Regenerate the on-chain Aiken test from a fresh Plonky3 proof and verify it.
#
# Usage:
#   ./run_pipeline.sh          # both pipelines (default)
#   ./run_pipeline.sh uni      # uni-stark
#   ./run_pipeline.sh batch    # batch-stark
#   ./run_pipeline.sh both     # run both pipelines
#   ./run_pipeline.sh check    # just verify the proof tests on-chain (no proof regen)
#
set -euo pipefail

# Resolve the repo root (directory holding this script) so paths work from anywhere.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLONKY3="$ROOT/plonky3"
AIKEN="$ROOT/aiken"

# Run `aiken check` for one module and print only aiken's own per-test result
# line (PASS/FAIL + mem/cpu). Aiken emits JSON when stdout isn't a TTY, so we run
# it under `script` to fake one and keep the pretty output. `-m` exits 0 even on
# an empty match (it only warns), so guard against that too.
aiken_check_module() {
    local module="$1"
    local out rc=0
    # Module-qualified pattern: match every test inside the module.
    out=$(cd "$AIKEN" && script -qec "aiken check -m '${module}.{..}'" /dev/null) || rc=$?
    if grep -qa "yielding no test scenarios" <<<"$out"; then
        echo "ERROR: no tests matched module '$module' — proof test did not run" >&2
        return 1
    fi
    # Print just the per-test result line(s): PASS/FAIL + [mem: ..., cpu: ...].
    grep -aE "mem:.*cpu:" <<<"$out"
    return $rc
}

run_uni() {
    echo "==> uni-stark: prove + export"
    (cd "$PLONKY3" && cargo run --release --bin export_proof proof.json)
    echo "==> uni-stark: convert to Aiken test"
    (cd "$PLONKY3" && python3 convert.py proof.json)
}

run_batch() {
    echo "==> batch-stark: prove + export"
    (cd "$PLONKY3" && cargo run --release --bin export_batch_proof batch_proof.json)
    echo "==> batch-stark: convert to Aiken test"
    (cd "$PLONKY3" && python3 convert.py batch_proof.json)
}

run_check() {
    echo "==> uni-stark: on-chain verify"
    aiken_check_module goldilocks_proof_test
    echo "==> batch-stark: on-chain verify"
    aiken_check_module goldilocks_batch_proof_test
}

case "${1:-both}" in
    uni)   run_uni;  aiken_check_module goldilocks_proof_test ;;
    batch) run_batch; aiken_check_module goldilocks_batch_proof_test ;;
    both)  run_uni; run_batch; run_check ;;
    check) run_check ;;
    *)     echo "usage: $0 [uni|batch|both|check]" >&2; exit 1 ;;
esac

echo "==> done"
