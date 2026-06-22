#!/usr/bin/env bash
#
# Set the FRI parameters (log_blowup, num_queries) consistently across the Rust
# provers and the Aiken verifier. These three must agree or the on-chain proof
# fails to verify.
#
# Usage:
#   ./set_fri_params.sh <log_blowup> <num_queries>
#   ./set_fri_params.sh 4 42
#
set -euo pipefail

if [[ $# -ne 2 || ! "$1" =~ ^[0-9]+$ || ! "$2" =~ ^[0-9]+$ ]]; then
    echo "usage: $0 <log_blowup> <num_queries>   (both non-negative integers)" >&2
    exit 1
fi

LOG_BLOWUP="$1"
NUM_QUERIES="$2"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FILES=(
    "$ROOT/plonky3/src/export_proof.rs"
    "$ROOT/plonky3/src/export_batch_proof.rs"
    "$ROOT/aiken/lib/stark/params.ak"
)

for f in "${FILES[@]}"; do
    # `: [0-9]+` only matches the value assignments, never the `log_blowup: Int`
    # type declaration or the `log_blowup=2` comments.
    sed -i -E \
        -e "s/(log_blowup:[[:space:]]*)[0-9]+/\1${LOG_BLOWUP}/" \
        -e "s/(num_queries:[[:space:]]*)[0-9]+/\1${NUM_QUERIES}/" \
        "$f"
    echo "==> ${f#"$ROOT/"}"
    grep -nE "log_blowup:[[:space:]]*[0-9]|num_queries:[[:space:]]*[0-9]" "$f"
done

echo "==> set log_blowup=${LOG_BLOWUP}, num_queries=${NUM_QUERIES}"
