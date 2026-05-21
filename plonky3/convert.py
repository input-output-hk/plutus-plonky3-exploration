#!/usr/bin/env python3
"""
Convert a Plonky3 Goldilocks Fibonacci STARK proof (exported as JSON by
export_proof.rs) into an Aiken test file that hard-codes the proof and
calls stark_verify(proof, pis).

Usage (from the plonky3/ directory):
    cargo run --release --bin export_proof proof.json        # generate proof.json
    python3 convert.py proof.json                            # generate the Aiken test
"""

import json
import sys
import os

# ── JSON helper functions ──────────────────────────────────────────────────────

def bytes_to_hex(byte_list):
    """[0, 1, ..., 255] -> '#"0001...ff"'"""
    return '#"' + "".join(f"{b:02x}" for b in byte_list) + '"'

def merkle_cap_to_aiken(cap_obj):
    """
    MerkleCap { cap: Vec<[u8; 32]> } serialized as {"cap": [[b0,...,b31]]}.
    With cap_height=0 there is exactly 1 element; take cap[0].
    """
    cap = cap_obj["cap"]
    assert len(cap) == 1, f"Expected cap length 1, got {len(cap)}"
    return bytes_to_hex(cap[0])

def merkle_path_to_aiken(path, indent):
    """Vec<[u8; 32]> -> Aiken list of ByteArray literals."""
    ind = " " * indent
    if not path:
        return "[]"
    items = [bytes_to_hex(node) for node in path]
    inner = (",\n" + ind + "  ").join(items)
    return f"[\n{ind}  {inner},\n{ind}]"

def ext2_to_aiken(ext_obj):
    """
    BinomialExtensionField<Goldilocks, 2> serialized as
    {"value": [{"value": u64}, {"value": u64}]}.
    """
    v = ext_obj["value"]
    c0 = v[0]["value"]
    c1 = v[1]["value"]
    return f"Ext2 {{ c0: {c0}, c1: {c1} }}"

def ext2_list_to_aiken(lst, indent):
    """Vec<Ext2> -> Aiken list."""
    ind = " " * indent
    if not lst:
        return "[]"
    items = [ext2_to_aiken(e) for e in lst]
    inner = (",\n" + ind + "  ").join(items)
    return f"[\n{ind}  {inner},\n{ind}]"

def int_list_to_aiken(lst, indent):
    """Vec<u64> (base-field row values) -> Aiken list of Int."""
    ind = " " * indent
    if not lst:
        return "[]"
    inner = (", ").join(str(v) for v in lst)
    return f"[{inner}]"

def batch_opening_to_aiken(bo, indent):
    """
    BatchOpening { opened_values: Vec<Vec<Val>>, opening_proof: Vec<[u8;32]> }
    opened_values rows contain Goldilocks elements serialized as {"value": u64}.
    """
    ind = " " * indent
    # opened_values: outer = matrices, inner = row values
    # Each Goldilocks element: {"value": u64}
    ov_rows = []
    for row in bo["opened_values"]:
        vals = [str(elem["value"]) for elem in row]
        ov_rows.append(f"[{', '.join(vals)}]")
    ov_str = f"[\n{ind}      " + (",\n" + ind + "      ").join(ov_rows) + f",\n{ind}    ]"
    path_str = merkle_path_to_aiken(bo["opening_proof"], indent + 4)
    return (
        f"BatchOpening {{\n"
        f"{ind}    opened_values: {ov_str},\n"
        f"{ind}    opening_proof: {path_str},\n"
        f"{ind}  }}"
    )

def commit_phase_step_to_aiken(step, indent):
    """CommitPhaseStep { log_arity, sibling_values: Vec<Ext2>, opening_proof }"""
    ind = " " * indent
    log_arity = step["log_arity"]
    sibs = ext2_list_to_aiken(step["sibling_values"], indent + 4)
    path = merkle_path_to_aiken(step["opening_proof"], indent + 4)
    return (
        f"CommitPhaseStep {{\n"
        f"{ind}    log_arity: {log_arity},\n"
        f"{ind}    sibling_values: {sibs},\n"
        f"{ind}    opening_proof: {path},\n"
        f"{ind}  }}"
    )

def query_proof_to_aiken(qp, indent):
    """QueryProof { input_proof: Vec<BatchOpening>, commit_phase_openings: Vec<CommitPhaseStep> }"""
    ind = " " * indent
    ip_parts = [batch_opening_to_aiken(bo, indent + 2) for bo in qp["input_proof"]]
    ip_str = (
        f"[\n{ind}    "
        + (",\n" + ind + "    ").join(ip_parts)
        + f",\n{ind}  ]"
    )
    cp_parts = [commit_phase_step_to_aiken(s, indent + 2) for s in qp["commit_phase_openings"]]
    cp_str = (
        f"[\n{ind}    "
        + (",\n" + ind + "    ").join(cp_parts)
        + f",\n{ind}  ]"
    )
    return (
        f"QueryProof {{\n"
        f"{ind}    input_proof: {ip_str},\n"
        f"{ind}    commit_phase_openings: {cp_str},\n"
        f"{ind}  }}"
    )

# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 convert.py proof.json", file=sys.stderr)
        sys.exit(1)

    with open(sys.argv[1]) as f:
        proof = json.load(f)

    db = proof["degree_bits"]
    trace_commit  = merkle_cap_to_aiken(proof["commitments"]["trace"])
    quot_commit   = merkle_cap_to_aiken(proof["commitments"]["quotient_chunks"])

    ov = proof["opened_values"]
    trace_local = ext2_list_to_aiken(ov["trace_local"], 6)
    trace_next  = ext2_list_to_aiken(ov["trace_next"], 6)

    # quotient_chunks: Vec<Vec<Ext2>>
    qc_parts = [ext2_list_to_aiken(chunk, 8) for chunk in ov["quotient_chunks"]]
    quot_chunks = (
        "[\n        "
        + (",\n        ").join(qc_parts)
        + ",\n      ]"
    )

    op = proof["opening_proof"]

    # commit_phase_commits: Vec<MerkleCap>
    cpc_list = [merkle_cap_to_aiken(c) for c in op["commit_phase_commits"]]
    cpc_str = "[\n        " + ",\n        ".join(cpc_list) + ",\n      ]"

    # commit_pow_witnesses: Vec<u64>
    # JSON serialises Goldilocks field elements as {"value": u64}; unwrap them.
    cpw_list = [
        str(w["value"] if isinstance(w, dict) else w)
        for w in op["commit_pow_witnesses"]
    ]
    cpw_str = "[" + ", ".join(cpw_list) + "]"

    # final_poly: Vec<Ext2>
    final_poly_str = ext2_list_to_aiken(op["final_poly"], 6)

    # query_pow_witness may also be wrapped as {"value": u64}
    qpw_raw = op["query_pow_witness"]
    query_pow = qpw_raw["value"] if isinstance(qpw_raw, dict) else qpw_raw

    # query_proofs: Vec<QueryProof>  — 100 entries, each is large
    qp_parts = [query_proof_to_aiken(qp, 6) for qp in op["query_proofs"]]
    qp_str = (
        "[\n        "
        + (",\n        ").join(qp_parts)
        + ",\n      ]"
    )

    out = f"""\
/// Auto-generated by convert.py from proof.json.
/// DO NOT EDIT — regenerate with:
///   cargo run --bin export_proof proof.json
///   python3 convert.py proof.json

use goldilocks/ext2.{{Ext2}}
use stark/proof.{{BatchOpening, CommitPhaseStep, FibPublicInputs, FriProof, OpenedValues, QueryProof, StarkProof}}
use stark/verifier

// ── End-to-end test: real Goldilocks Fibonacci STARK proof ────────────────────

test stark_verify_goldilocks_real_proof() {{
  let proof =
    StarkProof {{
      degree_bits: {db},
      trace_commit: {trace_commit},
      quotient_commit: {quot_commit},
      opened_values: OpenedValues {{
        trace_local: {trace_local},
        trace_next: {trace_next},
        quotient_chunks: {quot_chunks},
      }},
      opening_proof: FriProof {{
        commit_phase_commits: {cpc_str},
        commit_pow_witnesses: {cpw_str},
        final_poly: {final_poly_str},
        query_pow_witness: {query_pow},
        query_proofs: {qp_str},
      }},
    }}
  let pis = FibPublicInputs {{ a: 0, b: 1, x: 7032041643746701607 }}
  verifier.stark_verify(proof, pis)
}}
"""

    out_path = os.path.join(
        os.path.dirname(sys.argv[1]),
        "../aiken/lib/stark/goldilocks_proof_test.ak"
    )
    out_path = os.path.normpath(out_path)
    with open(out_path, "w") as f:
        f.write(out)

    print(f"Written to {out_path}")
    print(f"  degree_bits          = {db}")
    print(f"  query_proofs         = {len(op['query_proofs'])}")
    print(f"  commit_phase_commits = {len(op['commit_phase_commits'])}")
    print(f"  final_poly           = {len(op['final_poly'])}")

if __name__ == "__main__":
    main()
