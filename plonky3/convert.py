#!/usr/bin/env python3
"""
Convert a Plonky3 Goldilocks STARK proof (exported as JSON) into an Aiken test
file that hard-codes the proof and calls the verifier.

Two input shapes are auto-detected:
  - uni-stark (export_proof.rs):       top-level Proof object
      -> aiken/lib/stark/goldilocks_proof_test.ak, calls stark_verify(proof, pis)
  - batch-stark (export_batch_proof.rs): {"proof": BatchProof, "public_values": [...]}
      -> aiken/lib/stark/goldilocks_batch_proof_test.ak, calls stark_verify_batch(proof, pvs)

Usage (from the plonky3/ directory):
    cargo run --release --bin export_proof proof.json              # uni-stark
    python3 convert.py proof.json

    cargo run --release --bin export_batch_proof batch_proof.json  # batch-stark
    python3 convert.py batch_proof.json                                  # generate the Aiken test
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

def fri_proof_to_aiken(op):
    """FriProof { commit_phase_commits, commit_pow_witnesses, final_poly,
    query_pow_witness, query_proofs } -> Aiken literal (indented for nesting
    inside the proof record at depth 6)."""
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

    # query_proofs: Vec<QueryProof> — one entry per FRI query, each is large
    qp_parts = [query_proof_to_aiken(qp, 6) for qp in op["query_proofs"]]
    qp_str = (
        "[\n        "
        + (",\n        ").join(qp_parts)
        + ",\n      ]"
    )

    return (
        f"FriProof {{\n"
        f"        commit_phase_commits: {cpc_str},\n"
        f"        commit_pow_witnesses: {cpw_str},\n"
        f"        final_poly: {final_poly_str},\n"
        f"        query_pow_witness: {query_pow},\n"
        f"        query_proofs: {qp_str},\n"
        f"      }}"
    )

def write_output(out, out_name, src_path):
    out_path = os.path.join(
        os.path.dirname(src_path),
        f"../aiken/lib/stark/{out_name}"
    )
    out_path = os.path.normpath(out_path)
    with open(out_path, "w") as f:
        f.write(out)
    print(f"Written to {out_path}")

# ── Uni-stark (single FibonacciAir instance) ───────────────────────────────────

def convert_uni(proof, src_path):
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
    fri_str = fri_proof_to_aiken(op)

    out = f"""\
/// Auto-generated by convert.py from proof.json.
/// DO NOT EDIT — regenerate with:
///   cargo run --release --bin export_proof proof.json
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
      opening_proof: {fri_str},
    }}
  let pis = FibPublicInputs {{ a: 0, b: 1, x: 7032041643746701607 }}
  verifier.stark_verify(proof, pis)
}}
"""

    write_output(out, "goldilocks_proof_test.ak", src_path)
    print(f"  num_batched_polys    = {num_batched_polys(proof)}")
    print(f"  degree_bits          = {db}")
    print(f"  query_proofs         = {len(op['query_proofs'])}")
    print(f"  commit_phase_commits = {len(op['commit_phase_commits'])}")
    print(f"  final_poly           = {len(op['final_poly'])}")

# ── Batch-stark (MulAir + FibonacciAir, lookups off) ───────────────────────────

def _batched_polys_in(base):
    """
    Count (column, opening-point) pairs in one opened-values block:
      preprocessed (local + next, if present)
      + trace_local + trace_next                     (each opened at zeta, zeta*g)
      + sum over quotient chunks of chunk length     (chunk length == ext degree)
    """
    total = 0
    for key in ("preprocessed_local", "preprocessed_next", "trace_local", "trace_next"):
        total += len(base.get(key) or [])
    total += sum(len(chunk) for chunk in (base.get("quotient_chunks") or []))
    return total

def num_batched_polys(proof):
    """
    Count the (column, opening-point) pairs that get alpha-batched in the DEEP
    quotient. This is the `num_batched_polys` term fed to the proximity-gaps /
    list-decoding bound in security.py.

    Works for both proof shapes:
      - uni-stark: opened_values is one flat block.
      - batch-stark: opened_values.instances[].base_opened_values; summed over
        all instances.
    """
    ov = proof["opened_values"]
    if "instances" in ov:
        total = 0
        for inst in ov["instances"]:
            total += _batched_polys_in(inst["base_opened_values"])
            # Permutation (lookup) columns are alpha-batched too: each is opened
            # at zeta and zeta*g, so both lists count.
            total += len(inst.get("permutation_local") or [])
            total += len(inst.get("permutation_next") or [])
        return total
    return _batched_polys_in(ov)

def convert_batch(obj, src_path):
    proof = obj["proof"]
    pvs = obj["public_values"]

    # Milestone B scope: global LogUp lookups, but still no preprocessed and no
    # ZK. Fail loudly if the exporter starts producing those so this converter
    # is extended deliberately.
    coms = proof["commitments"]
    assert coms.get("random") is None, "ZK random commitment not supported yet"
    assert coms.get("permutation") is not None, \
        "expected a lookup permutation commitment (Milestone B); none found"

    db_list = proof["degree_bits"]
    db_str = "[" + ", ".join(str(d) for d in db_list) + "]"
    main_commit = merkle_cap_to_aiken(coms["main"])
    perm_commit = merkle_cap_to_aiken(coms["permutation"])
    quot_commit = merkle_cap_to_aiken(coms["quotient_chunks"])

    inst_parts = []
    for inst in proof["opened_values"]["instances"]:
        base = inst["base_opened_values"]
        assert base.get("preprocessed_local") is None, "preprocessed openings not supported yet"
        assert base.get("random") is None, "random openings not supported yet"

        trace_local = ext2_list_to_aiken(base["trace_local"], 10)
        # trace_next is Option<Vec<Ext2>>: None when the AIR never reads the next row.
        tn_raw = base["trace_next"]
        trace_next = ext2_list_to_aiken(tn_raw, 10) if tn_raw else "[]"
        # Permutation (running-sum) openings, base-flattened to aux_width * DIM.
        perm_local = ext2_list_to_aiken(inst["permutation_local"], 10)
        perm_next = ext2_list_to_aiken(inst["permutation_next"], 10)
        qc_parts = [ext2_list_to_aiken(chunk, 12) for chunk in base["quotient_chunks"]]
        quot_chunks = (
            "[\n            "
            + (",\n            ").join(qc_parts)
            + ",\n          ]"
        )
        inst_parts.append(
            f"InstanceOpenedValues {{\n"
            f"          trace_local: {trace_local},\n"
            f"          trace_next: {trace_next},\n"
            f"          permutation_local: {perm_local},\n"
            f"          permutation_next: {perm_next},\n"
            f"          quotient_chunks: {quot_chunks},\n"
            f"        }}"
        )
    ov_str = "[\n        " + ",\n        ".join(inst_parts) + ",\n      ]"

    # global_lookup_data: Vec<Vec<LookupData>> -> per-instance list of
    # expected_cumulated values, in registration order. Used both in the
    # transcript and in the per-lookup final running-sum constraint.
    gld = proof.get("global_lookup_data", [])
    ec_parts = [
        "[" + ", ".join(ext2_to_aiken(ld["expected_cumulated"]) for ld in inst_data) + "]"
        for inst_data in gld
    ]
    ec_str = "[" + ", ".join(ec_parts) + "]"

    # public_values: Vec<Vec<Goldilocks>> -> List<List<Int>>
    pv_parts = [
        "[" + ", ".join(str(v["value"] if isinstance(v, dict) else v) for v in pv) + "]"
        for pv in pvs
    ]
    pv_str = "[" + ", ".join(pv_parts) + "]"

    op = proof["opening_proof"]
    fri_str = fri_proof_to_aiken(op)

    out = f"""\
/// Auto-generated by convert.py from batch_proof.json.
/// DO NOT EDIT — regenerate with:
///   cargo run --release --bin export_batch_proof batch_proof.json
///   python3 convert.py batch_proof.json

use goldilocks/ext2.{{Ext2}}
use stark/proof.{{BatchOpening, BatchProof, CommitPhaseStep, FriProof, InstanceOpenedValues, QueryProof}}
use stark/verifier

// ── End-to-end test: real Goldilocks batch STARK proof (MulAir + FibonacciAir) ─

test stark_verify_batch_goldilocks_real_proof() {{
  let proof =
    BatchProof {{
      degree_bits: {db_str},
      main_commit: {main_commit},
      permutation_commit: {perm_commit},
      quotient_commit: {quot_commit},
      opened_values: {ov_str},
      expected_cumulated: {ec_str},
      opening_proof: {fri_str},
    }}
  let public_values = {pv_str}
  verifier.stark_verify_batch(proof, public_values)
}}
"""

    write_output(out, "goldilocks_batch_proof_test.ak", src_path)
    print(f"  instances            = {len(inst_parts)}")
    print(f"  num_batched_polys    = {num_batched_polys(proof)}")
    print(f"  global_lookups       = {[len(d) for d in gld]}")
    print(f"  degree_bits          = {db_list}")
    print(f"  query_proofs         = {len(op['query_proofs'])}")
    print(f"  commit_phase_commits = {len(op['commit_phase_commits'])}")
    print(f"  final_poly           = {len(op['final_poly'])}")

# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 convert.py proof.json", file=sys.stderr)
        sys.exit(1)

    with open(sys.argv[1]) as f:
        obj = json.load(f)

    if "batch" in os.path.basename(sys.argv[1]):
        convert_batch(obj, sys.argv[1])
    else:
        convert_uni(obj, sys.argv[1])

if __name__ == "__main__":
    main()
