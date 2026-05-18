// ── Tests ─────────────────────────────────────────────────────────────────────

use goldilocks/ext2.{Ext2}
use stark/params.{fib_trace_width, num_quotient_chunks}
use stark/proof.{
  FriProof, OpenedValues, valid_fri_proof_shape, valid_opened_values_shape,
}

test valid_opened_values_shape_accepts_correct() {
  let ov =
    OpenedValues {
      trace_local: [Ext2 { c0: 1, c1: 2 }, Ext2 { c0: 3, c1: 4 }],
      trace_next: [Ext2 { c0: 5, c1: 6 }, Ext2 { c0: 7, c1: 8 }],
      quotient_chunks: [[Ext2 { c0: 11, c1: 12 }]],
    }
  valid_opened_values_shape(ov, fib_trace_width, num_quotient_chunks)
}

test valid_opened_values_shape_rejects_short_trace() {
  let ov =
    OpenedValues {
      trace_local: [Ext2 { c0: 1, c1: 2 }],
      trace_next: [Ext2 { c0: 5, c1: 6 }, Ext2 { c0: 7, c1: 8 }],
      quotient_chunks: [[Ext2 { c0: 11, c1: 12 }]],
    }
  !valid_opened_values_shape(ov, fib_trace_width, num_quotient_chunks)
}

test valid_opened_values_shape_rejects_wrong_chunk_count() {
  let ov =
    OpenedValues {
      trace_local: [Ext2 { c0: 1, c1: 2 }, Ext2 { c0: 3, c1: 4 }],
      trace_next: [Ext2 { c0: 5, c1: 6 }, Ext2 { c0: 7, c1: 8 }],
      quotient_chunks: [[Ext2 { c0: 11, c1: 12 }], [Ext2 { c0: 13, c1: 14 }]],
    }
  !valid_opened_values_shape(ov, fib_trace_width, num_quotient_chunks)
}

//test valid_opened_values_shape_rejects_wrong_chunk_width() {
//  let ov =
//    OpenedValues {
//      trace_local: [Ext2 { c0: 1, c1: 2 }, Ext2 { c0: 3, c1: 4 }],
//      trace_next: [Ext2 { c0: 5, c1: 6 }, Ext2 { c0: 7, c1: 8 }],
//      quotient_chunks: [[10, 11, 99], [12, 13]],
//    }
//  !valid_opened_values_shape(ov, fib_trace_width, num_quotient_chunks)
//}

test valid_fri_proof_shape_accepts_correct() {
  let fp =
    FriProof {
      commit_phase_commits: [#"aa", #"bb", #"cc"],
      commit_pow_witnesses: [0, 0, 0],
      query_proofs: [],
      final_poly: [Ext2 { c0: 1, c1: 0 }],
      query_pow_witness: 0,
    }
  valid_fri_proof_shape(fp, 3, 0, 1)
}

test fri_proof_shape_rejects_mismatched_rounds() {
  let fp =
    FriProof {
      commit_phase_commits: [#"aa", #"bb"],
      commit_pow_witnesses: [0, 0, 0],
      query_proofs: [],
      final_poly: [Ext2 { c0: 1, c1: 0 }],
      query_pow_witness: 0,
    }
  !valid_fri_proof_shape(fp, 3, 0, 1)
}
