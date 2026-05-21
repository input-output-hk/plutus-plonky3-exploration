use cardano/transaction.{OutputReference, Transaction}
use goldilocks/ext2.{Ext2}
use goldilocks/field as gf
use stark/challenger
use stark/params
use stark/proof.{
  FibPublicInputs, FriProof, QueryProof, StarkProof, valid_fri_proof_shape,
}
use stark/verifier.{stark_verify}

// ── Cardano validator ─────────────────────────────────────────────────────────

/// Cardano on-chain wrapper for the Fibonacci STARK verifier (Plonky3 / Goldilocks).
///
/// The core verification logic lives in lib/stark/verifier.ak so that it can
/// be imported by both this validator and by lib tests.
/// Cardano spending validator wrapping the Fibonacci STARK verifier.
///
/// Datum   : FibPublicInputs — the Fibonacci triple (a, b, x) locked on-chain.
/// Redeemer: StarkProof<Ext2> — the proof that the trace with (a, b, x) exists.
validator fib_verifier {
  spend(
    datum: Option<FibPublicInputs>,
    redeemer: StarkProof<Ext2>,
    _self: OutputReference,
    _ctx: Transaction,
  ) {
    expect Some(pis) = datum
    stark_verify(redeemer, pis)
  }

  else(_ctx) {
    False
  }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

test stark_verify_transcript_init_produces_valid_state() {
  // Smoke-test: running the transcript up through zeta sampling
  // should not crash and should produce a non-trivial challenger state.
  let dummy_commit =
    #"0000000000000000000000000000000000000000000000000000000000000001"
  let st = challenger.init()
  let st = challenger.observe_val(st, 13)
  let st = challenger.observe_val(st, 13)
  let st = challenger.observe_val(st, 0)
  let st = challenger.observe_commitment(st, dummy_commit)
  let st = challenger.observe_val(st, 1)
  let st = challenger.observe_val(st, 1)
  let st = challenger.observe_val(st, 2)
  let (_, st) = challenger.sample_ext(st)
  let st = challenger.observe_commitment(st, dummy_commit)
  let (zeta, _st) = challenger.sample_ext(st)
  // zeta should be a non-zero element (virtually certain for a fresh hash)
  zeta.c0 != 0 || zeta.c1 != 0
}

test zeta_next_uses_trace_generator() {
  // zeta_next = ext2.scale(zeta, g_{degree_bits}).
  // For degree_bits=13, g_13 = two_adic_generator(13).
  let g13 = gf.two_adic_generator(13)
  let zeta = Ext2 { c0: 2, c1: 3 }
  let zeta_next = ext2.scale(zeta, g13)
  // Verify: scale multiplies every component by the scalar.
  zeta_next.c0 == gf.mul(zeta.c0, g13) && zeta_next.c1 == gf.mul(zeta.c1, g13)
}

test shape_check_rejects_too_few_queries() {
  // A FriProof with 1 query proof instead of 100 must fail the shape check.
  let fp = proof_fri_stub(params.degree_bits)
  !valid_fri_proof_shape(
    fp,
    params.num_fri_rounds(params.degree_bits),
    params.fri_params.num_queries,
    params.final_poly_len,
  )
}

test shape_check_rejects_zero_fri_rounds() {
  // A FriProof with 0 commit rounds must fail because num_fri_rounds(13)=13.
  let fp =
    FriProof {
      commit_phase_commits: [],
      commit_pow_witnesses: [],
      query_proofs: [],
      final_poly: [],
      query_pow_witness: 0,
    }
  !valid_fri_proof_shape(fp, 13, 100, 1)
}

// Helper: build a stub FriProof with exactly 1 query proof and correct round count.
fn proof_fri_stub(db: Int) -> FriProof<Ext2> {
  FriProof {
    commit_phase_commits: list_replicate(
      params.num_fri_rounds(db),
      #"0000000000000000000000000000000000000000000000000000000000000000",
    ),
    commit_pow_witnesses: list_replicate(params.num_fri_rounds(db), 0),
    query_proofs: [QueryProof { input_proof: [], commit_phase_openings: [] }],
    final_poly: [Ext2 { c0: 0, c1: 0 }],
    query_pow_witness: 0,
  }
}

fn list_replicate(n: Int, x: a) -> List<a> {
  if n <= 0 {
    []
  } else {
    [x, ..list_replicate(n - 1, x)]
  }
}
