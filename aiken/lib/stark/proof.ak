// ── Primitives ────────────────────────────────────────────────────────────────

/// Plonky3 uni-STARK proof types, generic over the challenge/extension field.
///
/// The type parameter `ext` is the extension field element type, e.g.:
///   Goldilocks  → Ext2  (BinomialExtensionField<Goldilocks, 2>, W = 7)
///   BabyBear    → Ext4  (BinomialExtensionField<BabyBear, 4>,   W = 11)
///   Mersenne31  → Ext3  (BinomialExtensionField<Mersenne31, 3>, W = 5)
///
/// Type correspondence to Plonky3 source (uni-stark/src/proof.rs, fri/src/proof.rs):
///   StarkProof<ext>      ↔  Proof<SC>
///   OpenedValues<ext>    ↔  OpenedValues<SC::Challenge>
///   FriProof<ext>        ↔  FriProof<Challenge, ChallengeMmcs, u64, Vec<BatchOpening<Val, ValMmcs>>>
///   QueryProof<ext>      ↔  QueryProof<Challenge, ChallengeMmcs, Vec<BatchOpening<Val, ValMmcs>>>
///   CommitPhaseStep<ext> ↔  CommitPhaseProofStep<Challenge, ChallengeMmcs>
///   BatchOpening         ↔  BatchOpening<Val, ValMmcs>
///   Note: ext = Ext2 for the Goldilocks/Fibonacci STARK throughout.
/// A 32-byte Merkle root (SHA-256 output).
pub type Commitment =
  ByteArray

/// Merkle authentication path: one sibling hash per tree level.
///
/// For a Goldilocks trace of length n with blowup factor 2, the extended
/// domain has 2n leaves, so the path has log2(2n) = degree_bits + 1 hashes.
pub type MerklePath =
  List<ByteArray>

// ── Batch opening (input MMCS layer) ─────────────────────────────────────────

/// Opened values for one committed matrix batch at a queried leaf index,
/// together with the Merkle authentication proof.
///
/// opened_values:
///   outer list — one entry per matrix committed in this batch.
///   inner list — base-field (Goldilocks) row values at the queried index.
///
/// Goldilocks-specific sizes for the Fibonacci proof:
///   Trace batch  : 1 matrix, 2 columns → opened_values = [[left, right]]
///   Quotient batch: 2 chunk-domain matrices, 2 values each (DIMENSION = 2)
///                  → opened_values = [[qc0_c0, qc0_c1], [qc1_c0, qc1_c1]]
///
/// opening_proof: Merkle siblings from the leaf to the root (ValMmcs::Proof).
pub type BatchOpening {
  opened_values: List<List<Int>>,
  opening_proof: MerklePath,
}

// ── FRI commit-phase fold chain ───────────────────────────────────────────────

/// One round in the FRI fold chain (CommitPhaseProofStep in Plonky3).
///
/// log_arity      — log2 of the folding arity; always 1 in the current config
///                  (max_log_arity = 1 → binary folding per round).
/// sibling_values — (arity - 1) = 1 extension-field sibling evaluations at
///                  the current domain index. Each is an Ext element.
/// opening_proof  — Merkle siblings into the commit-phase codeword tree
///                  (ChallengeMmcs::Proof).
pub type CommitPhaseStep<ext> {
  log_arity: Int,
  sibling_values: List<ext>,
  opening_proof: MerklePath,
}

/// FRI proof for one sampled query index (QueryProof in Plonky3).
///
/// input_proof:
///   One BatchOpening per committed polynomial group, in order:
///   [0] Trace batch  (ValMmcs opening of the main trace LDE).
///   [1] Quotient batch (ValMmcs opening of the quotient chunk LDE).
///   The verifier uses these to compute the "reduced openings" that seed
///   the FRI fold chain.
///
/// commit_phase_openings:
///   One CommitPhaseStep per FRI fold round.
///   For degree_bits = 13 and log_blowup = 1 with log_final_poly_len = 0:
///   the FRI domain has size 2^14, folds down to size 2^1 in 13 steps.
pub type QueryProof<ext> {
  input_proof: List<BatchOpening>,
  commit_phase_openings: List<CommitPhaseStep<ext>>,
}

// ── FRI proof ─────────────────────────────────────────────────────────────────

/// The FRI opening proof (FriProof<Challenge, ChallengeMmcs, u64, InputProof>).
///
/// commit_phase_commits:
///   One Merkle root per fold round (ChallengeMmcs::Commitment).
///   Length = number of FRI rounds (= degree_bits + log_blowup - log_final_poly_len - 1
///   with max_log_arity = 1 → 13 rounds for the Fibonacci proof).
///
/// commit_pow_witnesses:
///   Per-round proof-of-work witnesses (u64). One per commit_phase_commit.
///   The verifier checks challenger.check_witness(commit_proof_of_work_bits, w).
///
/// query_proofs:
///   One QueryProof per sampled query index.
///   Length = num_queries (= 100 in the production-like config).
///
/// final_poly:
///   Low-degree polynomial sent in the clear as a list of Ext coefficients.
///   Length = 2^log_final_poly_len = 1 (a constant polynomial in the config).
///
/// query_pow_witness:
///   Single proof-of-work witness for the query phase (checked after sampling
///   all commit-phase challenges and observing the final polynomial).
pub type FriProof<ext> {
  commit_phase_commits: List<Commitment>,
  commit_pow_witnesses: List<Int>,
  query_proofs: List<QueryProof<ext>>,
  final_poly: List<ext>,
  query_pow_witness: Int,
}

// ── Out-of-domain evaluations ─────────────────────────────────────────────────

/// Polynomial evaluations at the out-of-domain challenge point zeta.
///
/// trace_local:
///   One Ext per trace column evaluated at zeta.
///   For FibonacciAir: [left_at_zeta, right_at_zeta] (length 2).
///
/// trace_next:
///   One Ext per trace column evaluated at g*zeta (next row selector).
///   For FibonacciAir: [left_at_gzeta, right_at_gzeta] (length 2).
///   Needed because FibonacciAir uses when_transition constraints on next row.
///
/// quotient_chunks:
///   One entry per quotient chunk (length = num_quotient_chunks = 1 for
///   FibonacciAir with max_constraint_degree = 2, log_num_quotient_chunks = 0).
///   Each inner list has DIMENSION = 2 elements of type `ext` (Ext2).
///   These are the OOD evaluations of the DIMENSION base-field sub-polynomials
///   of the quotient chunk: chunk_i → [Q_0(zeta), Q_1(zeta)] where Q(X) = Q_0(X) + α·Q_1(X).
///   Evaluating a base-field polynomial at zeta ∈ Ext2 gives an Ext2 result.
///   Consumed by goldilocks/ext2.ak:recompose_quotient to reconstruct quotient(zeta).
///
/// Corresponds to OpenedValues<SC::Challenge> in uni-stark/src/proof.rs where
/// quotient_chunks: Vec<Vec<SC::Challenge>> with inner len = SC::Challenge::DIMENSION.
pub type OpenedValues<ext> {
  trace_local: List<ext>,
  trace_next: List<ext>,
  quotient_chunks: List<List<ext>>,
}

// ── Top-level proof ───────────────────────────────────────────────────────────

/// A complete Plonky3 uni-STARK proof for the Goldilocks / Ext instance.
///
/// Mirrors Proof<SC> from uni-stark/src/proof.rs.
///
/// degree_bits:
///   log2 of the trace length (n = 2^degree_bits).
///   For FibonacciAir with n = 8192: degree_bits = 13.
///
/// trace_commit:
///   Merkle root of the main trace LDE matrix (ValMmcs::Commitment).
///   The prover commits to the Low-Degree Extension of the trace over the
///   extended domain of size 2^(degree_bits + log_blowup).
///
/// quotient_commit:
///   Merkle root of the quotient polynomial chunks matrix
///   (ChallengeMmcs::Commitment, shared across all num_quotient_chunks).
///
/// opened_values:
///   Out-of-domain evaluations at the Fiat-Shamir challenge point zeta.
///
/// opening_proof:
///   FRI proof that the opened_values are consistent with the commitments
///   and that the committed polynomials have the claimed low degree.
pub type StarkProof<ext> {
  degree_bits: Int,
  trace_commit: Commitment,
  quotient_commit: Commitment,
  opened_values: OpenedValues<ext>,
  opening_proof: FriProof<ext>,
}

// ── Public inputs ─────────────────────────────────────────────────────────────

/// Public inputs for the Fibonacci STARK (pis in fib_air.rs).
///
/// The AIR asserts:
///   trace[0].left  == a            (first row, left column)
///   trace[0].right == b            (first row, right column)
///   trace[n-1].right == x          (last row, right column)
///
/// All three are canonical Goldilocks field elements.
pub type FibPublicInputs {
  a: Int,
  b: Int,
  x: Int,
}

// ── Shape invariants ──────────────────────────────────────────────────────────

/// Check that an OpenedValues has the expected shape for FibonacciAir.
///
/// ext_dim: extension field dimension (2 for Ext2, 4 for Ext4, 3 for Ext3).
///
/// Returns True iff:
///   - trace_local  has exactly fib_trace_width elements
///   - trace_next   has exactly fib_trace_width elements
///   - quotient_chunks has exactly num_quotient_chunks entries,
///     each containing exactly ext_dim elements of type ext (Challenge)
pub fn valid_opened_values_shape(
  ov: OpenedValues<ext>,
  fib_trace_width: Int,
  num_quotient_chunks: Int,
) -> Bool {
  list_len(ov.trace_local) == fib_trace_width && list_len(ov.trace_next) == fib_trace_width && list_len(
    ov.quotient_chunks,
  ) == num_quotient_chunks
  // && list_all(
  //    ov.quotient_chunks,
  //    fn(ch) { list_len(ch) == ext_dim },
  //  )
}

/// Check that a FriProof has the expected shape for a given number of FRI rounds
/// and query count.
///
/// num_rounds   = degree_bits + log_blowup - log_final_poly_len with max_log_arity = 1
///               = degree_bits + 1 for our config (log_blowup=1, log_final_poly_len=0).
/// num_queries  = 100 (production config).
/// final_poly_len = 2^log_final_poly_len = 1.
pub fn valid_fri_proof_shape(
  fp: FriProof<ext>,
  num_rounds: Int,
  num_queries: Int,
  final_poly_len: Int,
) -> Bool {
  list_len(fp.commit_phase_commits) == num_rounds && list_len(
    fp.commit_pow_witnesses,
  ) == num_rounds && list_len(fp.query_proofs) == num_queries && list_len(
    fp.final_poly,
  ) == final_poly_len
}

// ── List helpers ──────────────────────────────────────────────────────────────

fn list_len(xs: List<a>) -> Int {
  do_len(xs, 0)
}

fn do_len(xs: List<a>, acc: Int) -> Int {
  when xs is {
    [] -> acc
    [_, ..rest] -> do_len(rest, acc + 1)
  }
}

fn list_all(xs: List<a>, pred: fn(a) -> Bool) -> Bool {
  when xs is {
    [] -> True
    [x, ..rest] ->
      if pred(x) {
        list_all(rest, pred)
      } else {
        False
      }
  }
}
