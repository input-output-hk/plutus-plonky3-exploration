use aiken/primitive/string
use goldilocks/ext2.{Ext2}
use goldilocks/field as gf
use stark/mmcs
use stark/params
use stark/proof.{BatchOpening, CommitPhaseStep, OpenedValues}

// ── Constants ─────────────────────────────────────────────────────────────────

/// FRI verifier for the Plonky3 / Goldilocks STARK.
///
/// Mirrors the following Rust functions from fri/src/verifier.rs and
/// fri/src/two_adic_pcs.rs:
///
///   reverse_bits_len     – p3_util::reverse_bits_len
///   fold_row             – TwoAdicFriFolding::fold_row  (two_adic_pcs.rs:107)
///   open_input           – open_input  (verifier.rs:410)
///   verify_query         – verify_query (verifier.rs:273)
///   pcs_verify           – TwoAdicFriPcs::verify + verify_fri (verifier.rs:54)  [TODO]
///
/// FRI folding convention (TwoAdicFriFolding, binary arity):
///   Given evaluations [e0, e1] at points [-x, x] respectively, and challenge beta:
///     fold(e0, e1, x, beta) = (e0 + e1) / 2  +  beta * (e1 - e0) / (2 * x)
///
///   The two evaluation points for parent index k at log_folded_height h are:
///     x  = g_{h+1}^{reverse_bits_len(k, h)}
///     -x = x * g_1  (since g_1 = p-1 = -1)
///   After bit-reversal in fold_row, position 0 holds e_at_neg_x, position 1 holds e_at_x.
/// 2^{-1} mod p = (p + 1) / 2.
/// Goldilocks p = 2^64 - 2^32 + 1 (odd), so (p+1)/2 is an integer.
/// Satisfies: gf.mul(2, half) == 1.
const half: Int = 9223372034707292161

// ── A. Bit reversal ───────────────────────────────────────────────────────────

/// Reverse the `bits` least-significant bits of `n`.
///
/// Mirrors p3_util::reverse_bits_len(n: usize, bit_len: usize) -> usize.
///   = n.reverse_bits() >> (64 - bit_len)
///
/// Examples:
///   reverse_bits_len(1,  4) = 8    (0001 → 1000)
///   reverse_bits_len(6,  4) = 6    (0110 → 0110)
///   reverse_bits_len(1, 14) = 8192 (the MSB of a 14-bit integer)
pub fn reverse_bits_len(n: Int, bits: Int) -> Int {
  do_reverse_bits(n, bits, 0)
}

fn do_reverse_bits(n: Int, remaining: Int, acc: Int) -> Int {
  if remaining == 0 {
    acc
  } else {
    do_reverse_bits(n / 2, remaining - 1, acc * 2 + n % 2)
  }
}

// ── B. FRI fold (binary, TwoAdicFriFolding) ───────────────────────────────────

/// Fold two sibling FRI evaluations into the parent evaluation.
/// From TwoAdicFriFolding::fold_row (lines 107–129 of two_adic_pcs.rs which is same as fold_matrix for log_arity = 1):
///
/// Implements TwoAdicFriFolding::fold_row for log_arity = 1 (binary fold).
///
/// Arguments:
///   parent_index      – index in the FOLDED domain (after >>= 1).
///   log_folded_height – log2 of the folded domain size.
///   beta              – FRI folding challenge (Ext2).
///   e0                – evaluation at the POSITIVE point +x  (even storage index, position 0).
///   e1                – evaluation at the NEGATIVE point -x  (odd storage index, position 1).
///
/// The evaluation point x is:
///   x = two_adic_generator(log_folded_height + 1)^reverse_bits_len(parent_index, log_folded_height)
///
/// Plonky3 builds xs = [+x, -x] (shifted_powers then reverse_slice_index_bits, a no-op for arity=2),
/// so Lagrange interpolation through (+x, e0) and (-x, e1) gives:
///   result = (e0 + e1) / 2  +  beta * (e0 - e1) / (2 * x)
///
/// x is a power of a generator so it is never zero; the inverse always exists.
pub fn fold_row(
  parent_index: Int,
  log_folded_height: Int,
  beta: Ext2,
  // arity = 2^log_arity = 2
  e0: Ext2,
  e1: Ext2,
) -> Ext2 {
  // log_arity = 1
  let x =
    gf.pow(
      gf.two_adic_generator(log_folded_height + 1),
      reverse_bits_len(parent_index, log_folded_height),
    )
  let inv_x =
    when gf.inverse(x) is {
      None -> fail @"fold_row: x is zero"
      Some(v) -> v
    }
  // inv_2x = (2x)^{-1} = half * x^{-1}
  let inv_2x = gf.mul(half, inv_x)
  let sum_half = ext2.scale(ext2.add(e0, e1), half)
  let diff_scaled = ext2.scale(ext2.sub(e0, e1), inv_2x)
  ext2.add(sum_half, ext2.mul(beta, diff_scaled))
}

// ── C. Input-batch opening verifier ──────────────────────────────────────────

/// Verify Merkle batch proofs and compute the single reduced FRI opening for one query.
///
/// Mirrors open_input from fri/src/verifier.rs:410, specialised for the Fibonacci STARK:
///   - 2 batches: trace (1 matrix, 2 cols) and quotient (1 matrix, 2 cols, num_chunks=1)
///   - Both batches have log_height = log_global_max_height → reduced_index = index for both
///   - Evaluation point: x = Val::GENERATOR · g_n^{reverse_bits_len(index, n)}
///     where n = log_global_max_height and Val::GENERATOR = 7
///
/// Alpha-power ordering across the 6 (column, opening-point) pairs:
///   α^0 trace col 0 at ζ  |  α^2 trace col 0 at ζ_next  |  α^4 quot col 0 at ζ
///   α^1 trace col 1 at ζ  |  α^3 trace col 1 at ζ_next  |  α^5 quot col 1 at ζ
///
/// Returns None if any Merkle proof fails or a denominator (ζ - x) or (ζ_next - x) is zero.
pub fn open_input(
  index: Int,
  log_global_max_height: Int,
  alpha: Ext2,
  zeta: Ext2,
  zeta_next: Ext2,
  trace_opening: BatchOpening,
  quotient_opening: BatchOpening,
  trace_commit: ByteArray,
  quotient_commit: ByteArray,
  ov: OpenedValues<Ext2>,
) -> Option<Ext2> {
  // Each batch has exactly one matrix for the Fibonacci STARK.
  when
    (
      trace_opening.opened_values,
      quotient_opening.opened_values,
      ov.quotient_chunks,
    )
  is {
    ([trace_row, ..], [quot_row, ..], [quot_chunk, ..]) -> {
      // Step 1: Verify Merkle proofs.
      let trace_ok =
        mmcs.verify_batch(
          trace_commit,
          index,
          trace_row,
          trace_opening.opening_proof,
        )
      let quot_ok =
        mmcs.verify_batch(
          quotient_commit,
          index,
          quot_row,
          quotient_opening.opening_proof,
        )
      if !trace_ok || !quot_ok {
        None
      } else {
        // Step 2: LDE evaluation point.
        // x = 7 · g_n^{reverse_bits_len(index, n)}
        let x =
          gf.mul(
            gf.generator,
            gf.pow(
              gf.two_adic_generator(log_global_max_height),
              reverse_bits_len(index, log_global_max_height),
            ),
          )
        // Step 3: DEEP-polynomial denominators.
        let inv_z_x = ext2.inverse(ext2.sub_base(zeta, x))
        let inv_zn_x = ext2.inverse(ext2.sub_base(zeta_next, x))
        when (inv_z_x, inv_zn_x) is {
          (Some(inv_z), Some(inv_zn)) -> {
            // Step 4: Accumulate reduced opening ro over 6 DEEP-quotient terms.
            // Trace at ζ (α^0, α^1)
            let (ro0, ap0) =
              acc_cols(
                trace_row,
                ov.trace_local,
                inv_z,
                alpha,
                ext2.zero,
                ext2.one,
              )
            // Trace at ζ_next (α^2, α^3) — same row, different opening point
            let (ro1, ap1) =
              acc_cols(trace_row, ov.trace_next, inv_zn, alpha, ro0, ap0)
            // Quotient at ζ (α^4, α^5)
            let (ro2, _) =
              acc_cols(quot_row, quot_chunk, inv_z, alpha, ro1, ap1)
            Some(ro2)
          }
          _ -> None
        }
      }
    }
    _ -> None
  }
}

/// Accumulate DEEP-polynomial contributions for one matrix at one opening point.
///
/// Computes: for each column i,
///   ro      += alpha_pow · (ps_at_z[i] − ps_at_x[i]) · inv_denom
///   alpha_pow *= alpha
///
/// Mirrors the innermost loop of open_input in verifier.rs:493–501.
fn acc_cols(
  ps_at_x: List<Int>,
  ps_at_z: List<Ext2>,
  inv_denom: Ext2,
  alpha: Ext2,
  ro: Ext2,
  alpha_pow: Ext2,
) -> (Ext2, Ext2) {
  when (ps_at_x, ps_at_z) is {
    ([], []) -> (ro, alpha_pow)
    ([p_at_x, ..rest_row], [p_at_z, ..rest_ps]) -> {
      let diff = ext2.sub_base(p_at_z, p_at_x)
      let contrib = ext2.mul(alpha_pow, ext2.mul(diff, inv_denom))
      acc_cols(
        rest_row,
        rest_ps,
        inv_denom,
        alpha,
        ext2.add(ro, contrib),
        ext2.mul(alpha_pow, alpha),
      )
    }
    // Mismatched lengths — invalid proof shape; return as-is.
    _ -> (ro, alpha_pow)
  }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

// -- reverse_bits_len --

test rbl_zero() {
  reverse_bits_len(0, 4) == 0
}

test rbl_one_in_4_bits() {
  // 0001 → 1000 = 8
  reverse_bits_len(1, 4) == 8
}

test rbl_eight_in_4_bits() {
  // 1000 → 0001 = 1
  reverse_bits_len(8, 4) == 1
}

test rbl_six_in_4_bits() {
  // 0110 → 0110 = 6 (palindrome)
  reverse_bits_len(6, 4) == 6
}

test rbl_three_in_4_bits() {
  // 0011 → 1100 = 12
  reverse_bits_len(3, 4) == 12
}

test rbl_one_in_14_bits() {
  // 14-bit reversal of 1: MSB of 14-bit word = 2^13 = 8192
  reverse_bits_len(1, 14) == 8192
}

test rbl_roundtrip_4_bits() {
  // Reversing twice is identity.
  reverse_bits_len(reverse_bits_len(5, 4), 4) == 5
}

test rbl_roundtrip_14_bits() {
  reverse_bits_len(reverse_bits_len(1234, 14), 14) == 1234
}

// -- fold_row --

test half_is_inverse_of_2() {
  gf.mul(2, half) == 1
}

test fold_equal_evals_is_identity() {
  // When e0 = e1, fold = e0 regardless of beta (diff term vanishes).
  let e = Ext2 { c0: 5, c1: 3 }
  let beta = Ext2 { c0: 7, c1: 2 }
  ext2.eq_fast(fold_row(0, 1, beta, e, e), e)
}

test fold_beta_zero_is_average() {
  // beta = 0: result = (e0 + e1) / 2
  // e0 = (4, 0), e1 = (8, 0): average = (6, 0)
  // Verify: 12 * half mod p = 12 * (p+1)/2 = 6*(p+1) = 6p+6 ≡ 6 (mod p)
  let e0 = Ext2 { c0: 4, c1: 0 }
  let e1 = Ext2 { c0: 8, c1: 0 }
  ext2.eq_fast(fold_row(0, 1, ext2.zero, e0, e1), Ext2 { c0: 6, c1: 0 })
}

test fold_beta_zero_sym_average() {
  // e0 = p-1 = -1, e1 = 1: average = (-1+1)/2 = 0
  let e0 = Ext2 { c0: gf.prime - 1, c1: 0 }
  let e1 = Ext2 { c0: 1, c1: 0 }
  ext2.eq_fast(fold_row(0, 1, ext2.zero, e0, e1), ext2.zero)
}

test fold_symmetry() {
  // Swapping e0 ↔ e1 and negating beta gives the same result.
  // fold(-beta, e1, e0) should equal fold(beta, e0, e1)
  // because (e1+e0)/2 + (-beta)*(e1-e0)/(2x)
  //        = (e0+e1)/2 + beta*(e0-e1)/(2x) = fold(beta, e0, e1)
  let e0 = Ext2 { c0: 100, c1: 50 }
  let e1 = Ext2 { c0: 200, c1: 150 }
  let beta = Ext2 { c0: 3, c1: 7 }
  let neg_beta = ext2.neg(beta)
  ext2.eq_fast(fold_row(0, 1, beta, e0, e1), fold_row(0, 1, neg_beta, e1, e0))
}

test fold_produces_ext2() {
  // Smoke test: fold with non-trivial inputs returns a valid Ext2.
  let e0 = Ext2 { c0: 1, c1: 0 }
  let e1 = Ext2 { c0: 0, c1: 1 }
  let beta = Ext2 { c0: 2, c1: 3 }
  let result = fold_row(0, 1, beta, e0, e1)
  result.c0 >= 0 && result.c0 < gf.prime && result.c1 >= 0 && result.c1 < gf.prime
}

// -- acc_cols / open_input --

test acc_cols_empty() {
  // No columns → ro unchanged, alpha_pow unchanged.
  let (ro, ap) = acc_cols([], [], ext2.one, ext2.one, ext2.zero, ext2.one)
  ext2.eq_fast(ro, ext2.zero) && ext2.eq_fast(ap, ext2.one)
}

test acc_cols_single_column_zero_diff() {
  // p_at_z == from_base(p_at_x): diff = 0, ro unchanged.
  let inv_d = ext2.one
  let alpha = Ext2 { c0: 3, c1: 0 }
  let (ro, ap) =
    acc_cols([5], [Ext2 { c0: 5, c1: 0 }], inv_d, alpha, ext2.zero, ext2.one)
  // contrib = 1 * (5 - 5) * 1 = 0, ro stays 0; alpha_pow becomes alpha
  ext2.eq_fast(ro, ext2.zero) && ext2.eq_fast(ap, alpha)
}

test acc_cols_single_column_unit_contrib() {
  // p_at_z = (2,0), p_at_x = 1, inv_d = 1, alpha_pow = 1:
  // contrib = 1 * (2 - 1) * 1 = (1, 0); ro = (1, 0)
  let inv_d = ext2.one
  let alpha = Ext2 { c0: 7, c1: 0 }
  let (ro, ap) =
    acc_cols([1], [Ext2 { c0: 2, c1: 0 }], inv_d, alpha, ext2.zero, ext2.one)
  ext2.eq_fast(ro, Ext2 { c0: 1, c1: 0 }) && ext2.eq_fast(ap, alpha)
}

test acc_cols_alpha_pow_advances() {
  // Two columns, alpha_pow doubles each time.
  // inv_d = 1, alpha = (2,0), alpha_pow_start = (1,0)
  // col0: contrib = 1*(a-0)*1 = a=(1,0); alpha_pow → (2,0)
  // col1: contrib = 2*(b-0)*1 = 2b=(2,0) for b=(1,0); alpha_pow → (4,0)
  // ro = a + 2b = (3, 0)
  let alpha = Ext2 { c0: 2, c1: 0 }
  let (ro, _) =
    acc_cols(
      [0, 0],
      [Ext2 { c0: 1, c1: 0 }, Ext2 { c0: 1, c1: 0 }],
      ext2.one,
      alpha,
      ext2.zero,
      ext2.one,
    )
  ext2.eq_fast(ro, Ext2 { c0: 3, c1: 0 })
}

test open_input_empty_opened_values_returns_none() {
  // opened_values = [] → no first matrix row → None
  let empty_opening = BatchOpening { opened_values: [], opening_proof: [] }
  let ov = OpenedValues { trace_local: [], trace_next: [], quotient_chunks: [] }
  open_input(
    0,
    14,
    ext2.one,
    ext2.one,
    ext2.one,
    empty_opening,
    empty_opening,
    #"",
    #"",
    ov,
  ) == None
}

// ── D. FRI query chain verifier ───────────────────────────────────────────────

/// Verify one FRI query chain (verify_query in fri/src/verifier.rs:273),
/// specialised for binary folding (log_arity = 1 every round).
///
/// For the Fibonacci STARK, the chain has 13 rounds (degree_bits = 13,
/// log_blowup = 1, log_final_poly_len = 0 → log_global_max_height = 14,
/// log_final_height = 1).  There is only one batch of reduced openings, all
/// at log_global_max_height, so no "roll-in" step occurs mid-chain.
///
/// Arguments:
///   index              – query leaf index in the current FRI domain; starts
///                        at the sampled query index and is halved each round.
///   log_current_height – log2 of the current domain size (starts at 14).
///   betas              – per-round Ext2 folding challenges (one per round).
///   commits            – per-round ChallengeMmcs Merkle roots.
///   steps              – per-round CommitPhaseStep proofs.
///   folded_eval        – Ext2 seed (= ro from open_input at log_global_max_height).
///
/// The function recurses through (betas, commits, steps) in lock-step.
/// At each round it:
///   1. Reconstructs the two-element eval row [e0, e1] from folded_eval +
///      the single sibling in step.sibling_values.
///   2. Verifies the commit-phase Merkle proof via mmcs.verify_batch_ext.
///   3. Folds via fold_row to get the next folded_eval.
///
/// Returns Some((final_eval, final_domain_index)) when all rounds succeed,
/// or None on any Merkle failure, sibling-count mismatch, or list-length
/// mismatch.  The caller uses final_domain_index to evaluate the final poly.
pub fn verify_query(
  index: Int,
  log_current_height: Int,
  betas: List<Ext2>,
  commits: List<ByteArray>,
  steps: List<CommitPhaseStep<Ext2>>,
  folded_eval: Ext2,
) -> Option<(Ext2, Int)> {
  do_verify_query(
    index,
    log_current_height,
    betas,
    commits,
    steps,
    folded_eval,
    0,
  )
}

fn do_verify_query(
  index: Int,
  log_current_height: Int,
  betas: List<Ext2>,
  commits: List<ByteArray>,
  steps: List<CommitPhaseStep<Ext2>>,
  folded_eval: Ext2,
  round: Int,
) -> Option<(Ext2, Int)> {
  when (betas, commits, steps) is {
    // Base case: all rounds consumed — verify we landed at the expected final height.
    ([], [], []) ->
      if log_current_height != params.log_final_height {
        trace string.concat(
          @"FAIL: verify_query height mismatch at end, log_current_height=",
          string.from_int(log_current_height),
        )
        None
      } else {
        Some((folded_eval, index))
      }
    ([beta, ..rest_betas], [comm, ..rest_commits], [step, ..rest_steps]) ->
      // Binary folding: expect exactly 1 sibling (arity - 1 = 1).
      when step.sibling_values is {
        [sibling] ->
          if step.log_arity != 1 {
            trace string.concat(
              @"FAIL: verify_query wrong log_arity=",
              string.from_int(step.log_arity),
            )
            None
          } else {
            // Reconstruct [e0, e1]: evals[index % 2] = folded_eval, other = sibling.
            let (e0, e1) =
              if index % 2 == 0 {
                (folded_eval, sibling)
              } else {
                (sibling, folded_eval)
              }
            // Parent index and folded domain height.
            let parent_index = index / 2
            let log_folded_height = log_current_height - step.log_arity
            // Verify commit-phase Merkle proof.
            // ChallengeMmcs serialises each Ext2 as two base-field elements.
            let ok =
              mmcs.verify_batch_ext(
                comm,
                parent_index,
                [e0, e1],
                step.opening_proof,
              )
            if !ok {
              trace string.concat(
                @"FAIL: verify_query Merkle at round=",
                string.from_int(round),
              )
              None
            } else {
              let next_eval =
                fold_row(parent_index, log_folded_height, beta, e0, e1)
              do_verify_query(
                parent_index,
                log_folded_height,
                rest_betas,
                rest_commits,
                rest_steps,
                next_eval,
                round + 1,
              )
            }
          }
        // Wrong sibling count — only binary folding (1 sibling) is supported.
        _ -> {
          trace string.concat(
            @"FAIL: verify_query wrong sibling count at round=",
            string.from_int(round),
          )
          None
        }
      }
    // Mismatched list lengths — invalid proof shape.
    _ -> {
      trace @"FAIL: verify_query mismatched list lengths"
      None
    }
  }
}

// -- verify_query tests --

test verify_query_empty_rounds() {
  // No fold rounds: valid only when log_current_height already equals log_final_height.
  let init_eval = Ext2 { c0: 42, c1: 7 }
  verify_query(5, params.log_final_height, [], [], [], init_eval) == Some(
    (init_eval, 5),
  )
}

test verify_query_empty_rounds_wrong_height_returns_none() {
  // No fold rounds but height hasn't reached log_final_height — invalid proof shape.
  let init_eval = Ext2 { c0: 42, c1: 7 }
  verify_query(5, 14, [], [], [], init_eval) == None
}

test verify_query_mismatched_lists_returns_none() {
  // betas has 1 element but commits and steps are empty → shape error.
  verify_query(0, 14, [ext2.zero], [], [], ext2.one) == None
}

test verify_query_wrong_sibling_count_returns_none() {
  // sibling_values is empty but log_arity = 1 requires exactly 1 sibling.
  let step =
    CommitPhaseStep { log_arity: 1, sibling_values: [], opening_proof: [] }
  let dummy =
    #"0000000000000000000000000000000000000000000000000000000000000000"
  verify_query(0, 14, [ext2.zero], [dummy], [step], ext2.one) == None
}

test verify_query_bad_merkle_proof_returns_none() {
  // Merkle proof is an empty path, but commit is all-zeros (not the leaf hash).
  let step =
    CommitPhaseStep {
      log_arity: 1,
      sibling_values: [ext2.zero],
      opening_proof: [],
    }
  let bad_commit =
    #"0000000000000000000000000000000000000000000000000000000000000000"
  verify_query(0, 14, [ext2.zero], [bad_commit], [step], ext2.one) == None
}

test verify_query_one_round_valid() {
  // index = 0, index_in_group = 0 → e0 = init_eval, e1 = sibling.
  // Empty Merkle path: root = hash_leaf([e0.c0, e0.c1, e1.c0, e1.c1]).
  // beta = zero → fold = (e0 + e1) / 2 = ((1,0) + (0,0)) / 2 = (half, 0).
  let e0 = Ext2 { c0: 1, c1: 0 }
  let e1 = Ext2 { c0: 0, c1: 0 }
  // Start at height 2 so one fold (log_arity=1) lands at log_final_height=1.
  // parent_index = 0, log_folded_height = 2 - 1 = 1
  let root = mmcs.hash_leaf([1, 0, 0, 0])
  let expected = Ext2 { c0: half, c1: 0 }
  let step =
    CommitPhaseStep { log_arity: 1, sibling_values: [e1], opening_proof: [] }
  when verify_query(0, 2, [ext2.zero], [root], [step], e0) is {
    Some((result, final_idx)) ->
      ext2.eq_fast(result, expected) && final_idx == 0
    None -> False
  }
}

test verify_query_one_round_odd_index() {
  // index = 1, index_in_group = 1 → e0 = sibling, e1 = init_eval.
  // Empty Merkle path: root = hash_leaf([sibling.c0, sibling.c1, init.c0, init.c1]).
  // beta = zero → fold = (e0 + e1) / 2 = sibling = (2, 0), init = (4, 0) → avg = (3, 0)
  let sibling_eval = Ext2 { c0: 2, c1: 0 }
  let init_eval = Ext2 { c0: 4, c1: 0 }
  // e0 = sibling_eval, e1 = init_eval; start at height 2 → fold lands at log_final_height=1.
  let root = mmcs.hash_leaf([2, 0, 4, 0])
  // avg = (2+4)/2 = 3, in field: 6 * half = 3
  // 6 * half mod p: half = (p+1)/2, 6*(p+1)/2 = 3*(p+1) = 3p+3 ≡ 3 (mod p)
  let expected = Ext2 { c0: 3, c1: 0 }
  let step =
    CommitPhaseStep {
      log_arity: 1,
      sibling_values: [sibling_eval],
      opening_proof: [],
    }
  // Start at height 2 so one fold (log_arity=1) lands at log_final_height=1.
  when verify_query(1, 2, [ext2.zero], [root], [step], init_eval) is {
    Some((result, final_idx)) ->
      ext2.eq_fast(result, expected) && final_idx == 0
    None -> False
  }
}
