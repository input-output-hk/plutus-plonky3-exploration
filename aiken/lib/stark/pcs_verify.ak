use aiken/primitive/string
use goldilocks/ext2.{Ext2}
use goldilocks/field as gf
use stark/challenger.{ChallengerState}
use stark/fri
use stark/params
use stark/proof.{
  BatchProof, CommitPhaseStep, InstanceOpenedValues, OpenedValues, QueryProof,
  StarkProof,
}

// ── PCS verifier ───────────────────────────────────────────────────────────────

/// PCS (Polynomial Commitment Scheme) verification for the Plonky3 / Goldilocks Fibonacci STARK.
///
/// Implements TwoAdicFriPcs::verify + verify_fri (fri/src/verifier.rs:54–248),
/// specialised for the non-ZK, no-preprocessed-trace Fibonacci AIR.
///
/// Called from stark_verify (validators/fib_verifier.ak) after the uni-stark
/// transcript has already been run and zeta has been sampled.
///
/// ── Transcript continued from the caller ─────────────────────────────────────
///
///   pcs.verify (two_adic_pcs.rs:678–684):
///     observe trace_local               (2 Ext2 elements at zeta)
///     observe trace_next                (2 Ext2 elements at zeta_next)
///     observe quotient_chunks[0]        (2 Ext2 elements at zeta, 1 chunk × DIMENSION=2)
///
///   verify_fri (verifier.rs:54–248):
///     sample alpha_fri                  (FRI combination challenge)
///     for 13 rounds:
///       observe commit_phase_commits[i]
///       check_pow(commit_proof_of_work_bits=1, commit_pow_witnesses[i])
///       sample betas[i]
///     observe final_poly                (1 Ext2 coefficient, degree 0)
///     observe each log_arity            (13 × Val::from_usize(1))
///     check_pow(query_proof_of_work_bits=16, query_pow_witness)
///
///   query phase (verifier.rs:178–246):
///     for each of 100 queries:
///       index = sample_bits(log_global_max_height=14)
///       open_input(index, ...)          → ro (reduced opening, Ext2)
///       verify_query(index, ...)        → (folded_eval, final_idx)
///       x = g14^reverse_bits_len(final_idx, 14)   (no generator shift)
///       eval = eval_final_poly(final_poly, x)
///       assert folded_eval == eval
/// Verify the FRI opening proof, starting from the challenger state produced
/// by the uni-stark transcript (after sampling zeta).
///
/// Mirrors TwoAdicFriPcs::verify → verify_fri for the Fibonacci STARK.
///
/// Arguments:
///   st       – challenger state after zeta has been sampled by stark_verify.
///   proof    – the full STARK proof (opened values and FRI proof consumed here).
///   zeta     – OOD challenge point (Ext2).
///   zeta_next – next-row OOD point = zeta · g_{degree_bits} (Ext2).
pub fn pcs_verify(
  st: ChallengerState,
  proof: StarkProof<Ext2>,
  zeta: Ext2,
  zeta_next: Ext2,
) -> Bool {
  let fp = proof.opening_proof

  // ── 1. pcs.verify: observe opened values ────────────────────────────────────
  let st = observe_opened_values(st, proof.opened_values)

  // ── 2. FRI combination challenge (alpha_fri) ────────────────────────────────
  let (alpha_fri, st) = challenger.sample_ext(st)

  // ── 3. Commit phase: observe, check PoW per round, sample betas ─────────────
  when
    process_commit_rounds(st, fp.commit_phase_commits, fp.commit_pow_witnesses)
  is {
    None -> {
      trace @"FAIL: commit-phase PoW"
      False
    }
    Some((betas, st)) -> {
      // ── 4. Observe final polynomial ────────────────────────────────────────
      let st = challenger.observe_exts(st, fp.final_poly)

      // ── 5. Observe per-round log_arities ───────────────────────────────────
      // Extracted from the first query proof (verifier.rs:96–105).
      let log_arities = extract_log_arities(fp.query_proofs)
      let st = challenger.observe_vals(st, log_arities)

      // log_global_max_height = sum(log_arities) + log_blowup + log_final_poly_len
      let log_global_max_height =
        list_sum(log_arities) + params.fri_params.log_blowup + params.fri_params.log_final_poly_len

      // ── 6. Query proof-of-work ─────────────────────────────────────────────
      let (pow_ok, st) =
        challenger.check_pow(
          st,
          params.fri_params.query_proof_of_work_bits,
          fp.query_pow_witness,
        )
      if !pow_ok {
        trace @"FAIL: query PoW"
        False
      } else {
        // ── 7. Query phase ────────────────────────────────────────────────
        verify_all_queries(
          st,
          log_global_max_height,
          alpha_fri,
          zeta,
          zeta_next,
          betas,
          fp.commit_phase_commits,
          fp.final_poly,
          fp.query_proofs,
          proof.trace_commit,
          proof.quotient_commit,
          proof.opened_values,
          0,
        )
      }
    }
  }
}

// ── Batch PCS verifier ─────────────────────────────────────────────────────────

/// Batch-proof variant of pcs_verify (TwoAdicFriPcs::verify → verify_fri for
/// the MulAir + FibonacciAir batch proof).
///
/// Identical transcript structure to pcs_verify; only the opened-values
/// observation and the per-query input opening differ:
///   - opened values are observed rounds → matrices → points → values
///     (two_adic_pcs.rs:678-684): for each instance, trace_local then
///     trace_next; then for each instance, each quotient chunk.
///   - open_input walks one Merkle row per instance in each of the two
///     batches (fri.open_input_batch).
///
/// zeta_next: all instances share the same trace domain (equal degree_bits,
/// see params.batch_degree_bits), so the per-instance next_point(zeta) of
/// batch-stark/verifier.rs:289-291 collapses to the single value passed here.
pub fn pcs_verify_batch(
  st: ChallengerState,
  proof: BatchProof<Ext2>,
  zeta: Ext2,
  zeta_next: Ext2,
) -> Bool {
  let fp = proof.opening_proof

  // ── 1. pcs.verify: observe opened values ────────────────────────────────────
  let st = observe_batch_opened_values(st, proof.opened_values)

  // ── 2. FRI combination challenge (alpha_fri) ────────────────────────────────
  let (alpha_fri, st) = challenger.sample_ext(st)

  // ── 3. Commit phase: observe, check PoW per round, sample betas ─────────────
  when
    process_commit_rounds(st, fp.commit_phase_commits, fp.commit_pow_witnesses)
  is {
    None -> {
      trace @"FAIL: commit-phase PoW"
      False
    }
    Some((betas, st)) -> {
      // ── 4. Observe final polynomial ────────────────────────────────────────
      let st = challenger.observe_exts(st, fp.final_poly)

      // ── 5. Observe per-round log_arities ───────────────────────────────────
      let log_arities = extract_log_arities(fp.query_proofs)
      let st = challenger.observe_vals(st, log_arities)

      let log_global_max_height =
        list_sum(log_arities) + params.fri_params.log_blowup + params.fri_params.log_final_poly_len

      // ── 6. Query proof-of-work ─────────────────────────────────────────────
      let (pow_ok, st) =
        challenger.check_pow(
          st,
          params.fri_params.query_proof_of_work_bits,
          fp.query_pow_witness,
        )
      if !pow_ok {
        trace @"FAIL: query PoW"
        False
      } else {
        // ── 7. Query phase ────────────────────────────────────────────────
        verify_all_queries_batch(
          st,
          log_global_max_height,
          alpha_fri,
          zeta,
          zeta_next,
          betas,
          fp.commit_phase_commits,
          fp.final_poly,
          fp.query_proofs,
          proof.main_commit,
          proof.quotient_commit,
          proof.opened_values,
          0,
        )
      }
    }
  }
}

/// Verify all batch FRI query proofs, sampling a fresh index for each one.
fn verify_all_queries_batch(
  st: ChallengerState,
  log_global_max_height: Int,
  alpha_fri: Ext2,
  zeta: Ext2,
  zeta_next: Ext2,
  betas: List<Ext2>,
  commits: List<ByteArray>,
  final_poly: List<Ext2>,
  query_proofs: List<QueryProof<Ext2>>,
  main_commit: ByteArray,
  quotient_commit: ByteArray,
  instances: List<InstanceOpenedValues<Ext2>>,
  query_idx: Int,
) -> Bool {
  when query_proofs is {
    [] -> True
    [qp, ..rest] -> {
      let (index, st) = challenger.sample_bits(st, log_global_max_height)
      let ok =
        verify_single_query_batch(
          index,
          log_global_max_height,
          alpha_fri,
          zeta,
          zeta_next,
          betas,
          commits,
          final_poly,
          qp,
          main_commit,
          quotient_commit,
          instances,
        )
      if !ok {
        trace string.concat(@"FAIL: batch query ", string.from_int(query_idx))
        False
      } else {
        verify_all_queries_batch(
          st,
          log_global_max_height,
          alpha_fri,
          zeta,
          zeta_next,
          betas,
          commits,
          final_poly,
          rest,
          main_commit,
          quotient_commit,
          instances,
          query_idx + 1,
        )
      }
    }
  }
}

/// Verify one batch FRI query: open_input_batch → verify_query → final poly.
fn verify_single_query_batch(
  index: Int,
  log_global_max_height: Int,
  alpha_fri: Ext2,
  zeta: Ext2,
  zeta_next: Ext2,
  betas: List<Ext2>,
  commits: List<ByteArray>,
  final_poly: List<Ext2>,
  qp: QueryProof<Ext2>,
  main_commit: ByteArray,
  quotient_commit: ByteArray,
  instances: List<InstanceOpenedValues<Ext2>>,
) -> Bool {
  // input_proof in coms_to_verify order: [main, quotient_chunks]
  // (no random/preprocessed/permutation rounds in this configuration).
  when qp.input_proof is {
    [main_opening, quotient_opening, ..] ->
      when
        fri.open_input_batch(
          index,
          log_global_max_height,
          alpha_fri,
          zeta,
          zeta_next,
          main_opening,
          quotient_opening,
          main_commit,
          quotient_commit,
          instances,
        )
      is {
        None -> {
          trace @"FAIL: open_input_batch (Merkle or denominator)"
          False
        }
        Some(ro) ->
          when
            fri.verify_query(
              index,
              log_global_max_height,
              betas,
              commits,
              qp.commit_phase_openings,
              ro,
            )
          is {
            None -> {
              trace @"FAIL: verify_query (FRI fold chain)"
              False
            }
            Some((folded_eval, final_idx)) -> {
              let x =
                gf.pow(
                  gf.two_adic_generator(log_global_max_height),
                  fri.reverse_bits_len(final_idx, log_global_max_height),
                )
              let poly_ok =
                ext2.eq_fast(folded_eval, eval_final_poly(final_poly, x))
              trace if poly_ok {
                @"poly ok"
              } else {
                @"FAIL: final poly mismatch"
              }
              poly_ok
            }
          }
      }
    _ -> False
  }
}

/// Observe batch opened values rounds → matrices → points → values
/// (two_adic_pcs.rs:678-684): main round first (per instance: trace_local at
/// zeta, then trace_next at zeta_next), then the quotient round (per
/// instance, each chunk at zeta).
fn observe_batch_opened_values(
  st: ChallengerState,
  instances: List<InstanceOpenedValues<Ext2>>,
) -> ChallengerState {
  let st = observe_main_round(st, instances)
  observe_quotient_round(st, instances)
}

fn observe_main_round(
  st: ChallengerState,
  instances: List<InstanceOpenedValues<Ext2>>,
) -> ChallengerState {
  when instances is {
    [] -> st
    [inst, ..rest] -> {
      let st = challenger.observe_exts(st, inst.trace_local)
      let st = challenger.observe_exts(st, inst.trace_next)
      observe_main_round(st, rest)
    }
  }
}

fn observe_quotient_round(
  st: ChallengerState,
  instances: List<InstanceOpenedValues<Ext2>>,
) -> ChallengerState {
  when instances is {
    [] -> st
    [inst, ..rest] ->
      observe_quotient_round(
        observe_quotient_chunks(st, inst.quotient_chunks),
        rest,
      )
  }
}

// ── Transcript helpers ─────────────────────────────────────────────────────────

/// Observe opened values in the same order pcs.verify feeds them to the challenger.
///
/// Matches the loop in two_adic_pcs.rs:678–684 over coms_to_verify:
///   [0] trace round:   (zeta, trace_local), (zeta_next, trace_next)
///   [1] quotient round: (zeta, quotient_chunks[0])
fn observe_opened_values(
  st: ChallengerState,
  ov: OpenedValues<Ext2>,
) -> ChallengerState {
  let st = challenger.observe_exts(st, ov.trace_local)
  let st = challenger.observe_exts(st, ov.trace_next)
  observe_quotient_chunks(st, ov.quotient_chunks)
}

fn observe_quotient_chunks(
  st: ChallengerState,
  chunks: List<List<Ext2>>,
) -> ChallengerState {
  when chunks is {
    [] -> st
    [chunk, ..rest] ->
      observe_quotient_chunks(challenger.observe_exts(st, chunk), rest)
  }
}

// ── Commit-phase processing ────────────────────────────────────────────────────

/// Process all FRI commit-phase rounds.
///
/// For each round: observe the commitment, check proof-of-work, sample a beta challenge.
/// Betas are returned in forward (round) order.
/// Returns None on any PoW failure or list-length mismatch.
fn process_commit_rounds(
  st: ChallengerState,
  commits: List<ByteArray>,
  witnesses: List<Int>,
) -> Option<(List<Ext2>, ChallengerState)> {
  when (commits, witnesses) is {
    ([], []) -> Some(([], st))
    ([commit, ..rest_commits], [witness, ..rest_witnesses]) -> {
      let st = challenger.observe_commitment(st, commit)
      let (pow_ok, st) =
        challenger.check_pow(
          st,
          params.fri_params.commit_proof_of_work_bits,
          witness,
        )
      if !pow_ok {
        None
      } else {
        let (beta, st) = challenger.sample_ext(st)
        when process_commit_rounds(st, rest_commits, rest_witnesses) is {
          None -> None
          Some((betas, st)) -> Some(([beta, ..betas], st))
        }
      }
    }
    _ -> None
  }
}

// ── Query phase ────────────────────────────────────────────────────────────────

/// Verify all FRI query proofs, sampling a fresh index for each one.
fn verify_all_queries(
  st: ChallengerState,
  log_global_max_height: Int,
  alpha_fri: Ext2,
  zeta: Ext2,
  zeta_next: Ext2,
  betas: List<Ext2>,
  commits: List<ByteArray>,
  final_poly: List<Ext2>,
  query_proofs: List<QueryProof<Ext2>>,
  trace_commit: ByteArray,
  quotient_commit: ByteArray,
  ov: OpenedValues<Ext2>,
  query_idx: Int,
) -> Bool {
  when query_proofs is {
    [] -> True
    [qp, ..rest] -> {
      let (index, st) = challenger.sample_bits(st, log_global_max_height)
      let ok =
        verify_single_query(
          index,
          log_global_max_height,
          alpha_fri,
          zeta,
          zeta_next,
          betas,
          commits,
          final_poly,
          qp,
          trace_commit,
          quotient_commit,
          ov,
        )
      if !ok {
        trace string.concat(@"FAIL: query ", string.from_int(query_idx))
        False
      } else {
        verify_all_queries(
          st,
          log_global_max_height,
          alpha_fri,
          zeta,
          zeta_next,
          betas,
          commits,
          final_poly,
          rest,
          trace_commit,
          quotient_commit,
          ov,
          query_idx + 1,
        )
      }
    }
  }
}

/// Verify one FRI query: open_input → verify_query → final polynomial check.
fn verify_single_query(
  index: Int,
  log_global_max_height: Int,
  alpha_fri: Ext2,
  zeta: Ext2,
  zeta_next: Ext2,
  betas: List<Ext2>,
  commits: List<ByteArray>,
  final_poly: List<Ext2>,
  qp: QueryProof<Ext2>,
  trace_commit: ByteArray,
  quotient_commit: ByteArray,
  ov: OpenedValues<Ext2>,
) -> Bool {
  when qp.input_proof is {
    [trace_opening, quotient_opening, ..] ->
      when
        fri.open_input(
          index,
          log_global_max_height,
          alpha_fri,
          zeta,
          zeta_next,
          trace_opening,
          quotient_opening,
          trace_commit,
          quotient_commit,
          ov,
        )
      is {
        None -> {
          trace @"FAIL: open_input (Merkle or denominator)"
          False
        }
        Some(ro) ->
          when
            fri.verify_query(
              index,
              log_global_max_height,
              betas,
              commits,
              qp.commit_phase_openings,
              ro,
            )
          is {
            None -> {
              trace @"FAIL: verify_query (FRI fold chain)"
              False
            }
            Some((folded_eval, final_idx)) -> {
              // Final poly evaluation point: no generator shift (verifier.rs:231–232).
              let x =
                gf.pow(
                  gf.two_adic_generator(log_global_max_height),
                  fri.reverse_bits_len(final_idx, log_global_max_height),
                )
              let poly_ok =
                ext2.eq_fast(folded_eval, eval_final_poly(final_poly, x))
              trace if poly_ok {
                @"poly ok"
              } else {
                @"FAIL: final poly mismatch"
              }
              poly_ok
            }
          }
      }
    _ -> False
  }
}

// ── Final polynomial evaluation ────────────────────────────────────────────────

/// Evaluate a polynomial at a base-field point using Horner's method.
///
/// `coeffs` ordered from the constant term upward: [c0, c1, ..., cn]
/// represents c0 + c1·x + ... + cn·x^n.
///
/// Mirrors the Rust evaluation in verify_fri (verifier.rs:238–241):
///   let mut eval = Challenge::ZERO;
///   for &coeff in proof.final_poly.iter().rev() { eval = eval * x + coeff; }
fn eval_final_poly(coeffs: List<Ext2>, x: Int) -> Ext2 {
  do_eval_horner(list_reverse_ext(coeffs), x, ext2.zero)
}

fn do_eval_horner(rev_coeffs: List<Ext2>, x: Int, acc: Ext2) -> Ext2 {
  when rev_coeffs is {
    [] -> acc
    [c, ..rest] -> do_eval_horner(rest, x, ext2.add(ext2.scale(acc, x), c))
  }
}

// ── Proof-structure helpers ────────────────────────────────────────────────────

/// Extract per-round log_arities from the first query proof's commit_phase_openings.
fn extract_log_arities(query_proofs: List<QueryProof<Ext2>>) -> List<Int> {
  when query_proofs is {
    [] -> []
    [qp, ..] -> steps_to_log_arities(qp.commit_phase_openings)
  }
}

fn steps_to_log_arities(steps: List<CommitPhaseStep<Ext2>>) -> List<Int> {
  when steps is {
    [] -> []
    [step, ..rest] -> [step.log_arity, ..steps_to_log_arities(rest)]
  }
}

// ── List utilities ─────────────────────────────────────────────────────────────

fn list_reverse_ext(xs: List<Ext2>) -> List<Ext2> {
  do_reverse_ext(xs, [])
}

fn do_reverse_ext(xs: List<Ext2>, acc: List<Ext2>) -> List<Ext2> {
  when xs is {
    [] -> acc
    [x, ..rest] -> do_reverse_ext(rest, [x, ..acc])
  }
}

fn list_sum(xs: List<Int>) -> Int {
  when xs is {
    [] -> 0
    [x, ..rest] -> x + list_sum(rest)
  }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

test eval_final_poly_constant() {
  let c0 = Ext2 { c0: 42, c1: 7 }
  ext2.eq_fast(eval_final_poly([c0], 99), c0)
}

test eval_final_poly_linear() {
  // [c0, c1] = c0 + c1·x.  c0=(1,0), c1=(2,0), x=3 → (7,0).
  let c0 = Ext2 { c0: 1, c1: 0 }
  let c1 = Ext2 { c0: 2, c1: 0 }
  ext2.eq_fast(eval_final_poly([c0, c1], 3), Ext2 { c0: 7, c1: 0 })
}

test eval_final_poly_at_zero() {
  let c0 = Ext2 { c0: 5, c1: 3 }
  let c1 = Ext2 { c0: 11, c1: 17 }
  ext2.eq_fast(eval_final_poly([c0, c1], 0), c0)
}

test list_sum_empty() {
  list_sum([]) == 0
}

test list_sum_nonempty() {
  list_sum([1, 2, 3, 4, 5]) == 15
}

test list_reverse_ext_empty() {
  list_reverse_ext([]) == []
}

test list_reverse_ext_three_elements() {
  let a = Ext2 { c0: 1, c1: 2 }
  let b = Ext2 { c0: 3, c1: 4 }
  let c = Ext2 { c0: 5, c1: 6 }
  list_reverse_ext([a, b, c]) == [c, b, a]
}

test extract_log_arities_empty_proofs() {
  extract_log_arities([]) == []
}

test extract_log_arities_from_steps() {
  let step1 =
    CommitPhaseStep { log_arity: 1, sibling_values: [], opening_proof: [] }
  let step2 =
    CommitPhaseStep { log_arity: 2, sibling_values: [], opening_proof: [] }
  let qp = QueryProof { input_proof: [], commit_phase_openings: [step1, step2] }
  extract_log_arities([qp]) == [1, 2]
}

test log_global_max_height_from_arities() {
  // 13 rounds of log_arity=1 give sum=13; adding log_blowup+log_final_poly_len
  // yields log_global_max_height.
  //   log_blowup=1 → 13 + 1 + 0 = 14
  //   log_blowup=2 → 13 + 2 + 0 = 15
  let arities = [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
  list_sum(arities) + params.fri_params.log_blowup + params.fri_params.log_final_poly_len == params.degree_bits + params.fri_params.log_blowup + params.fri_params.log_final_poly_len
}

test observe_opened_values_clears_output() {
  let ov =
    OpenedValues {
      trace_local: [Ext2 { c0: 1, c1: 0 }],
      trace_next: [Ext2 { c0: 2, c1: 0 }],
      quotient_chunks: [[Ext2 { c0: 3, c1: 0 }]],
    }
  let st = observe_opened_values(challenger.init(), ov)
  st.output == #"" && st.consumed == 0
}

test process_commit_rounds_empty() {
  let st = challenger.init()
  process_commit_rounds(st, [], []) == Some(([], st))
}

test process_commit_rounds_mismatched_lengths_returns_none() {
  let dummy =
    #"0000000000000000000000000000000000000000000000000000000000000000"
  process_commit_rounds(challenger.init(), [dummy], []) == None
}
