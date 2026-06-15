use goldilocks/ext2.{Ext2}
use goldilocks/field as gf
use stark/challenger.{ChallengerState}
use stark/params
use stark/pcs_verify as pcs
use stark/proof.{
  BatchProof, FibPublicInputs, StarkProof, valid_batch_proof_shape,
  valid_fri_proof_shape, valid_opened_values_shape,
}
use stark/verify_constraints as vc

/// Core Fibonacci STARK verifier logic (Plonky3 / Goldilocks).
///
/// This module is imported by both:
///   - validators/fib_verifier.ak  (the Cardano on-chain validator)
///   - lib/stark/goldilocks_proof_test.ak  (the end-to-end test)
///
/// Implements `verify` from uni-stark/src/verifier.rs:201–212 and 214–457,
/// specialised for FibonacciAir with no preprocessed trace and no ZK
/// randomisation.
///
/// ── Uni-stark transcript (verifier.rs:326–356) ───────────────────────────────
///
///   observe_val(degree_bits)           // from_usize(degree_bits)
///   observe_val(degree_bits)           // from_usize(degree_bits - is_zk()=0)
///   observe_val(0)                     // from_usize(preprocessed_width=0)
///   observe_commitment(trace_commit)
///   observe_val(pis.a)
///   observe_val(pis.b)
///   observe_val(pis.x)
///   alpha = sample_ext()               // constraint-combination challenge
///   observe_commitment(quotient_commit)
///   zeta  = sample_ext()               // OOD evaluation point
///   zeta_next = zeta · g_{degree_bits}
/// Verify a Goldilocks Fibonacci STARK proof against public inputs.
///
/// Returns True iff both the FRI opening proof and the AIR constraints
/// check out for the claimed (a, b, x) triple.
pub fn stark_verify(proof: StarkProof<Ext2>, pis: FibPublicInputs) -> Bool {
  // ── Shape validation (mirrors Err(InvalidProofShape), verifier.rs:249) ────
  // degree_bits must match the compiled circuit (13 for n=8192).
  let shape_ok =
    proof.degree_bits == params.degree_bits && valid_opened_values_shape(
      proof.opened_values,
      params.fib_trace_width,
      params.num_quotient_chunks,
    ) && valid_fri_proof_shape(
      proof.opening_proof,
      params.num_fri_rounds(proof.degree_bits),
      params.fri_params.num_queries,
      params.final_poly_len,
    )
  if !shape_ok {
    trace @"FAIL: shape check"
    False
  } else {
    // ── Uni-stark transcript (verifier.rs:326–356) ──────────────────────────
    let st = challenger.init()
    // Instance header (verifier.rs:326–328).
    let st = challenger.observe_val(st, proof.degree_bits)
    // degree_bits - is_zk() = degree_bits for non-ZK (verifier.rs:327).
    let st = challenger.observe_val(st, proof.degree_bits)
    // preprocessed_width = 0: FibonacciAir has no preprocessed trace.
    let st = challenger.observe_val(st, 0)
    // Main trace commitment (verifier.rs:334).
    let st = challenger.observe_commitment(st, proof.trace_commit)
    // Public values (verifier.rs:338: observe_slice([a, b, x])).
    let st = challenger.observe_val(st, pis.a)
    let st = challenger.observe_val(st, pis.b)
    let st = challenger.observe_val(st, pis.x)
    // Constraint-combination challenge (verifier.rs:344).
    let (alpha, st) = challenger.sample_ext(st)
    // Quotient commitment (verifier.rs:345).
    let st = challenger.observe_commitment(st, proof.quotient_commit)
    // OOD evaluation point (verifier.rs:356).
    let (zeta, st) = challenger.sample_ext(st)
    // Next-row OOD point: zeta_next = zeta · g_{degree_bits} (verifier.rs:357–358).
    let zeta_next = ext2.scale(zeta, gf.two_adic_generator(proof.degree_bits))

    // ── PCS verification (FRI opening proof) ──────────────────────────────
    if !pcs.pcs_verify(st, proof, zeta, zeta_next) {
      trace @"FAIL: PCS / FRI opening"
      False
    } else {
      // ── AIR constraint verification ──────────────────────────────────────
      let result =
        vc.verify_constraints(
          proof.opened_values,
          pis,
          zeta,
          alpha,
          proof.degree_bits,
        )
      trace if result {
        @"constraints ok"
      } else {
        @"FAIL: AIR constraints"
      }
      result
    }
  }
}

// ── Batch verifier (multi-AIR, batch-stark) ───────────────────────────────────

/// Verify a Goldilocks batch STARK proof (MulAir + FibonacciAir, no lookups).
///
/// Ports `verify_batch` from batch-stark/src/verifier.rs:30-564, specialised
/// to the no-lookup, no-preprocessed, non-ZK configuration produced by
/// export_batch_proof.rs.
///
/// public_values: one list per instance, prover order — [] for MulAir,
/// [a, b, x] for FibonacciAir.
///
/// ── Batch transcript (verifier.rs:81-247) ─────────────────────────────────────
///
/// Unlike the uni-stark header, the instance metadata is observed as algebra
/// (extension) elements: observe_base_as_algebra_element::<Ext2>(x) embeds x
/// and observes BOTH coefficients, i.e. the bytes of [x, 0]
/// (challenger/src/lib.rs:141-146). Public values stay base elements (8 bytes).
///
///   observe_ext(Ext2(n_instances, 0))                 // verifier.rs:83
///   for each instance i:                              // config.rs:25-39
///     observe_ext(Ext2(degree_bits[i], 0))            //   log_ext_degree
///     observe_ext(Ext2(degree_bits[i], 0))            //   log_degree (is_zk=0)
///     observe_ext(Ext2(width[i], 0))
///     observe_ext(Ext2(num_quotient_chunks[i], 0))
///   observe_commitment(main_commit)                   // verifier.rs:196
///   for each instance: observe_vals(public_values[i]) // verifier.rs:197-199
///   for each instance: observe_ext(Ext2(0, 0))        // preprocessed width = 0
///   (no global preprocessed commitment; no lookup challenges — empty lookups
///    sample nothing in get_perm_challenges, common.rs:275-313;
///    no permutation commitment)
///   alpha = sample_ext()                              // verifier.rs:235
///   observe_commitment(quotient_commit)               // verifier.rs:238
///   (no random commitment: non-ZK)
///   zeta  = sample_ext()                              // verifier.rs:247
pub fn stark_verify_batch(
  proof: BatchProof<Ext2>,
  public_values: List<List<Int>>,
) -> Bool {
  // ── Shape validation (verifier.rs:61-67, 124-186) ─────────────────────────
  let shape_ok =
    proof.degree_bits == params.batch_degree_bits && public_value_lengths_ok(
      public_values,
      params.batch_num_public_values,
    ) && valid_batch_proof_shape(
      proof,
      params.batch_trace_widths,
      params.batch_num_quotient_chunks,
      params.num_fri_rounds(params.batch_max_degree_bits),
      params.fri_params.num_queries,
      params.final_poly_len,
    )
  if !shape_ok {
    trace @"FAIL: batch shape check"
    False
  } else {
    // ── Batch transcript (see doc comment above) ──────────────────────────
    let st = challenger.init()
    let st = observe_usize_as_ext(st, params.batch_n_instances)
    let st =
      observe_instance_bindings(
        st,
        proof.degree_bits,
        params.batch_trace_widths,
        params.batch_num_quotient_chunks,
      )
    let st = challenger.observe_commitment(st, proof.main_commit)
    let st = observe_public_values(st, public_values)
    let st = observe_preprocessed_widths(st, params.batch_n_instances)
    let (alpha, st) = challenger.sample_ext(st)
    let st = challenger.observe_commitment(st, proof.quotient_commit)
    let (zeta, st) = challenger.sample_ext(st)
    // Next-row OOD point: zeta · g_{db}. Upstream computes this per instance
    // (trace_domains[i].next_point(zeta), verifier.rs:289-291); all instances
    // share degree_bits here so it collapses to one value.
    let zeta_next =
      ext2.scale(zeta, gf.two_adic_generator(params.batch_max_degree_bits))

    // ── PCS verification (FRI opening proof) ──────────────────────────────
    if !pcs.pcs_verify_batch(st, proof, zeta, zeta_next) {
      trace @"FAIL: batch PCS / FRI opening"
      False
    } else {
      // ── Per-instance AIR constraint verification ──────────────────────────
      // (batch-stark/verifier.rs:431-547; both instances share degree_bits.)
      let result =
        vc.verify_constraints_batch(
          proof.opened_values,
          public_values,
          zeta,
          alpha,
          params.batch_max_degree_bits,
        )
      trace if result {
        @"batch constraints ok"
      } else {
        @"FAIL: batch AIR constraints"
      }
      result
    }
  }
}

/// observe_base_as_algebra_element::<Ext2>(x): embed x into Ext2 and observe
/// both coefficients, [x, 0] (challenger/src/lib.rs:141-146).
fn observe_usize_as_ext(st: ChallengerState, n: Int) -> ChallengerState {
  challenger.observe_ext(st, Ext2 { c0: n, c1: 0 })
}

/// Per-instance binding data (config.rs:25-39), zip-walking the per-instance
/// parameter lists. Lengths were validated by the shape check.
fn observe_instance_bindings(
  st: ChallengerState,
  dbs: List<Int>,
  widths: List<Int>,
  nums_chunks: List<Int>,
) -> ChallengerState {
  when (dbs, widths, nums_chunks) is {
    ([db, ..rest_db], [w, ..rest_w], [nc, ..rest_nc]) -> {
      // log_ext_degree, then log_degree = log_ext_degree - is_zk() = same here.
      let st = observe_usize_as_ext(st, db)
      let st = observe_usize_as_ext(st, db)
      let st = observe_usize_as_ext(st, w)
      let st = observe_usize_as_ext(st, nc)
      observe_instance_bindings(st, rest_db, rest_w, rest_nc)
    }
    _ -> st
  }
}

/// observe_slice(pv) per instance, in order (verifier.rs:197-199).
fn observe_public_values(
  st: ChallengerState,
  pvs: List<List<Int>>,
) -> ChallengerState {
  when pvs is {
    [] -> st
    [pv, ..rest] -> observe_public_values(challenger.observe_vals(st, pv), rest)
  }
}

/// Preprocessed width = 0 per instance, as an algebra element
/// (verifier.rs:203-205). No instance has a preprocessed trace.
fn observe_preprocessed_widths(
  st: ChallengerState,
  n_instances: Int,
) -> ChallengerState {
  if n_instances <= 0 {
    st
  } else {
    observe_preprocessed_widths(observe_usize_as_ext(st, 0), n_instances - 1)
  }
}

/// Each instance's public value list must have the expected length
/// (verifier.rs:62 checks the outer length; the inner lengths feed eval).
fn public_value_lengths_ok(pvs: List<List<Int>>, expected: List<Int>) -> Bool {
  when (pvs, expected) is {
    ([], []) -> True
    ([pv, ..rest_pv], [n, ..rest_n]) ->
      if pv_len(pv, 0) == n {
        public_value_lengths_ok(rest_pv, rest_n)
      } else {
        False
      }
    _ -> False
  }
}

fn pv_len(xs: List<Int>, acc: Int) -> Int {
  when xs is {
    [] -> acc
    [_, ..rest] -> pv_len(rest, acc + 1)
  }
}
