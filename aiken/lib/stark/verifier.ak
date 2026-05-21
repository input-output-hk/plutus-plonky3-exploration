use goldilocks/ext2.{Ext2}
use goldilocks/field as gf
use stark/challenger
use stark/params
use stark/pcs_verify as pcs
use stark/proof.{
  FibPublicInputs, StarkProof, valid_fri_proof_shape, valid_opened_values_shape,
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
