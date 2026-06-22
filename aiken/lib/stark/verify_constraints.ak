use goldilocks/ext2.{Ext2}
use goldilocks/field as gf
use stark/logup
use stark/proof.{FibPublicInputs, InstanceOpenedValues, OpenedValues}

// ── Public verifier ────────────────────────────────────────────────────────────

/// AIR constraint verifier for the Goldilocks Fibonacci STARK.
///
/// Implements verify_constraints from uni-stark/src/verifier.rs:76–133,
/// specialised for FibonacciAir (2 trace columns, no preprocessed trace,
/// 5 constraints, num_quotient_chunks = 1).
///
/// ── Selectors at zeta ────────────────────────────────────────────────────────
///
/// For init_trace_domain (shift = 1, log_size = degree_bits):
///   unshifted = zeta · shift_inverse = zeta
///   Z_H(zeta) = zeta^n − 1   where n = 2^degree_bits
///   g         = two_adic_generator(degree_bits)
///
///   is_first_row  = Z_H(zeta) / (zeta − 1)          (Lagrange at row 0)
///   is_last_row   = Z_H(zeta) / (zeta − g^{−1})     (Lagrange at row n−1)
///   is_transition = zeta − g^{−1}                    (non-zero except on last row)
///   inv_vanishing = 1 / Z_H(zeta)
///
/// ── FibonacciAir constraints (from fib_air.rs) ───────────────────────────────
///
///   c0 = is_first_row  · (tl[0] − pis.a)
///   c1 = is_first_row  · (tl[1] − pis.b)
///   c2 = is_transition · (tl[1] − tn[0])
///   c3 = is_transition · (tl[0] + tl[1] − tn[1])
///   c4 = is_last_row   · (tl[1] − pis.x)
///
///   folded = fold_constraints([c0..c4], alpha)
///          = c0·α^4 + c1·α^3 + c2·α^2 + c3·α + c4
///
/// ── Final check ──────────────────────────────────────────────────────────────
///
///   folded · inv_vanishing == quotient(zeta)
///
///   quotient(zeta) is recomposed from the single quotient chunk:
///   For num_quotient_chunks = 1, zp_0 = 1 (empty product of Lagrange zp factors),
///   so quotient(zeta) = basis(0)·chunk[0] + basis(1)·chunk[1]
///                     = chunk[0] + α·chunk[1]
///   where chunk[e] = Q_e(zeta) ∈ Ext2 (OOD eval of e-th base-field sub-polynomial).
/// Check that constraints(zeta) / Z_H(zeta) == quotient(zeta).
///
/// Arguments:
///   ov          – OOD evaluations (trace_local, trace_next, quotient_chunks).
///   pis         – Fibonacci public inputs (a, b, x).
///   zeta        – out-of-domain challenge (Ext2).
///   alpha       – constraint-combination challenge (Ext2).
///   degree_bits – log2 of the trace length (= 13 for n = 8192).
pub fn verify_constraints(
  ov: OpenedValues<Ext2>,
  pis: FibPublicInputs,
  zeta: Ext2,
  alpha: Ext2,
  degree_bits: Int,
) -> Bool {
  // ── Vanishing polynomial ───────────────────────────────────────────────────
  // Z_H(zeta) = zeta^(2^degree_bits) - 1  (shift = 1 so unshifted = zeta).
  let z_h = ext2.vanishing_poly(zeta, degree_bits)

  // ── g^{-1}: inverse of the subgroup generator (precomputed table lookup) ───
  let g_inv = gf.two_adic_generator_inverse(degree_bits)
  // ── Denominator inverses ───────────────────────────────────────────────
  let zeta_minus_1 = ext2.sub_base(zeta, 1)
  let zeta_minus_g_inv = ext2.sub_base(zeta, g_inv)
  when
    (
      ext2.inverse(zeta_minus_1),
      ext2.inverse(zeta_minus_g_inv),
      ext2.inverse(z_h),
    )
  is {
    // Any None means zeta hit the trace domain – valid proof won't do this.
    (Some(inv_zm1), Some(inv_zmg), Some(inv_zh)) -> {
      let is_first_row = ext2.mul(z_h, inv_zm1)
      let is_last_row = ext2.mul(z_h, inv_zmg)
      // is_transition = zeta - g^{-1}  (the DENOMINATOR of is_last_row, not 1 - is_last_row)
      let is_transition = zeta_minus_g_inv

      // ── Constraint terms ──────────────────────────────────────────────
      when (ov.trace_local, ov.trace_next, ov.quotient_chunks) is {
        ([tl0, tl1], [tn0, tn1], [chunk]) -> {
          // FibonacciAir constraints in eval order (air.rs:38–63).
          // when_first_row.assert_eq(local.left, a)
          let c0 = ext2.mul(is_first_row, ext2.sub_base(tl0, pis.a))
          // when_first_row.assert_eq(local.right, b)
          let c1 = ext2.mul(is_first_row, ext2.sub_base(tl1, pis.b))
          // when_transition.assert_eq(local.right, next.left)
          let c2 = ext2.mul(is_transition, ext2.sub(tl1, tn0))
          // when_transition.assert_eq(local.left + local.right, next.right)
          let c3 = ext2.mul(is_transition, ext2.sub(ext2.add(tl0, tl1), tn1))
          // when_last_row.assert_eq(local.right, x)
          let c4 = ext2.mul(is_last_row, ext2.sub_base(tl1, pis.x))

          // Horner accumulation: acc = alpha*acc + c  (VerifierConstraintFolder::assert_zero)
          let folded = ext2.fold_constraints([c0, c1, c2, c3, c4], alpha)

          // ── Quotient recomposition ────────────────────────────────────
          when recompose_one_chunk(chunk) is {
            None -> False
            Some(quotient) ->
              // folded * inv_vanishing == quotient
              ext2.eq_fast(ext2.mul(folded, inv_zh), quotient)
          }
        }
        // Wrong proof shape: trace_local/trace_next need 2 elements each;
        // quotient_chunks must have exactly 1 chunk for FibonacciAir.
        _ -> False
      }
    }
    _ -> False
  }
}

// ── Batch constraint verifier (multi-AIR) ─────────────────────────────────────

/// Per-instance constraint verification for the batch proof, including the
/// LogUp lookup constraints (batch-stark/src/verifier.rs:431-561 →
/// verify_constraints_with_lookups, verifier.rs:598-673, and the cross-instance
/// global cumulative check, verifier.rs:549-561).
///
/// Hard-specialised to the export_batch_proof.rs instance list:
///   [0] MulAir       (width 7, no public values; 2 local + 2 global lookups)
///   [1] FibonacciAir (width 2, public values [a, b, x]; 1 global lookup)
///
/// expected_cumulated / per_instance_challenges carry one sub-list per instance
/// in prover order: the global-lookup final values and the per-column (alpha,
/// beta) challenges (indexed 2*column), respectively.
///
/// Both instances share zeta and the folding alpha and the same trace domain
/// size, so the selectors coincide; they are still evaluated per instance.
/// Finally every global lookup belongs to the single "MulFib" interaction, so
/// all expected_cumulated values must sum to zero.
pub fn verify_constraints_batch(
  instances: List<InstanceOpenedValues<Ext2>>,
  public_values: List<List<Int>>,
  expected_cumulated: List<List<Ext2>>,
  per_instance_challenges: List<List<Ext2>>,
  zeta: Ext2,
  alpha: Ext2,
  degree_bits: Int,
) -> Bool {
  when
    (instances, public_values, expected_cumulated, per_instance_challenges)
  is {
    ([mul_ov, fib_ov], [[], [a, b, x]], [mul_ec, fib_ec], [mul_ch, fib_ch]) -> {
      let mul_ok =
        verify_mul_constraints(mul_ov, mul_ec, mul_ch, zeta, alpha, degree_bits)
      trace if mul_ok {
        @"mul constraints ok"
      } else {
        @"FAIL: MulAir constraints"
      }
      let fib_ok =
        verify_fib_constraints(
          fib_ov,
          a,
          b,
          x,
          fib_ec,
          fib_ch,
          zeta,
          alpha,
          degree_bits,
        )
      trace if fib_ok {
        @"fib constraints ok"
      } else {
        @"FAIL: FibonacciAir constraints"
      }
      // Cross-instance global cumulative check: all "MulFib" final values sum
      // to zero (verifier.rs:549-561). Every global lookup here is "MulFib".
      let cumul_ok =
        ext2.eq_fast(ext2.add(ext2.sum(mul_ec), ext2.sum(fib_ec)), ext2.zero)
      trace if cumul_ok {
        @"cumulative sum ok"
      } else {
        @"FAIL: global cumulative sum != 0"
      }
      mul_ok && fib_ok && cumul_ok
    }
    _ -> False
  }
}

/// MulAir constraints + LogUp lookups (export_batch_proof.rs eval order), at zeta.
///
/// Columns (width 7, reps = 2): [a0, b0, c0, a1, b1, c1, lut]. The lut column
/// (index 6) is the permutation of the 'a' columns used by the local lookups.
///
/// Constraint fold order (16 terms): the 6 AIR constraints, then the lookup
/// terms in registration order [rep0_local, rep0_global, rep1_local,
/// rep1_global]:
///   AIR, per rep (s = 3*rep): a*b-c (raw), is_transition*(b-next[s]),
///     is_transition*(a+b-next[s+1])
///   local  (cols 0, 2): [anchor, (s_next-s_local)*denom - numerator],
///     where the tuple is (receive a (+1), send lut (-1)) →
///     denom=(alpha-a)(alpha-lut), numerator=a-lut
///   global (cols 1, 3): [anchor, transition, final], tuple (a,b) sent (-1) →
///     denom=alpha-(a*beta+b), numerator=-1
fn verify_mul_constraints(
  ov: InstanceOpenedValues<Ext2>,
  expected: List<Ext2>,
  challenges: List<Ext2>,
  zeta: Ext2,
  alpha: Ext2,
  degree_bits: Int,
) -> Bool {
  let z_h = ext2.vanishing_poly(zeta, degree_bits)
  let g_inv = gf.two_adic_generator_inverse(degree_bits)
  let zeta_minus_1 = ext2.sub_base(zeta, 1)
  let is_transition = ext2.sub_base(zeta, g_inv)
  when
    (ext2.inverse(zeta_minus_1), ext2.inverse(is_transition), ext2.inverse(z_h))
  is {
    (Some(inv_zm1), Some(inv_zmg), Some(inv_zh)) -> {
      let is_first_row = ext2.mul(z_h, inv_zm1)
      let is_last_row = ext2.mul(z_h, inv_zmg)
      expect [l0, l1, l2, l3, l4, l5, l6] = ov.trace_local
      expect [n0, n1, _n2, n3, n4, _n5, _n6] = ov.trace_next
      expect [pl0, pl1, pl2, pl3, pl4, pl5, pl6, pl7] = ov.permutation_local
      expect [pn0, pn1, pn2, pn3, pn4, pn5, pn6, pn7] = ov.permutation_next
      // Per-column (alpha, beta), indexed 2*column; local betas unused.
      expect [ca0, _cb0, ca1, cb1, ca2, _cb2, ca3, cb3] = challenges
      expect [exp0, exp1] = expected

      // AIR constraints (6).
      let c0 = ext2.sub(ext2.mul(l0, l1), l2)
      let c1 = ext2.mul(is_transition, ext2.sub(l1, n0))
      let c2 = ext2.mul(is_transition, ext2.sub(ext2.add(l0, l1), n1))
      let c3 = ext2.sub(ext2.mul(l3, l4), l5)
      let c4 = ext2.mul(is_transition, ext2.sub(l4, n3))
      let c5 = ext2.mul(is_transition, ext2.sub(ext2.add(l3, l4), n4))

      // Running-sum columns (one per lookup), recomposed from base-flattened
      // openings at zeta (local) and zeta_next (next).
      let s0 = logup.recompose_col(pl0, pl1)
      let sn0 = logup.recompose_col(pn0, pn1)
      let s1 = logup.recompose_col(pl2, pl3)
      let sn1 = logup.recompose_col(pn2, pn3)
      let s2 = logup.recompose_col(pl4, pl5)
      let sn2 = logup.recompose_col(pn4, pn5)
      let s3 = logup.recompose_col(pl6, pl7)
      let sn3 = logup.recompose_col(pn6, pn7)

      // col0: rep0 local — receive a=l0 (+1), send lut=l6 (-1).
      let den_l0 = ext2.mul(ext2.sub(ca0, l0), ext2.sub(ca0, l6))
      let (a0t, l0t) =
        logup.local_terms(s0, sn0, den_l0, ext2.sub(l0, l6), is_first_row)
      // col1: rep0 global — send (a=l0, b=l1) (-1).
      let den_g0 = ext2.sub(ca1, logup.combine([l0, l1], cb1))
      let (a1t, t1t, f1t) =
        logup.global_terms(
          s1,
          sn1,
          den_g0,
          ext2.neg(ext2.one),
          exp0,
          is_first_row,
          is_transition,
          is_last_row,
        )
      // col2: rep1 local — receive a=l3 (+1), send lut=l6 (-1).
      let den_l1 = ext2.mul(ext2.sub(ca2, l3), ext2.sub(ca2, l6))
      let (a2t, l2t) =
        logup.local_terms(s2, sn2, den_l1, ext2.sub(l3, l6), is_first_row)
      // col3: rep1 global — send (a=l3, b=l4) (-1).
      let den_g1 = ext2.sub(ca3, logup.combine([l3, l4], cb3))
      let (a3t, t3t, f3t) =
        logup.global_terms(
          s3,
          sn3,
          den_g1,
          ext2.neg(ext2.one),
          exp1,
          is_first_row,
          is_transition,
          is_last_row,
        )

      let folded =
        ext2.fold_constraints(
          [
            c0, c1, c2, c3, c4, c5, a0t, l0t, a1t, t1t, f1t, a2t, l2t, a3t, t3t,
            f3t,
          ],
          alpha,
        )
      when recompose_two_chunks(ov.quotient_chunks, zeta, degree_bits) is {
        None -> False
        Some(quotient) -> ext2.eq_fast(ext2.mul(folded, inv_zh), quotient)
      }
    }
    _ -> False
  }
}

/// FibonacciAir constraints + its global LogUp lookup, at zeta.
///
/// Fold order (8 terms): the 5 AIR constraints (same as the uni-stark verifier)
/// then the global lookup [anchor, transition, final]. The lookup receives the
/// tuple (left, right) with multiplicity 2, so numerator = +2 and
/// denom = alpha - (left*beta + right).
fn verify_fib_constraints(
  ov: InstanceOpenedValues<Ext2>,
  a: Int,
  b: Int,
  x: Int,
  expected: List<Ext2>,
  challenges: List<Ext2>,
  zeta: Ext2,
  alpha: Ext2,
  degree_bits: Int,
) -> Bool {
  let z_h = ext2.vanishing_poly(zeta, degree_bits)
  let g_inv = gf.two_adic_generator_inverse(degree_bits)
  let zeta_minus_1 = ext2.sub_base(zeta, 1)
  let is_transition = ext2.sub_base(zeta, g_inv)
  when
    (ext2.inverse(zeta_minus_1), ext2.inverse(is_transition), ext2.inverse(z_h))
  is {
    (Some(inv_zm1), Some(inv_zmg), Some(inv_zh)) -> {
      let is_first_row = ext2.mul(z_h, inv_zm1)
      let is_last_row = ext2.mul(z_h, inv_zmg)
      expect [tl0, tl1] = ov.trace_local
      expect [tn0, tn1] = ov.trace_next
      expect [pl0, pl1] = ov.permutation_local
      expect [pn0, pn1] = ov.permutation_next
      expect [lalpha, lbeta] = challenges
      expect [exp0] = expected

      // AIR constraints (5), identical to the uni-stark FibonacciAir.
      let c0 = ext2.mul(is_first_row, ext2.sub_base(tl0, a))
      let c1 = ext2.mul(is_first_row, ext2.sub_base(tl1, b))
      let c2 = ext2.mul(is_transition, ext2.sub(tl1, tn0))
      let c3 = ext2.mul(is_transition, ext2.sub(ext2.add(tl0, tl1), tn1))
      let c4 = ext2.mul(is_last_row, ext2.sub_base(tl1, x))

      // Global lookup: receive (left, right) with multiplicity 2.
      let s0 = logup.recompose_col(pl0, pl1)
      let sn0 = logup.recompose_col(pn0, pn1)
      let den = ext2.sub(lalpha, logup.combine([tl0, tl1], lbeta))
      let (at, tt, ft) =
        logup.global_terms(
          s0,
          sn0,
          den,
          ext2.from_base(2),
          exp0,
          is_first_row,
          is_transition,
          is_last_row,
        )

      let folded =
        ext2.fold_constraints([c0, c1, c2, c3, c4, at, tt, ft], alpha)
      when recompose_two_chunks(ov.quotient_chunks, zeta, degree_bits) is {
        None -> False
        Some(quotient) -> ext2.eq_fast(ext2.mul(folded, inv_zh), quotient)
      }
    }
    _ -> False
  }
}

// ── Quotient recomposition ─────────────────────────────────────────────────────

/// Reconstruct quotient(zeta) from the 2-chunk split (num_quotient_chunks = 2,
/// used by the batch proof once lookups raise both AIRs to constraint degree 3).
///
/// The disjoint quotient domain is create_disjoint_domain(2^(degree_bits+1)) —
/// shift = Val::generator (7), size 2^(degree_bits+1) — split into two cosets of
/// size 2^degree_bits:
///   H_0: shift 7,            Z_{H_0}(x) = x^(2^db) - c
///   H_1: shift 7*g_{db+1},   Z_{H_1}(x) = x^(2^db) + c   (g_{db+1}^(2^db) = -1)
/// with c = 7^(2^db). Since first_point(H_i) = its shift:
///   Z_{H_1}(first_0 = 7)         = 2c
///   Z_{H_0}(first_1 = 7*g_{db+1}) = -2c
/// Feeds ext2.recompose_quotient (mirrors recompose_quotient_from_chunks,
/// uni-stark/src/verifier.rs:29-69).
fn recompose_two_chunks(
  chunks: List<List<Ext2>>,
  zeta: Ext2,
  degree_bits: Int,
) -> Option<Ext2> {
  // c = 7^(2^degree_bits) in the base field (c1 = 0 by construction).
  let c = ext2.exp_power_of_2(ext2.from_base(gf.generator), degree_bits).c0
  let two_c = gf.add(c, c)
  let z_pow = ext2.exp_power_of_2(zeta, degree_bits)
  let vps_at_zeta =
    [ext2.sub_base(z_pow, c), ext2.add(z_pow, ext2.from_base(c))]
  // Row-major [i*2+j]; only the off-diagonal entries (1, 2) are read.
  let vps_at_firsts =
    [ext2.zero, ext2.from_base(two_c), ext2.from_base(gf.neg(two_c)), ext2.zero]
  ext2.recompose_quotient(vps_at_zeta, vps_at_firsts, chunks, 2)
}

/// Reconstruct quotient(zeta) from a single chunk of DIMENSION=2 evaluations.
///
/// With num_quotient_chunks = 1, the Lagrange factor zp_0 = 1 (empty product),
/// so quotient = Σ_e basis(e) · chunk[e] = chunk[0] + (0,1) · chunk[1].
///
/// Mirrors recompose_quotient_from_chunks (verifier.rs:29–68) specialised to 1 chunk.
fn recompose_one_chunk(chunk: List<Ext2>) -> Option<Ext2> {
  when chunk is {
    [q0, q1] ->
      // basis(0) · q0 + basis(1) · q1 = q0 + (0,1) · q1
      Some(ext2.add(q0, ext2.mul(ext2.basis(1), q1)))
    _ -> None
  }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

test recompose_one_chunk_identity_coefficients() {
  // q0 = (1,0), q1 = (0,0): quotient = (1,0) + (0,1)*(0,0) = (1,0)
  let q0 = Ext2 { c0: 1, c1: 0 }
  let q1 = Ext2 { c0: 0, c1: 0 }
  recompose_one_chunk([q0, q1]) == Some(Ext2 { c0: 1, c1: 0 })
}

test recompose_one_chunk_basis1_contribution() {
  // q0 = (0,0), q1 = (1,0): quotient = (0,1) * (1,0)
  // (0,1) * (1,0): c0 = 0*1 + 7*1*0 = 0, c1 = 0*0 + 1*1 = 1 → (0,1)
  let q0 = Ext2 { c0: 0, c1: 0 }
  let q1 = Ext2 { c0: 1, c1: 0 }
  recompose_one_chunk([q0, q1]) == Some(Ext2 { c0: 0, c1: 1 })
}

test recompose_one_chunk_both_components() {
  // q0 = (1,0), q1 = (1,0): quotient = (1,0) + (0,1)*(1,0) = (1,0) + (0,1) = (1,1)
  let q0 = Ext2 { c0: 1, c1: 0 }
  let q1 = Ext2 { c0: 1, c1: 0 }
  recompose_one_chunk([q0, q1]) == Some(Ext2 { c0: 1, c1: 1 })
}

test recompose_one_chunk_wrong_size_returns_none() {
  recompose_one_chunk([]) == None
}

test recompose_one_chunk_one_element_returns_none() {
  recompose_one_chunk([Ext2 { c0: 1, c1: 0 }]) == None
}

test recompose_one_chunk_three_elements_returns_none() {
  let e = Ext2 { c0: 1, c1: 0 }
  recompose_one_chunk([e, e, e]) == None
}

test vanishing_poly_at_generator() {
  // g2 = two_adic_generator(2) has order 4 = 2^2.
  // Z_H(g2) for log_n=2: g2^4 - 1 = 1 - 1 = 0.
  let g2 = Ext2 { c0: gf.two_adic_generator(2), c1: 0 }
  ext2.eq_fast(ext2.vanishing_poly(g2, 2), ext2.zero)
}

test is_first_row_at_one() {
  // At point zeta = (1, 0), zeta - 1 = 0, so is_first_row denominator is 0.
  // verify_constraints should return False when zeta is on the trace domain.
  let zeta_one = Ext2 { c0: 1, c1: 0 }
  let ov =
    OpenedValues {
      trace_local: [ext2.zero, ext2.zero],
      trace_next: [ext2.zero, ext2.zero],
      quotient_chunks: [[ext2.zero, ext2.zero]],
    }
  let pis = FibPublicInputs { a: 0, b: 1, x: 1 }
  // zeta = 1 means zeta_minus_1 = 0 → inverse fails → False
  !verify_constraints(ov, pis, zeta_one, ext2.one, 13)
}

// The Milestone-A zero-trace batch tests were removed: with lookups enabled,
// an all-zero witness no longer satisfies the running-sum constraints (the
// numerator is the lookup multiplicity, which is non-zero), and a valid lookup
// witness is impractical to hand-construct. The batch path is exercised
// end-to-end by goldilocks_batch_proof_test.ak; the LogUp primitives have unit
// tests in logup.ak.

test verify_constraints_trivial_zero_trace() {
  // All trace values = 0, pis all = 0, alpha = any value.
  // Every constraint = 0 (since selectors times zero = zero).
  // folded = 0, quotient = 0.
  // Check: 0 * inv_zh == 0 → True (assuming zeta not on domain).
  // Use a known OOD point: zeta = (2, 0).
  let zeta = Ext2 { c0: 2, c1: 0 }
  let ov =
    OpenedValues {
      trace_local: [ext2.zero, ext2.zero],
      trace_next: [ext2.zero, ext2.zero],
      quotient_chunks: [[ext2.zero, ext2.zero]],
    }
  let pis = FibPublicInputs { a: 0, b: 0, x: 0 }
  verify_constraints(ov, pis, zeta, ext2.one, 13)
}
