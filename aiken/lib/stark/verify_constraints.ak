use goldilocks/ext2.{Ext2}
use goldilocks/field as gf
use stark/proof.{FibPublicInputs, OpenedValues}

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

  // ── g^{-1}: inverse of the subgroup generator in the base field ───────────
  let g = gf.two_adic_generator(degree_bits)
  when gf.inverse(g) is {
    None -> False
    Some(g_inv) -> {
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
              let c3 =
                ext2.mul(is_transition, ext2.sub(ext2.add(tl0, tl1), tn1))
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
  }
}

// ── Quotient recomposition ─────────────────────────────────────────────────────

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
