use goldilocks/ext2.{Ext2}

/// LogUp lookup-argument constraint terms for the batch verifier.
///
/// Ports the per-lookup constraints that `LogUpGadget::eval_update` adds to the
/// AIR (p3-lookup logup.rs:156-265). Each lookup owns one running-sum (aux)
/// column `s`; the verifier evaluates the running-sum constraints at the OOD
/// point zeta and folds them in alongside the AIR constraints.
///
/// The element-combination challenge `beta` and running-sum challenge `alpha`
/// are sampled per lookup (logup.rs:209-211); they are NOT the constraint-
/// folding alpha. Local lookups draw fresh challenges, global lookups share
/// challenges by interaction name (common.rs get_perm_challenges).
/// Recompose one base-flattened running-sum column (a DIMENSION = 2 group of
/// OOD openings) into its ext value: v0 * basis(0) + v1 * basis(1) = v0 + v1*X.
///
/// Mirrors the `recompose` closure in batch-stark/verifier.rs:465-485 for
/// DIMENSION = 2 — the same basis dot-product used for quotient chunks.
pub fn recompose_col(v0: Ext2, v1: Ext2) -> Ext2 {
  ext2.add(v0, ext2.mul(ext2.basis(1), v1))
}

/// combine_elements (logup.rs:72-92): Horner fold of one lookup tuple with the
/// element-combination challenge `beta`:
///   [e0, e1, ..., e_{k-1}]  ->  e0*beta^{k-1} + e1*beta^{k-2} + ... + e_{k-1}
/// For a single-element tuple this is just e0 (beta unused).
pub fn combine(elements: List<Ext2>, beta: Ext2) -> Ext2 {
  do_combine(elements, beta, ext2.zero)
}

fn do_combine(elements: List<Ext2>, beta: Ext2, acc: Ext2) -> Ext2 {
  when elements is {
    [] -> acc
    [e, ..rest] -> do_combine(rest, beta, ext2.add(e, ext2.mul(acc, beta)))
  }
}

/// The three constraint terms of a GLOBAL lookup (eval_update with an
/// expected_cumulated value, logup.rs:225-253), in the order the gadget emits
/// them so they fold consistently with the prover:
///   anchor     = is_first_row  * s_local
///   transition = is_transition * ((s_next - s_local) * denom - numerator)
///   final      = is_last_row   * ((expected - s_local) * denom - numerator)
///
/// `denom` is the common denominator ∏(alpha - combined_i) and `numerator` is
/// ∑ m_i ∏_{j≠i}(alpha - combined_j) of the lookup's rational sum; the caller
/// computes them from the tuple(s) and signed multiplicities.
pub fn global_terms(
  s_local: Ext2,
  s_next: Ext2,
  denom: Ext2,
  numerator: Ext2,
  expected: Ext2,
  is_first_row: Ext2,
  is_transition: Ext2,
  is_last_row: Ext2,
) -> (Ext2, Ext2, Ext2) {
  let anchor = ext2.mul(is_first_row, s_local)
  let transition =
    ext2.mul(
      is_transition,
      ext2.sub(ext2.mul(ext2.sub(s_next, s_local), denom), numerator),
    )
  let final_term =
    ext2.mul(
      is_last_row,
      ext2.sub(ext2.mul(ext2.sub(expected, s_local), denom), numerator),
    )
  (anchor, transition, final_term)
}

/// The two constraint terms of a LOCAL lookup (eval_update without an
/// expected_cumulated value, logup.rs:228, 263), in emit order:
///   anchor = is_first_row * s_local
///   local  = (s_next - s_local) * denom - numerator     (holds on every row;
///            the last-row wraparound makes the un-gated form valid)
pub fn local_terms(
  s_local: Ext2,
  s_next: Ext2,
  denom: Ext2,
  numerator: Ext2,
  is_first_row: Ext2,
) -> (Ext2, Ext2) {
  let anchor = ext2.mul(is_first_row, s_local)
  let local = ext2.sub(ext2.mul(ext2.sub(s_next, s_local), denom), numerator)
  (anchor, local)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

test recompose_col_basis() {
  // v0 + v1*X with v0 = (3,0), v1 = (1,0) → (3,0) + (0,1) = (3,1).
  let v0 = Ext2 { c0: 3, c1: 0 }
  let v1 = Ext2 { c0: 1, c1: 0 }
  ext2.eq_fast(recompose_col(v0, v1), Ext2 { c0: 3, c1: 1 })
}

test combine_single_element_ignores_beta() {
  let e = Ext2 { c0: 5, c1: 7 }
  let beta = Ext2 { c0: 99, c1: 11 }
  ext2.eq_fast(combine([e], beta), e)
}

test combine_two_elements_is_horner() {
  // [a, b] -> a*beta + b
  let a = Ext2 { c0: 2, c1: 0 }
  let b = Ext2 { c0: 3, c1: 0 }
  let beta = Ext2 { c0: 4, c1: 0 }
  // 2*4 + 3 = 11
  ext2.eq_fast(combine([a, b], beta), Ext2 { c0: 11, c1: 0 })
}

test global_terms_zero_on_satisfying_row() {
  // With s_local = s_next = 0 on a non-boundary row (is_first = is_last = 0,
  // is_transition = 1) the transition term is -numerator; pick numerator = 0
  // so all three terms vanish.
  let (a, t, f) =
    global_terms(
      ext2.zero,
      ext2.zero,
      ext2.one,
      ext2.zero,
      ext2.zero,
      ext2.zero,
      ext2.one,
      ext2.zero,
    )
  ext2.eq_fast(a, ext2.zero) && ext2.eq_fast(t, ext2.zero) && ext2.eq_fast(
    f,
    ext2.zero,
  )
}
