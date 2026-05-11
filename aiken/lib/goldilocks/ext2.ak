use goldilocks/field as f

/// BinomialExtensionField<Goldilocks, 2>: F_p[X] / (X^2 - W), W = 7.
///
/// Elements: (c0, c1) ↔ c0 + c1·α  where α^2 = W = 7.
///
/// From goldilocks/src/extension.rs:
///   `const W: Goldilocks = Goldilocks::new(7)` (degree-2 extension).
///   Verifiable: x^2 - 7 is irreducible over GF(p).
///
/// Operations mirror those in `binomial_extension.rs` (quadratic_mul, quadratic_inv)
/// and are used by the uni-stark verifier path:
///   selectors_at_point  →  pow, sub, inverse, mul, from_base
///   verify_constraints  →  mul, add, sub, scale, eq
///   recompose_quotient  →  pow, sub, inverse, product, scale, basis, sum
/// Non-residue W: extension satisfies α^2 = W = 7.
const w: Int = 7

// ── Type ──────────────────────────────────────────────────────────────────────

/// An element of BinomialExtensionField<Goldilocks, 2>.
/// Each component is a canonical Goldilocks element in [0, p).
pub type Ext2 {
  c0: Int,
  c1: Int,
}

// ── Constants ─────────────────────────────────────────────────────────────────

pub const zero: Ext2 = Ext2 { c0: 0, c1: 0 }

pub const one: Ext2 = Ext2 { c0: 1, c1: 0 }

// ── Constructors ──────────────────────────────────────────────────────────────

/// Embed a Goldilocks element into the extension as the constant term.
pub fn from_base(x: Int) -> Ext2 {
  Ext2 { c0: x, c1: 0 }
}

/// The i-th standard basis vector e_i (0 ≤ i ≤ 1).
/// Used to reassemble quotient chunks: Σ_i basis(i) * coeff_i.
pub fn basis(i: Int) -> Ext2 {
  if i == 0 {
    Ext2 { c0: 1, c1: 0 }
  } else {
    Ext2 { c0: 0, c1: 1 }
  }
}

// ── Comparison ────────────────────────────────────────────────────────────────

/// Structural equality of extension elements (component-wise).
/// Assume all the elements are in [0, p)
pub fn eq_fast(a: Ext2, b: Ext2) -> Bool {
  a.c0 == b.c0 && a.c1 == b.c1
}

// ── Arithmetic ────────────────────────────────────────────────────────────────

/// Negate both components.
pub fn neg(a: Ext2) -> Ext2 {
  Ext2 { c0: f.neg(a.c0), c1: f.neg(a.c1) }
}

/// Component-wise addition.
pub fn add(a: Ext2, b: Ext2) -> Ext2 {
  Ext2 { c0: f.add(a.c0, b.c0), c1: f.add(a.c1, b.c1) }
}

/// Component-wise subtraction.
pub fn sub(a: Ext2, b: Ext2) -> Ext2 {
  Ext2 { c0: f.sub(a.c0, b.c0), c1: f.sub(a.c1, b.c1) }
}

/// Multiply extension element by a Goldilocks base-field scalar.
pub fn scale(a: Ext2, s: Int) -> Ext2 {
  Ext2 { c0: f.mul(a.c0, s), c1: f.mul(a.c1, s) }
}

/// Full extension × extension multiplication in F[X]/(X^2 - W), W = 7.
///
/// (a0 + a1·α)(b0 + b1·α) = (a0·b0 + W·a1·b1) + (a0·b1 + a1·b0)·α
///
/// Direct translation of `quadratic_mul` (binomial_extension.rs, degree-2 case):
///   res[0] = a0·b0 + W·a1·b1
///   res[1] = a0·b1 + a1·b0
pub fn mul(a: Ext2, b: Ext2) -> Ext2 {
  Ext2 {
    c0: f.add(f.mul(a.c0, b.c0), f.mul(w, f.mul(a.c1, b.c1))),
    c1: f.add(f.mul(a.c0, b.c1), f.mul(a.c1, b.c0)),
  }
}

/// Multiplicative inverse in F[X]/(X^2 - W), W = 7.
///
/// For a = a0 + a1·α, the norm is:
///   N(a) = a0^2 - W·a1^2  (= a · ā  where ā = a0 - a1·α)
///
/// a^{-1} = ā / N(a) = (a0/N, -a1/N)
///
/// Direct translation of `quadratic_inv` (binomial_extension.rs, degree-2 case).
pub fn inverse(a: Ext2) -> Option<Ext2> {
  let a0 = a.c0
  let a1 = a.c1
  if a0 == 0 && a1 == 0 {
    None
  } else {
    let norm = f.sub(f.mul(a0, a0), f.mul(w, f.mul(a1, a1)))
    when f.inverse(norm) is {
      None -> None
      Some(inv_norm) ->
        Some(Ext2 { c0: f.mul(a0, inv_norm), c1: f.mul(f.neg(a1), inv_norm) })
    }
  }
}

/// Binary square-and-multiply exponentiation over the extension field.
pub fn pow(base: Ext2, exp: Int) -> Ext2 {
  do_pow(base, exp, one)
}

fn do_pow(base: Ext2, exp: Int, acc: Ext2) -> Ext2 {
  if exp == 0 {
    acc
  } else if exp % 2 == 1 {
    do_pow(mul(base, base), exp / 2, mul(acc, base))
  } else {
    do_pow(mul(base, base), exp / 2, acc)
  }
}

/// Repeated squaring: compute base^{2^k} with exactly k squarings.
pub fn exp_power_of_2(base: Ext2, k: Int) -> Ext2 {
  if k == 0 {
    base
  } else {
    exp_power_of_2(mul(base, base), k - 1)
  }
}

// ── List operations ───────────────────────────────────────────────────────────

/// Sum a list of extension elements.
pub fn sum(xs: List<Ext2>) -> Ext2 {
  do_sum(xs, zero)
}

fn do_sum(xs: List<Ext2>, acc: Ext2) -> Ext2 {
  when xs is {
    [] -> acc
    [x, ..rest] -> do_sum(rest, add(acc, x))
  }
}

/// Product of a list of extension elements.
pub fn product(xs: List<Ext2>) -> Ext2 {
  do_product(xs, one)
}

fn do_product(xs: List<Ext2>, acc: Ext2) -> Ext2 {
  when xs is {
    [] -> acc
    [x, ..rest] -> do_product(rest, mul(acc, x))
  }
}

// ── STARK-specific helpers ────────────────────────────────────────────────────

/// Evaluate vanishing polynomial Z_H at `zeta`: zeta^n - 1.
/// For a domain of size n = 2^log_n, uses repeated squaring.
pub fn vanishing_poly(zeta: Ext2, log_n: Int) -> Ext2 {
  sub(exp_power_of_2(zeta, log_n), one)
}

/// Fold constraints with alpha (Horner accumulation).
/// acc = 0; for each c: acc = alpha * acc + c
/// Ordered from lowest alpha power to highest.
pub fn fold_constraints(constraints: List<Ext2>, alpha: Ext2) -> Ext2 {
  do_fold(constraints, alpha, zero)
}

fn do_fold(cs: List<Ext2>, alpha: Ext2, acc: Ext2) -> Ext2 {
  when cs is {
    [] -> acc
    [c, ..rest] -> do_fold(rest, alpha, add(mul(acc, alpha), c))
  }
}

/// Reconstruct quotient(zeta) from its chunks.
///
/// Mirrors `recompose_quotient_from_chunks` (uni-stark/src/verifier.rs):
///   zp_i = Π_{j≠i} [Z_{H_j}(zeta) * Z_{H_j}(first_i)^{-1}]
///   quotient = Σ_i zp_i * chunk_as_ext2(chunk_i)
///
/// Arguments:
///   vps_at_zeta   – [Z_{H_i}(zeta)] for each chunk domain i
///   vps_at_firsts – Z_{H_j}(first_i) for each pair, row-major [i*n+j]
///   chunks        – quotient_chunks, each a list of 2 base-field coefficients
///   num_chunks    – number of chunks
pub fn recompose_quotient(
  vps_at_zeta: List<Ext2>,
  vps_at_firsts: List<Ext2>,
  chunks: List<List<Int>>,
  num_chunks: Int,
) -> Option<Ext2> {
  when compute_zps(vps_at_zeta, vps_at_firsts, num_chunks, 0, []) is {
    None -> None
    Some(zps) -> Some(sum(zip_mul_chunk(zps, chunks)))
  }
}

fn compute_zps(
  vps_zeta: List<Ext2>,
  vps_firsts: List<Ext2>,
  num_chunks: Int,
  i: Int,
  acc: List<Ext2>,
) -> Option<List<Ext2>> {
  when vps_zeta is {
    [] -> Some(list_reverse(acc))
    [_, ..rest_zeta] ->
      when zp_i(vps_zeta, vps_firsts, num_chunks, i) is {
        None -> None
        Some(zp) ->
          compute_zps(rest_zeta, vps_firsts, num_chunks, i + 1, [zp, ..acc])
      }
  }
}

fn zp_i(
  vps_zeta: List<Ext2>,
  vps_firsts: List<Ext2>,
  num_chunks: Int,
  i: Int,
) -> Option<Ext2> {
  do_zp_i(vps_zeta, vps_firsts, num_chunks, i, 0, one)
}

fn do_zp_i(
  vps_zeta: List<Ext2>,
  vps_firsts: List<Ext2>,
  n: Int,
  i: Int,
  j: Int,
  acc: Ext2,
) -> Option<Ext2> {
  when vps_zeta is {
    [] -> Some(acc)
    [vp_j_zeta, ..rest] ->
      if i == j {
        do_zp_i(rest, vps_firsts, n, i, j + 1, acc)
      } else {
        when list_nth(vps_firsts, i * n + j) is {
          None -> None
          Some(vp_j_first_i) ->
            when inverse(vp_j_first_i) is {
              None -> None
              Some(inv) ->
                do_zp_i(
                  rest,
                  vps_firsts,
                  n,
                  i,
                  j + 1,
                  mul(acc, mul(vp_j_zeta, inv)),
                )
            }
        }
      }
  }
}

fn zip_mul_chunk(zps: List<Ext2>, chunks: List<List<Int>>) -> List<Ext2> {
  when zps is {
    [] -> []
    [zp, ..rest_zps] ->
      when chunks is {
        [] -> []
        [ch, ..rest_chunks] ->
          [mul(zp, chunk_to_ext(ch, 0)), ..zip_mul_chunk(rest_zps, rest_chunks)]
      }
  }
}

fn chunk_to_ext(coeffs: List<Int>, i: Int) -> Ext2 {
  when coeffs is {
    [] -> zero
    [c, ..rest] -> add(scale(basis(i), c), chunk_to_ext(rest, i + 1))
  }
}

fn list_nth(xs: List<a>, i: Int) -> Option<a> {
  when xs is {
    [] -> None
    [x, ..rest] ->
      if i == 0 {
        Some(x)
      } else {
        list_nth(rest, i - 1)
      }
  }
}

fn list_reverse(xs: List<a>) -> List<a> {
  do_reverse(xs, [])
}

fn do_reverse(xs: List<a>, acc: List<a>) -> List<a> {
  when xs is {
    [] -> acc
    [x, ..rest] -> do_reverse(rest, [x, ..acc])
  }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

test add_zero() {
  let a = Ext2 { c0: 1, c1: 2 }
  eq_fast(add(a, zero), a)
}

test mul_one() {
  let a = Ext2 { c0: 5, c1: 6 }
  eq_fast(mul(a, one), a)
}

test mul_commutative() {
  let a = Ext2 { c0: 2, c1: 3 }
  let b = Ext2 { c0: 5, c1: 7 }
  eq_fast(mul(a, b), mul(b, a))
}

test alpha_squared_equals_w() {
  // α^2 = W = 7 (the defining relation of the degree-2 extension)
  let alpha = Ext2 { c0: 0, c1: 1 }
  eq_fast(mul(alpha, alpha), from_base(w))
}

test mul_explicit() {
  // (1 + α)(1 + α) = 1 + 2α + α^2 = 1 + 7 + 2α = 8 + 2α
  let a = Ext2 { c0: 1, c1: 1 }
  eq_fast(mul(a, a), Ext2 { c0: 8, c1: 2 })
}

test pow_2_equals_mul() {
  let a = Ext2 { c0: 3, c1: 5 }
  eq_fast(pow(a, 2), mul(a, a))
}

test exp_power_of_2_k0() {
  let a = Ext2 { c0: 3, c1: 5 }
  eq_fast(exp_power_of_2(a, 0), a)
}

test exp_power_of_2_k1() {
  let a = Ext2 { c0: 3, c1: 5 }
  eq_fast(exp_power_of_2(a, 1), mul(a, a))
}

test inverse_round_trip() {
  let a = Ext2 { c0: 1, c1: 2 }
  when inverse(a) is {
    None -> False
    Some(inv) -> eq_fast(mul(a, inv), one)
  }
}

test inverse_base_element() {
  let a = from_base(7)
  when inverse(a) is {
    None -> False
    Some(inv) -> eq_fast(mul(a, inv), one)
  }
}

test inverse_of_zero() {
  inverse(zero) == None
}

test vanishing_poly_at_root() {
  // Domain of size 2 (log_n = 1): generator g = p-1.
  // g^2 = 1, so Z_H(g) = g^2 - 1 = 0.
  let g = from_base(f.prime - 1)
  eq_fast(vanishing_poly(g, 1), zero)
}

test fold_two_constraints() {
  // fold([c0, c1], alpha) = c0 * alpha + c1
  let c0 = from_base(2)
  let c1 = from_base(3)
  let alpha = from_base(5)
  eq_fast(fold_constraints([c0, c1], alpha), from_base(13))
}

test scale_by_zero() {
  let a = Ext2 { c0: 1, c1: 2 }
  eq_fast(scale(a, 0), zero)
}

test w_is_7() {
  // Goldilocks degree-2 extension uses W = 7.
  w == 7
}

test neg_round_trip() {
  let a = Ext2 { c0: 100, c1: 200 }
  eq_fast(add(a, neg(a)), zero)
}

// ── Cost benchmarks ───────────────────────────────────────────────────────────

test add_cost_100() {
  let a = Ext2 { c0: 2, c1: 3 }
  let b = Ext2 { c0: 12, c1: 13 }
  do_add_loop(a, b, 100)
}

fn do_add_loop(a: Ext2, b: Ext2, remaining: Int) -> Bool {
  if remaining == 0 {
    True
  } else {
    let c = add(a, b)
    do_add_loop(c, b, remaining - 1)
  }
}

test mul_loop_100() {
  let a = Ext2 { c0: f.prime - 2, c1: 3 }
  let b = Ext2 { c0: 12, c1: f.prime - 13 }
  do_mul_loop(a, b, 100)
}

fn do_mul_loop(a: Ext2, b: Ext2, remaining: Int) -> Bool {
  if remaining == 0 {
    True
  } else {
    let c = mul(a, b)
    do_mul_loop(c, b, remaining - 1)
  }
}

test inverse_loop_100() {
  let a = Ext2 { c0: 2, c1: 3 }
  do_inverse_loop(a, 100)
}

fn do_inverse_loop(a: Ext2, remaining: Int) -> Bool {
  if remaining == 0 {
    True
  } else {
    when inverse(a) is {
      None -> False
      Some(c) -> do_inverse_loop(c, remaining - 1)
    }
  }
}
