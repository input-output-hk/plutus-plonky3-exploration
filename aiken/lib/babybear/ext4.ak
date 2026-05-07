use babybear/field as f

/// BinomialExtensionField<BabyBear, 4>: F_p[X] / (X^4 - W), W = 11.
///
/// Elements are represented as (c0, c1, c2, c3) ↔ c0 + c1·α + c2·α² + c3·α³
/// where α^4 = W = 11 in BabyBear (from BabyBearParameters::W).
///
/// Only operations required by the uni-stark verifier are included:
///
///   recompose_quotient_from_chunks  →  pow, sub, inverse, product, scale, basis, sum
///   verify_constraints / folder     →  mul, add, sub, scale, eq
///   quartic_inv (D=4)               →  tower decomposition through the quadratic subfield
/// Non-residue W: the extension satisfies α^4 = W.
/// From BabyBearParameters: const W: BabyBear = BabyBear::new(11).
const w: Int = 11

// ── Type ──────────────────────────────────────────────────────────────────────

/// An element of BinomialExtensionField<BabyBear, 4>.
/// Each component is a canonical BabyBear element in [0, p).
pub type Ext4 {
  c0: Int,
  c1: Int,
  c2: Int,
  c3: Int,
}

// ── Constants ─────────────────────────────────────────────────────────────────

pub const zero: Ext4 = Ext4 { c0: 0, c1: 0, c2: 0, c3: 0 }

pub const one: Ext4 = Ext4 { c0: 1, c1: 0, c2: 0, c3: 0 }

// ── Constructors ──────────────────────────────────────────────────────────────

/// Embed a BabyBear element into the extension as the constant term.
pub fn from_base(x: Int) -> Ext4 {
  Ext4 { c0: x, c1: 0, c2: 0, c3: 0 }
}

/// Return the i-th standard basis vector e_i (0 ≤ i ≤ 3).
///
/// Used in `recompose_quotient_from_chunks` as `SC::Challenge::ith_basis_element(e_i)`.
/// Each quotient chunk has DIMENSION=4 base-field coefficients; they are
/// reassembled into an extension element via Σ_i (e_i * coeff_i).
pub fn basis(i: Int) -> Ext4 {
  if i == 0 {
    Ext4 { c0: 1, c1: 0, c2: 0, c3: 0 }
  } else if i == 1 {
    Ext4 { c0: 0, c1: 1, c2: 0, c3: 0 }
  } else if i == 2 {
    Ext4 { c0: 0, c1: 0, c2: 1, c3: 0 }
  } else {
    Ext4 { c0: 0, c1: 0, c2: 0, c3: 1 }
  }
}

// ── Comparison ────────────────────────────────────────────────────────────────

/// Assume all the elements are in [0, p)
pub fn eq_fast(a: Ext4, b: Ext4) -> Bool {
  a.c0 == b.c0 && a.c1 == b.c1 && a.c2 == b.c2 && a.c3 == b.c3
}

// ── Arithmetic ────────────────────────────────────────────────────────────────

/// Negate every component.
pub fn neg(a: Ext4) -> Ext4 {
  Ext4 { c0: f.neg(a.c0), c1: f.neg(a.c1), c2: f.neg(a.c2), c3: f.neg(a.c3) }
}

/// Component-wise addition.
/// Used in: constraint accumulator, quotient chunk sum, vanishing poly products.
pub fn add(a: Ext4, b: Ext4) -> Ext4 {
  Ext4 {
    c0: f.add(a.c0, b.c0),
    c1: f.add(a.c1, b.c1),
    c2: f.add(a.c2, b.c2),
    c3: f.add(a.c3, b.c3),
  }
}

/// Component-wise subtraction.
/// Used in: vanishing poly `zeta^n - 1`, constraint expressions.
pub fn sub(a: Ext4, b: Ext4) -> Ext4 {
  Ext4 {
    c0: f.sub(a.c0, b.c0),
    c1: f.sub(a.c1, b.c1),
    c2: f.sub(a.c2, b.c2),
    c3: f.sub(a.c3, b.c3),
  }
}

/// Scale an extension element by a BabyBear scalar (multiplies each component).
///
/// Used in:
///   - `recompose_quotient_from_chunks`: `ith_basis_element(e_i) * coeff_i`
///     where coeff_i is a Val<SC> (base field element).
///   - `verify_constraints`: `folded_constraints * sels.inv_vanishing`
///     where inv_vanishing is a base field element.
pub fn scale(a: Ext4, s: Int) -> Ext4 {
  Ext4 {
    c0: f.mul(a.c0, s),
    c1: f.mul(a.c1, s),
    c2: f.mul(a.c2, s),
    c3: f.mul(a.c3, s),
  }
}

/// Full extension × extension multiplication in F[X]/(X^4 - W).
///
/// Direct translation of `quartic_mul` (binomial_extension.rs):
///   res[0] = a0·b0 + W·(a1·b3 + a2·b2 + a3·b1)
///   res[1] = a0·b1 + a1·b0 + W·(a2·b3 + a3·b2)
///   res[2] = a0·b2 + a1·b1 + a2·b0 + W·a3·b3
///   res[3] = a0·b3 + a1·b2 + a2·b1 + a3·b0
///
/// Used in: zps product, `alpha^i * constraint_i` in the constraint folder.
pub fn mul(a: Ext4, b: Ext4) -> Ext4 {
  let a0 = a.c0
  let a1 = a.c1
  let a2 = a.c2
  let a3 = a.c3
  let b0 = b.c0
  let b1 = b.c1
  let b2 = b.c2
  let b3 = b.c3
  // Reductions mod W (the terms that wrap around X^4 → W)
  let wc0 = f.add(f.add(f.mul(a1, b3), f.mul(a2, b2)), f.mul(a3, b1))
  let wc1 = f.add(f.mul(a2, b3), f.mul(a3, b2))
  Ext4 {
    c0: f.add(f.mul(a0, b0), f.mul(w, wc0)),
    c1: f.add(f.add(f.mul(a0, b1), f.mul(a1, b0)), f.mul(w, wc1)),
    c2: f.add(
      f.add(f.add(f.mul(a0, b2), f.mul(a1, b1)), f.mul(a2, b0)),
      f.mul(w, f.mul(a3, b3)),
    ),
    c3: f.add(
      f.add(f.add(f.mul(a0, b3), f.mul(a1, b2)), f.mul(a2, b1)),
      f.mul(a3, b0),
    ),
  }
}

/// Binary square-and-multiply exponentiation.
/// Used in: `vanishing_poly_at_point(zeta)` = zeta^n - 1.
pub fn pow(base: Ext4, exp: Int) -> Ext4 {
  do_pow(base, exp, one)
}

fn do_pow(base: Ext4, exp: Int, acc: Ext4) -> Ext4 {
  if exp == 0 {
    acc
  } else if exp % 2 == 1 {
    do_pow(mul(base, base), exp / 2, mul(acc, base))
  } else {
    do_pow(mul(base, base), exp / 2, acc)
  }
}

/// Multiplicative inverse using the tower decomposition from `quartic_inv`.
///
/// Used in: `recompose_quotient_from_chunks` — each zp_i factor contains
///   `vanishing_poly_at_point(domain_i.first_point()).inverse()`.
///
/// Algorithm (matches quartic_inv, binomial_extension.rs §11.3.6b):
///   Given a = a0 + a1·X + a2·X² + a3·X³ = (a0 + a2·X²) + (a1 + a3·X²)·X,
///   Write a = P + Q·X  with P = a0 + a2·Y,  Q = a1 + a3·Y,  Y = X².
///   Tower: F < F[Y]/(Y²-W) < F[X]/(X⁴-W).
///
///   1. norm = P² - Q²·Y  in F[Y]/(Y²-W):
///        norm_0 = a0² + W·a2² - 2W·a1·a3
///        norm_1 = 2·a0·a2 - a1² - W·a3²
///
///   2. norm_inv = norm⁻¹ in F[Y]/(Y²-W)  (quadratic inverse):
///        denom = norm_0² - W·norm_1²   (base field element)
///        norm_inv = (norm_0, -norm_1) / denom
///
///   3. a⁻¹ = (P - Q·X) · norm_inv
///        out_evn = (a0, a2) × norm_inv  (quadratic mul)
///        out_odd = (a1, a3) × norm_inv  (quadratic mul)
///        result  = [out_evn[0], -out_odd[0], out_evn[1], -out_odd[1]]
pub fn inverse(a: Ext4) -> Option<Ext4> {
  let a0 = a.c0
  let a1 = a.c1
  let a2 = a.c2
  let a3 = a.c3
  if a0 == 0 && a1 == 0 && a2 == 0 && a3 == 0 {
    None
  } else {
    // Step 1: norm in the quadratic subfield F[Y]/(Y²-W)
    let w_c1_c3 = f.mul(w, f.mul(a1, a3))
    let norm_0 =
      f.sub(
        f.add(f.mul(a0, a0), f.mul(w, f.mul(a2, a2))),
        f.add(w_c1_c3, w_c1_c3),
      )
    let c0_c2 = f.mul(a0, a2)
    let norm_1 =
      f.sub(f.sub(f.add(c0_c2, c0_c2), f.mul(a1, a1)), f.mul(w, f.mul(a3, a3)))
    // Step 2: quadratic inverse of (norm_0, norm_1)
    //   denom = norm_0² - W·norm_1²
    let denom = f.sub(f.mul(norm_0, norm_0), f.mul(w, f.mul(norm_1, norm_1)))
    when f.inverse_gcd(denom) is {
      None -> None
      Some(inv_d) -> {
        // norm_inv = (norm_0 / denom,  -norm_1 / denom)
        let in0 = f.mul(norm_0, inv_d)
        let in1 = f.mul(f.neg(norm_1), inv_d)
        // Step 3: the inverse of a is given by:
        // a⁻¹ = ((a0 + a2·X²) - (a1 + a3·X²)·X)·norm⁻¹
        //  = (a0 + a2·X²)·norm⁻¹ - (a1 + a3·X²)·norm⁻¹·X
        // = (a0 + a2 Y) (in0 + in1 Y) - (a1 + a3 Y) (in0 + in1 Y) X
        // = a0 * in0 + a2 * in1 * w + (a0 * in1 + a2 * in0) Y -
        //   (a1 * in0 + a3 * in1 * w + (a1 * in1 + a3 * in0) Y) X       as Y^2 = w
        // =  a0 * in0 + a2 * in1 * w
        //  - (a1 * in0 + a3 * in1 * w) X
        //  + (a0 * in1 + a2 * in0) X^2
        //  - (a1 * in1 + a3 * in0) X^3
        let evn0 = f.add(f.mul(a0, in0), f.mul(w, f.mul(a2, in1)))
        let evn1 = f.add(f.mul(a0, in1), f.mul(a2, in0))
        let odd0 = f.add(f.mul(a1, in0), f.mul(w, f.mul(a3, in1)))
        let odd1 = f.add(f.mul(a1, in1), f.mul(a3, in0))
        Some(Ext4 { c0: evn0, c1: f.neg(odd0), c2: evn1, c3: f.neg(odd1) })
      }
    }
  }
}

// ── List operations ───────────────────────────────────────────────────────────

/// Sum a list of extension elements.
/// Used in: `sum::<SC::Challenge>()` over quotient chunk contributions.
pub fn sum(xs: List<Ext4>) -> Ext4 {
  do_sum(xs, zero)
}

fn do_sum(xs: List<Ext4>, acc: Ext4) -> Ext4 {
  when xs is {
    [] -> acc
    [x, ..rest] -> do_sum(rest, add(acc, x))
  }
}

/// Product of a list of extension elements.
/// Used in: building zp_i as a product of vanishing-poly ratios.
pub fn product(xs: List<Ext4>) -> Ext4 {
  do_product(xs, one)
}

fn do_product(xs: List<Ext4>, acc: Ext4) -> Ext4 {
  when xs is {
    [] -> acc
    [x, ..rest] -> do_product(rest, mul(acc, x))
  }
}

// ── STARK-specific helpers ────────────────────────────────────────────────────

/// Evaluate the vanishing polynomial Z_H at `zeta`:  zeta^n - 1.
///
/// Used in both `recompose_quotient_from_chunks` (for zp_i weights)
/// and `verify_constraints` (via `selectors_at_point`).
pub fn vanishing_poly(zeta: Ext4, n: Int) -> Ext4 {
  sub(pow(zeta, n), one)
}

/// Fold constraints with the random challenge `alpha` (from the constraint folder).
///
/// Computes Σ_i alpha^i · constraints[i], the core accumulation in
/// `VerifierConstraintFolder`:  `accumulator = alpha * accumulator + constraint`.
///
/// `constraints` is ordered from i=0 (lowest power of alpha) upward.
pub fn fold_constraints(constraints: List<Ext4>, alpha: Ext4) -> Ext4 {
  do_fold(constraints, alpha, zero)
}

fn do_fold(cs: List<Ext4>, alpha: Ext4, acc: Ext4) -> Ext4 {
  when cs is {
    [] -> acc
    [c, ..rest] -> do_fold(rest, alpha, add(mul(acc, alpha), c))
  }
}

/// Reconstruct the quotient evaluation from its chunks.
///
/// Mirrors `recompose_quotient_from_chunks` (uni-stark/src/verifier.rs):
///   For each chunk i, compute zp_i = Π_{j≠i} [Z_{H_j}(zeta) / Z_{H_j}(first_i)].
///   Then quotient(zeta) = Σ_i zp_i · (Σ_e basis(e) · chunk_i[e]).
///
/// Inputs:
///   - `vps_at_zeta`   : Z_{H_i}(zeta) for each chunk domain i
///   - `vps_at_firsts` : Z_{H_i}(first_j) for each pair (i, j), row-major
///     i.e., vps_at_firsts[i * num_chunks + j] = Z_{H_j}(first_i)
///   - `chunks`        : quotient_chunks, each a list of 4 base-field coefficients
pub fn recompose_quotient(
  vps_at_zeta: List<Ext4>,
  vps_at_firsts: List<Ext4>,
  chunks: List<List<Int>>,
  num_chunks: Int,
) -> Option<Ext4> {
  let zps_opt = compute_zps(vps_at_zeta, vps_at_firsts, num_chunks, 0, [])
  when zps_opt is {
    None -> None
    Some(zps) -> Some(sum(zip_mul_chunk(zps, chunks, 0)))
  }
}

fn compute_zps(
  vps_zeta: List<Ext4>,
  vps_firsts: List<Ext4>,
  num_chunks: Int,
  i: Int,
  acc: List<Ext4>,
) -> Option<List<Ext4>> {
  when vps_zeta is {
    [] -> Some(reverse(acc))
    [_, ..rest_zeta] ->
      when zp_i(vps_zeta, vps_firsts, num_chunks, i) is {
        None -> None
        Some(zp) ->
          compute_zps(rest_zeta, vps_firsts, num_chunks, i + 1, [zp, ..acc])
      }
  }
}

fn zp_i(
  vps_zeta: List<Ext4>,
  vps_firsts: List<Ext4>,
  num_chunks: Int,
  i: Int,
) -> Option<Ext4> {
  do_zp_i(vps_zeta, vps_firsts, num_chunks, i, 0, one)
}

fn do_zp_i(
  vps_zeta: List<Ext4>,
  vps_firsts: List<Ext4>,
  n: Int,
  i: Int,
  j: Int,
  acc: Ext4,
) -> Option<Ext4> {
  when vps_zeta is {
    [] -> Some(acc)
    [vp_j_zeta, ..rest] ->
      if i == j {
        do_zp_i(rest, vps_firsts, n, i, j + 1, acc)
      } else {
        // vp_j(first_i) = vps_firsts[i * n + j]
        when nth(vps_firsts, i * n + j) is {
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

fn zip_mul_chunk(zps: List<Ext4>, chunks: List<List<Int>>, i: Int) -> List<Ext4> {
  when zps is {
    [] -> []
    [zp, ..rest_zps] ->
      when chunks is {
        [] -> []
        [ch, ..rest_chunks] -> {
          let next_i = i + 1
          [
            mul(zp, chunk_to_ext(ch, 0)),
            ..zip_mul_chunk(rest_zps, rest_chunks, next_i)
          ]
        }
      }
  }
}

/// Reconstruct an extension element from 4 base-field coefficients using basis vectors.
/// Σ_e basis(e) * coeff[e]
fn chunk_to_ext(coeffs: List<Int>, i: Int) -> Ext4 {
  when coeffs is {
    [] -> zero
    [c, ..rest] -> add(scale(basis(i), c), chunk_to_ext(rest, i + 1))
  }
}

fn nth(xs: List<a>, i: Int) -> Option<a> {
  when xs is {
    [] -> None
    [x, ..rest] ->
      if i == 0 {
        Some(x)
      } else {
        nth(rest, i - 1)
      }
  }
}

fn reverse(xs: List<a>) -> List<a> {
  do_reverse(xs, [])
}

fn do_reverse(xs: List<a>, acc: List<a>) -> List<a> {
  when xs is {
    [] -> acc
    [x, ..rest] -> do_reverse(rest, [x, ..acc])
  }
}

// ── Tests ─────────────────────────────────────────────────────────────────────
test equal() {
  let a = Ext4 { c0: 1, c1: 2, c2: 3, c3: 4 }
  eq_fast(a, a)
}

test add_zero() {
  let a = Ext4 { c0: 1, c1: 2, c2: 3, c3: 4 }
  eq_fast(add(a, zero), a)
}

test mul_one() {
  let a = Ext4 { c0: 5, c1: 6, c2: 7, c3: 8 }
  eq_fast(mul(a, one), a)
}

test mul_commutative() {
  let a = Ext4 { c0: 2, c1: 3, c2: 0, c3: 0 }
  let b = Ext4 { c0: 5, c1: 0, c2: 7, c3: 0 }
  eq_fast(mul(a, b), mul(b, a))
}

test mul_uses_w() {
  // (α) * (α) = α² → c2 = 1, others 0
  let alpha = Ext4 { c0: 0, c1: 1, c2: 0, c3: 0 }
  eq_fast(mul(alpha, alpha), Ext4 { c0: 0, c1: 0, c2: 1, c3: 0 })
}

test alpha_4_equals_w() {
  // α^4 = W = 11 (defining relation of the extension)
  let alpha = Ext4 { c0: 0, c1: 1, c2: 0, c3: 0 }
  eq_fast(pow(alpha, 4), from_base(w))
}

test inverse_round_trip() {
  let a = Ext4 { c0: 1, c1: 2, c2: 3, c3: 4 }
  when inverse(a) is {
    None -> False
    Some(inv) -> eq_fast(mul(a, inv), one)
  }
}

test inverse_of_base_element() {
  // inverse of a base element embedded in the extension
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
  // For a domain of size n with generator g, g^n = 1, so Z_H(g) = g^n - 1 = 0.
  // Use g = 1 (trivially g^1 = 1): Z_{H1}(1) = 1^1 - 1 = 0.
  eq_fast(vanishing_poly(one, 1), zero)
}

test fold_single_constraint() {
  // fold([c], alpha) = 0 * alpha + c = c
  let c = Ext4 { c0: 3, c1: 0, c2: 0, c3: 0 }
  let alpha = Ext4 { c0: 5, c1: 1, c2: 0, c3: 0 }
  eq_fast(fold_constraints([c], alpha), c)
}

test fold_two_constraints() {
  // fold([c0, c1], alpha) = (0*alpha + c0)*alpha + c1 = c0*alpha + c1
  let c0 = from_base(2)
  let c1 = from_base(3)
  let alpha = from_base(5)
  // expected = 2*5 + 3 = 13
  eq_fast(fold_constraints([c0, c1], alpha), from_base(13))
}

test sum_basis_vectors() {
  // Σ_i basis(i) = 1 + α + α² + α³ (with all coefficients 1)
  let s = sum([basis(0), basis(1), basis(2), basis(3)])
  eq_fast(s, Ext4 { c0: 1, c1: 1, c2: 1, c3: 1 })
}

test product_of_one() {
  let a = Ext4 { c0: 2, c1: 3, c2: 0, c3: 0 }
  eq_fast(product([one, a, one]), a)
}

test add_loop_10() {
  let a = Ext4 { c0: 2, c1: 3, c2: 5, c3: 7 }
  let b = Ext4 { c0: 12, c1: 13, c2: 15, c3: 17 }
  do_add_loop(a, b, 10)
}

fn do_add_loop(a: Ext4, b: Ext4, remaining: Int) -> Bool {
  if remaining == 0 {
    True
  } else {
    let c = add(a, b)
    do_add_loop(c, b, remaining - 1)
  }
}

test mul_loop_15418() {
  let a = Ext4 { c0: 2, c1: 3, c2: 5, c3: 7 }
  let b = Ext4 { c0: 12, c1: 13, c2: 15, c3: 17 }
  do_mul_loop(a, b, 15418)
}

fn do_mul_loop(a: Ext4, b: Ext4, remaining: Int) -> Bool {
  if remaining == 0 {
    True
  } else {
    let c = mul(a, b)
    do_mul_loop(c, b, remaining - 1)
  }
}

test inverse_loop_1600() {
  let a = Ext4 { c0: 2, c1: 3, c2: 5, c3: 7 }
  do_inverse_loop(a, 1600)
}

fn do_inverse_loop(a: Ext4, remaining: Int) -> Bool {
  if remaining == 0 {
    True
  } else {
    when inverse(a) is {
      None -> False
      Some(c) -> do_inverse_loop(c, remaining - 1)
    }
  }
}
