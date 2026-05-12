use mersenne31/field as f

/// BinomialExtensionField<Mersenne31, 3>: F_p[X] / (X^3 - W), W = 5.
///
/// Elements: (c0, c1, c2) ↔ c0 + c1·α + c2·α²  where α³ = 5.
///
/// From `BinomiallyExtendable<3>` for Mersenne31:
///   W = 5, DTH_ROOT = 1513477735.
/// Used as `CircleChallenge = BinomialExtensionField<CircleVal, 3>` in the
/// Circle PCS Fibonacci STARK test.
///
/// Multiplication uses Karatsuba (cubic_mul in binomial_extension.rs):
///   c0 = a0b0 + W·((a1+a2)(b1+b2) - a1b1 - a2b2)
///   c1 = (a0+a1)(b0+b1) - a0b0 - a1b1 + W·a2b2
///   c2 = (a0+a2)(b0+b2) - a0b0 - a2b2 + a1b1
///
/// Inversion (cubic_inv in binomial_extension.rs):
const w: Int = 5

// ── Type ──────────────────────────────────────────────────────────────────────

pub type Ext3 {
  c0: Int,
  c1: Int,
  c2: Int,
}

// ── Constants ─────────────────────────────────────────────────────────────────

pub const zero: Ext3 = Ext3 { c0: 0, c1: 0, c2: 0 }

pub const one: Ext3 = Ext3 { c0: 1, c1: 0, c2: 0 }

// ── Constructors ──────────────────────────────────────────────────────────────

pub fn from_base(x: Int) -> Ext3 {
  Ext3 { c0: x, c1: 0, c2: 0 }
}

pub fn basis(i: Int) -> Ext3 {
  if i == 0 {
    Ext3 { c0: 1, c1: 0, c2: 0 }
  } else if i == 1 {
    Ext3 { c0: 0, c1: 1, c2: 0 }
  } else {
    Ext3 { c0: 0, c1: 0, c2: 1 }
  }
}

// ── Comparison ────────────────────────────────────────────────────────────────
/// Assume all the elements are in [0, p)
pub fn eq_fast(a: Ext3, b: Ext3) -> Bool {
  a.c0 == b.c0 && a.c1 == b.c1 && a.c2 == b.c2
}

// ── Arithmetic ────────────────────────────────────────────────────────────────

pub fn neg(a: Ext3) -> Ext3 {
  Ext3 { c0: f.neg(a.c0), c1: f.neg(a.c1), c2: f.neg(a.c2) }
}

pub fn add(a: Ext3, b: Ext3) -> Ext3 {
  Ext3 { c0: f.add(a.c0, b.c0), c1: f.add(a.c1, b.c1), c2: f.add(a.c2, b.c2) }
}

pub fn sub(a: Ext3, b: Ext3) -> Ext3 {
  Ext3 { c0: f.sub(a.c0, b.c0), c1: f.sub(a.c1, b.c1), c2: f.sub(a.c2, b.c2) }
}

pub fn scale(a: Ext3, s: Int) -> Ext3 {
  Ext3 { c0: f.mul(a.c0, s), c1: f.mul(a.c1, s), c2: f.mul(a.c2, s) }
}

/// Karatsuba cubic multiplication in F[X]/(X³ - W), W = 5.
pub fn mul(a: Ext3, b: Ext3) -> Ext3 {
  let a0 = a.c0
  let a1 = a.c1
  let a2 = a.c2
  let b0 = b.c0
  let b1 = b.c1
  let b2 = b.c2

  let a0b0 = f.mul(a0, b0)
  let a1b1 = f.mul(a1, b1)
  let a2b2 = f.mul(a2, b2)

  // c0 = a0b0 + W·((a1+a2)(b1+b2) - a1b1 - a2b2)
  let cross01 = f.sub(f.sub(f.mul(f.add(a1, a2), f.add(b1, b2)), a1b1), a2b2)
  let c0 = f.add(a0b0, f.mul(w, cross01))

  // c1 = (a0+a1)(b0+b1) - a0b0 - a1b1 + W·a2b2
  let cross00 = f.sub(f.sub(f.mul(f.add(a0, a1), f.add(b0, b1)), a0b0), a1b1)
  let c1 = f.add(cross00, f.mul(w, a2b2))

  // c2 = (a0+a2)(b0+b2) - a0b0 - a2b2 + a1b1
  let cross02 = f.sub(f.sub(f.mul(f.add(a0, a2), f.add(b0, b2)), a0b0), a2b2)
  let c2 = f.add(cross02, a1b1)

  Ext3 { c0, c1, c2 }
}

/// cubic_square from binomial_extension.rs
pub fn square(a: Ext3) -> Ext3 {
  let a0 = a.c0
  let a1 = a.c1
  let a2 = a.c2

  let a1_double = f.add(a1, a1)
  let a2w = f.mul(a2, w)
  let c0 = f.add(f.mul(a0, a0), f.mul(a1_double, a2w))
  let c1 = f.add(f.mul(a2w, a2), f.mul(a0, a1_double))
  let c2 = {
    let t = f.mul(a0, a2)
    f.add(f.mul(a1, a1), f.add(t, t))
  }

  Ext3 { c0, c1, c2 }
}

/// Binary exponentiation over the extension field.
pub fn pow(base: Ext3, exp: Int) -> Ext3 {
  do_pow(base, exp, one)
}

fn do_pow(base: Ext3, exp: Int, acc: Ext3) -> Ext3 {
  if exp == 0 {
    acc
  } else if exp % 2 == 1 {
    do_pow(mul(base, base), exp / 2, mul(acc, base))
  } else {
    do_pow(mul(base, base), exp / 2, acc)
  }
}

/// Repeated squaring: base^{2^k} with exactly k squarings.
pub fn exp_power_of_2(base: Ext3, k: Int) -> Ext3 {
  if k == 0 {
    base
  } else {
    exp_power_of_2(mul(base, base), k - 1)
  }
}

/// Multiplicative inverse (cubic_inv in binomial_extension.rs).
/// a0_square = a0^2
/// a1_square = a1^2
/// a2w = w*a2
/// a0a1 = a0*a1
/// scalar = (a0^3 + w * a1^3+w^2 a2^3-3 * w * a0*a1*a2)^-1
///        = (a0_square * a0 + w * a1 * a1_square + a2w^2 * a2 - 3 * a2w * a0a1).inverse
/// res1 = scalar * (a0_square - a1*a2w)
/// res2 = scalar * (a2w * a2 - a0a1)
/// res3 = scalar * (a1_square - a0*a2)
pub fn inverse(a: Ext3) -> Option<Ext3> {
  let a0 = a.c0
  let a1 = a.c1
  let a2 = a.c2
  if a0 == 0 && a1 == 0 && a2 == 0 {
    None
  } else {
    let a0_square = f.mul(a0, a0)
    let a1_square = f.mul(a1, a1)
    let a2w = f.mul(w, a2)
    let a0a1 = f.mul(a0, a1)

    let scalar =
      f.sub(
        f.add(
          f.add(f.mul(a0_square, a0), f.mul(w, f.mul(a1, a1_square))),
          f.mul(a2, f.mul(a2w, a2w)),
        ),
        f.mul(3, f.mul(a2w, a0a1)),
      )

    when f.inverse(scalar) is {
      None -> None
      Some(inv_scalar) ->
        Some(
          Ext3 {
            c0: f.mul(inv_scalar, f.sub(a0_square, f.mul(a1, a2w))),
            c1: f.mul(inv_scalar, f.sub(f.mul(a2w, a2), a0a1)),
            c2: f.mul(inv_scalar, f.sub(a1_square, f.mul(a0, a2))),
          },
        )
    }
  }
}

// ── List utilities ────────────────────────────────────────────────────────────

pub fn sum(xs: List<Ext3>) -> Ext3 {
  do_sum(xs, zero)
}

fn do_sum(xs: List<Ext3>, acc: Ext3) -> Ext3 {
  when xs is {
    [] -> acc
    [x, ..rest] -> do_sum(rest, add(acc, x))
  }
}

pub fn product(xs: List<Ext3>) -> Ext3 {
  do_product(xs, one)
}

fn do_product(xs: List<Ext3>, acc: Ext3) -> Ext3 {
  when xs is {
    [] -> acc
    [x, ..rest] -> do_product(rest, mul(acc, x))
  }
}

// ── STARK helpers ─────────────────────────────────────────────────────────────

/// Fold constraints with alpha via Horner accumulation.
pub fn fold_constraints(constraints: List<Ext3>, alpha: Ext3) -> Ext3 {
  do_fold(constraints, alpha, zero)
}

fn do_fold(cs: List<Ext3>, alpha: Ext3, acc: Ext3) -> Ext3 {
  when cs is {
    [] -> acc
    [c, ..rest] -> do_fold(rest, alpha, add(mul(acc, alpha), c))
  }
}

/// Reconstruct quotient(zeta) from its chunks (basis decomposition).
/// chunks: list of lists of 3 base-field coefficients.
pub fn recompose_quotient(
  vps_at_zeta: List<Ext3>,
  vps_at_firsts: List<Int>,
  chunks: List<List<Int>>,
  num_chunks: Int,
) -> Option<Ext3> {
  when compute_zps(vps_at_zeta, vps_at_firsts, num_chunks, 0, []) is {
    None -> None
    Some(zps) -> Some(sum(zip_mul_chunk(zps, chunks)))
  }
}

fn compute_zps(
  vps_zeta: List<Ext3>,
  vps_firsts: List<Int>,
  num_chunks: Int,
  i: Int,
  acc: List<Ext3>,
) -> Option<List<Ext3>> {
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
  vps_zeta: List<Ext3>,
  vps_firsts: List<Int>,
  num_chunks: Int,
  i: Int,
) -> Option<Ext3> {
  do_zp_i(vps_zeta, vps_firsts, num_chunks, i, 0, one)
}

fn do_zp_i(
  vps_zeta: List<Ext3>,
  vps_firsts: List<Int>,
  n: Int,
  i: Int,
  j: Int,
  acc: Ext3,
) -> Option<Ext3> {
  when vps_zeta is {
    [] -> Some(acc)
    [vp_j_zeta, ..rest] ->
      if i == j {
        do_zp_i(rest, vps_firsts, n, i, j + 1, acc)
      } else {
        when list_nth_int(vps_firsts, i * n + j) is {
          None -> None
          Some(vp_j_first_i_base) -> {
            // first_point is base-field; embed as Ext3 then invert
            let vp_j_first_i = from_base(vp_j_first_i_base)
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
}

fn zip_mul_chunk(zps: List<Ext3>, chunks: List<List<Int>>) -> List<Ext3> {
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

fn chunk_to_ext(coeffs: List<Int>, i: Int) -> Ext3 {
  when coeffs is {
    [] -> zero
    [c, ..rest] -> add(scale(basis(i), c), chunk_to_ext(rest, i + 1))
  }
}

fn list_nth_int(xs: List<Int>, i: Int) -> Option<Int> {
  when xs is {
    [] -> None
    [x, ..rest] ->
      if i == 0 {
        Some(x)
      } else {
        list_nth_int(rest, i - 1)
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
  let a = Ext3 { c0: 1, c1: 2, c2: 3 }
  eq_fast(add(a, zero), a)
}

test mul_one() {
  let a = Ext3 { c0: 5, c1: 6, c2: 7 }
  eq_fast(mul(a, one), a)
}

test alpha_cubed_equals_w() {
  // α³ = W = 5
  let alpha = Ext3 { c0: 0, c1: 1, c2: 0 }
  eq_fast(pow(alpha, 3), from_base(w))
}

test alpha_squared() {
  let alpha = Ext3 { c0: 0, c1: 1, c2: 0 }
  eq_fast(mul(alpha, alpha), Ext3 { c0: 0, c1: 0, c2: 1 })
}

test mul_commutative() {
  let a = Ext3 { c0: 2, c1: 3, c2: 0 }
  let b = Ext3 { c0: 5, c1: 0, c2: 7 }
  eq_fast(mul(a, b), mul(b, a))
}

test inverse_round_trip() {
  let a = Ext3 { c0: 1, c1: 2, c2: 3 }
  when inverse(a) is {
    None -> False
    Some(inv) -> eq_fast(mul(a, inv), one)
  }
}

test inverse_zero_is_none() {
  inverse(zero) == None
}

test inverse_base_element() {
  when inverse(from_base(7)) is {
    None -> False
    Some(inv) -> eq_fast(mul(from_base(7), inv), one)
  }
}

test fold_two() {
  let c0 = from_base(2)
  let c1 = from_base(3)
  let alpha = from_base(5)
  // Horner: alpha * c0 + c1 = 10 + 3 = 13
  eq_fast(fold_constraints([c0, c1], alpha), from_base(13))
}

test w_is_5() {
  w == 5
}

test square_zero() {
  eq_fast(square(zero), zero)
}

test square_one() {
  eq_fast(square(one), one)
}

// square must agree with mul(a, a)
test square_equals_mul_self() {
  let a = Ext3 { c0: 1, c1: 2, c2: 3 }
  eq_fast(square(a), mul(a, a))
}

// concrete: (1,2,3)² = (61, 49, 10) over Z (all < p, so no reduction)
test square_concrete() {
  let a = Ext3 { c0: 1, c1: 2, c2: 3 }
  eq_fast(square(a), Ext3 { c0: 61, c1: 49, c2: 10 })
}

// ── Cost benchmarks ───────────────────────────────────────────────────────────

test add_cost_100() {
  let a = Ext3 { c0: 2, c1: 3, c2: 5 }
  let b = Ext3 { c0: 12, c1: 13, c2: 15 }
  do_add_loop(a, b, 100)
}

fn do_add_loop(a: Ext3, b: Ext3, remaining: Int) -> Bool {
  if remaining == 0 {
    True
  } else {
    let c = add(a, b)
    do_add_loop(c, b, remaining - 1)
  }
}

test sub_cost_100() {
  let a = Ext3 { c0: 2, c1: 3, c2: 5 }
  let b = Ext3 { c0: 12, c1: 13, c2: 15 }
  do_sub_loop(a, b, 100)
}

fn do_sub_loop(a: Ext3, b: Ext3, remaining: Int) -> Bool {
  if remaining == 0 {
    True
  } else {
    let c = sub(a, b)
    do_add_loop(c, b, remaining - 1)
  }
}

test mul_cost_100() {
  let a = Ext3 { c0: 2, c1: 3, c2: 5 }
  let b = Ext3 { c0: 12, c1: 13, c2: 15 }
  do_mul_loop(a, b, 100)
}

fn do_mul_loop(a: Ext3, b: Ext3, remaining: Int) -> Bool {
  if remaining == 0 {
    True
  } else {
    let c = mul(a, b)
    do_mul_loop(c, b, remaining - 1)
  }
}

test square_cost_100() {
  let a = Ext3 { c0: 12, c1: 13, c2: 15 }
  do_square_loop(a, 100)
}

fn do_square_loop(a: Ext3, remaining: Int) -> Bool {
  if remaining == 0 {
    True
  } else {
    do_square_loop(square(a), remaining - 1)
  }
}

test inverse_cost_100() {
  let a = Ext3 { c0: 2, c1: 3, c2: 5 }
  do_inverse_loop(a, 100)
}

fn do_inverse_loop(a: Ext3, remaining: Int) -> Bool {
  if remaining == 0 {
    True
  } else {
    when inverse(a) is {
      None -> False
      Some(c) -> do_inverse_loop(c, remaining - 1)
    }
  }
}
