// ── Constants ─────────────────────────────────────────────────────────────────

/// BabyBear prime field: F_p where p = 2^31 - 2^27 + 1 = 2013265921.
///
/// All functions accept and return canonical representatives in [0, p).
/// Inputs outside this range produce unspecified results unless `from_int`
/// is used to normalise them first.
/// The BabyBear prime: 2^31 - 2^27 + 1.
pub const prime: Int = 2013265921

/// Multiplicative generator of the field (order = p - 1).
pub const generator: Int = 31

/// The 2-adicity of the field: 2^27 divides p - 1 but 2^28 does not.
pub const two_adicity: Int = 27

// ── Validation ────────────────────────────────────────────────────────────────

/// True iff `a` is a canonical field element (in [0, p)).
pub fn is_valid(a: Int) -> Bool {
  a >= 0 && a < prime
}

/// Reduce any integer into [0, p).
pub fn from_int(n: Int) -> Int {
  n % prime
}

// ── Arithmetic ────────────────────────────────────────────────────────────────

/// (a + b) mod p.
pub fn add(a: Int, b: Int) -> Int {
  ( a + b ) % prime
}

/// (a - b) mod p.
pub fn sub(a: Int, b: Int) -> Int {
  // a - b + p is in [1, 2p-1], always positive, so % is Euclidean here.
  ( a - b ) % prime
}

/// (a * b) mod p.
pub fn mul(a: Int, b: Int) -> Int {
  a * b % prime
}

/// -a mod p.
pub fn neg(a: Int) -> Int {
  -a % prime
}

/// a^2 mod p.
pub fn square(a: Int) -> Int {
  mul(a, a)
}

/// a^exp mod p via binary square-and-multiply. Requires exp >= 0.
pub fn pow(base: Int, exp: Int) -> Int {
  do_pow(base % prime, exp, 1)
}

fn do_pow(base: Int, exp: Int, acc: Int) -> Int {
  if exp == 0 {
    acc
  } else if exp % 2 == 1 {
    do_pow(mul(base, base), exp / 2, mul(acc, base))
  } else {
    do_pow(mul(base, base), exp / 2, acc)
  }
}

/// Multiplicative inverse via Fermat's little theorem: a^(p-2) mod p.
/// Returns `None` for the zero element.
pub fn inverse_fermat(a: Int) -> Option<Int> {
  if a == 0 {
    None
  } else {
    Some(pow(a, prime - 2))
  }
}

/// a / b = a * b^{-1} mod p.  Returns `None` if b == 0.
pub fn div_fermat(a: Int, b: Int) -> Option<Int> {
  when inverse_fermat(b) is {
    None -> None
    Some(b_inv) -> Some(mul(a, b_inv))
  }
}

// ── GCD-based inverse ─────────────────────────────────────────────────────────

/// Modular inverse via the **Extended Euclidean Algorithm**.
///
/// Runs in O(log p) ≈ 31–44 tail-recursive steps, each doing one integer
/// division.  No exponentiation — contrast with `inverse` which calls
/// `pow(a, p−2)` requiring ~90 field multiplications.
///
/// Relation to Plonky3: `gcd_inversion_prime_field_32` (util/src/lib.rs) is a
/// *binary GCD* variant optimised for 32-bit hardware (only bit-shifts and
/// subtractions, no division).  See `inverse_binary_gcd` below for a direct
/// port of that algorithm.
pub fn inverse_gcd(a: Int) -> Option<Int> {
  if a == 0 {
    None
  } else {
    Some(do_eea(prime, a, 0, 1))
  }
}

/// Tail-recursive EEA state.
///
/// Loop invariant (where a0 is the original input to `inverse_gcd`):
///   prev_r ≡ prev_s · a0  (mod p)
///   r      ≡      s · a0  (mod p)
///
/// When r reaches 0, prev_r = gcd = 1, so prev_s · a0 ≡ 1 (mod p).
fn do_eea(prev_r: Int, r: Int, prev_s: Int, s: Int) -> Int {
  if r == 0 {
    from_int(prev_s)
  } else {
    let q = prev_r / r
    do_eea(r, prev_r - q * r, s, prev_s - q * s)
  }
}

/// GCD-based field division.  Returns `None` if b == 0.
pub fn div_gcd(a: Int, b: Int) -> Option<Int> {
  when inverse_gcd(b) is {
    None -> None
    Some(b_inv) -> Some(mul(a, b_inv))
  }
}

/// Modular inverse via the **binary GCD** algorithm from Plonky3.
///
/// A direct translation of `gcd_inversion_prime_field_32` (util/src/lib.rs).
/// Runs exactly `2 * 31 - 2 = 60` iterations using only odd-test, subtract,
/// halve, and double — no division inside the loop.
///
/// Loop invariant (i = 60 - remaining steps):
///   2^i · a ≡ u · a0  (mod p)
///   2^i · b ≡ v · a0  (mod p)
///
/// After 60 iterations b = 1, so v ≡ 2^60 · a0^{-1} (mod p).
/// The final step corrects this scaling: a0^{-1} = v · 2^{-60} mod p.
///
/// In Plonky3 the correction is free (absorbed into Montgomery form).
/// Here it requires one field multiplication by the constant 2^{-60} mod p,
/// computed as `pow(2, prime - 61)`.  Precompute and pass this constant as a
/// parameter if you call this in a tight loop.
pub fn inverse_binary_gcd(a0: Int) -> Option<Int> {
  if a0 == 0 {
    None
  } else {
    let v = do_binary_gcd(a0, prime, 1, 0, 60)
    // v may be negative; reduce to canonical [0, p).
    let v_can = from_int(v)
    // 2^{-60} mod p = 975175684  (verified: 1709039071 * 975175684 mod p = 1)
    Some(mul(v_can, 975175684))
  }
}

/// Tail-recursive binary GCD kernel.
///
/// State carried: a, b (non-negative GCD sequence), u, v (signed cofactors),
/// steps remaining.
///
/// Each step (mirroring the Rust source):
///   if a is odd:
///     if a < b: swap (a,b) and (u,v)
///     a -= b;  u -= v          -- a is now even
///   a >>= 1;  v <<= 1
fn do_binary_gcd(a: Int, b: Int, u: Int, v: Int, steps: Int) -> Int {
  if steps == 0 {
    v
  } else if a % 2 == 1 {
    if a < b {
      // Swap (a,b),(u,v) then subtract: new state before shift = (b-a, a, v-u, u)
      do_binary_gcd(( b - a ) / 2, a, v - u, u * 2, steps - 1)
    } else {
      // Subtract only: new state before shift = (a-b, b, u-v, v)
      do_binary_gcd(( a - b ) / 2, b, u - v, v * 2, steps - 1)
    }
  } else {
    // a is even: shift a right, double v to restore the invariant
    do_binary_gcd(a / 2, b, u, v * 2, steps - 1)
  }
}

// ── Polynomial & vector utilities ─────────────────────────────────────────────

/// Evaluate a polynomial at `point` using Horner's method.
///
/// `coeffs` must be ordered from the **highest** degree term to the constant:
///   [c_n, c_{n-1}, ..., c_1, c_0]
/// represents  c_n * x^n + ... + c_1 * x + c_0.
pub fn eval_poly(coeffs: List<Int>, point: Int) -> Int {
  do_eval_poly(coeffs, point, 0)
}

fn do_eval_poly(coeffs: List<Int>, point: Int, acc: Int) -> Int {
  when coeffs is {
    [] -> acc
    [c, ..rest] -> do_eval_poly(rest, point, add(mul(acc, point), c))
  }
}

/// Sum of a list of field elements.
pub fn sum(xs: List<Int>) -> Int {
  do_sum(xs, 0)
}

fn do_sum(xs: List<Int>, acc: Int) -> Int {
  when xs is {
    [] -> acc
    [x, ..rest] -> do_sum(rest, add(acc, x))
  }
}

/// Dot product of two equally-sized field element lists.
pub fn inner_product(a: List<Int>, b: List<Int>) -> Int {
  do_inner_product(a, b, 0)
}

fn do_inner_product(a: List<Int>, b: List<Int>, acc: Int) -> Int {
  when a is {
    [] -> acc
    [x, ..rest_a] ->
      when b is {
        [] -> acc
        [y, ..rest_b] -> do_inner_product(rest_a, rest_b, add(acc, mul(x, y)))
      }
  }
}

// ── Tests ─────────────────────────────────────────────────────────────────────
test basic_mod() {
  // modulus results always within [0, p)
  7 % 7 == 0 && 11 % 7 == 4 && -3 % 7 == 4 && -10 % 7 == 4
}

test add_wraps_at_prime() {
  add(prime - 1, 1) == 0
}

test add_no_wrap() {
  add(3, 4) == 7
}

test sub_wraps_at_zero() {
  sub(0, 1) == prime - 1
}

test sub_same_elements() {
  sub(42, 42) == 0
}

test mul_small() {
  mul(2, 3) == 6
}

test mul_example_from_rust_tests() {
  // 0x34167c58 * 0x61f3207b = 0x1b5c8046 in BabyBear (from baby_bear.rs tests)
  mul(0x34167c58, 0x61f3207b) == 0x1b5c8046
}

test neg_one() {
  neg(1) == prime - 1
}

test neg_zero() {
  neg(0) == 0
}

test neg_inverts_add() {
  add(5, neg(5)) == 0
}

test square_example() {
  square(4) == 16
}

test pow_small_exponent() {
  pow(2, 10) == 1024
}

test pow_zero_exponent() {
  pow(99, 0) == 1
}

test pow_one_exponent() {
  pow(99, 1) == 99
}

test inverse_fermat_round_trip() {
  when inverse_fermat(7) is {
    None -> False
    Some(inv) -> mul(7, inv) == 1
  }
}

test inverse_fermat_of_zero() {
  inverse_fermat(0) == None
}

test div_fermat_exact() {
  // 6 / 3 = 2
  when div_fermat(6, 3) is {
    None -> False
    Some(result) -> result == 2
  }
}

test div_fermat_by_zero() {
  div_fermat(5, 0) == None
}

test eval_poly_constant() {
  // P(x) = 7  =>  P(100) = 7
  eval_poly([7], 100) == 7
}

test eval_poly_linear() {
  // P(x) = 2x + 3  =>  P(5) = 13
  eval_poly([2, 3], 5) == 13
}

test eval_poly_quadratic() {
  // P(x) = x^2 + x + 1  =>  P(2) = 7
  eval_poly([1, 1, 1], 2) == 7
}

test eval_poly_at_zero() {
  // P(0) = constant term regardless of higher coefficients
  eval_poly([5, 3, 1], 0) == 1
}

test inner_product_basic() {
  // [1,2,3] · [4,5,6] = 4 + 10 + 18 = 32
  inner_product([1, 2, 3], [4, 5, 6]) == 32
}

test inner_product_empty() {
  inner_product([], []) == 0
}

test sum_basic() {
  sum([1, 2, 3, 4]) == 10
}

test from_int_negative() {
  from_int(-1) == prime - 1
}

test from_int_large() {
  from_int(prime + 5) == 5
}

test inverse_gcd_round_trip() {
  when inverse_gcd(7) is {
    None -> False
    Some(inv) -> mul(7, inv) == 1
  }
}

test inverse_gcd_of_zero() {
  inverse_gcd(0) == None
}

test inverse_gcd_matches_fermat() {
  // Both methods must agree on every input.
  inverse_gcd(12345) == inverse_fermat(12345)
}

test div_gcd_exact() {
  when div_gcd(6, 3) is {
    None -> False
    Some(result) -> result == 2
  }
}

test div_gcd_by_zero() {
  div_gcd(5, 0) == None
}

test inverse_binary_gcd_round_trip() {
  when inverse_binary_gcd(7) is {
    None -> False
    Some(inv) -> mul(7, inv) == 1
  }
}

test inverse_binary_gcd_of_zero() {
  inverse_binary_gcd(0) == None
}

test inverse_binary_gcd_matches_fermat() {
  // All three inversion methods must agree.
  let a = 12345
  let c = inverse_fermat(a)
  and {
    inverse_binary_gcd(a) == c,
    inverse_gcd(a) == c,
  }
}

test inverse_binary_gcd_generator() {
  // Invert the field generator (31).
  when inverse_binary_gcd(31) is {
    None -> False
    Some(inv) -> mul(31, inv) == 1
  }
}
