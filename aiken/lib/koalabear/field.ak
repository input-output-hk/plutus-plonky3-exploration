// ── Constants ─────────────────────────────────────────────────────────────────

/// KoalaBear prime field: F_p where p = 2^31 - 2^24 + 1 = 2130706433.
///
/// All functions accept and return canonical representatives in [0, p).
/// Inputs outside this range produce unspecified results unless `from_int`
/// is used to normalise them first.
///
/// Corresponds to `KoalaBear = MontyField31<KoalaBearParameters>` in Plonky3.
/// The KoalaBear prime: 2^31 - 2^24 + 1 = 0x7f000001.
/// Highest two-adicity (24) among 31-bit primes where x→x^3 is an automorphism.
pub const prime: Int = 2130706433

/// Multiplicative generator of the field (order = p - 1).
/// From KoalaBearParameters: MONTY_GEN = KoalaBear::new(3), canonical value 3.
pub const generator: Int = 3

/// The 2-adicity of the field: 2^24 divides p - 1 but 2^25 does not.
pub const two_adicity: Int = 24

/// Two-adic generators: `two_adic_generators[k]` has multiplicative order 2^k.
/// Canonical values from KoalaBearParameters::TWO_ADIC_GENERATORS.
/// `two_adic_generators[24]` = 1791270792 is the primitive 2^24-th root of unity.
pub const two_adic_generators: List<Int> =
  [
    1, 2130706432, 2113994754, 1748172362, 148625052, 170455089, 1548376985,
    699882112, 392596362, 665670555, 860702919, 2000983452, 1989134074,
    809067698, 1047035213, 1168510561, 1848593786, 373019801, 1816824389,
    339671193, 1364057261, 1213133211, 542991299, 1760025929, 1791270792,
  ]

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

/// Multiplicative inverse via the Extended Euclidean Algorithm.
/// Returns `None` for the zero element.
/// O(log p) steps — preferred over Fermat (which costs ~90 field multiplications).
pub fn inverse(a: Int) -> Option<Int> {
  if a == 0 {
    None
  } else {
    Some(do_eea(prime, a, 0, 1))
  }
}

fn do_eea(prev_r: Int, r: Int, prev_s: Int, s: Int) -> Int {
  if r == 0 {
    from_int(prev_s)
  } else {
    let q = prev_r / r
    do_eea(r, prev_r - q * r, s, prev_s - q * s)
  }
}

/// a / b = a * b^{-1} mod p.  Returns `None` if b == 0.
pub fn div(a: Int, b: Int) -> Option<Int> {
  when inverse(b) is {
    None -> None
    Some(b_inv) -> Some(mul(a, b_inv))
  }
}

// ── Two-adic generator lookup ─────────────────────────────────────────────────

/// Return the two-adic generator of order 2^k (0 ≤ k ≤ 24).
/// Panics if k > 24.
pub fn two_adic_generator(k: Int) -> Int {
  do_nth(two_adic_generators, k)
}

fn do_nth(xs: List<Int>, i: Int) -> Int {
  when xs is {
    [] -> fail @"two_adic_generator: index out of range"
    [x, ..rest] ->
      if i == 0 {
        x
      } else {
        do_nth(rest, i - 1)
      }
  }
}

// ── Polynomial & vector utilities ─────────────────────────────────────────────

/// Evaluate a polynomial at `point` via Horner's method.
/// `coeffs` ordered highest-degree first: [c_n, ..., c_0].
pub fn eval_poly(coeffs: List<Int>, point: Int) -> Int {
  do_eval_poly(coeffs, point, 0)
}

fn do_eval_poly(coeffs: List<Int>, point: Int, acc: Int) -> Int {
  when coeffs is {
    [] -> acc
    [c, ..rest] -> do_eval_poly(rest, point, add(mul(acc, point), c))
  }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

test prime_value() {
  // 2^31 - 2^24 + 1
  prime == 2147483648 - 16777216 + 1
}

test add_wraps_at_prime() {
  add(prime - 1, 1) == 0
}

test sub_wraps_at_zero() {
  sub(0, 1) == prime - 1
}

test mul_small() {
  mul(2, 3) == 6
}

test mul_from_rust_test() {
  // From KoalaBear Rust tests: 0x34167c58 * 0x61f3207b = 0x54b46b81 in KoalaBear.
  mul(0x34167c58, 0x61f3207b) == 0x54b46b81
}

test neg_one() {
  neg(1) == prime - 1
}

test neg_zero() {
  neg(0) == 0
}

test inverse_round_trip() {
  when inverse(7) is {
    None -> False
    Some(inv) -> mul(7, inv) == 1
  }
}

test inverse_of_zero() {
  inverse(0) == None
}

test inverse_of_generator() {
  when inverse(generator) is {
    None -> False
    Some(inv) -> mul(generator, inv) == 1
  }
}

test two_adic_generator_0() {
  two_adic_generator(0) == 1
}

test two_adic_generator_1_is_neg_one() {
  // The unique element of order 2 is -1 = p - 1.
  two_adic_generator(1) == prime - 1
}

test two_adic_generator_24_order() {
  // g^{2^24} = 1 in the field (g has multiplicative order 2^24).
  let g = two_adic_generator(24)
  pow(g, 16777216) == 1
}

test two_adic_generator_squaring_reduces_order() {
  // Squaring two_adic_generator(k) gives two_adic_generator(k-1).
  let g3 = two_adic_generator(3)
  let g2 = two_adic_generator(2)
  mul(g3, g3) == g2
}

test generator_order_divides_p_minus_1() {
  // generator^{(p-1)} = 1 by Fermat.
  pow(generator, prime - 1) == 1
}

test from_int_negative() {
  from_int(-1) == prime - 1
}

test from_int_large() {
  from_int(prime + 5) == 5
}

// ── Cost benchmarks ───────────────────────────────────────────────────────────

fn repeat_add(a: Int, b: Int, n: Int) -> Int {
  if n <= 0 {
    a
  } else {
    repeat_add(add(a, b), b, n - 1)
  }
}

fn repeat_mul(a: Int, b: Int, n: Int) -> Int {
  if n <= 0 {
    a
  } else {
    repeat_mul(mul(a, b), b, n - 1)
  }
}

fn repeat_inverse(a: Int, n: Int) -> Int {
  if n <= 0 {
    a
  } else {
    let next =
      when inverse(a) is {
        None -> 1
        Some(inv) -> inv
      }
    repeat_inverse(next, n - 1)
  }
}

test add_cost_100() {
  let result = repeat_add(prime - 15, prime - 31, 100)
  result == result
}

test mul_cost_100() {
  let result = repeat_mul(prime - 31, prime - 11, 100)
  result == result
}

test inverse_cost_100() {
  let result = repeat_inverse(31, 100)
  result == result
}
