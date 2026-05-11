// ── Constants ─────────────────────────────────────────────────────────────────

/// Goldilocks prime field: F_p where p = 2^64 - 2^32 + 1 = 18446744069414584321.
///
/// All functions accept and return canonical representatives in [0, p).
/// Inputs outside this range must be normalised via `from_int` first.
///
/// Corresponds to `Goldilocks` in p3-goldilocks.
/// The Goldilocks prime: 2^64 - 2^32 + 1.
pub const prime: Int = 18446744069414584321

/// Multiplicative generator of the field (order = p - 1).
/// Goldilocks has primitive root 7.
pub const generator: Int = 7

/// The 2-adicity of the field: 2^32 divides p - 1 but 2^33 does not.
pub const two_adicity: Int = 32

/// Two-adic generators: `two_adic_generators[k]` has multiplicative order 2^k.
/// Canonical values from Goldilocks::TWO_ADIC_GENERATORS (goldilocks/src/goldilocks.rs).
/// `two_adic_generators[32]` is the primitive 2^32-th root of unity.
pub const two_adic_generators: List<Int> =
  [
    // g[0]  = 1                            (order 1)
    0x1,
    // g[1]  = p - 1                        (order 2)
    0xffffffff00000000,
    // g[2]                                 (order 4)
    0x1000000000000,
    // g[3]                                 (order 8)
    0xfffffffeff000001,
    // g[4]                                 (order 16)
    0xefffffff00000001,
    // g[5]                                 (order 32)
    0x3fffffffc000,
    // g[6]                                 (order 64)
    0x8000000000,
    // g[7]                                 (order 128)
    0xf80007ff08000001,
    // g[8]
    0xbf79143ce60ca966,
    // g[9]
    0x1905d02a5c411f4e,
    // g[10]
    0x9d8f2ad78bfed972,
    // g[11]
    0x653b4801da1c8cf,
    // g[12]
    0xf2c35199959dfcb6,
    // g[13]
    0x1544ef2335d17997,
    // g[14]
    0xe0ee099310bba1e2,
    // g[15]
    0xf6b2cffe2306baac,
    // g[16]
    0x54df9630bf79450e,
    // g[17]
    0xabd0a6e8aa3d8a0e,
    // g[18]
    0x81281a7b05f9beac,
    // g[19]
    0xfbd41c6b8caa3302,
    // g[20]
    0x30ba2ecd5e93e76d,
    // g[21]
    0xf502aef532322654,
    // g[22]
    0x4b2a18ade67246b5,
    // g[23]
    0xea9d5a1336fbc98b,
    // g[24]
    0x86cdcc31c307e171,
    // g[25]
    0x4bbaf5976ecfefd8,
    // g[26]
    0xed41d05b78d6e286,
    // g[27]
    0x10d78dd8915a171d,
    // g[28]
    0x59049500004a4485,
    // g[29]
    0xdfa8c93ba46d2666,
    // g[30]
    0x7e9bd009b86a0845,
    // g[31]
    0x400a7f755588e659,
    // g[32]  primitive 2^32-th root of unity
    0x185629dcda58878c,
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
/// Aiken uses arbitrary-precision integers so no overflow occurs.
pub fn mul(a: Int, b: Int) -> Int {
  a * b % prime
}

/// -a mod p.
pub fn neg(a: Int) -> Int {
  if a == 0 {
    0
  } else {
    -a % prime
  }
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

/// Return the two-adic generator of order 2^k (0 ≤ k ≤ 32).
/// Panics if k > 32.
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
  // 2^64 - 2^32 + 1
  prime == 18446744073709551616 - 4294967296 + 1
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

test mul_generator_squared() {
  // generator = 7, 7*7 = 49 < p
  mul(generator, generator) == 49
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

test two_adic_generator_32_order() {
  // g^{2^32} = 1 in the field.
  let g = two_adic_generator(32)
  pow(g, 4294967296) == 1
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
