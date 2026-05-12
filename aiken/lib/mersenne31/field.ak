// ── Constants ─────────────────────────────────────────────────────────────────

/// Mersenne31 prime field: F_p where p = 2^31 - 1 = 2147483647.
///
/// All functions accept and return canonical representatives in [0, p).
/// Corresponds to `Mersenne31` in Plonky3 (mersenne-31/src/mersenne_31.rs).
/// The Mersenne31 prime: 2^31 - 1 = 0x7fffffff.
pub const prime: Int = 2147483647

// ── Validation ────────────────────────────────────────────────────────────────

pub fn is_valid(a: Int) -> Bool {
  a >= 0 && a < prime
}

pub fn from_int(n: Int) -> Int {
  n % prime
}

// ── Arithmetic ────────────────────────────────────────────────────────────────

pub fn add(a: Int, b: Int) -> Int {
  ( a + b ) % prime
}

pub fn sub(a: Int, b: Int) -> Int {
  ( a - b ) % prime
}

pub fn mul(a: Int, b: Int) -> Int {
  a * b % prime
}

pub fn neg(a: Int) -> Int {
  -a % prime
}

pub fn square(a: Int) -> Int {
  mul(a, a)
}

pub fn double(a: Int) -> Int {
  add(a, a)
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

/// Multiplicative inverse via EEA. Returns None for zero.
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

pub fn div(a: Int, b: Int) -> Option<Int> {
  when inverse(b) is {
    None -> None
    Some(b_inv) -> Some(mul(a, b_inv))
  }
}

/// Multiply by 2^k mod p using repeated doubling.
pub fn mul_2exp(a: Int, k: Int) -> Int {
  if k == 0 {
    a
  } else {
    mul_2exp(double(a), k - 1)
  }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

test prime_is_mersenne() {
  prime == 2147483648 - 1
}

test add_wraps() {
  add(prime - 1, 1) == 0
}

test sub_wraps() {
  sub(0, 1) == prime - 1
}

test mul_small() {
  mul(3, 5) == 15
}

test neg_zero() {
  neg(0) == 0
}

test neg_one() {
  neg(1) == prime - 1
}

test inverse_round_trip() {
  when inverse(7) is {
    None -> False
    Some(inv) -> mul(7, inv) == 1
  }
}

test inverse_zero_is_none() {
  inverse(0) == None
}

test pow_fermat() {
  pow(3, prime - 1) == 1
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
