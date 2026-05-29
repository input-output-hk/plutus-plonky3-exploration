// ── Constants ─────────────────────────────────────────────────────────────────

use aiken/builtin

/// Mersenne31 prime field: F_p where p = 2^31 - 1 = 2147483647.
///
/// All functions accept and return canonical representatives in [0, p).
/// Corresponds to `Mersenne31` in Plonky3 (mersenne-31/src/mersenne_31.rs).
/// The Mersenne31 prime: 2^31 - 1 = 0x7fffffff.
pub const prime: Int = 2147483647

/// 2^31: the split point for the Mersenne fold.
const two31: Int = 2147483648

/// 8-byte big-endian mask for bits [0,30]: 0x000000007fffffff.
/// Used by `mul2_bs` for the AND-based low-bits extraction.
const mask31: ByteArray = #"000000007fffffff"

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

/// Reduce x (up to 62-bit) into [0, p) using the Mersenne fold identity:
///   2^31 ≡ 1 (mod p)  ⟹  x ≡ (x >> 31) + (x & 0x7fffffff)  (mod p)
///
/// In Plutus, `% 2^31` and `/ 2^31` (power-of-2) go through GMP's
/// mpz_fdiv_r_2exp / right-shift path, which is cheaper than a general
/// odd-prime division.  Two folds suffice for any 62-bit input:
///
///   fold 1:  r  = (x / 2^31) + (x % 2^31)       r  ∈ [0, 2^32−2]
///   step 2:  if r ≥ 2^31 then r ← r − p          r  ∈ [0, p]
///   step 3:  if r ≥ p    then r ← r − p          r  ∈ [0, p)
fn mersenne_reduce(x: Int) -> Int {
  let r = x / two31 + x % two31
  let r2 =
    if r >= two31 {
      r - prime
    } else {
      r
    }
  if r2 >= prime {
    r2 - prime
  } else {
    r2
  }
}

/// Like `mul` but reduces via the Mersenne fold instead of `% prime`.
///
/// Replaces one general `modInteger(62-bit, 31-bit)` with two power-of-2
/// div/mod calls plus two conditional subtracts.  Benchmarks in the cost
/// tests below show which wins for your Plutus version.
pub fn mul_fold(a: Int, b: Int) -> Int {
  mersenne_reduce(a * b)
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

// ── CIP-58 ByteString route (mul_fold_bs) ────────────────────────────────────────
//
// Uses builtin.shift_bytearray (CIP-58) for x >> 31
// and   builtin.and_bytearray  (CIP-58) for x & 0x7fffffff.
// Both operate directly on bits in the 8-byte big-endian encoding of x.
//
// Steps:
//   1. Encode product as 8-byte big-endian ByteArray
//   2. hi = bytearray >> 31  (shift_bytearray with negative = right-shift)
//   3. lo = bytearray AND mask31
//   4. Fold and conditionally subtract as usual

fn mul_fold_bs(a: Int, b: Int) -> Int {
  let x = a * b
  let bs = builtin.integer_to_bytearray(True, 8, x)
  let hi = builtin.bytearray_to_integer(True, builtin.shift_bytearray(bs, -31))
  let lo =
    builtin.bytearray_to_integer(True, builtin.and_bytearray(False, bs, mask31))
  let r = hi + lo
  let r2 =
    if r >= two31 {
      r - prime
    } else {
      r
    }
  if r2 >= prime {
    r2 - prime
  } else {
    r2
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

// ── mul2 correctness ──────────────────────────────────────────────────────────

test mul_fold_agrees_with_mul_small() {
  mul_fold(3, 5) == mul(3, 5)
}

test mul_fold_agrees_with_mul_large() {
  mul_fold(prime - 1, prime - 1) == mul(prime - 1, prime - 1)
}

test mul_fold_wraps_correctly() {
  // (p-1)^2 = p^2 - 2p + 1 ≡ 1 (mod p)
  mul_fold(prime - 1, prime - 1) == 1
}

test mul_fold_zero() {
  mul_fold(0, prime - 1) == 0
}

test mul2_one() {
  mul_fold(1, prime - 1) == prime - 1
}

test mul_fold_agrees_with_mul_midrange() {
  // pick values that exercise the carry path (product > 2^31)
  mul_fold(1073741824, 2) == mul(1073741824, 2)
}

test mul_fold_matches_mul_all_corners() {
  and {
    mul_fold(0, 0) == 0,
    mul_fold(prime - 1, 1) == prime - 1,
    mul_fold(prime - 1, 2) == mul(prime - 1, 2),
    mul_fold(1073741823, 1073741823) == mul(1073741823, 1073741823),
  }
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

fn repeat_mul_fold(a: Int, b: Int, n: Int) -> Int {
  if n <= 0 {
    a
  } else {
    repeat_mul_fold(mul_fold(a, b), b, n - 1)
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

test mul_fold_cost_100() {
  let result = repeat_mul_fold(prime - 31, prime - 11, 100)
  result == result
}

test inverse_cost_100() {
  let result = repeat_inverse(31, 100)
  result == result
}

test mul_fold_bs_agrees_small() {
  mul_fold_bs(3, 5) == 15
}

test mul_fold_bs_agrees_large() {
  mul_fold_bs(prime - 1, prime - 1) == 1
}

fn repeat_mul_fold_bs(a: Int, b: Int, n: Int) -> Int {
  if n <= 0 {
    a
  } else {
    repeat_mul_fold_bs(mul_fold_bs(a, b), b, n - 1)
  }
}

test mul_fold_bs_cost_100() {
  let result = repeat_mul_fold_bs(prime - 31, prime - 11, 100)
  result == result
}
