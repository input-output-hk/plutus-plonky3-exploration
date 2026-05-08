use babybear/field
use cardano/transaction.{OutputReference, Transaction}

/// Polynomial-evaluation puzzle over the BabyBear field.
///
/// Funds locked at this script address can be spent by any redeemer that
/// supplies polynomial coefficients P such that P(point) = expected (mod p),
/// where `point` and `expected` are stored in the datum.
///
/// This is the core verification step in a univariate STARK verifier:
/// checking that a committed polynomial evaluates to the expected value at a
/// queried point.
/// Maximum degree of the witness polynomial (inclusive).
/// Keeps on-chain execution units bounded.
const max_degree: Int = 16

// ── Types ─────────────────────────────────────────────────────────────────────

/// Stored on-chain: the public evaluation statement.
pub type Datum {
  /// Evaluation point x in BabyBear.
  point: Int,
  /// Expected value P(x) mod p.
  expected: Int,
}

/// Provided by the redeemer: the polynomial witness.
pub type Redeemer {
  /// Coefficients in decreasing degree order: [c_n, c_{n-1}, ..., c_0].
  /// Represents c_n * x^n + ... + c_1 * x + c_0.
  coefficients: List<Int>,
}

// ── List helpers (no stdlib import needed) ────────────────────────────────────

fn length(xs: List<a>) -> Int {
  do_length(xs, 0)
}

fn do_length(xs: List<a>, acc: Int) -> Int {
  when xs is {
    [] -> acc
    [_, ..rest] -> do_length(rest, acc + 1)
  }
}

fn all(xs: List<a>, pred: fn(a) -> Bool) -> Bool {
  when xs is {
    [] -> True
    [x, ..rest] ->
      if pred(x) {
        all(rest, pred)
      } else {
        False
      }
  }
}

// ── Validator ─────────────────────────────────────────────────────────────────

validator poly_eval_puzzle {
  spend(
    datum: Option<Datum>,
    redeemer: Redeemer,
    _self: OutputReference,
    _ctx: Transaction,
  ) {
    // The datum must be present.
    expect Some(d) = datum

    let degree = length(redeemer.coefficients) - 1

    and {
      // Degree bounds: at least a constant term, at most max_degree.
      degree >= 0,
      degree <= max_degree,
      // All values must be canonical BabyBear field elements.
      field.is_valid(d.point),
      field.is_valid(d.expected),
      all(redeemer.coefficients, field.is_valid),
      // Core check: P(point) == expected in BabyBear.
      field.eval_poly(redeemer.coefficients, d.point) == d.expected,
    }
  }

  // Reject any other purpose (minting, withdrawals, etc.).
  else(_ctx) {
    False
  }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

test spend_linear_polynomial() {
  // P(x) = 2x + 3; datum: point=5, expected=13; redeemer: [2, 3]
  let datum = Some(Datum { point: 5, expected: 13 })
  let redeemer = Redeemer { coefficients: [2, 3] }
  let degree = length(redeemer.coefficients) - 1
  expect Some(d) = datum
  and {
    degree >= 0,
    degree <= max_degree,
    field.is_valid(d.point),
    field.is_valid(d.expected),
    all(redeemer.coefficients, field.is_valid),
    field.eval_poly(redeemer.coefficients, d.point) == d.expected,
  }
}

test spend_quadratic_polynomial() {
  // P(x) = x^2 + x + 1; datum: point=10, expected=111; redeemer: [1, 1, 1]
  let datum = Some(Datum { point: 10, expected: 111 })
  let redeemer = Redeemer { coefficients: [1, 1, 1] }
  let degree = length(redeemer.coefficients) - 1
  expect Some(d) = datum
  and {
    degree >= 0,
    degree <= max_degree,
    field.is_valid(d.point),
    field.is_valid(d.expected),
    all(redeemer.coefficients, field.is_valid),
    field.eval_poly(redeemer.coefficients, d.point) == d.expected,
  }
}

test spend_constant_polynomial() {
  // P(x) = 42; datum: point=999, expected=42; redeemer: [42]
  let datum = Some(Datum { point: 999, expected: 42 })
  let redeemer = Redeemer { coefficients: [42] }
  let degree = length(redeemer.coefficients) - 1
  expect Some(d) = datum
  and {
    degree >= 0,
    degree <= max_degree,
    field.is_valid(d.point),
    field.is_valid(d.expected),
    all(redeemer.coefficients, field.is_valid),
    field.eval_poly(redeemer.coefficients, d.point) == d.expected,
  }
}

test wrong_evaluation_fails() {
  // P(x) = 2x + 3 evaluated at 5 should be 13, not 99
  field.eval_poly([2, 3], 5) != 99
}

test out_of_range_coefficient_rejected() {
  // A coefficient equal to p is not a valid field element
  !field.is_valid(field.prime)
}

test degree_too_high_rejected() {
  // 18 coefficients => degree 17 which exceeds max_degree => rejected
  let too_many = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18]
  length(too_many) - 1 > max_degree
}
