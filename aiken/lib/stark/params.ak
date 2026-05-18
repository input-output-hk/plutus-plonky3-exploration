/// Circuit parameters
/// Number of main trace columns for FibonacciAir (left, right).
pub const fib_trace_width: Int = 2

pub const degree: Int = 8192

pub const degree_bits: Int = 13

/// Quotient chunks: log2_ceil(max_constraint_degree - 1) = log2_ceil(1) = 0.
/// num_quotient_chunks = 1. (quotient_chunks[0].len() = 2 is the Ext2 DIMENSION,
/// not the outer chunk count.)
pub const log_num_quotient_chunks: Int = 0

pub const num_quotient_chunks: Int = 1

/// Fri parameters
pub type FriParams {
  log_blowup: Int,
  log_final_poly_len: Int,
  max_log_arity: Int,
  num_queries: Int,
  commit_proof_of_work_bits: Int,
  query_proof_of_work_bits: Int,
}

pub const fri_params: FriParams =
  FriParams {
    log_blowup: 1,
    log_final_poly_len: 0,
    max_log_arity: 1,
    num_queries: 100,
    commit_proof_of_work_bits: 1,
    query_proof_of_work_bits: 16,
  }

/// Letting s = shift, and g = generator (of order 2^log_size), the coset in
/// question is
///     s * <g> = {s, s * g, s * g^2, ..., s * g^(2^log_size - 1)}
/// A two-adic multiplicative coset s·<g> where g has order 2^log_size.
///
/// shift_inverse = shift^{-1} mod p, kept for prover-side coset arithmetic.
/// Verifier uses: first_point = shift, vanishing_poly(x) = x^n - shift^n.
pub type TwoAdicMultiplicativeCoset {
  shift: Int,
  shift_inverse: Int,
  log_size: Int,
}

/// Two Adicity PCS parameters for Goldilocks
pub const trace_domain: TwoAdicMultiplicativeCoset =
  TwoAdicMultiplicativeCoset {
    shift: 1,
    shift_inverse: 1,
    log_size: degree_bits,
  }

pub const init_trace_domain: TwoAdicMultiplicativeCoset =
  TwoAdicMultiplicativeCoset {
    shift: 1,
    shift_inverse: 1,
    log_size: degree_bits,
  }

/// Quotient domain: {7 · omega_13^i}, size = 2^13.
/// trace_domain.create_disjoint_domain(2^13) uses shift = Val::generator = 7.
/// shift_inverse = 7^{-1} mod p = 2635249152773512046.
pub const quotient_domain: TwoAdicMultiplicativeCoset =
  TwoAdicMultiplicativeCoset {
    shift: 7,
    shift_inverse: 2635249152773512046,
    log_size: degree_bits,
  }

/// Quotient chunk domains: split_domains(1) = [quotient_domain].
/// With num_quotient_chunks = 1 there is exactly one chunk domain.
pub const quotient_chunks_domains: List<TwoAdicMultiplicativeCoset> =
  [
    TwoAdicMultiplicativeCoset {
      shift: 7,
      shift_inverse: 2635249152773512046,
      log_size: degree_bits,
    },
  ]

/// Randomized quotient chunk domain used by the FRI batch-opening verifier.
/// = pcs.natural_domain_for_degree(chunk_size) with is_zk = 0 → shift = 1.
pub const randomized_quotient_chunks_domains: List<TwoAdicMultiplicativeCoset> =
  [
    TwoAdicMultiplicativeCoset {
      shift: 1,
      shift_inverse: 1,
      log_size: degree_bits,
    },
  ]

// ── Derived quantities ────────────────────────────────────────────────────────

/// log2 of the global FRI max domain height = degree_bits + log_blowup.
pub fn log_max_height(db: Int) -> Int {
  db + fri_params.log_blowup
}

/// log2 of the final FRI domain height = log_blowup + log_final_poly_len = 1.
pub const log_final_height: Int = 1

/// Number of FRI fold rounds for a proof with the given degree_bits.
///   num_rounds = log_max_height - log_final_height
///              = degree_bits - log_final_poly_len
///   For degree_bits = 13: 13 rounds.
pub fn num_fri_rounds(db: Int) -> Int {
  db - fri_params.log_final_poly_len
}

/// Final polynomial length = 2^log_final_poly_len = 1.
pub const final_poly_len: Int = 1

// ── Domain helpers ────────────────────────────────────────────────────────────

/// First point of a coset = shift.
pub fn first_point(d: TwoAdicMultiplicativeCoset) -> Int {
  d.shift
}

// ── Tests ─────────────────────────────────────────────────────────────────────

test num_fri_rounds_13() {
  num_fri_rounds(degree_bits) == 13
}

test log_max_height_14() {
  log_max_height(degree_bits) == 14
}

test soundness_bits_116() {
  fri_params.log_blowup * fri_params.num_queries + fri_params.query_proof_of_work_bits == 116
}

test one_quotient_chunk_domain() {
  when quotient_chunks_domains is {
    [_] -> True
    _ -> False
  }
}

test one_randomized_domain() {
  when randomized_quotient_chunks_domains is {
    [_] -> True
    _ -> False
  }
}
