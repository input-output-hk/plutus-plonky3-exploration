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

// ── Batch proof parameters (MulAir + FibonacciAir, lookups off) ──────────────
// Mirror the configuration in plonky3/src/export_batch_proof.rs. All lists are
// per instance, in prover order: [MulAir, FibonacciAir].

/// Number of instances in the batch proof.
pub const batch_n_instances: Int = 2

/// Per-instance log2 of the extended trace domain size (= log2(n_i), is_zk = 0).
/// Both traces have 2^13 rows (export_batch_proof.rs: log_n = 13).
pub const batch_degree_bits: List<Int> = [13, 13]

/// Largest per-instance degree_bits; drives the FRI round count.
pub const batch_max_degree_bits: Int = 13

/// Per-instance main trace widths: MulAir = reps*3 + 1 = 7, FibonacciAir = 2.
pub const batch_trace_widths: List<Int> = [7, 2]

/// Per-instance public value counts: MulAir has none, FibonacciAir has (a, b, x).
pub const batch_num_public_values: List<Int> = [0, 3]

/// Per-instance quotient chunk counts. With lookups enabled, the running-sum
/// transition/last-row constraints are `selector * ((s_next-s_local)*denom -
/// num)`: the selector (degree 1) times (s factor degree 1) times denom
/// (degree up to 2 for the local lookups' 2-tuple) makes both AIRs degree 3, so
/// log_num_quotient_chunks = log2_ceil(3-1) = 1 → 2 chunks each.
pub const batch_num_quotient_chunks: List<Int> = [2, 2]

/// Per-instance auxiliary (running-sum) column counts = number of registered
/// lookups per instance. MulAir registers, per rep, one local lookup (a vs its
/// permuted `lut` column) and one global lookup (sends (a,b) to "MulFib")
/// → 4 columns; FibAir receives one global lookup → 1. The committed
/// permutation matrix is aux_width * DIMENSION base columns wide.
pub const batch_aux_widths: List<Int> = [4, 1]

/// Per-instance global-lookup counts (= expected_cumulated length per instance).
/// Only global lookups carry an expected_cumulated value: MulAir 2, FibAir 1.
pub const batch_num_global_lookups: List<Int> = [2, 1]

/// Fri parameters
pub type FriParams {
  log_blowup: Int,
  log_final_poly_len: Int,
  max_log_arity: Int,
  num_queries: Int,
  commit_proof_of_work_bits: Int,
  query_proof_of_work_bits: Int,
}

// These must stay identical to the Rust prover's FriParameters
// (plonky3/src/export_proof.rs and export_batch_proof.rs) — they define the
// proof, so any change here also means regenerating the proof. "CHANGEABLE"
// below means "supported by this verifier if mirrored on the prover"; "FIXED"
// means the verifier hard-codes the value and other settings would be verified
// incorrectly.
pub const fri_params: FriParams =
  FriParams {
    // CHANGEABLE (security/cost). LDE (Low-Degree Extension) blowup factor. Used only via
    // log_max_height = degree_bits + log_blowup, log_final_height, and
    // log_global_max_height. Larger ⇒ more soundness per query but a bigger LDE.
    log_blowup: 8,
    // FIXED at 0. The final-polynomial check (pcs_verify.ak) evaluates the
    // final poly at a full-domain point, which only coincides with the correct
    // value when the poly is a constant (length 2^0 = 1). A non-constant final
    // poly would need evaluation on the smaller final domain — not implemented.
    log_final_poly_len: 0,
    // FIXED at 1 (binary folding only). fold_row takes exactly two evaluations
    // (e0, e1) and verify_query rejects any commit-phase step whose log_arity
    // != 1 or that does not carry exactly one sibling. This field is not read
    // anywhere — the binary structure is hard-coded in fri.ak — so changing it
    // does nothing; higher arities are genuinely unsupported.
    max_log_arity: 1,
    // CHANGEABLE (soundness/cost). Number of FRI query openings; the verifier
    // loops over every query_proofs entry.
    num_queries: 22,
    // CHANGEABLE (soundness). Commit-phase grinding bits, checked per round via
    // challenger.check_pow in pcs_verify.process_commit_rounds.
    commit_proof_of_work_bits: 16,
    // CHANGEABLE (soundness). Query-phase grinding bits, checked once before the
    // query loop via challenger.check_pow.
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

/// log2 of the final FRI domain height = log_blowup + log_final_poly_len.
///
/// Mirrors fri/src/verifier.rs:173:
///   let log_final_height = params.log_blowup + params.log_final_poly_len;
///
///   log_blowup=1, log_final_poly_len=0 → log_final_height=1
///   log_blowup=2, log_final_poly_len=0 → log_final_height=2
pub const log_final_height: Int =
  fri_params.log_blowup + fri_params.log_final_poly_len

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

test log_max_height_is_degree_bits_plus_blowup() {
  // log_blowup=1 → 14;  log_blowup=2 → 15
  log_max_height(degree_bits) == degree_bits + fri_params.log_blowup
}

test log_final_height_is_blowup_plus_final_poly_len() {
  // log_blowup=1 → 1;  log_blowup=2 → 2
  log_final_height == fri_params.log_blowup + fri_params.log_final_poly_len
}

test soundness_bits_sufficient() {
  // Conjectured bits = log_blowup * num_queries + query_pow_bits.
  // log_blowup=1 → 116;  log_blowup=2 → 216.
  fri_params.log_blowup * fri_params.num_queries + fri_params.query_proof_of_work_bits >= 100
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
