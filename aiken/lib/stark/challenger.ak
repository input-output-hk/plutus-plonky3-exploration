use aiken/builtin
use goldilocks/ext2.{Ext2}
use goldilocks/field as gf

// ── State ─────────────────────────────────────────────────────────────────────

/// Fiat-Shamir duplex transcript for the Plonky3 STARK verifier.
///
/// Mirrors HashChallenger<u8, SHA-256, 32> wrapped by
/// SerializingChallenger64<Goldilocks, _> from Plonky3
/// (challenger/src/hash_challenger.rs, challenger/src/serializing_challenger.rs).
///
/// Transcript rules (identical to Plonky3):
///   observe(x): append LE bytes of x to input_buf; clear output_buf.
///   sample():   if output_buf empty → sha256(input_buf) → output_buf, clear
///               input_buf; consume bytes from the front of output_buf.
///
/// Full verifier transcript order (non-ZK, no preprocessed, FibonacciAir):
///   observe felt(degree_bits)          ─┐
///   observe felt(degree_bits)           │  instance
///   observe felt(0)                     │  (preprocessed_width = 0)
///   observe commitment(trace_commit)    │
///   observe felts(public_values)       ─┘
///   alpha  ← sample_ext()
///   observe commitment(quotient_commit)
///   zeta   ← sample_ext()
///   alpha_fri ← sample_ext()           ─── FRI batch-combination challenge
///   for each FRI round i:
///     observe commitment(commit_phase_commits[i])
///     check_pow(commit_proof_of_work_bits, commit_pow_witnesses[i])
///     beta[i] ← sample_ext()
///   observe exts(final_poly)
///   for each round: observe felt(log_arity = 1)
///   check_pow(query_proof_of_work_bits, query_pow_witness)
///   for each query: index ← sample_bits(log_max_height)
pub type ChallengerState {
  /// Bytes accumulated since the last hash (cleared on flush).
  input_buf: ByteArray,
  /// Remaining bytes from the last SHA-256 output (consumed front-to-back).
  output_buf: ByteArray,
}

pub fn init() -> ChallengerState {
  ChallengerState { input_buf: #"", output_buf: #"" }
}

// ── Observe (absorb) ──────────────────────────────────────────────────────────

/// Append raw bytes to the transcript, invalidating any pending output.
pub fn observe_bytes(st: ChallengerState, bytes: ByteArray) -> ChallengerState {
  ChallengerState {
    input_buf: builtin.append_bytearray(st.input_buf, bytes),
    output_buf: #"",
  }
}

/// Observe a Goldilocks base-field element as 8 little-endian bytes.
/// Mirrors SerializingChallenger64::observe(F) → 8 LE bytes via to_canonical_u64.
pub fn observe_val(st: ChallengerState, x: Int) -> ChallengerState {
  observe_bytes(st, builtin.integer_to_bytearray(False, 8, x))
}

/// Observe an Ext2 element: c0 then c1 (each 8 bytes LE).
/// Mirrors CanObserve<EF> via as_base_slice(): [c0, c1].
pub fn observe_ext(st: ChallengerState, e: Ext2) -> ChallengerState {
  observe_val(observe_val(st, e.c0), e.c1)
}

/// Observe a raw byte-string commitment (e.g. 32-byte SHA-256 Merkle root).
pub fn observe_commitment(st: ChallengerState, c: ByteArray) -> ChallengerState {
  observe_bytes(st, c)
}

/// Observe a list of base-field elements one by one.
/// Mirrors observe_slice(&[F]).
pub fn observe_vals(st: ChallengerState, xs: List<Int>) -> ChallengerState {
  when xs is {
    [] -> st
    [x, ..rest] -> observe_vals(observe_val(st, x), rest)
  }
}

/// Observe a list of Ext2 elements one by one (used for the FRI final_poly).
/// Mirrors observe_algebra_slice(&[EF]).
pub fn observe_exts(st: ChallengerState, es: List<Ext2>) -> ChallengerState {
  when es is {
    [] -> st
    [e, ..rest] -> observe_exts(observe_ext(st, e), rest)
  }
}

// ── Sample (squeeze) ──────────────────────────────────────────────────────────

/// If output_buf is empty: SHA-256(input_buf) → output_buf, clear input_buf.
fn ensure_output(st: ChallengerState) -> ChallengerState {
  if builtin.length_of_bytearray(st.output_buf) == 0 {
    ChallengerState {
      input_buf: #"",
      output_buf: builtin.sha2_256(st.input_buf),
    }
  } else {
    st
  }
}

/// Consume exactly n bytes from the front of output_buf, flushing as needed.
fn take_n_bytes(st: ChallengerState, n: Int) -> (ByteArray, ChallengerState) {
  do_take(st, n, #"")
}

fn do_take(
  st: ChallengerState,
  remaining: Int,
  acc: ByteArray,
) -> (ByteArray, ChallengerState) {
  if remaining == 0 {
    (acc, st)
  } else {
    let st1 = ensure_output(st)
    let available = builtin.length_of_bytearray(st1.output_buf)
    let chunk =
      if remaining <= available {
        remaining
      } else {
        available
      }
    let taken = builtin.slice_bytearray(0, chunk, st1.output_buf)
    let rest = builtin.slice_bytearray(chunk, available - chunk, st1.output_buf)
    do_take(
      ChallengerState { ..st1, output_buf: rest },
      remaining - chunk,
      builtin.append_bytearray(acc, taken),
    )
  }
}

/// Sample a Goldilocks base-field element.
/// Takes 8 bytes, interprets as LE u64, reduces mod p.
/// Mirrors SerializingChallenger64::sample() → F.
pub fn sample_val(st: ChallengerState) -> (Int, ChallengerState) {
  let (bytes, st1) = take_n_bytes(st, 8)
  let raw = builtin.bytearray_to_integer(False, bytes)
  (gf.from_int(raw), st1)
}

/// Sample an Ext2 challenge element (two consecutive Goldilocks felts).
/// Mirrors challenger.sample_algebra_element() for Challenge = Ext2.
pub fn sample_ext(st: ChallengerState) -> (Ext2, ChallengerState) {
  let (c0, st1) = sample_val(st)
  let (c1, st2) = sample_val(st1)
  (Ext2 { c0, c1 }, st2)
}

/// Sample n bits: take 8 bytes as LE u64, return the n least-significant bits.
/// Mirrors SerializingChallenger64::sample_bits(n) → usize.
///
/// Used for:
///   query index: sample_bits(log_max_height)  →  index ∈ [0, 2^log_max_height)
///   PoW check:   sample_bits(pow_bits)        →  must equal 0
pub fn sample_bits(st: ChallengerState, n: Int) -> (Int, ChallengerState) {
  let (bytes, st1) = take_n_bytes(st, 8)
  let raw = builtin.bytearray_to_integer(False, bytes)
  (raw % pow2(n), st1)
}

// ── Proof-of-work verification ────────────────────────────────────────────────

/// Verify a proof-of-work witness for `bits` zero-bits.
///
/// Mirrors GrindingChallenger::check_witness (non-ZK variant):
///   1. observe witness as a Goldilocks element (8 LE bytes).
///   2. sample `bits` bits from the refreshed transcript.
///   3. Return True iff sampled value == 0.
///
/// Config values:
///   commit_proof_of_work_bits = 1   (per FRI commit round)
///   query_proof_of_work_bits  = 16  (once, before query sampling)
pub fn check_pow(
  st: ChallengerState,
  bits: Int,
  witness: Int,
) -> (Bool, ChallengerState) {
  let st1 = observe_val(st, witness)
  let (result, st2) = sample_bits(st1, bits)
  (result == 0, st2)
}

// ── Helper ────────────────────────────────────────────────────────────────────

fn pow2(n: Int) -> Int {
  do_pow2(n, 1)
}

fn do_pow2(n: Int, acc: Int) -> Int {
  if n <= 0 {
    acc
  } else {
    do_pow2(n - 1, acc * 2)
  }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

test init_has_empty_buffers() {
  let st = init()
  builtin.length_of_bytearray(st.input_buf) == 0 && builtin.length_of_bytearray(
    st.output_buf,
  ) == 0
}

test observe_val_appends_8_le_bytes() {
  // 1 in LE u64 = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
  let st = observe_val(init(), 1)
  st.input_buf == #"0100000000000000"
}

test observe_val_clears_output() {
  // Seed some output first, then observe should clear it.
  let st0 = ChallengerState { input_buf: #"", output_buf: #"aabbccdd" }
  let st1 = observe_val(st0, 42)
  builtin.length_of_bytearray(st1.output_buf) == 0
}

test observe_commitment_appends_raw_bytes() {
  let commit =
    #"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
  let st = observe_commitment(init(), commit)
  st.input_buf == commit
}

test sample_val_is_deterministic() {
  // Same initial state → same result.
  let st = observe_val(init(), 42)
  let (v1, _) = sample_val(st)
  let (v2, _) = sample_val(st)
  v1 == v2
}

test two_samples_consume_different_bytes() {
  // Consecutive samples draw from different parts of the 32-byte SHA-256 output.
  let st = observe_val(init(), 99)
  let (v1, st1) = sample_val(st)
  let (v2, _) = sample_val(st1)
  // Overwhelmingly likely to differ; collision probability ≈ 2^{-64}.
  v1 != v2
}

test sample_ext_produces_pair() {
  let st = observe_val(init(), 7)
  let (e, _) = sample_ext(st)
  // Both components are valid Goldilocks elements (in [0, p)).
  e.c0 >= 0 && e.c0 < gf.prime && e.c1 >= 0 && e.c1 < gf.prime
}

test sample_bits_within_range() {
  let st = observe_val(init(), 0)
  let (idx, _) = sample_bits(st, 14)
  idx >= 0 && idx < 16384
}

test check_pow_zero_bits_always_passes() {
  // 0 bits of PoW: x % 1 == 0 for all x.
  let (ok, _) = check_pow(init(), 0, 12345)
  ok
}

test check_pow_is_deterministic() {
  let (ok1, _) = check_pow(init(), 1, 0)
  let (ok2, _) = check_pow(init(), 1, 0)
  ok1 == ok2
}
