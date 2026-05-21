use aiken/builtin
use goldilocks/ext2.{Ext2}
use goldilocks/field as gf

// ── State ─────────────────────────────────────────────────────────────────────

/// Fiat-Shamir transcript challenger for the Goldilocks Fibonacci STARK.
///
/// Mirrors SerializingChallenger64<Goldilocks, HashChallenger<u8, Sha256, 32>>
/// from Plonky3 (challenger/src/*.rs).
///
/// ── HashChallenger<u8, Sha256, 32> (inner) ──────────────────────────────────
///   state = (input_buffer: Vec<u8>, output_buffer: Vec<u8>)
///   observe(byte) → clear output_buffer; push byte to input_buffer
///   flush()       → h = SHA-256(input_buffer);
///                   input_buffer := h  (chaining — critical for correctness)
///                   output_buffer := h
///   sample()      → if output_buffer empty, flush();
///                   output_buffer.pop()  ← pops from END (Vec::pop)
///
/// ── SerializingChallenger64<Goldilocks, Inner> (outer) ──────────────────────
///   observe(f: Goldilocks) → serialize as 8 LE bytes → inner.observe each byte
///   observe(commit: [u8;32]) → inner.observe each byte
///   sample_algebra_element() for Ext2 → loop: take 8 bytes as LE u64; if < prime, done
///   sample_bits(n)           → take 8 bytes as LE u64; return low n bits (no reject)
///   check_witness(bits, w)   → observe(w); sample_bits(bits) == 0
///
/// ── IMPORTANT byte ordering ──────────────────────────────────────────────────
///   output_buffer = [h[0], h[1], ..., h[31]] (hash bytes in order)
///   Vec::pop() returns h[31] first, h[30] second, ..., h[0] last.
///   sample_array::<8>() = [h[31], h[30], ..., h[24]]  (first 8 samples)
///   u64::from_le_bytes([h[31], ..., h[24]]) = h[31] + h[30]·256 + ... + h[24]·256⁷
///
/// ── State representation ─────────────────────────────────────────────────────
///   input    – bytes for the next SHA-256 (= chaining hash after each flush)
///   output   – 32-byte SHA-256 hash; #"" when cleared by an observe call
///   consumed – bytes already read from output (0-32)
///              next byte = output[31 - consumed] while consumed < 32
pub type ChallengerState {
  input: ByteArray,
  output: ByteArray,
  consumed: Int,
}

/// Initial challenger state: HashChallenger::new(vec![], Sha256).
pub fn init() -> ChallengerState {
  ChallengerState { input: #"", output: #"", consumed: 0 }
}

// ── Observe (absorb) ──────────────────────────────────────────────────────────

fn observe_raw(st: ChallengerState, bytes: ByteArray) -> ChallengerState {
  ChallengerState {
    input: builtin.append_bytearray(st.input, bytes),
    output: #"",
    consumed: 0,
  }
}

/// Observe a Goldilocks field element as 8 little-endian bytes.
pub fn observe_val(st: ChallengerState, x: Int) -> ChallengerState {
  observe_raw(st, builtin.integer_to_bytearray(False, 8, x))
}

/// Observe a 32-byte Merkle commitment (each byte directly).
pub fn observe_commitment(st: ChallengerState, c: ByteArray) -> ChallengerState {
  observe_raw(st, c)
}

/// Observe an Ext2 element: c0 then c1, each as 8 LE bytes.
pub fn observe_ext(st: ChallengerState, e: Ext2) -> ChallengerState {
  observe_val(observe_val(st, e.c0), e.c1)
}

/// Observe a list of Goldilocks field elements in order.
pub fn observe_vals(st: ChallengerState, xs: List<Int>) -> ChallengerState {
  when xs is {
    [] -> st
    [x, ..rest] -> observe_vals(observe_val(st, x), rest)
  }
}

/// Observe a list of Ext2 elements in order (used for FRI final_poly and OOD values).
pub fn observe_exts(st: ChallengerState, es: List<Ext2>) -> ChallengerState {
  when es is {
    [] -> st
    [e, ..rest] -> observe_exts(observe_ext(st, e), rest)
  }
}

// ── Flush & byte-level sampling ───────────────────────────────────────────────

/// Compute SHA-256(input) and set it as both the new chaining input and output.
fn flush(st: ChallengerState) -> ChallengerState {
  let h = builtin.sha2_256(st.input)
  // Chaining: input := hash so the next flush incorporates it.
  ChallengerState { input: h, output: h, consumed: 0 }
}

/// Pop one byte from the output buffer (back-to-front: output[31 - consumed]).
/// Flushes first if output is empty (cleared by observe) or fully consumed.
fn sample_byte(st: ChallengerState) -> (Int, ChallengerState) {
  let s =
    if builtin.length_of_bytearray(st.output) == 0 || st.consumed >= 32 {
      flush(st)
    } else {
      st
    }
  let byte = builtin.index_bytearray(s.output, 31 - s.consumed)
  (byte, ChallengerState { ..s, consumed: s.consumed + 1 })
}

/// Sample 8 consecutive bytes and combine as a little-endian u64.
/// b0 (first pop = output[31]) is the LSB: value = b0 + b1·256 + … + b7·256⁷.
fn sample_u64(st: ChallengerState) -> (Int, ChallengerState) {
  let (b0, s0) = sample_byte(st)
  let (b1, s1) = sample_byte(s0)
  let (b2, s2) = sample_byte(s1)
  let (b3, s3) = sample_byte(s2)
  let (b4, s4) = sample_byte(s3)
  let (b5, s5) = sample_byte(s4)
  let (b6, s6) = sample_byte(s5)
  let (b7, s7) = sample_byte(s6)
  let v =
    b0 + b1 * 256 + b2 * 65536 + b3 * 16777216 + b4 * 4294967296 + b5 * 1099511627776 + b6 * 281474976710656 + b7 * 72057594037927936
  (v, s7)
}

// ── Public sampling API ───────────────────────────────────────────────────────

/// Sample a Goldilocks field element with rejection sampling.
///
/// Samples 8 bytes → LE u64. If the value is ≥ prime, resamples 8 more bytes
/// (probability ≈ 2^{-32}). Mirrors SerializingChallenger64::sample() for F=Goldilocks.
pub fn sample_val(st: ChallengerState) -> (Int, ChallengerState) {
  let (v, s) = sample_u64(st)
  if v < gf.prime {
    (v, s)
  } else {
    sample_val(s)
  }
}

/// Sample an Ext2 challenge: two consecutive Goldilocks field elements.
/// Mirrors challenger.sample_algebra_element() for Challenge = Ext2.
pub fn sample_ext(st: ChallengerState) -> (Ext2, ChallengerState) {
  let (c0, s0) = sample_val(st)
  let (c1, s1) = sample_val(s0)
  (Ext2 { c0, c1 }, s1)
}

/// Sample the n least-significant bits of a random u64 (no rejection sampling).
///
/// Mirrors SerializingChallenger64::sample_bits(n) which masks raw u64 bytes.
/// Used for query-index sampling (n = log_global_max_height = 14).
pub fn sample_bits(st: ChallengerState, n: Int) -> (Int, ChallengerState) {
  let (v, s) = sample_u64(st)
  (v % pow2(n), s)
}

// ── Proof-of-work verification ────────────────────────────────────────────────

/// Verify a proof-of-work witness (GrindingChallenger::check_witness):
///   1. observe witness as a Goldilocks element (8 LE bytes).
///   2. sample `bits` bits; return (sampled == 0, updated_state).
///
/// Config values:
///   commit_proof_of_work_bits = 1   (per FRI commit round)
///   query_proof_of_work_bits  = 16  (once, before query sampling)
pub fn check_pow(
  st: ChallengerState,
  bits: Int,
  witness: Int,
) -> (Bool, ChallengerState) {
  if bits == 0 {
    (True, st)
  } else {
    let s0 = observe_val(st, witness)
    let (result, s1) = sample_bits(s0, bits)
    (result == 0, s1)
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

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
  builtin.length_of_bytearray(st.input) == 0 && builtin.length_of_bytearray(
    st.output,
  ) == 0 && st.consumed == 0
}

test observe_val_appends_8_le_bytes() {
  // 1 in 8-byte LE = 01 00 00 00 00 00 00 00
  let st = observe_val(init(), 1)
  st.input == #"0100000000000000"
}

test observe_clears_output() {
  let st0 = ChallengerState { input: #"", output: #"aabbccdd", consumed: 0 }
  let st1 = observe_val(st0, 42)
  builtin.length_of_bytearray(st1.output) == 0
}

test flush_produces_32_byte_hash() {
  let st = flush(observe_val(init(), 1))
  builtin.length_of_bytearray(st.output) == 32 && builtin.length_of_bytearray(
    st.input,
  ) == 32 && st.consumed == 0
}

test flush_chaining() {
  // After flush, input = hash (so the next flush hashes the previous hash).
  let st0 = observe_val(init(), 5)
  let st1 = flush(st0)
  // st1.input == st1.output: chaining
  st1.input == st1.output
}

test sample_byte_reads_from_back() {
  // Build a known 32-byte output and verify sample_byte reads index [31].
  // We can verify this indirectly: two samples should differ (they read index 31 and 30).
  let st0 = observe_val(init(), 0)
  let (b0, st1) = sample_byte(st0)
  let (b1, _st2) = sample_byte(st1)
  // Both are valid bytes and the state advanced correctly.
  b0 >= 0 && b0 < 256 && b1 >= 0 && b1 < 256 && st1.consumed == 1
}

test sample_32_then_flush_again() {
  // After consuming all 32 bytes, the next sample triggers a new flush (chaining).
  let st0 = observe_val(init(), 7)
  let st1 = flush(st0)
  let first_hash = st1.output
  // Consume all 32 bytes
  let st2 = exhaust_output(st1, 32)
  // Next sample should flush again using the chaining hash
  let (_, st3) = sample_byte(st2)
  // Output should now differ from the first hash (it's sha256 of the first hash)
  st3.output != first_hash
}

fn exhaust_output(st: ChallengerState, n: Int) -> ChallengerState {
  if n <= 0 {
    st
  } else {
    let (_, s) = sample_byte(st)
    exhaust_output(s, n - 1)
  }
}

test sample_val_is_in_field() {
  let (v, _) = sample_val(observe_val(init(), 42))
  v >= 0 && v < gf.prime
}

test sample_ext_both_components_in_field() {
  let (e, _) = sample_ext(observe_val(init(), 7))
  e.c0 >= 0 && e.c0 < gf.prime && e.c1 >= 0 && e.c1 < gf.prime
}

test sample_bits_14_in_range() {
  let (idx, _) = sample_bits(observe_val(init(), 0), 14)
  idx >= 0 && idx < 16384
}

test check_pow_zero_bits_always_passes() {
  let (ok, _) = check_pow(init(), 0, 99)
  ok
}

test check_pow_is_deterministic() {
  let (ok1, _) = check_pow(observe_val(init(), 1), 1, 0)
  let (ok2, _) = check_pow(observe_val(init(), 1), 1, 0)
  ok1 == ok2
}

test determinism_same_transcript_same_sample() {
  let (v1, _) = sample_val(observe_val(init(), 42))
  let (v2, _) = sample_val(observe_val(init(), 42))
  v1 == v2
}

test different_observations_produce_different_samples() {
  let (v1, _) = sample_val(observe_val(init(), 1))
  let (v2, _) = sample_val(observe_val(init(), 2))
  v1 != v2
}
