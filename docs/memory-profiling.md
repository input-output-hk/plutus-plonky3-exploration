# Verifier memory profiling (Goldilocks uni-stark Fibonacci)

Profiling of `stark_verify` via the end-to-end test
`stark_verify_goldilocks_real_proof` (`aiken/lib/stark/goldilocks_proof_test.ak`).

Reported by `aiken check` for the full test:

```
mem: 232,852,244   cpu: 76,083,394,959
```

For context, Cardano mainnet allows ~14 M mem / ~10 B cpu per transaction, so
this proof is ~16× over the memory budget and ~7.6× over cpu.

Proof configuration (`aiken/lib/stark/params.ak`):
`degree_bits = 13`, `log_blowup = 8`, `num_queries = 22`,
`query_proof_of_work_bits = 16` → `log_global_max_height = 21`, 13 FRI fold
rounds.

## Method

The numbers below were produced empirically, not estimated:

1. **Phase split** — a temporary harness reused the real proof literal as a
   function and ran each phase (transcript / PCS-FRI / AIR constraints) as a
   separate `test`; the per-test `mem` deltas attribute the budget.
2. **Operation split inside PCS** — each heavy primitive was temporarily
   stubbed to a no-op (Merkle verification, `gf.pow`, `gf.inverse`, `ext2.mul`,
   `ext2` add/sub/scale, the challenger SHA-256 flush), re-running the PCS test
   each time. The drop after each stub = that operation's share. The final-poly
   check was forced to pass so all 22 queries still ran with stubbed arithmetic.

All stubs were reverted afterward; the suite is green and the test is back to
232,852,244 mem. The per-operation deltas sum to the PCS phase total (✓).

Calibration anchors (per-call mem, incl. loop overhead), from existing
micro-benchmarks: SHA-256 compress (64 B) ≈ 2,916; `ext2.mul` ≈ 23,300;
`ext2.inverse` ≈ 55,200; `ext2.add` ≈ 11,700.

## Breakdown

| Component | mem | % of total |
|---|---:|---:|
| **PCS / FRI verification** | **230,197,726** | **98.9%** |
| ├─ FRI loop recursion + proof-structure deconstruction + challenger sampling | 72,069,700 | 30.9% |
| ├─ Merkle SHA-256 (`mmcs`) | 56,212,740 | 24.1% |
| ├─ `gf.inverse` (Extended Euclidean) | 54,537,604 | 23.4% |
| ├─ `gf.pow` (square-and-multiply) | 26,638,086 | 11.4% |
| ├─ `ext2.mul` | 11,034,408 | 4.7% |
| └─ `ext2` add/sub/scale | 9,705,810 | 4.2% |
| AIR constraints (`verify_constraints`) | 1,615,881 | 0.7% |
| Fiat-Shamir transcript | 726,747 | 0.3% |
| Proof construction | 1,829 | ~0% |

Phase totals measured directly: transcript 726,747; PCS 230,197,726;
constraints 1,615,881; construction 1,829.

Notable: hashing is *not* the dominant cost. Field arithmetic on FRI
evaluation points (`gf.inverse` + `gf.pow` = ~35%) and pure structural overhead
(~31%) together dominate. The challenger's own SHA-256 flushing was negligible
(~33 K).

## Proposed Optimizations (priority order)

### 1. Carry the FRI evaluation point `x` (and `inv_x`) down the fold chain by squaring — attacks ~35% (`gf.pow` + most of `gf.inverse`)

`fri.fold_row` currently recomputes, every round and every query (286×):

```
x      = gf.pow(g_{h+1}, reverse_bits_len(parent_index, h))   // ~20 base muls
inv_x  = gf.inverse(x)                                        // full EEA
```

But the FRI domains are nested, so the point at the next (folded) layer relates
to the current one by a single squaring. Derivation (with `b = log_folded`,
`n = index`, `g = g_{b+1}`):

```
x       = g^{ rbl(n, b) }
x_next  = g_b^{ rbl(n>>1, b-1) } = (g^2)^{ rbl(n>>1, b-1) }
rbl(n, b) = rbl(n>>1, b-1) + (n & 1)·2^{b-1}
=> x^2 = x_next · g^{(n&1)·2^b} = x_next · (-1)^{n&1}     (g^{2^b} = -1)
=> x_next = x^2 · (-1)^{n&1} = ± x^2
```

So per query: compute `x` and `inv_x` **once** at the top of the chain (1 EEA),
then each round do `x := ±x²` and `inv_x := ±inv_x²` (one base mul + a
conditional negate each). This replaces ~13 `gf.pow` + ~13 EEAs per query with
1 EEA + ~13 squarings. This is also how Plonky3's verifier folds the point.

`fold_row` only ever used `inv_x` (via `inv_2x = half·inv_x`), never `x`
directly, so the implementation takes `inv_x` as a parameter and `verify_query`
carries it down the chain. The identity `x_next = ±x²` (sign = `(-1)^{parent_index&1}`)
is checked against from-scratch recomputation by the `inv_x_chain_matches_scratch`
test in `fri.ak`. Both the uni-stark and batch paths share `verify_query`, so both
benefit. **Implemented — measured result:**

| | mem | cpu |
|---|---:|---:|
| Before | 232,852,244 | 76,083,394,959 |
| After #1 | 142,826,575 | 48,022,137,264 |
| Reduction | −90,025,669 (−38.7%) | −28,061,257,695 (−36.9%) |

### 2. Single-slice challenger sampling — read each u64 in one slice instead of eight per-byte pops

The challenger sampled one byte at a time: `sample_u64` made 8 `sample_byte`
calls, each allocating a fresh `ChallengerState`, then reassembled the value via
a big multiply-add chain. Replaced with a single `slice_bytearray` +
`bytearray_to_integer` per u64. `consumed` is always a multiple of 8 (every
consumer draws whole u64s, and observe/flush reset it to 0), so the 8 bytes
never span a flush boundary. Semantics are unchanged — every test, including the
end-to-end proof, produces identical challenges; a regression test
(`sample_u64_equals_per_byte_reference`) pins the new `sample_u64` against the
original byte-at-a-time recombination for every reachable state.

This alignment holds for any `SerializingChallenger64` (8-byte) instantiation
regardless of circuit or public-input changes — observes reset `consumed` to 0
and every draw advances it by 8. It would only break under a non-8-byte sampler,
i.e. a `SerializingChallenger32` (4-byte) port for a 31-bit field (BabyBear,
KoalaBear, Mersenne31). An `expect s.consumed % 8 == 0` guard enforces the
precondition, so such a port fails loudly rather than silently diverging.

**Implemented — measured result (on top of #1):**

| | mem | cpu |
|---|---:|---:|
| After #1 | 142,826,575 | 48,022,137,264 |
| After #2 | 134,048,495 | 44,974,991,312 |
| Reduction | −8,778,080 (−6.1%) | −3,047,145,952 (−6.3%) |

Cumulative from the 232,852,244 baseline: **−42.4% mem, −40.9% cpu.**

Still open in this bucket: most of the ~31% is the FRI query/fold loop
deconstructing the proof's nested list structure (Merkle paths, opened values)
across 22 queries × 13 rounds, plus tuple/`Option` churn in
`acc_cols`/`dot_diff`/`do_verify_query`. Reducing it further means restructuring
how the proof is traversed, not a local rewrite.

### 3. Build FRI commit-phase leaves directly from the Ext2 row

`verify_batch_ext` (the commit-phase Merkle leaf — 13 rounds × 22 queries = 286
calls) flattened each `[Ext2(c0,c1), …]` row into an intermediate `List<Int>`
via `append_int` — which is O(n²) (it reverses the accumulator on every element)
— and then walked that list a second time to build the SHA-256 byte payload.
Replaced with a single pass that serialises each `Ext2` straight to bytes
(`le8(c0) ++ le8(c1)`), skipping the intermediate list and its O(n²) append.
Byte-for-byte identical (pinned by the `ext_row_leaf_matches_flatten` test); the
end-to-end proof still verifies. This cost was attributed to the Merkle bucket in
the original profile (stubbing the Merkle verify also skipped the flatten), which
is why removing it lands a much larger ~22 M than "leaf hashing" alone suggests.

**Implemented — measured result (on top of #2):**

| | mem | cpu |
|---|---:|---:|
| After #2 | 134,252,155 | 45,052,654,928 |
| After #3 | 112,208,423 | 38,971,739,584 |
| Reduction | −22,043,732 (−16.4%) | −6,080,915,344 (−13.5%) |

Cumulative from the 232,852,244 baseline: **−51.8% mem, −48.8% cpu.**

## Deferred opportunities

Not implemented here — each is gated on a decision rather than a mechanical
change (a security-parameter choice, or a single-transaction-only assumption).

### Reduce the FRI query count (right-size soundness parameters)

The FRI parameters (`params.ak` → `fri_params`) are `log_blowup = 8`,
`num_queries = 22`, `query_proof_of_work_bits = 16`, giving a conjectured
soundness of `log_blowup × num_queries + query_pow_bits = 8·22 + 16 = 192` bits
(formula from `docs/benchmark.md`) — roughly **2× a 100-bit target**.

The query phase is per-query and accounts for almost the entire verifier cost
(the commit phase and transcript are a small shared remainder), so cutting
`num_queries` scales the dominant cost **near-linearly** and is **split-safe**
(fewer/smaller shards, no cross-query coupling). To reach ~100 conjectured bits
at `log_blowup = 8` you need `8q + 16 ≥ 100` → `q ≥ 11`, i.e. 22 → 11 queries,
roughly **halving** the query-phase work.

**Why it is *not* applied here:** it is a *security-parameter decision*, not a
mechanical optimization. It requires (a) choosing the target soundness level and
(b) deciding whether the *conjectured* soundness model is acceptable, or a
*provable* margin is required — `docs/benchmark.md` notes the Johnson bound is
substantially lower than the conjectured figure (e.g. ~50-bit vs 116-bit for the
`log_blowup = 1, num_queries = 100` config). That's a protocol/security call, so
it is left as a deliberate parameter choice rather than baked in.

Related knob: `log_blowup` trades per-query Merkle path length and `gf.pow`
exponent size (`log_global_max_height = degree_bits + log_blowup`) against the
number of queries needed for a given soundness (the fold-round count stays
`degree_bits` regardless). A joint `(log_blowup, num_queries)` choice can be
tuned once the target is fixed.

### Batch inversion of field elements (Montgomery's trick) — single-transaction only

`N` independent inversions can be replaced by `1` inversion + `3(N−1)`
multiplications: accumulate the running products `p_i = a_0·a_1·…·a_i`, invert
the last one once, then walk back multiplying out each factor. Since a single
`gf.inverse` (Extended Euclidean) is ~165 K mem and a multiply is far cheaper,
this is a large win when many inversions are batched.

**Why it is *not* implemented:**

1. **Optimization #1 already drained the bulk.** Before any work there were
   ~330 field inversions (≈54.5 M). #1 collapsed the 286 fold-chain inversions
   to ~1 per query. What remains is small — roughly 66 EEAs (~11 M):
   - `initial_inv_x` (from #1): 1 per query → 22
   - `open_input` DEEP denominators (`inv_z_x`, `inv_zn_x`): 2 per query → 44

2. **The split-safe form is marginal.** Batching only the two denominators
   *within* one `open_input` saves ~1 inversion per query ≈ ~3.6 M (~2.7% of the
   current 134 M) — not worth the added complexity on its own.

3. **The high-impact form breaks query splitting.** The real win comes from
   batching inversions *across all queries* (collect every denominator — and the
   per-query `initial_inv_x` seeds — into one pass: 1 inversion + muls). But that
   couples all queries into a single computation, which is incompatible with the
   plan to shard queries across separate transactions (see the cross-query
   coupling discussion: any shared inversion accumulator destroys per-query
   independence).

**When to revisit:** if the whole proof is verified in a **single transaction**
(no sharding), cross-query batch inversion becomes viable. Collect all ~66
inversion inputs (44 `open_input` denominators + 22 `initial_inv_x` seeds, or as
many as is convenient), do one `gf.inverse` + `3(N−1)` muls, and recover the
individual inverses. Estimated saving on top of #1+#2: replacing ~65 EEAs with 1
≈ **~10 M mem**. In that single-tx setting it is one of the cleaner remaining
wins; under sharding it is off the table.
