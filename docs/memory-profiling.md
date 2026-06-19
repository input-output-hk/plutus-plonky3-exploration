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

### 2. Batch inversion (Montgomery's trick)

For inversions #1 does not already remove (e.g. the per-query DEEP denominators
in `open_input`): N inversions → 1 inversion + 3(N−1) muls.

### 3. Trim the ~31% structural overhead

`challenger.sample_byte` allocates a fresh `ChallengerState` per byte (8 per
u64) and reassembles via a big multiply-add chain; slicing 8 bytes at once would
help. The `acc_cols`/`dot_diff`/fold loops also churn tuples/`Option`s.
