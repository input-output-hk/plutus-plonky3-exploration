# Architecture

A developer-facing tour of this repository: how the two halves fit together, the
proof pipeline that links them, and a module-by-module map of both sides. For the
_why_ (motivation, security model), see [`README.md`](README.md) and
[`docs/proposal-plonky3-stark-verification-on-cardano.md`](docs/proposal-plonky3-stark-verification-on-cardano.md).
For the _algorithm_ (FRI/PCS/MMCS spec), read [`docs/plonky3.md`](docs/plonky3.md)
before touching `aiken/lib/stark/`.

> This is a research prototype, not a library. Everything is hard-specialised to a
> single configuration (see [Specialisation](#specialisation)); changing any fixed
> parameter requires coordinated edits on both sides.

## The big picture

The repo has two halves that communicate **only** through a JSON proof file:

```
┌─────────────────────────┐         JSON          ┌──────────────────────────┐
│  plonky3/  (Rust)        │   proof.json /         │  aiken/  (Plutus v3)      │
│                          │   batch_proof.json     │                          │
│  Plonky3 v0.5.1 prover   │ ─────────────────────► │  from-scratch verifier   │
│  + native verifier       │   via convert.py       │  runs ON-CHAIN           │
│  (source of truth)       │                        │  (mirrors Rust byte-     │
│                          │                        │   for-byte)              │
└─────────────────────────┘                        └──────────────────────────┘
```

The Rust side is the **source of truth**. The Aiken side re-implements the
Plonky3 uni-STARK and batch-STARK verifiers from scratch and must reproduce the
prover's transcript and arithmetic exactly — every SHA-256 absorption, every
field operation, every byte layout. When they disagree, the Rust side is right
and the Aiken side has the bug.

## The proof pipeline

Both flows (uni-STARK and batch-STARK) follow the same three steps:

```
   prove (Rust)              convert (Python)            verify (Plutus)
┌────────────────┐       ┌────────────────────┐      ┌─────────────────────┐
│ export_proof   │  JSON │ convert.py          │  .ak │ aiken check -m ...  │
│ export_batch_  │ ─────►│ auto-detects uni vs │ ────►│ runs stark_verify   │
│   proof        │       │ batch, emits a test │      │ over the literal,   │
└────────────────┘       │ literal             │      │ prints mem/cpu cost │
                         └────────────────────┘      └─────────────────────┘
```

1. **Prove** — a Rust binary generates a proof, natively re-verifies it (a guard
   against shipping a broken proof), prints timing/size, and writes the proof as
   JSON.
2. **Convert** — `plonky3/convert.py` reads the JSON, auto-detects whether it is a
   uni-STARK or batch-STARK proof, and writes a hard-coded Aiken `test` literal
   that embeds the entire proof and calls the verifier. The two generated files
   are **never edited by hand**:
   - `aiken/lib/stark/goldilocks_proof_test.ak` (uni-STARK)
   - `aiken/lib/stark/goldilocks_batch_proof_test.ak` (batch-STARK)
3. **Verify** — `aiken check -m <pattern>` runs the generated test through the
   on-chain verifier and prints the Plutus memory/CPU budget. Staying under the
   Plutus limit is the metric the project tracks (see
   [`docs/benchmark.md`](docs/benchmark.md)).

### Helper scripts

| Script                                   | What it does                                                                                                                                                                                                                                                         |
| ---------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [`run_pipeline.sh`](run_pipeline.sh)     | Runs the full prove→convert→verify pipeline. `./run_pipeline.sh [uni\|batch\|both\|check]` — `check` re-verifies the existing test literals without regenerating proofs.                                                                                             |
| [`set_fri_params.sh`](set_fri_params.sh) | Sets `log_blowup` and `num_queries` consistently across `export_proof.rs`, `export_batch_proof.rs`, **and** `aiken/lib/stark/params.ak` in one shot. `./set_fri_params.sh <log_blowup> <num_queries>`. These three must agree or the on-chain proof fails to verify. |

## Specialisation

The verifier is **not** generic. Both sides are hard-wired to one configuration;
changing any of these requires coordinated changes in the Rust provers
(`export_proof.rs` / `export_batch_proof.rs`) and the Aiken `lib/stark/` +
`lib/goldilocks/` code.

| Aspect         | Value                                                                                                                                      |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| **Field**      | Goldilocks, `p = 2^64 − 2^32 + 1`                                                                                                          |
| **Extension**  | `Ext2 = BinomialExtensionField<Goldilocks, 2>`, `X² − 7` (W = 7)                                                                           |
| **Hash**       | SHA-256 (`SerializingHasher` + `CompressionFunctionFromHasher`, arity 2, 32-byte digests)                                                  |
| **PCS**        | `TwoAdicFriPcs`, `MerkleTreeMmcs` with `cap_height = 0` (commitment = a single root)                                                       |
| **Challenger** | `SerializingChallenger64<Goldilocks, HashChallenger<u8, Sha256, 32>>`                                                                      |
| **FRI**        | binary arity (`max_log_arity = 1`), `log_blowup = 8`, `num_queries = 22`, `commit/query_proof_of_work_bits = 16`, `log_final_poly_len = 0` |
| **Sizes**      | `n = 8192`, `degree_bits = 13`                                                                                                             |
| **ZK**         | none                                                                                                                                       |

Two AIRs are exercised:

- **`FibonacciAir`** (uni-STARK) — 2 trace columns, 3 public values `(a, b, x)`,
  `max_constraint_degree = 2`, no preprocessed trace. `num_quotient_chunks = 1`;
  note `quotient_chunks[0].len() == 2` is the **Ext2 dimension**, not a chunk
  count — a recurring point of confusion.
- **`FibonacciAir` + `MulAir`** (batch-STARK) — two instances proved together,
  joined by a **global LogUp lookup**. `MulAir` sends `(a, b)` per rep to the
  global interaction `"MulFib"` (multiplicity 1, two reps); `FibAir` receives
  `(left, right)` with multiplicity 2. Because the traces match, the cumulated
  lookup sum is 0.

---

## Rust side — `plonky3/`

Rust generates and natively verifies proofs using Plonky3 v0.5.1.

> **Local Plonky3 checkout required.** `plonky3/Cargo.toml` has a `[patch]`
> section overriding every `p3-*` crate to a sibling checkout at `../../Plonky3/`.
> Without `Plonky3/` cloned next to this repo (at upstream tag `v0.5.1`), the build
> fails.

### Binaries (`[[bin]]` targets in `Cargo.toml`)

| Binary               | Source                      | Purpose                                                                                                        |
| -------------------- | --------------------------- | -------------------------------------------------------------------------------------------------------------- |
| `export_proof`       | `src/export_proof.rs`       | Goldilocks uni-STARK: prove, re-verify, dump proof to JSON.                                                    |
| `export_batch_proof` | `src/export_batch_proof.rs` | Goldilocks batch-STARK (`MulAir` + `FibonacciAir` with a global LogUp lookup): prove, re-verify, dump to JSON. |

---

## Aiken side — `aiken/`

A from-scratch port of the Plonky3 verifier that runs inside Plutus v3. Each
`lib/stark/` module cites the upstream `verifier.rs` / `two_adic_pcs.rs` /
`fri/verifier.rs` line ranges it mirrors — keep those references accurate, they
are the map back to the reference implementation.

### `lib/stark/` — the verifier

| Module                  | Role                                                                                                                                                                   | Key exports                                                                                                                                 |
| ----------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `verifier.ak`           | Top-level orchestration: shape checks → Fiat-Shamir transcript → PCS verify → constraint verify. Shared by the validator and the e2e tests.                            | `stark_verify`, `stark_verify_batch`                                                                                                        |
| `challenger.ak`         | Fiat-Shamir transcript mirroring `SerializingChallenger64`. The SHA-256 chaining in `flush()` is correctness-critical.                                                 | `observe_*` (absorb), `sample_val`/`sample_ext`/`sample_bits`, `check_pow`                                                                  |
| `pcs_verify.ak`         | `TwoAdicFriPcs::verify` — observes opened values, drives the FRI commit/query phases.                                                                                  | `pcs_verify`, `pcs_verify_batch`                                                                                                            |
| `fri.ak`                | FRI query/fold/commit-phase logic.                                                                                                                                     | `open_input`, `open_input_batch`, `verify_query`, `fold_row`, `reverse_bits_len`, `pow_reverse_bits`                                        |
| `mmcs.ak`               | Merkle multi-matrix opening verification (SHA-256).                                                                                                                    | `verify_batch`, `verify_batch_ext`, `hash_leaf`, `compress`                                                                                 |
| `verify_constraints.ak` | Evaluates AIR constraints at `zeta` and checks `constraints(zeta)/Z_H(zeta) == quotient(zeta)`; the batch variant also checks the cross-instance LogUp cumulative sum. | `verify_constraints`, `verify_constraints_batch`                                                                                            |
| `logup.ak`              | LogUp lookup-argument running-sum constraint terms.                                                                                                                    | `recompose_col`, `combine`, `global_terms`, `local_terms`                                                                                   |
| `proof.ak`              | Proof datatypes (generic over the extension field `ext`) + shape validators.                                                                                           | `StarkProof`, `BatchProof`, `OpenedValues`, `FriProof`, `QueryProof`, `BatchOpening`, `CommitPhaseStep`, `FibPublicInputs`, `valid_*_shape` |
| `params.ak`             | All fixed circuit/FRI parameters and domain definitions.                                                                                                               | `fri_params`, `degree_bits`, `num_quotient_chunks`, `batch_*`, domain helpers                                                               |

Generated, do-not-edit test literals also live here:
`goldilocks_proof_test.ak`, `goldilocks_batch_proof_test.ak`. Hand-written tests:
`proof_test.ak`, plus `lib/hash_test.ak`.

### `lib/<field>/` — field arithmetic

Each field directory exposes a `field.ak` (base field) and an `extN.ak`
(degree-N extension) with the same shape:

| Directory     | Files                 | Field                                             |
| ------------- | --------------------- | ------------------------------------------------- |
| `goldilocks/` | `field.ak`, `ext2.ak` | `p = 2^64 − 2^32 + 1`, W = 7 — **the live field** |
| `babybear/`   | `field.ak`, `ext4.ak` | `p = 2^31 − 2^27 + 1`                             |
| `koalabear/`  | `field.ak`, `ext4.ak` | `p = 2^31 − 2^24 + 1`                             |
| `mersenne31/` | `field.ak`, `ext3.ak` | `p = 2^31 − 1`                                    |

`field.ak` provides modular arithmetic (`add`/`sub`/`mul`/`neg`/`square`/`pow`/
`inverse`/`div`), the precomputed two-adic generator tables, and `eval_poly`.
`extN.ak` provides extension arithmetic plus the STARK helpers `vanishing_poly`,
`fold_constraints`, and `recompose_quotient`. Only Goldilocks is wired into the
live verifier; the others exist for the cross-field comparisons in
[`docs/benchmark.md`](docs/benchmark.md).

### `validators/` — Plutus entry points

| Validator         | What it is                                                                                                                                                                                                                 |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `fib_verifier.ak` | Thin spend validator: datum = `FibPublicInputs`, redeemer = `StarkProof<Ext2>`, body = `stark_verify(redeemer, pis)`. The verification logic deliberately lives in `lib/stark/verifier.ak` so it is shared with the tests. |
| `poly_eval.ak`    | A standalone polynomial-evaluation puzzle over BabyBear — a simpler, separate experiment unrelated to the STARK pipeline.                                                                                                  |

---

## Data flow through one verification

`stark_verify` (uni-STARK) follows the Plonky3 uni-STARK verifier:

1. **Shape checks** — `proof.ak` validators confirm trace width, quotient-chunk
   count, FRI round/query counts, and final-poly length match `params.ak`.
2. **Fiat-Shamir** — `challenger.ak` reconstructs the transcript: observe the
   trace commitment and public values, sample `alpha`; observe the quotient
   commitment, sample `zeta`. The SHA-256 absorption order must match the prover
   exactly.
3. **PCS verify** — `pcs_verify.ak` observes the opened values, then for each FRI
   query reduces the openings (`fri.ak::open_input`), folds down the commit phase
   (`fold_row` / `verify_query`), and authenticates every Merkle path
   (`mmcs.ak`).
4. **Constraint verify** — `verify_constraints.ak` evaluates the AIR constraints
   at `zeta`, folds them with `alpha`, and checks
   `Σ αⁱ·Cᵢ(zeta) == Z_H(zeta)·quotient(zeta)`.

`stark_verify_batch` extends this to two instances and adds the LogUp permutation
columns and the cross-instance cumulative-sum check (`logup.ak` +
`verify_constraints_batch`).

---

## Where to start reading

- **Changing FRI parameters (`log_blowup`, `num_queries`)?** Use `set_fri_params.sh` — it edits the Rust provers and `params.ak` together so they stay in sync.
- **Debugging a verification mismatch?** The transcript (`challenger.ak`) and the byte layout in `mmcs.ak` are the usual suspects; diff against the native `verify_proof` run.
- **Understanding the algorithm?** [`docs/plonky3.md`](docs/plonky3.md) first, then `verifier.ak` → `pcs_verify.ak` → `fri.ak`.
- **Cost numbers?** [`docs/benchmark.md`](docs/benchmark.md).
