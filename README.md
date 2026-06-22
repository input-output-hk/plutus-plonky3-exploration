# plutus-plonky3-exploration

Explorations and prototypes for verifying Plonky3 STARK proofs on Cardano.

> ### ⚠️ Important Disclaimer & Acceptance of Risk
>
> **This repository contains prototype implementations.** This code is provided "as is" for research and educational purposes
> only. It has not been thoroughly tested and audited and is not intended for production use. By using this code, you
> acknowledge and accept all associated risks, and our company disclaims any liability for damages or losses.

## Intent

[Plonky3](https://github.com/Plonky3/Plonky3) is a modular, production-grade STARK framework — the backbone of SP1 zkVM.

This repository investigates whether Plonky3 proofs can be verified on Cardano within Plutus execution limits, using existing builtins (SHA-256, integer arithmetic).

Cardano's current ZK path (Groth16/PLONK over BLS12-381) is pairing-based and therefore vulnerable to quantum attacks. STARKs are mature post-quantum alternative — they rely only on hash functions and field arithmetic, no elliptic curves — so the open question is whether a STARK verifier fits inside Plutus. This is a feasibility study, not a production verifier: the aim is concrete cost numbers and a gap analysis (which builtins, limit increases, or multi-tx patterns would be needed). See [docs/proposal-plonky3-stark-verification-on-cardano.md](docs/proposal-plonky3-stark-verification-on-cardano.md) for the full motivation.

## Repository layout

The repo has two halves that talk to each other through a JSON proof file:

- **`plonky3/`** — Rust. Generates STARK proofs with [Plonky3](https://github.com/Plonky3/Plonky3) v0.5.1 and serialises them to JSON.
- **`aiken/`** — Aiken (Plutus v3). A from-scratch re-implementation of the Plonky3 uni-stark and batch-stark verifier that runs **on-chain**, specialised to the Goldilocks field and a `FibonacciAir` example circuit.
- **`docs/`** — [`benchmark.md`](docs/benchmark.md) (all cost numbers), [`plonky3.md`](docs/plonky3.md) (FRI/PCS/MMCS verification spec), and the [proposal](docs/proposal-plonky3-stark-verification-on-cardano.md).

## Quickstart

### Prerequisites

- [Rust](https://www.rust-lang.org/tools/install) toolchain and [Aiken](https://aiken-lang.org/installation-instructions).

### Generate a STARK proof and run the Plutus verifier

Both flows follow the same three steps: **prove** in Rust (dump the proof to JSON) → **convert**
the JSON into an Aiken `test` literal → run the **Plutus verifier** over that literal with `aiken check`.
`convert.py` auto-detects whether the JSON is a uni-stark or batch-stark proof and writes the
matching generated file (`goldilocks_proof_test.ak` / `goldilocks_batch_proof_test.ak` — do not edit
either by hand).

**Uni-STARK** (single `FibonacciAir`):

```bash
cd plonky3
cargo run --release --bin export_proof proof.json   # prove → proof.json
python3 convert.py proof.json                        # → aiken/lib/stark/goldilocks_proof_test.ak
cd ../aiken && aiken check -m stark_verify_goldilocks_real_proof
```

**Batch-STARK** (`FibonacciAir` + `MulAir`):

```bash
cd plonky3
cargo run --release --bin export_batch_proof batch_proof.json   # prove → batch_proof.json
python3 convert.py batch_proof.json                             # → aiken/lib/stark/goldilocks_batch_proof_test.ak
cd ../aiken && aiken check -m stark_verify_batch_goldilocks_real_proof
```

`aiken check` prints the memory/CPU budget for each `test` (e.g. `[mem: 220.13 M, cpu: 75.27 B]`) — staying under Plutus limits is the metric this project tracks.

## Main results

A full on-chain verification of the batch-stark proof (Goldilocks², `FibonacciAir` + `MulAir`,
each `n = 2¹³`) measured as a single Aiken `test` costs **220.13 M mem / 75.27 B cpu** at
`log_blowup = 8`. The Plutus per-transaction limit is far smaller, so the proof is verified across
**multiple transactions** — one per FRI query plus one for the shared work.

At **93-bit security** (`query_pow = 16`, `commit_pow = 16`), trading `log_blowup` against
`num_queries`:

| log_blowup | num_queries | Proof size (bytes) | plutus_mem | plutus_cpu |
| ---------- | ----------- | ------------------ | ---------- | ---------- |
| 2          | 83          | 443,613            | 681.31 M   | 233.93 B   |
| 4          | 42          | 268,290            | 369.38 M   | 126.65 B   |
| 8          | 22          | 186,345            | 220.13 M   | 75.27 B    |

With `log_blowup = 8`, the **per-query cost is ≈ 9.47 M mem / 3.23 B cpu** — comfortably under the
~14 M per-transaction memory limit — and the query-independent work fits in one transaction, so the
full proof is verifiable in roughly **22 + 1 = 23 transactions**.

See [docs/benchmark.md](docs/benchmark.md) for the complete tables, including the uni-stark results,
cross-field comparisons, proven-soundness (Johnson-bound) numbers, and recursion/aggregation benchmarks.

## License

Copyright 2026 Input Output Global

Licensed under the Apache License, Version 2.0 (the "License"). You may not use this repository except in compliance
with the License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific
language governing permissions and limitations under the License
