# Benchmark

## Fibonacci with uni-stark

Production-like parameters

```
FriParameters {
    log_blowup: 1,
    log_final_poly_len: 0,
    max_log_arity: 1,
    num_queries: 100,
    commit_proof_of_work_bits: 0,
    query_proof_of_work_bits: 16,
    mmcs,
}

- Conjectured soundness bits 116
- Johnson bound ~50-bit (without PoW)
```

`Conjectured soundness bits = log_blowup * num_queries + query_proof_of_work_bits`

|                     | BabyBear  | KoalaBear | Goldilocks | CircleStark |
| ------------------- | --------- | --------- | ---------- | ----------- |
| log_blowup          | 1         | 1         | 1          | 1           |
| Proof degree bits   | 13        | 13        | 13         | 13          |
| n                   | 8192      | 8192      | 8192       | 8192        |
| quotient_chunks len | 4         | 4         | 2          | 3           |
| Proving time (ms)   | 27.419676 | 22.963627 | 27.009029  | 52.098038   |
| Verifying time (ms) | 2.618049  | 2.552546  | 2.802918   | 2.790042    |
| Proof size (bytes)  | 414607    | 414493    | 414633     | 458782      |

```
FriParameters {
    log_blowup: 2,
    log_final_poly_len: 0,
    max_log_arity: 1,
    num_queries: 100,
    commit_proof_of_work_bits: 0,
    query_proof_of_work_bits: 16,
    mmcs,
}

- Conjectured soundness bits 216
- Johnson bound ~100-bit (without PoW)
```

### Goldilocks with sha256

- `log_blowup = 2`
- Proving time = 51.468141ms
- quotient_chunks len = 2
- Proof size 2adic: 462706 bytes for n = 8192
- Proof degree bits: 13
- Verifying time = 3.036942ms

---

## Aiken

Plonky3 verification

### Fri + TwoAdicFriPcs:

```
log_blowup = 1

Full verifier:
    ┍━ stark/goldilocks_proof_test ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    │ PASS [mem: 726.80 M, cpu: 238.02 B] stark_verify_goldilocks_real_proof
    ┕━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 1 tests | 1 passed | 0 failed
```

```
log_blowup = 2

Full verifier:
┍━ stark/goldilocks_proof_test ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    │ PASS [mem: 768.05 M, cpu: 251.38 B] stark_verify_goldilocks_real_proof
    ┕━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 1 tests | 1 passed | 0 failed
```

Babybear/KoalaBear:

- `log_blowup = 1`
- `SHA256 calls on 512 bit = 13429`
- `binomial extension add = 3509`
- `binomial extension mul = 15418`
- `binomial extension inverse = 1603`

Goldilocks:

- `log_blowup = 1`
- `SHA256 calls on 512 bit = 13442`
- `binomial extension add = 3307`
- `binomial extension mul = 14816`
- `binomial extension inverse = 1603`

### Fri + CirclePcs:

Mersenne31:

- `log_blowup = 1`
- `SHA256 calls on 512 bit = 15230`
- `binomial extension add = 5168`
- `binomial extension sub = 2960`
- `binomial extension mul = 6026`
- `cubic square = 2150`
- `cubic inverse = 610`

### Hash 14,000 times on 512-bit input

- `log_blowup = 1`

|        | keccak_256 | sha2_256 | sha3_256 | blake2b_256 |
| ------ | ---------- | -------- | -------- | ----------- |
| memory | 40.82 M    | 40.82 M  | 40.82 M  | 40.82 M     |
| cpu    | 48.51 B    | 15.94 B  | 37.25 B  | 13.37 B     |

### Bionomial extension field

- `log_blowup = 1`

|                 |              |  Memory   |   CPU    |
| :-------------: | :----------: | :-------: | :------: |
|  babybear_ext4  |   add_3509   |  80.75 M  | 28.37 B  |
|                 |  mul_15418   | 966.60 M  | 316.41 B |
|                 | inverse_1603 |  255.9 M  | 79.94 B  |
|                 | -- total --  | 1303.25 M | 424.72 B |
| koalabear_ext4  |   add_3509   |  80.75 M  | 28.37 B  |
|                 |  mul_15418   | 966.60 M  | 316.41 B |
|                 | inverse_1603 | 224.08 M  | 70.21 B  |
|                 | -- total --  | 1271.43 M | 414.99 B |
| goldilocks_ext2 |   add_3307   |  38.51 M  | 12.84 B  |
|                 |  mul_14816   | 344.28 M  | 118.76 B |
|                 | inverse_1603 |  88.43 M  | 27.57 B  |
|                 | -- total --  | 471.22 M  | 159.17 B |
| mersenne31_ext3 |   add_5168   |  88.36 M  | 30.34 B  |
|                 |   sub_2960   |  50.61 M  | 17.37 B  |
|                 |   mul_6026   | 285.37 M  | 92.10 B  |
|                 | square_2150  |  57.50 M  | 18.18 B  |
|                 | inverse_610  |  52.14 M  | 16.24 B  |
|                 | -- total --  | 533.98 M  | 174.23 B |

---

## Proven soundness

The formula for computing the number of queries needed to reach a security target is
`num_queries = ceil( −(security − query_pow) / log₂(1 − δ) )`. Plonky3 only evaluates this for
conjectured soundness, not for proven soundness (e.g. the Johnson bound), where
`δ = 1 − √ρ − η`, `ρ = 1/2^{log_blowup}`, and η is a small correction factor. A smaller η
yields a lower `num_queries`, so we want the smallest η that still meets the security target.
leanMultisig provides an algorithm that finds this optimal `η = √ρ / 2^log_c` for
sumcheck + KoalaBear⁵; we adapted it by stripping out the sumcheck-specific calculation so it
applies generically.

Selecting η also requires checking that the commit-phase soundness, calculated by
`extension_field_size − errors`, reaches the security target. This bound is independent
of `num_queries` and decreases as `log_blowup` grows, so beyond some point the security target becomes
unreachable no matter how many queries are used. Concretely, the calculation puts 128-bit
Goldilocks² at ~89 bits of commit-phase soundness and 124-bit KoalaBear⁴ at ~85 bits.
To reach ~100-bit security we can recover the missing bits by grinding `commit_pow` - this slows the prover but
lets us keep Goldilocks². Reaching ~120-bit security instead requires a larger extension
field - Goldilocks³ or KoalaBear⁵ - which increases the on-chain CPU and memory costs.

### 96-bit security

query_pow = 16, commit_pow = 16, Goldilocks², Fibonacci circuit n = 2¹³ = 8192

| log_blowup | num_queries | Proving time | Proof size (bytes) | Verifying time | plutus_mem | plutus_cpu |
| ---------- | ----------- | ------------ | ------------------ | -------------- | ---------- | ---------- |
| 2          | 83          | 161.07705ms  | 384126             | 2.610589ms     | 640.81 M   | 209.51 B   |
| 4          | 42          | 304.008673ms | 235050             | 1.575957ms     | 365.96 M   | 119.60 B   |
| 8          | 22          | 2.397145461s | 165661             | 1.168463ms     | 232.06 M   | 75.89 B    |
| 16         | unreachable | —            | —                  | —              | —          | —          |

### 105-bit security

query_pow = 16, commit_pow = 16, Goldilocks², Fibonacci circuit n = 2¹³ = 8192

| log_blowup | num_queries | Proving time | Proof size (bytes) | Verifying time | plutus_mem | plutus_cpu |
| ---------- | ----------- | ------------ | ------------------ | -------------- | ---------- | ---------- |
| 2          | 98          | 162.101287ms | 453422             | 2.819012ms     | 753.32 M   | 246.29 B   |
| 4          | 51          | 307.952548ms | 285277             | 1.771928ms     | 440.39 M   | 143.92 B   |
| 8          | unreachable | —            | —                  | —              | —          | —          |

Goldilocks has `two_adicity = 32`. The FRI/LDE evaluation domain must be a two-adic
multiplicative coset, so its size `2^(log_n + log_blowup)` is bounded by the field's
two-adicity: `log_n + log_blowup ≤ 32`, where `log_n` is the log₂ of the trace height.
For example, `log_blowup = 8` caps the trace at `log_n = 24`.
Moreover, as mentioned above, a larger `log_blowup` lowers the commit-phase soundness, so beyond some point the
target is unreachable regardless of `num_queries`. That is why `log_blowup = 16` cannot
reach 100-bit security, and `log_blowup = 8` cannot reach 105-bit.

The on-chain `stark_verifier` contract already supports any `log_blowup` and `num_queries`; they
just need to be set in `params.ak` before calling the verifier. At 96-bit security with
`log_blowup = 8` and `num_queries = 22`, the proof is 165,661 bytes and contains 22 query
proofs. We expect to verify each query proof in a single transaction, and thus the full proof
in ~25 transactions.

---

## Plonky3-Recursion

### Recursive Keccak

```bash
cargo run --release --example recursive_keccak -- --field koala-bear --num-hashes 1000 --num-recursive-layers 3

cargo run --profile optimized --example recursive_keccak -- --field koala-bear --num-hashes 1000 --num-recursive-layers 3
```

| Prover            | Proof size (bytes) 500h | Proving time (s) 500h | Verify time (ms) 500h | Proof size (bytes) 1000h | Proving time (s) 1000h | Verify time (ms) 1000h |
| ----------------- | ----------------------- | --------------------- | --------------------- | ------------------------ | ---------------------- | ---------------------- |
| plonky3-uni-stark | 988,200                 | 17.7                  | 28.2                  | 1,003,013                | 36.1                   | 29.2                   |
| plonky3-recursion | 518,487                 | 26.1                  | 11.9                  | 518,500                  | 27.1                   | 11.9                   |
| plonky3-recursion | 427,853                 | 3.77                  | 10.5                  | 428,091                  | 4.04                   | 10.1                   |
| plonky3-recursion | 404,370                 | 3.75                  | 9.69                  | 404,546                  | 3.99                   | 9.51                   |

#### With more optimisation

```bash
RUSTFLAGS=-Ctarget-cpu=native RUSTFLAGS=-Copt-level=3 RUST_LOG=info cargo run --release \
    --example recursive_keccak --features parallel -- -n 1000
```

| Prover            | Proof size (bytes) 500h | Proving time (s) 500h | Verify time (ms) 500h | Proof size (bytes) 1000h | Proving time (s) 1000h | Verify time (ms) 1000h |
| ----------------- | ----------------------- | --------------------- | --------------------- | ------------------------ | ---------------------- | ---------------------- |
| plonky3-uni-stark | 988,200                 | 3.4                   | 28.2                  | 1,003,013                | 6.11                   | 29.2                   |
| plonky3-recursion | 518,487                 | 5.18                  | 11.9                  | 518,500                  | 4.21                   | 11.9                   |
| plonky3-recursion | 427,853                 | 0.779                 | 10.5                  | 428,091                  | 0.855                  | 10.1                   |
| plonky3-recursion | 404,370                 | 0.807                 | 9.69                  | 404,546                  | 0.738                  | 9.51                   |

---

### Recursive Fibonacci

```bash
cargo run --release --example recursive_fibonacci -- \
    --field koala-bear --n 10000 --num-recursive-layers 3
```

| Prover              | Proof size (bytes) 10k iters | Proving time (s) 10k iters | Verify time (ms) 10k iters |
| ------------------- | ---------------------------- | -------------------------- | -------------------------- |
| plonky3-batch-stark | 264,799                      | 0.382                      | 6.26                       |
| plonky3-recursion   | 435,716                      | 3.18                       | 10.4                       |
| plonky3-recursion   | 404,424                      | 3.95                       | 12.2                       |
| plonky3-recursion   | 404,538                      | 4.08                       | 9.67                       |

#### With more optimisation

```bash
RUSTFLAGS=-Ctarget-cpu=native RUSTFLAGS=-Copt-level=3 RUST_LOG=info cargo run --release \
    --example recursive_fibonacci --features parallel -- -n 10000
```

| Prover              | Proof size (bytes) 10k iters | Proving time (s) 10k iters | Verify time (ms) 10k iters |
| ------------------- | ---------------------------- | -------------------------- | -------------------------- |
| plonky3-batch-stark | 264,799                      | 0.088                      | 6.26                       |
| plonky3-recursion   | 435,716                      | 0.604                      | 10.4                       |
| plonky3-recursion   | 404,424                      | 0.776                      | 12.2                       |
| plonky3-recursion   | 404,538                      | 0.761                      | 9.67                       |

---

### Recursive Aggregation

```bash
cargo run --release --example recursive_aggregation -- \
    --field koala-bear --num-recursive-layers 2
```

**2-to-1 proof merging — 4 base proofs, 2 aggregation levels**

| Prover              | Proof size (bytes) | Proving time (s) | Verify time (ms) |
| ------------------- | ------------------ | ---------------- | ---------------- |
| plonky3-batch-stark | 142,200            | 0.0435           | 3.83             |
| plonky3-batch-stark | 141,961            | 0.0291           | 3.55             |
| plonky3-batch-stark | 142,107            | 0.0375           | 3.86             |
| plonky3-batch-stark | 142,275            | 0.0439           | 3.75             |
| plonky3-aggregation | 434,191            | 4.77             | 10.2             |
| plonky3-aggregation | 434,252            | 3.97             | 11.1             |
| plonky3-aggregation | 424,540            | 7.81             | 10.3             |

#### With more optimisation

```bash
RUSTFLAGS=-Ctarget-cpu=native RUSTFLAGS=-Copt-level=3 RUST_LOG=info cargo run --release \
    --example recursive_aggregation --features parallel -- --field koala-bear
```

**4 base proofs, 2 aggregation levels, 2-to-1 proof merging**

| Prover              | Proof size (bytes) | Proving time (s) | Verify time (ms) |
| ------------------- | ------------------ | ---------------- | ---------------- |
| plonky3-batch-stark | 142,200            | 0.0538           | 3.83             |
| plonky3-batch-stark | 141,961            | 0.0519           | 3.55             |
| plonky3-batch-stark | 142,107            | 0.0397           | 3.86             |
| plonky3-batch-stark | 142,275            | 0.0372           | 3.75             |
| plonky3-aggregation | 434,191            | 1.44             | 10.2             |
| plonky3-aggregation | 434,252            | 1.21             | 11.1             |
| plonky3-aggregation | 424,540            | 2.27             | 10.3             |

---
