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
- Johnson bound 50-bit (without PoW)
```

`Conjectured soundness bits = log_blowup * num_queries + query_proof_of_work_bits`

### Babybear with sha256

- `log_blowup = 1`
- Proving time = 27.419676ms
- quotient_chunks len = 4
- Proof size 2adic: 414607 bytes for n = 8192
- Proof degree bits: 13
- Verifying time = 2.618049ms

### KoalaBear with sha256

- `log_blowup = 1`
- Proving time = 22.963627ms
- quotient_chunks len = 4
- Proof size 2adic: 414493 bytes for n = 8192
- Proof degree bits: 13
- Verifying time = 2.552546ms

### Goldilocks with sha256

- `log_blowup = 1`
- Proving time = 27.009029ms
- quotient_chunks len = 2
- Proof size 2adic: 414633 bytes for n = 8192
- Proof degree bits: 13
- Verifying time = 2.802918ms

### CircleStark with sha256

- `log_blowup = 1`
- Proving time = 52.098038ms
- quotient_chunks len = 3
- Proof size: 458782 bytes for n = 8192
- Proof degree bits: 13
- Verifying time = 2.790042ms

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
- Johnson bound 100-bit (without PoW)
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
