# Proposal: Plonky3 STARK Verification on Cardano

## Problem

Cardano's current ZK verification path (Groth16/PLONK/Halo2 over BLS12-381) relies on pairing-based cryptography, which is vulnerable to quantum attacks via Shor's algorithm. As NIST PQC standards are deployed across the industry and the quantum threat timeline tightens, Cardano needs a path to post-quantum ZK verification.

STARKs are the most mature post-quantum proof systems — they rely only on hash functions and field arithmetic, no elliptic curves. However, no one has analysed whether STARK verification is feasible within Cardano's execution constraints, and if not, what's missing.

## Why Plonky3

Plonky3 is the leading production-grade STARK framework:

- **Powers SP1** (Succinct) — one of the two dominant zkVMs, used for Ethereum light clients, cross-chain bridges, and rollup proving
- **Backbone of Ethereum Foundation's post-quantum initiative** — leanMultisig (part of "Lean Ethereum") was originally built on Plonky3 infrastructure for SNARK-based signature aggregation
- **Modular design** — configurable field (BabyBear, Mersenne31, Goldilocks), hash function (Poseidon2, BLAKE3, Keccak, SHA-256), and commitment scheme (FRI, Brakedown)
- **Active development** — canonical repo at github.com/Plonky3/Plonky3, actively maintained, production-deployed

Plonky3's hash-function agnosticism is particularly relevant: preliminary analysis suggests that configuring the final proof layer to use blake2b or Keccak (which Cardano already has as a cheap Plutus builtin) could make verification feasible without new CIPs.

## Proposed Work

Build a **Plonky3 STARK verifier in Aiken** and benchmark it against Cardano's execution limits. The goal is not (yet) a production verifier but a concrete feasibility study that answers: *can Cardano verify post-quantum STARK proofs, and what's missing?*

### Deliverables

1. **Plonky3 verifier implementation in Aiken** — a script that verifies a Plonky3 STARK proof (blake2b Merkle commitments, BabyBear or Goldilocks field arithmetic, FRI verification).

2. **Benchmarks** — concrete measurements of CPU, memory, and script size for each verifier component:
   - Field arithmetic cost (BabyBear/Goldilocks multiplications, additions, inversions)
   - Hash throughput (blake2b Merkle path verification)
   - FRI query verification
   - Total verification cost and number of transactions required

3. **Poseidon2 feasibility assessment** — can Poseidon2 be implemented in Aiken at acceptable cost? This matters for verifying proofs from existing systems (SP1, Stwo) that use Poseidon2 internally. Benchmark interpreted Poseidon2 in Aiken and quantify the gap vs. a hypothetical native builtin.

4. **Gap analysis** — a concrete list of what Cardano would need (builtins, execution limit increases, multi-tx patterns) to make STARK verification practical.


## Expected Outcomes

- **Confirm or refute** preliminary analysis suggesting verification is feasible in 5–10 transactions with blake2b
- **Concrete cost numbers** for STARK operations in Plutus — replacing the current order-of-magnitude estimates with actual benchmarks
- **Hands-on experience** with post-quantum proof systems on Cardano — building institutional knowledge for future work
- **Actionable CIP recommendations** — if specific builtins (Poseidon2, small-field arithmetic) would transform feasibility, we'll have the benchmarks to justify the proposals
- **Foundation for future work** — the Aiken verifier and benchmarking framework can be extended to other STARK variants (Stwo/Circle STARKs, WHIR-based systems)

## Relation to Other Work

**Groth16/BN254 Wrapper Toolkit (Proposal 1).** This proposal complements the wrapper toolkit, which addresses the near-term production path using pairing-based crypto. The two serve different timelines: the wrapper gives Cardano ZK capabilities now; this proposal builds toward a post-quantum future.

**Ethereum Foundation's Lean Ethereum initiative.** The EF is tackling the same problem — migrating Ethereum's consensus layer away from BLS signatures toward hash-based (post-quantum) alternatives, using SNARK-based aggregation built on Plonky3 infrastructure. Our work on Plonky3 verification parallels this effort and positions Cardano to benefit from the same research.

**Cardano post-quantum migration.** Cardano's consensus currently relies on Ed25519 and BLS signatures, both vulnerable to quantum attacks. A future migration to post-quantum primitives might require also post-quantum SNARKs/STARKs to be run on-chain.

## Open Questions

- **Extension field costs:** STARK verification uses extension fields for 128-bit security, which multiplies the cost of base field operations. The actual complexity of both base and extension field arithmetic on Cardano needs to be investigated.
- **blake2b:** Plonky3 has Keccak and SHA-256 backends which are supported by Cardano. But the most efficient hash-function is blake2b. We might need to implement a blake2b hasher for Plonky3.
- **Multi-transaction verification:** Proofs of 50–150 KB exceed the 16 KB tx limit and need to be split across several UTxOs. We need to explore whether we could split and submit concurrently to reduce the on-chain latency.

