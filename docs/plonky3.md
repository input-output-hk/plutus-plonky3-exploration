# Plonky3 Glossary

**MerkleTreeMmcs**: A vector commitment scheme backed by a MerkleTree. A MerkleTreeMmcs is a generalization of the standard MerkleTree commitment scheme which supports committing to several matrices of different dimensions. MerkleTreeMmcs generalizes a classical Merkle Tree to support committing to a list of matrices by arranging their rows into a unified binary tree. The tallest matrix defines the maximum height, and smaller matrices are integrated at appropriate depths.

Say we wish to commit to 2 matrices M and N with dimensions (8, i) and (2, j) respectively. Let H denote the hash function and C the compression function for our tree. Then MerkleTreeMmcs produces a commitment to M and N using the following tree structure:

```
                              root = c00 = C(c10, c11)
                        /                                     \
    c10 = C(C(c20, c21), H(N[0]))         c11 = C(C(c22, c23), H(N[1]))
           /                \                                  /             \
  c20=C(L,R)   c21=C(L,R)                        c22=C(L,R)   c23=C(L,R)
   L/     \R    L/     \R                          L/     \R    L/     \R
H(M[0]) H(M[1]) H(M[2]) H(M[3])          H(M[4]) H(M[5]) H(M[6]) H(M[7])
```

E.g. we start by making a standard MerkleTree commitment for each row of M and then add in the rows of N when we get to the correct level. A proof for the values of say `M[5]` and `N[1]` consists of the siblings `H(M[4]), c23, c10`.

**MerkleTreeHidingMmcs**: This is similar to MerkleTreeMmcs, but each leaf is "salted" with random elements. This turns the Merkle tree into a hiding commitment.

**ExtensionMmcs**: A wrapper to lift an MMCS from a base field F to an extension field EF. ExtensionMmcs allows committing to and opening matrices over an extension field by internally using an MMCS defined on the base field. It works by flattening each extension field element into its base field coordinates for commitment, and then reconstructing them on opening.

**SerializingChallenger32**: Given a challenger that can observe and sample bytes, produces a challenger that is able to sample and observe field elements of a PrimeField32.

**Radix2DitParallel**: A parallel FFT algorithm which divides a butterfly network's layers into two halves. For the first half, we apply a butterfly network with smaller blocks in earlier layers, i.e. either DIT or Bowers G. Then we bit-reverse, and for the second half, we continue executing the same network but in bit-reversed order. This way we're always working with small blocks, so within each half, we can have a certain amount of parallelism with no cross-thread communication.

**TwoAdicFriPcs**: A polynomial commitment scheme using FRI to generate opening proofs. We commit to a polynomial `f` via its evaluation vectors over a coset `gH` where `|H| >= 2 * deg(f)`. A value `f(z)` is opened by using a FRI proof to show that the evaluations of `(f(x) - f(z))/(x - z)` over `gH` are low degree.

**HidingFriPcs**: A hiding FRI PCS. Both MMCSs must also be hiding; this is not enforced at compile time so it's the user's responsibility to configure.

---

## Comparison of CirclePcs with TwoAdicFriPcs

CirclePcs and TwoAdicFriPcs are both Polynomial Commitment Schemes (PCS) built on top of FRI, but they target different evaluation domains / algebraic structures.

### Main difference

**TwoAdicFriPcs**

- Designed for a two-adic domain: a multiplicative subgroup/coset whose size is a power of two.
- This is the classic FRI setup used for many STARKs.
- It relies on a two-adic FFT / DFT-style structure for committing and interpolating.
- Best fit when your trace lives naturally on a power-of-two domain.

**CirclePcs**

- Designed for the circle domain used by the circle/STARK variant.
- Uses a circle-specific domain and folding strategy rather than the standard two-adic one.
- It has extra machinery for:
  - circle evaluation order / permutation,
  - circle-specific interpolation and quotient reduction,
  - a special first-layer folding step before standard FRI continues.
- Best fit when the protocol is built around the circle domain.

### Practical implications

**Domain structure**

- TwoAdicFriPcs: domains are power-of-two multiplicative subgroups/cosets.
- CirclePcs: domains are points on a circle-like algebraic domain with its own indexing and permutation rules.

**Folding / FRI handling**

- TwoAdicFriPcs: standard FRI folding pipeline.
- CirclePcs: does an extra circle-specific reduction and a special first fold layer before handing off to FRI.

**Commitment/opening behavior**

- TwoAdicFriPcs: straightforward for evaluations over two-adic domains.
- CirclePcs: includes additional steps to adapt circle evaluations into something FRI can verify.

**When they are used**

- Use TwoAdicFriPcs for conventional two-adic STARK pipelines.
- Use CirclePcs when the proof system is built for the circle domain and its associated optimizations/structure.

**Short version**

- TwoAdicFriPcs = standard power-of-two FRI PCS
- CirclePcs = circle-domain-specific FRI PCS with extra preprocessing/folding logic

---

# Verifier Components for Fri + TwoAdicFriPcs

- **get_log_num_quotient_chunks**: estimates how many chunks the quotient polynomial needs to be split into, based on the AIR's constraint degree.
  - Fast path: use `max_constraint_degree()`. If the AIR provides a degree hint:
    - it takes that hinted degree, adds `is_zk` if zero-knowledge masking, increases the degree by 1, clamps it to at least 2 and computes: `log2_ceil(constraint_degree - 1)`
    - This gives the power-of-two chunk count needed to cover the quotient degree.
  - Fallback: compute it exactly. If no degree hint is available, it calls `get_log_quotient_degree_extension(...)` to compute the quotient degree from the AIR structure and layout directly.

- **natural_domain_for_degree**:
  - TwoAdicMultiplicativeCoset: Returns the coset `shift * generator`, where the generator is a canonical (i.e. fixed in the implementation of `F: TwoAdicField`) generator of the unique subgroup of the units of `F` of order `2^log_size`.
  - Letting `s = shift`, and `g = generator` (of order `2^log_size`), the coset in question is `s * <g> = {s, s * g, s * g^2, ..., s * g^(2^log_size - 1)}`

- **create_disjoint_domain**: builds a new two-adic multiplicative coset that is guaranteed to be disjoint from the current one, as long as `min_size` is valid. For example, if the original domain is `{1, h, h², ..., h⁷}`, then the disjoint domain is `{g, gh, gh², ..., gh⁷}`. Because `g` is a generator of the full multiplicative group, it is not inside the same subgroup H, so this shifted coset does not overlap with the original one.

- **split_domains**: Given a standard domain of size N, it decomposes it into `num_quotient_chunks` twin-cosets, where each chunk has size `N/num_quotient_chunks`, the chunks are disjoint and together they cover the original domain. For example, if the original domain is a standard two-adic domain like `{1, g, g^2, g^3, ..., g^15}`, then splitting into 4 chunks might give domains such as:

  ```
  {1, g^4, g^8, g^12}
  {g, g^5, g^9, g^13}
  {g^2, g^6, g^10, g^14}
  {g^3, g^7, g^11, g^15}
  ```

  Each one is a valid smaller domain, and together they cover the original one.

- `alpha = hash(degree_bits, degree_bits - is_zk, preprocessed_width, commitments_trace, preprocessed_commit, public_values)`
- `zeta = hash(alpha, commitments_quotient_chunks, commitments_random)`

- **Periodic columns** are columns whose values repeat with a fixed period that divides the trace length. They are derived from public parameters and are never committed as part of the trace — instead, both prover and verifier compute them from the data provided here. For a trace of length `n` evaluated over a multiplicative subgroup `H = {g⁰, g¹, ..., gⁿ⁻¹}`, a periodic column with period `p` (where `p` divides `n`, both powers of 2) is defined as follows: Let `r = n/p` be the number of repetitions. The `p` values are interpreted as evaluations of a polynomial `f(x)` of degree `< p` over the subgroup `Hʳ = {g⁰, gʳ, g²ʳ, ..., g^((p-1)r)}` of order `p`. The periodic extension `f'(X) = f(Xʳ)` has degree `< p·r = n` and satisfies `f'(gⁱ) = f(gⁱʳ)`, which cycles through the `p` values as `i` increases. Periodic columns are public parameters and must be committed during initialization of the Fiat-Shamir transcript. The values returned are evaluations over a subgroup; callers may convert to coefficient form for efficient evaluation if needed. For example, if full domain size = 8, period = 2, then `folds = log2(8) - log2(2) = 3 - 1 = 2`. That means the query point is folded to `zeta^(2^2) = zeta^4`.

- `coms_to_verify` is a list describing which commitment to verify, over which domain, at which point, with which opened values.
  `zeta` is for the current row and `zeta_next` for the next row, if the AIR uses a next row

```
vec![
  (commitments.random, vec![(trace_domain, vec![(zeta, opened_values.random)])]),     if zk is enabled
  (commitments.trace, vec![(trace_domain, vec![(zeta, opened_values.trace_local), (zeta_next, opened_values.trace_next)]])),
  (commitments.quotient_chunks, vec![(rqc_domain, vec![(zeta, quotient_chunk)]),...])
        for rqc_domain in randomized_quotient_chunks_domains and quotient_chunk in opened_values.quotient_chunks
  (preprocessed_commit, vec![(trace_domain, vec![(zeta, opened_values.preprocessed_local), (zeta_next, opened_values.preprocessed_next)])]) if any
]
```

## FRI verification:

- `fri_alpha = hash(zeta, opening_points in commitments)`
- Verify that all query proofs have the same number of commit-phase openings as there are commit-phase commitments, i.e., `query_proof.commit_phase_openings.len() == proof.commit_phase_commits.len()`
- `log_arities`: extracts the folding schedule from the first query proof:
  - look at the first query proof
  - iterate over all commit-phase opening steps in that query proof
  - read each step's `log_arity`
- Check that every query proof uses the same folding schedule as `log_arities`
- `betas`: generate all of the random challenges for the FRI rounds, checking PoW per round. For each `(comm, witness)` from `(commit_phase_commits, commit_pow_witnesses)`:
  - Absorb `comm` into the transcript
  - Check whether a given witness satisfies the PoW condition. After absorbing the witness, the challenger samples bits random bits and verifies that all bits sampled are zero. The sample method returns the next challenge value from a hash-based transcript. The hash challenger keeps an `output_buffer` of already-derived values: if that buffer is empty, it calls `flush()` to hash the current transcript input state and produces new output values; then removes and returns one element from the `output_buffer`. It's a configurable proof-of-work mechanism that intentionally makes proof generation harder, while keeping verification cheap. By requiring a PoW witness there, the protocol makes it harder for the prover to repeatedly reshuffle the transcript until it gets "nice" query positions or favorable randomness.

- Verify each `query_proof` in `proof.query_proofs`:
  - Generate a random index by sampling bits from the challenger
  - `open_input` verifies and combines the prover's input openings at the chosen index, then returns the reduced openings that will be fed into the FRI folding process.
    - For each `log_height`, store the alpha power and compute the reduced opening: `log_height -> (alpha_pow, reduced_opening)`
    - Iterate over each batch opening and its matching commitment metadata
      - Compute `batch_heights` where each height is the domain size multiplied by the blowup factor
      - Create `batch_dims` Dimensions for MMCS verification where `width = 0` is just a placeholder here.
      - `reduced_index`: If a batch has a smaller domain than the global query domain, the same logical query index must be shifted down. If the batch is empty, it uses 0. It maps an index from a larger tree into a smaller subtree.
      - `verify_batch` (Details see below): This function verifies a batched Merkle opening for several matrix rows against a Merkle cap commitment. The prover claims: "these are the rows from these matrices at index, and here is the proof". The verifier:
        - checks the rows/proof have the right shape,
        - recomputes the leaf hash for the opened rows,
        - walks up the Merkle tree using the proof,
        - checks that the final digest matches one of the values in the committed cap.

- **Reduced Opening Computation for FRI**: multiple polynomials, each claimed to evaluate to certain values at certain points, are reduced into a single "reduced opening" polynomial per height. This avoids running FRI separately for each one.
  - Computing the evaluation point `x = g * ω^i` where `g` is the base field generator and `ω` is the appropriate root of unity (generator for the multiplicative group of order `2^log_height`).
  - `reduced_openings` is a map from `log_height → (alpha_pow, ro)`. Each height gets its own accumulator, since polynomials of different heights live on different domains. `alpha_pow` tracks the current power of the random challenge `α`, and `ro` accumulates the reduced opening value.
  - The DEEP quotient computation: For each polynomial `f` and opening point `z`, this computes: `ro += αⁿ · (f(z) - f(x)) / (z - x)`
    - `f(z) = p_at_z`: the claimed evaluation at the out-of-domain point `z` (sent by the prover, to be verified by FRI)
    - `f(x) = p_at_x`: the known evaluation at `x`, verified by the Merkle batch proof earlier
    - `(z - x)⁻¹`: the quotient divisor — if `f(z)` is correct, then `f(z) - f(x)` vanishes appropriately and this is a valid polynomial evaluation
    - `αⁿ`: a different power of the random challenge for each polynomial, ensuring linear independence (so a cheating prover can't cancel errors across polynomials)
  - The accumulation across all polynomials gives a single value `ro` per height, which represents a random linear combination of all the DEEP quotients.
  - If a matrix has height 1, its polynomial is constant `f(z) = f(x)`, so the quotient `(f(z) - f(x))/(z - x)` must be exactly 0.
  - After `index >> folding.extra_query_index_bits()`, only the domain bits remain in `domain_index`. This value is now a valid index into the evaluation domain of size `1 << log_global_max_height`.

- **verify_query**: This function verifies a single query path through a FRI. FRI repeatedly folds a polynomial evaluation domain in half (or by larger arities). The prover commits to each folded layer. The verifier picks a random index and checks that the fold at every layer is consistent with those commitments. This function performs exactly that check for one query index. For each commit step `(beta, commitment, opening)`:
  - Reconstruct the evaluation row: The prover supplies the `arity - 1` sibling evaluations. The verifier inserts the value it already knows (`folded_eval`) at `index % arity`, producing the full row of `arity` evaluations: `evals[index_in_group] = folded_eval`
  - Verify against the Merkle commitment: This checks that the reconstructed row of evaluations is actually in the committed matrix at the right index
  - Fold the group of sibling nodes to get the evaluation of the parent FRI node. Using the random challenge `beta`, combine the `arity` evaluations into a single value.
    - Take the generator `g` of a group of size `2^(log_height + log_arity)`, raise it to the bit-reversed index power. This gives the "anchor" element `subgroup_start` of the coset corresponding to this row. The bit-reversal (`reverse_bits_len`) is because FRI domains are typically stored in bit-reversed order.
    - Generates `arity` consecutive powers of the `log_arity` subgroup generator, starting from `subgroup_start`. These are the actual field elements: `{subgroup_start · h⁰, subgroup_start · h¹, ..., subgroup_start · h^(arity-1)}`. Then bit-reverses the ordering to match how evals are laid out in memory.
    - `fold_row`: Fold the group of sibling nodes to get the evaluation of the parent FRI node. Treats `(xs[i], evals[i])` as point-value pairs defining a unique polynomial of degree `< arity`. Evaluates that polynomial (on the extension field) at the random challenge `beta`. This collapses the `arity` evaluations into 1.
  - If a reduced opening is scheduled exactly at this new height, consume it. The factor `beta^arity` is used as a blinding coefficient to keep the combination independent.

  After loop:
  - Final height check must end exactly at configured `log_final_height`.
  - Remaining reduced-openings check: any leftovers mean malformed proof schedule.
  - Returns final computed folded claim `folded_eval` for caller's final polynomial comparison.

- Open the final polynomial at index `domain_index`, which corresponds to evaluating the polynomial at `x^k`, where `x` is the 2-adic generator of order `log_global_max_height` and `k = reverse_bits_len(domain_index, log_global_max_height)`.
- Evaluate `proof.final_poly` at `x`. The loop uses Horner's method (`eval = eval * x + coeff`) for efficient polynomial evaluation.
- Final condition: if the directly evaluated final polynomial value (`eval`) does not match the folded value (`folded_eval`), the proof is invalid, so it returns `FinalPolyMismatch`.

- **recompose_quotient_from_chunks**: This function reconstructs a quotient polynomial value at a point `zeta` from its chunked representation. This is because the quotient polynomial is often split into chunks to keep each piece's degree manageable. Each chunk lives on its own coset domain. To evaluate the full quotient at `zeta`, it needs to recombine them.
  - Compute Lagrange Interpolation Weights (`zps`): For each domain `i`, this computes a Lagrange basis weight `zp_i = ∏_j Z_j(ζ) / Z_j(x_i)` where `Z_j` is the vanishing polynomial of domain `j`, and `x_i` is the first point of domain `i`. Some optimisation here: the inverse of `Z_j(x_i)` can be done all together after the product.
  - Reconstruct the Field Element from Basis Components: `chunk_i = Σ_k c_k * b_k` where `k` is the k-th basis element.
  - Finally it computes the weighted sum `Σ_i zp_i * chunk_i`. This is a Lagrange interpolation across the chunk domains. Each chunk's value is weighted so they combine into the correct total quotient evaluation.

- **verify_constraints**: Verifies that the folded constraints match the quotient polynomial at `zeta`. This evaluates the `Air` constraints at the out-of-domain point and checks that `constraints(zeta) / Z_H(zeta) = quotient(zeta)`.
  - The Vanishing Polynomial is `Z_gH(X) = ∏_{h∈H}(X - gh) = (g⁻¹X)^|H| - 1`
  - `selectors_at_point`: The trace domain is a coset `gH` — not the subgroup `H` itself, but a shift of it: `gH = {g, g·h, g·h², ..., g·h^(n-1)}`, where `g` is the shift (coset factor) and `h` is the generator of `H`.
    - The Lagrange selector for selecting the first row (`g·h⁰ = g`) is `Z_gH(X) / (g⁻¹X - 1)`
    - The Lagrange selector for selecting the last row (`g·h^(n-1) = g·h⁻¹`) is `Z_gH(X) / (g⁻¹X - h⁻¹)`
    - The Lagrange selector of the subset consisting of everything but the last row: `g⁻¹X - h⁻¹`
  - Build the constraint folder: It holds all the evaluation context (trace values, selectors, public inputs) and an accumulator that will collect the random linear combination of all constraint evaluations, weighted by powers of alpha.
  - Evaluate all constraints: Runs the AIR's constraint logic against the folder. Each constraint contributes to `folder.accumulator` via the alpha folding — this compresses all constraints into a single field element: `accumulator = c_0 + α·c_1 + α²·c_2 + ...`
  - Final check: Multiplies the folded constraints by `1/Z_H(ζ)` and checks equality with the prover's claimed `quotient(ζ)`. If they don't match, the proof is rejected.

### verify_batch

1. **Unpack the proof**
   1. `opened_values`: the actual matrix rows the prover says were opened
   2. `opening_proof`: sibling hashes needed to reconstruct the path to the cap

2. **Check batch size**: There must be exactly one opened row per committed matrix.

3. **Sort matrices by height, tallest first**: This lets the verifier process matrices in the same order the tree effectively "sees" them from top to bottom. The `enumerate()` is important because the code still needs the original index into `opened_values`.

4. **Reject incompatible heights**: Matrix heights that round up to the same power of two must be equal. This ensures matrices whose heights round up to the same power of two are not "mismatched" in a way that would make them impossible to combine consistently. So if two heights would occupy the same logical leaf level, they must actually be equal.

5. **Get the tallest matrix height**: `max_height` is the tallest committed matrix, and `curr_height_padded` is the current tree height padded so the arity N works cleanly.

6. The global row index must be smaller than the tallest matrix.

7. **Take all matrices with exactly the same height as the tallest one and hash the corresponding opened values**:

   ```
   digest = hash(opened_values[i] || opened_values[j] || ...)
   ```

   for all `i, j` at the tallest height group.

8. **Walking Up the Tree (The Main Loop)**: Each iteration of the loop moves one level up the Merkle tree. The key subtlety is that the tree is not purely binary — it can use N-ary steps where N is a compile-time const. At each level:
   1. **Select the arity** (`select_arity_step`): Decides whether to do an N-ary or binary merge at this level, based on the current padded height and the remaining matrix heights. This replays the same schedule the prover used when building the tree.
   2. **Consume siblings from the proof**: Takes `step - 1` sibling digests from `opening_proof`.
   3. **Reconstruct the parent**: Places the current digest at position `pos_in_group = index % step` among its siblings, then compresses all N inputs (padding with default digests if `step < N`):
      ```
      inputs = [sibling_0, ..., digest (at pos_in_group), ..., sibling_{step-2}, default, ...]
      parent = compress(inputs)
      ```
   4. **Advance**: `index /= step`, moving the logical position one level up.
   5. **Matrix injection**: If any shorter matrices have rows that align to this new level (i.e. their height rounds up to the same power of two as the new logical height), they are hashed and mixed into the running digest via a binary compress:
      ```
      injection = hash(opened_values for shorter matrices at this level)
      digest    = compress([digest, injection, default, default, ...])
      ```
      This is how the commitment scheme handles matrices of different heights: shorter matrices "join" the tree at the level corresponding to their height.

9. **Cap Check**: After the proof is exhausted, the index has been divided down all the way into the cap layer — the top of the tree where roots are stored. The final check is `commit[cap_index] == digest`. If it matches, the proof is valid. Otherwise, `CapMismatch` is returned.

Summary diagram

```
Leaf level:    hash(tall matrix rows)  →  digest
                       ↓
Level 1:    compress([siblings..., digest, ...])  →  digest
                       ↓             ↑ inject shorter matrices here
Level 2:    compress([siblings..., digest, ...])  →  digest
                       ↓
  ...
                       ↓
Cap layer:  commit[cap_index] == digest?
```
