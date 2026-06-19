use aiken/builtin
use goldilocks/ext2.{Ext2}

// ── Leaf hashing ──────────────────────────────────────────────────────────────

/// Merkle multi-matrix commitment scheme verification for the Plonky3 Fibonacci STARK.
///
/// Mirrors MerkleTreeMmcs<Val, u8, SerializingHasher<Sha256>, CompressionFunctionFromHasher<Sha256, 2, 32>, 2, 32>
/// with cap_height = 0 (the commitment is a single 32-byte SHA-256 root).
///
/// Hashing conventions (N = 2, binary):
///   leaf_hash(rows) = sha256(le8 bytes of every row, concatenated in matrix order)
///   compress(l, r)  = sha256(l || r)         -- CompressionFunctionFromHasher flattens then hashes
///
/// verify_batch(root, index, rows, path):
///   1. leaf = leaf_hash(rows)   -- one row per committed matrix, mirrors
///      hash_iter_slices over all matrices at the leaf height
///      (merkle-tree/src/mmcs.rs:296-352, tallest-first stable order =
///      insertion order when heights are equal).
///   2. For each sibling in path (leaf → root):
///        if index % 2 == 0 : parent = sha256(current || sibling)
///        else               : parent = sha256(sibling || current)
///        index /= 2
///   3. Assert current == root.
///
/// ASSUMPTION: all matrices in one commitment have the same height, so they
/// all enter the single leaf hash. Plonky3 also supports matrices of smaller
/// heights, whose row digests are injected at intermediate levels of the walk
/// (mmcs.rs `has_intermediate` / injection logic) — TODO: not supported here;
/// both the uni-stark proof and the batch proof (all traces at 2^10, all
/// quotient chunks at 2^10, LDE 2^18) satisfy the equal-height assumption.
///
/// verify_batch_ext(root, index, ext_row, path):
///   Flatten each Ext2 element to [c0, c1] then call verify_batch.
///   Used for FRI commit-phase openings (ChallengeMmcs = ExtensionMmcs<Val, Ext2, ValMmcs>).
/// Serialise one Goldilocks element as 8 LE bytes and append to acc.
fn append_le8(acc: ByteArray, x: Int) -> ByteArray {
  builtin.append_bytearray(acc, builtin.integer_to_bytearray(False, 8, x))
}

/// Build the byte payload for SHA-256: concatenation of 8-LE-byte encodings.
fn row_to_bytes(values: List<Int>) -> ByteArray {
  do_row_to_bytes(values, #"")
}

fn do_row_to_bytes(values: List<Int>, acc: ByteArray) -> ByteArray {
  when values is {
    [] -> acc
    [v, ..rest] -> do_row_to_bytes(rest, append_le8(acc, v))
  }
}

/// SHA-256 leaf hash of a single row: sha256(le8(v0) || le8(v1) || ...).
/// Mirrors SerializingHasher<Sha256>::hash_iter(row) via F::into_byte_stream.
pub fn hash_leaf(values: List<Int>) -> ByteArray {
  builtin.sha2_256(row_to_bytes(values))
}

/// SHA-256 leaf hash of one row per committed matrix, all concatenated.
/// Mirrors hash_iter_slices over every matrix at the leaf height
/// (merkle-tree/src/mmcs.rs). Since the le8 serialization concatenates,
/// hash_leaf_multi([r0, r1]) == hash_leaf(r0 ++ r1).
pub fn hash_leaf_multi(rows: List<List<Int>>) -> ByteArray {
  builtin.sha2_256(do_rows_to_bytes(rows, #""))
}

fn do_rows_to_bytes(rows: List<List<Int>>, acc: ByteArray) -> ByteArray {
  when rows is {
    [] -> acc
    [r, ..rest] -> do_rows_to_bytes(rest, do_row_to_bytes(r, acc))
  }
}

// ── Internal node compression ─────────────────────────────────────────────────

/// Compress two 32-byte child digests: sha256(left || right).
/// Mirrors CompressionFunctionFromHasher<Sha256, 2, 32>::compress([left, right]).
pub fn compress(left: ByteArray, right: ByteArray) -> ByteArray {
  builtin.sha2_256(builtin.append_bytearray(left, right))
}

// ── Merkle path verification ──────────────────────────────────────────────────

/// Walk from a known leaf hash up to the root using `siblings`.
/// `index` is the leaf's position in the full (padded) tree, advanced by /2 each level.
fn verify_merkle_path(
  root: ByteArray,
  index: Int,
  current: ByteArray,
  siblings: List<ByteArray>,
) -> Bool {
  when siblings is {
    [] -> current == root
    [sibling, ..rest] -> {
      let parent =
        if index % 2 == 0 {
          compress(current, sibling)
        } else {
          compress(sibling, current)
        }
      verify_merkle_path(root, index / 2, parent, rest)
    }
  }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Verify a multi-matrix batch opening against a 32-byte SHA-256 Merkle root.
///
/// Arguments:
///   root   – the 32-byte Merkle commitment (cap_height = 0 → single root).
///   index  – the leaf index queried (already adjusted by the caller for height).
///   rows   – one base-field (Goldilocks) row per committed matrix at that
///            index, in commit order (= BatchOpening.opened_values). All
///            matrices must share the leaf height (see module header).
///   path   – Merkle sibling hashes from the leaf level to the root.
///
/// Used for:
///   • ValMmcs input-batch openings: 1 matrix per batch in the uni-stark
///     proof, one matrix per instance in the batch proof.
///   • Call site in fri.ak: open_input verifies both batches.
pub fn verify_batch(
  root: ByteArray,
  index: Int,
  rows: List<List<Int>>,
  path: List<ByteArray>,
) -> Bool {
  let leaf = hash_leaf_multi(rows)
  verify_merkle_path(root, index, leaf, path)
}

/// Verify an Ext2 row opening: flatten each Ext2 to base-field values and hash
/// the single resulting leaf.
///
/// Mirrors ExtensionMmcs::verify_batch which calls EF::flatten_to_base on each
/// opened vector, effectively turning [Ext2(c0,c1), ...] into [c0, c1, ...].
///
/// Builds the leaf bytes directly from the Ext2 row (c0,c1 → 8 LE bytes each)
/// rather than materialising the intermediate flattened List<Int> and walking
/// it a second time. Byte-for-byte identical to
/// `verify_batch(root, index, [flatten_ext_row(row)], path)`.
///
/// Used for FRI commit-phase openings where ChallengeMmcs = ExtensionMmcs<Val, Ext2, ValMmcs>.
pub fn verify_batch_ext(
  root: ByteArray,
  index: Int,
  row: List<Ext2>,
  path: List<ByteArray>,
) -> Bool {
  let leaf = builtin.sha2_256(ext_row_to_bytes(row, #""))
  verify_merkle_path(root, index, leaf, path)
}

/// Serialise [Ext2(c0,c1), ...] as le8(c0) ++ le8(c1) ++ ... appended to `acc`.
fn ext_row_to_bytes(row: List<Ext2>, acc: ByteArray) -> ByteArray {
  when row is {
    [] -> acc
    [e, ..rest] ->
      ext_row_to_bytes(rest, append_le8(append_le8(acc, e.c0), e.c1))
  }
}

/// Flatten [Ext2(c0,c1), ...] → [c0, c1, ...].
fn flatten_ext_row(row: List<Ext2>) -> List<Int> {
  do_flatten_ext(row, [])
}

fn do_flatten_ext(row: List<Ext2>, acc: List<Int>) -> List<Int> {
  when row is {
    [] -> acc
    [e, ..rest] ->
      // append in order: existing acc then c0 then c1
      do_flatten_ext(rest, append_int(append_int(acc, e.c0), e.c1))
  }
}

fn append_int(xs: List<Int>, x: Int) -> List<Int> {
  do_append_int(xs, x, [])
}

fn do_append_int(xs: List<Int>, x: Int, acc: List<Int>) -> List<Int> {
  when xs is {
    [] -> reverse_int(do_cons(x, acc))
    [h, ..rest] -> do_append_int(rest, x, do_cons(h, acc))
  }
}

fn do_cons(x: Int, xs: List<Int>) -> List<Int> {
  [x, ..xs]
}

fn reverse_int(xs: List<Int>) -> List<Int> {
  do_reverse_int(xs, [])
}

fn do_reverse_int(xs: List<Int>, acc: List<Int>) -> List<Int> {
  when xs is {
    [] -> acc
    [h, ..rest] -> do_reverse_int(rest, [h, ..acc])
  }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

test hash_leaf_single_value() {
  // sha256(0x0000000000000000) – verify leaf hash is 32 bytes
  let h = hash_leaf([0])
  builtin.length_of_bytearray(h) == 32
}

test hash_leaf_two_values() {
  // sha256(LE(1) || LE(2)) – verify it is 32 bytes and different from single-value hash
  let h1 = hash_leaf([1])
  let h12 = hash_leaf([1, 2])
  builtin.length_of_bytearray(h12) == 32 && h1 != h12
}

test compress_is_32_bytes() {
  let z = #"0000000000000000000000000000000000000000000000000000000000000000"
  let c = compress(z, z)
  builtin.length_of_bytearray(c) == 32
}

test compress_order_matters() {
  let a = #"0101010101010101010101010101010101010101010101010101010101010101"
  let b = #"0202020202020202020202020202020202020202020202020202020202020202"
  compress(a, b) != compress(b, a)
}

test verify_batch_single_leaf_tree() {
  // A tree with a single leaf has an empty path; root == leaf_hash.
  let row = [42]
  let root = hash_leaf(row)
  verify_batch(root, 0, [row], [])
}

test verify_batch_two_leaf_tree() {
  // Build a 2-leaf tree manually and verify both leaves.
  let row0 = [10, 20]
  let row1 = [30, 40]
  let h0 = hash_leaf(row0)
  let h1 = hash_leaf(row1)
  let root = compress(h0, h1)
  // Leaf 0: index=0 (even) → parent = compress(h0, h1)
  let ok0 = verify_batch(root, 0, [row0], [h1])
  // Leaf 1: index=1 (odd) → parent = compress(h1_sibling=h0, h1)
  let ok1 = verify_batch(root, 1, [row1], [h0])
  ok0 && ok1
}

test verify_batch_four_leaf_tree() {
  // 4-leaf binary tree: root = compress(compress(h0,h1), compress(h2,h3))
  let rows = [[1], [2], [3], [4]]
  let hs =
    when rows is {
      [r0, r1, r2, r3] ->
        [hash_leaf(r0), hash_leaf(r1), hash_leaf(r2), hash_leaf(r3)]
      _ -> fail
    }
  let (h0, h1, h2, h3) =
    when hs is {
      [a, b, c, d] -> (a, b, c, d)
      _ -> fail
    }
  let left_parent = compress(h0, h1)
  let right_parent = compress(h2, h3)
  let root = compress(left_parent, right_parent)
  // Leaf at index 2 (row [3]): sibling = h3, then sibling = left_parent
  let path2 = [h3, left_parent]
  verify_batch(root, 2, [[3]], path2)
}

test verify_batch_wrong_row_fails() {
  let row = [99]
  let root = hash_leaf([100])
  !verify_batch(root, 0, [row], [])
}

test hash_leaf_multi_is_concat() {
  // Multi-matrix leaf hash == single hash of the concatenated rows, since
  // the le8 serialization concatenates (mirrors hash_iter_slices upstream).
  hash_leaf_multi([[1, 2], [3]]) == hash_leaf([1, 2, 3])
}

test verify_batch_two_matrices() {
  // Two equal-height matrices (widths 2 and 1) in one 2-leaf tree:
  // leaf_i = sha256(m0_row_i || m1_row_i).
  let leaf0 = hash_leaf_multi([[10, 20], [50]])
  let leaf1 = hash_leaf_multi([[30, 40], [60]])
  let root = compress(leaf0, leaf1)
  let ok0 = verify_batch(root, 0, [[10, 20], [50]], [leaf1])
  let ok1 = verify_batch(root, 1, [[30, 40], [60]], [leaf0])
  ok0 && ok1
}

test verify_batch_matrix_order_matters() {
  // Swapping matrix order changes the leaf hash — commit order is binding.
  let root = hash_leaf_multi([[1], [2]])
  !verify_batch(root, 0, [[2], [1]], [])
}

test flatten_ext_row_empty() {
  flatten_ext_row([]) == []
}

test flatten_ext_row_one_element() {
  let e = Ext2 { c0: 5, c1: 7 }
  flatten_ext_row([e]) == [5, 7]
}

test flatten_ext_row_two_elements() {
  let e0 = Ext2 { c0: 1, c1: 2 }
  let e1 = Ext2 { c0: 3, c1: 4 }
  flatten_ext_row([e0, e1]) == [1, 2, 3, 4]
}

test verify_batch_ext_single_leaf() {
  let e = Ext2 { c0: 11, c1: 22 }
  let root = hash_leaf([11, 22])
  verify_batch_ext(root, 0, [e], [])
}

test ext_row_leaf_matches_flatten() {
  // The direct Ext2 -> bytes leaf must equal the old flatten-then-hash path
  // (verify_batch over [flatten_ext_row(row)]), for a multi-element row.
  let row = [Ext2 { c0: 1, c1: 2 }, Ext2 { c0: 3, c1: 4 }]
  builtin.sha2_256(ext_row_to_bytes(row, #"")) == hash_leaf_multi(
    [flatten_ext_row(row)],
  )
}
