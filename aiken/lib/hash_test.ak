use aiken/builtin

fn repeat_keccak(hash: ByteArray, n: Int) -> ByteArray {
  if n <= 0 {
    hash
  } else {
    repeat_keccak(builtin.keccak_256(builtin.append_bytearray(hash, hash)), n - 1)
  }
}

test keccak_hash_cost() {
  let preimage: ByteArray = #"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
  let hash = repeat_keccak(preimage, 14000)
  hash == hash
}

fn repeat_sha2(hash: ByteArray, n: Int) -> ByteArray {
  if n <= 0 {
    hash
  } else {
    repeat_sha2(builtin.sha2_256(builtin.append_bytearray(hash, hash)), n - 1)
  }
}

test sha2_hash_cost() {
  let preimage: ByteArray = #"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
  let hash = repeat_sha2(preimage, 14000)
  hash == hash
}

fn repeat_sha3(hash: ByteArray, n: Int) -> ByteArray {
  if n <= 0 {
    hash
  } else {
   repeat_sha3(builtin.sha3_256(builtin.append_bytearray(hash, hash)), n - 1)
  }
}

test sha3_hash_cost() {
  let preimage: ByteArray = #"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
  let hash = repeat_sha3(preimage, 14000)
  hash == hash
}

fn repeat_blake2b(hash: ByteArray, n: Int) -> ByteArray {
  if n <= 0 {
    hash
  } else {
  repeat_blake2b(builtin.blake2b_256(builtin.append_bytearray(hash, hash)), n - 1)
  }
}

test blake2b_hash_cost() {
  let preimage: ByteArray = #"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
  let hash = repeat_blake2b(preimage, 14000)
  hash == hash
}