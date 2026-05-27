/// Read a Goldilocks Fibonacci STARK proof from a JSON file and verify it.
///
/// Usage: cargo run --release --bin verify_proof [proof.json]
///
/// The proof.json must have been produced by `export_proof`.
/// The StarkConfig here must match the one used during proving exactly.
use std::fs;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_challenger::{HashChallenger, SerializingChallenger64};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_goldilocks::Goldilocks;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_sha256::Sha256;
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};
use p3_uni_stark::{Proof, StarkConfig, verify};

// ── Fibonacci AIR ────────────────────────────────────────────────────────────
// Must match the AIR used in export_proof.rs exactly.

struct FibonacciAir {}

impl<F> BaseAir<F> for FibonacciAir {
    fn width(&self) -> usize {
        2
    }
    fn num_public_values(&self) -> usize {
        3
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(2)
    }
}

impl<AB: AirBuilder> Air<AB> for FibonacciAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let pis = builder.public_values();

        let a = pis[0];
        let b = pis[1];
        let x = pis[2];

        let local: &[AB::Var] = main.current_slice();
        let next: &[AB::Var] = main.next_slice();

        builder.when_first_row().assert_eq(local[0].clone(), a);
        builder.when_first_row().assert_eq(local[1].clone(), b);
        builder
            .when_transition()
            .assert_eq(local[1].clone(), next[0].clone());
        builder
            .when_transition()
            .assert_eq(local[0].clone() + local[1].clone(), next[1].clone());
        builder.when_last_row().assert_eq(local[1].clone(), x);
    }
}

// ── Main ─────────────────────────────────────────────────────────────────────

fn main() {
    // ── Type aliases — must be identical to export_proof.rs ──────────────────
    type Val = Goldilocks;
    type Challenge = BinomialExtensionField<Val, 2>;
    type Challenger = SerializingChallenger64<Val, HashChallenger<u8, Sha256, 32>>;
    type ByteHash = Sha256;
    type MyHash = SerializingHasher<ByteHash>;
    type MyCompress = CompressionFunctionFromHasher<ByteHash, 2, 32>;
    type ValMmcs = MerkleTreeMmcs<Val, u8, MyHash, MyCompress, 2, 32>;
    type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
    type Dft = Radix2DitParallel<Val>;
    type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
    type Config = StarkConfig<Pcs, Challenge, Challenger>;

    // ── Public inputs (must match the values used during proving) ─────────────
    let x: u64 = 7032041643746701607; // fib(8192) mod p
    let pis: Vec<Val> = vec![Val::ZERO, Val::ONE, Val::from_u64(x)];

    // ── Rebuild the identical StarkConfig ────────────────────────────────────
    let hash = MyHash::new(Sha256 {});
    let compress = MyCompress::new(Sha256 {});
    let val_mmcs = ValMmcs::new(hash, compress, 0);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::default();
    let fri_params = FriParameters {
        log_blowup: 2,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: 100,
        commit_proof_of_work_bits: 1,
        query_proof_of_work_bits: 16,
        mmcs: challenge_mmcs,
    };
    let pcs = Pcs::new(dft, val_mmcs, fri_params);
    let challenger = Challenger::from_hasher(vec![], Sha256 {});
    let config = Config::new(pcs, challenger);

    // ── Read and deserialise the proof ────────────────────────────────────────
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "proof.json".to_string());

    eprintln!("Reading proof from {} …", path);
    let json = fs::read_to_string(&path).unwrap_or_else(|e| panic!("Cannot read {path}: {e}"));

    let proof: Proof<Config> = serde_json::from_str(&json).expect("JSON deserialisation failed");

    eprintln!("Proof loaded. Verifying …");
    let start = std::time::Instant::now();

    match verify(&config, &FibonacciAir {}, &proof, &pis) {
        Ok(()) => {
            let elapsed = start.elapsed();
            eprintln!("✓ Proof verified successfully in {:?}", elapsed);
        }
        Err(e) => {
            eprintln!("✗ Verification FAILED: {:?}", e);
            std::process::exit(1);
        }
    }
}
