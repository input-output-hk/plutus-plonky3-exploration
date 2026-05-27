/// Generate a Goldilocks Fibonacci STARK proof and dump it as JSON to stdout.
///
/// Usage: cargo run --release --bin export_proof proof.json
///
/// The JSON is then fed to convert.py to produce the Aiken test literal.
use std::fs;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_challenger::{HashChallenger, SerializingChallenger64};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_goldilocks::Goldilocks;
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_sha256::Sha256;
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};
use p3_uni_stark::{StarkConfig, prove};

// ── Fibonacci AIR (duplicated from fib_air.rs to keep this binary self-contained) ──

pub struct FibonacciAir {}

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

pub fn generate_trace<F: PrimeField64>(a: u64, b: u64, n: usize) -> RowMajorMatrix<F> {
    assert!(n.is_power_of_two());
    let mut values = vec![F::ZERO; n * 2];
    values[0] = F::from_u64(a);
    values[1] = F::from_u64(b);
    for i in 1..n {
        let left = values[(i - 1) * 2 + 1];
        let right = values[(i - 1) * 2] + values[(i - 1) * 2 + 1];
        values[i * 2] = left;
        values[i * 2 + 1] = right;
    }
    RowMajorMatrix::new(values, 2)
}

// ── Main ─────────────────────────────────────────────────────────────────────

fn main() {
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

    let n: usize = 8192;
    // x = fib(8192) mod p  (matches run_goldilocks in fib_air.rs)
    let x: u64 = 7032041643746701607;

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

    let trace = generate_trace::<Val>(0, 1, n);
    let pis = vec![Val::ZERO, Val::ONE, Val::from_u64(x)];

    let out_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "proof.json".to_string());

    eprintln!("Generating proof...");
    let proof = prove(&config, &FibonacciAir {}, trace, &pis);
    eprintln!("Done. Serializing to JSON...");

    let json = serde_json::to_string(&proof).expect("JSON serialization failed");
    fs::write(&out_path, json).expect("Failed to write proof file");
    eprintln!("Proof written to {}", out_path);
}
