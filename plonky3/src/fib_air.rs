use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_challenger::{DuplexChallenger, HashChallenger, SerializingChallenger32};
use p3_koala_bear::KoalaBear;

use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_fri::{FriParameters, TwoAdicFriPcs};

use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_sha256::Sha256;

use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};
use p3_uni_stark::{StarkConfig, prove, verify};
use rand::SeedableRng;
use rand::rngs::SmallRng;

/// For testing the public values feature
pub struct FibonacciAir {}

impl<F> BaseAir<F> for FibonacciAir {
    fn width(&self) -> usize {
        NUM_FIBONACCI_COLS
    }

    fn num_public_values(&self) -> usize {
        3
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        // All constraints are guarded by is_first_row / is_transition / is_last_row
        // (degree 1) applied to degree-1 expressions (trace vars minus public values),
        // giving a max constraint degree of 2.
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

        let local: &FibonacciRow<AB::Var> = main.current_slice().borrow();
        let next: &FibonacciRow<AB::Var> = main.next_slice().borrow();

        let mut when_first_row = builder.when_first_row();

        when_first_row.assert_eq(local.left, a);
        when_first_row.assert_eq(local.right, b);

        let mut when_transition = builder.when_transition();

        // a' <- b
        when_transition.assert_eq(local.right, next.left);

        // b' <- a + b
        when_transition.assert_eq(local.left + local.right, next.right);

        builder.when_last_row().assert_eq(local.right, x);
    }
}

pub fn generate_trace_rows<F: PrimeField64>(a: u64, b: u64, n: usize) -> RowMajorMatrix<F> {
    assert!(n.is_power_of_two());

    let mut trace = RowMajorMatrix::new(F::zero_vec(n * NUM_FIBONACCI_COLS), NUM_FIBONACCI_COLS);

    let (prefix, rows, suffix) = unsafe { trace.values.align_to_mut::<FibonacciRow<F>>() };
    assert!(prefix.is_empty(), "Alignment should match");
    assert!(suffix.is_empty(), "Alignment should match");
    assert_eq!(rows.len(), n);

    rows[0] = FibonacciRow::new(F::from_u64(a), F::from_u64(b));

    for i in 1..n {
        rows[i].left = rows[i - 1].right;
        rows[i].right = rows[i - 1].left + rows[i - 1].right;
    }

    trace
}

const NUM_FIBONACCI_COLS: usize = 2;

pub struct FibonacciRow<F> {
    pub left: F,
    pub right: F,
}

impl<F> FibonacciRow<F> {
    const fn new(left: F, right: F) -> Self {
        Self { left, right }
    }
}

impl<F> Borrow<FibonacciRow<F>> for [F] {
    fn borrow(&self) -> &FibonacciRow<F> {
        debug_assert_eq!(self.len(), NUM_FIBONACCI_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to::<FibonacciRow<F>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

// Keccak hash
type Val = BabyBear;
//type Val = KoalaBear;
//type ByteHash = Keccak256Hash;
type ByteHash = Sha256;
type MyHash = SerializingHasher<ByteHash>;
type MyCompress = CompressionFunctionFromHasher<ByteHash, 2, 32>;
type ValMmcs = MerkleTreeMmcs<Val, u8, MyHash, MyCompress, 2, 32>;
type Challenge = BinomialExtensionField<Val, 4>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;
type Dft = Radix2DitParallel<Val>;
type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
type MyConfig = StarkConfig<Pcs, Challenge, Challenger>;

fn make_bytehash_config(log_final_poly_len: usize) -> MyConfig {
    let hash = MyHash::new(ByteHash {});
    let compress = MyCompress::new(ByteHash {});
    let val_mmcs = ValMmcs::new(hash, compress, 0);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::default();
    let fri_params = FriParameters {
        log_blowup: 1,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: 100,
        commit_proof_of_work_bits: 1,
        query_proof_of_work_bits: 16,
        mmcs: challenge_mmcs,
    };
    println!(
        "conjectured soundness bits {}",
        fri_params.conjectured_soundness_bits()
    );
    let pcs = Pcs::new(dft, val_mmcs, fri_params);
    let challenger = Challenger::from_hasher(vec![], ByteHash {});
    MyConfig::new(pcs, challenger)
}

fn main() {
    // let n = 1 << 3;
    // let x = 21;
    let n = 8192;
    let x = 1256953032;
    // let n = 16384;
    // let x = 1363957518;
    // let n = 32768;
    // let x = 441216660;
    let log_final_poly_len = 2;

    let trace = generate_trace_rows::<Val>(0, 1, n);
    let config = make_bytehash_config(log_final_poly_len);
    let pis = vec![BabyBear::ZERO, BabyBear::ONE, BabyBear::from_u64(x)];
    //    let pis = vec![KoalaBear::ZERO, KoalaBear::ONE, KoalaBear::from_u64(x)];

    let start = std::time::Instant::now();
    let proof = prove(&config, &FibonacciAir {}, trace, &pis);
    let elapsed = start.elapsed();
    println!("proving time = {:?}", elapsed);

    println!(
        "quotient_chunks len = {:?}",
        proof.opened_values.quotient_chunks[0].len()
    );
    println!("proof commitments = {:?}", proof.commitments);

    {
        let proof_bytes = postcard::to_allocvec(&proof).expect("Failed to serialize proof");
        println!(
            "Proof size 2adic: {} bytes for n = {:?}",
            proof_bytes.len(),
            n
        );
        println!("Proof degree bits: {}", proof.degree_bits);
    }

    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

    let start = std::time::Instant::now();
    verify(&config, &FibonacciAir {}, &proof, &pis).expect("verification failed");
    let elapsed = start.elapsed();
    println!("verifying time = {:?}", elapsed);
}
