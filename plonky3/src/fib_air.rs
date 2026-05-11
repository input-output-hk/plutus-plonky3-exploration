use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_challenger::{HashChallenger, SerializingChallenger32, SerializingChallenger64};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_goldilocks::Goldilocks;
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_sha256::Sha256;
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};
use p3_uni_stark::{StarkConfig, prove, verify};

pub struct FibonacciAir {}

impl<F> BaseAir<F> for FibonacciAir {
    fn width(&self) -> usize {
        NUM_FIBONACCI_COLS
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

type ByteHash = Sha256;
type MyHash = SerializingHasher<ByteHash>;
type MyCompress = CompressionFunctionFromHasher<ByteHash, 2, 32>;

fn run_baby_bear() {
    type Val = BabyBear;
    type Challenge = BinomialExtensionField<Val, 4>;
    type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;
    type ValMmcs = MerkleTreeMmcs<Val, u8, MyHash, MyCompress, 2, 32>;
    type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
    type Dft = Radix2DitParallel<Val>;
    type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
    type Config = StarkConfig<Pcs, Challenge, Challenger>;

    let n = 8192;
    let x = 1256953032u64;

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
        "Conjectured soundness bits {}",
        fri_params.conjectured_soundness_bits()
    );
    let pcs = Pcs::new(dft, val_mmcs, fri_params);
    let challenger = Challenger::from_hasher(vec![], ByteHash {});
    let config = Config::new(pcs, challenger);

    let trace = generate_trace_rows::<Val>(0, 1, n);
    let pis = vec![Val::ZERO, Val::ONE, Val::from_u64(x)];

    prove_and_verify(&config, n, &pis, trace);
}

fn run_koala_bear() {
    type Val = KoalaBear;
    type Challenge = BinomialExtensionField<Val, 4>;
    type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;
    type ValMmcs = MerkleTreeMmcs<Val, u8, MyHash, MyCompress, 2, 32>;
    type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
    type Dft = Radix2DitParallel<Val>;
    type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
    type Config = StarkConfig<Pcs, Challenge, Challenger>;

    let n = 8192;
    let x = 1651027547u64;

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
        "Conjectured soundness bits {}",
        fri_params.conjectured_soundness_bits()
    );
    let pcs = Pcs::new(dft, val_mmcs, fri_params);
    let challenger = Challenger::from_hasher(vec![], ByteHash {});
    let config = Config::new(pcs, challenger);

    let trace = generate_trace_rows::<Val>(0, 1, n);
    let pis = vec![Val::ZERO, Val::ONE, Val::from_u64(x)];

    prove_and_verify(&config, n, &pis, trace);
}

fn run_goldilocks() {
    type Val = Goldilocks;
    type Challenge = BinomialExtensionField<Val, 2>;
    type Challenger = SerializingChallenger64<Val, HashChallenger<u8, ByteHash, 32>>;
    type ValMmcs = MerkleTreeMmcs<Val, u8, MyHash, MyCompress, 2, 32>;
    type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
    type Dft = Radix2DitParallel<Val>;
    type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
    type Config = StarkConfig<Pcs, Challenge, Challenger>;

    let n = 8192;
    let x = 7032041643746701607u64;

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
        "Conjectured soundness bits {}",
        fri_params.conjectured_soundness_bits()
    );
    let pcs = Pcs::new(dft, val_mmcs, fri_params);
    let challenger = Challenger::from_hasher(vec![], ByteHash {});
    let config = Config::new(pcs, challenger);

    let trace = generate_trace_rows::<Val>(0, 1, n);
    let pis = vec![Val::ZERO, Val::ONE, Val::from_u64(x)];

    prove_and_verify(&config, n, &pis, trace);
}

fn prove_and_verify<SC>(
    config: &SC,
    n: usize,
    pis: &[p3_uni_stark::Val<SC>],
    trace: RowMajorMatrix<p3_uni_stark::Val<SC>>,
) where
    SC: p3_uni_stark::StarkGenericConfig,
{
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

    let start = std::time::Instant::now();
    let proof = prove(config, &FibonacciAir {}, trace, pis);
    let elapsed = start.elapsed();
    println!("Proving time = {:?}", elapsed);

    println!(
        "quotient_chunks len = {:?}",
        proof.opened_values.quotient_chunks[0].len()
    );

    {
        let proof_bytes = postcard::to_allocvec(&proof).expect("Failed to serialize proof");
        println!(
            "Proof size 2adic: {} bytes for n = {:?}",
            proof_bytes.len(),
            n
        );
        println!("Proof degree bits: {}", proof.degree_bits);
    }

    let start = std::time::Instant::now();
    verify(config, &FibonacciAir {}, &proof, pis).expect("verification failed");
    let elapsed = start.elapsed();
    println!("Verifying time = {:?}", elapsed);
}

fn main() {
    let field = std::env::args().nth(1).unwrap_or_else(|| "g".to_string());
    match field.as_str() {
        "b" => run_baby_bear(),
        "k" => run_koala_bear(),
        "g" => run_goldilocks(),
        _ => {
            eprintln!(
                "Unknown field '{}'. Choose: b (babybear), k (koalabear), g (goldilocks)",
                field
            );
            std::process::exit(1);
        }
    }
}
