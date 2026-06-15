/// Generate a Goldilocks batch STARK proof (MulAir + FibonacciAir, lookups off)
/// and dump it as JSON to a file.
///
/// Usage: cargo run --release --bin export_batch_proof batch_proof.json
///
/// The JSON is then fed to convert.py to produce the Aiken batch test literal.
///
/// The StarkConfig (field, hash, FRI params, cap_height) must stay identical to
/// fib_batch.rs — both mirror aiken/lib/stark/params.ak. The AIRs are duplicated
/// from fib_batch.rs (minus the lookup-registration wrappers, which contribute
/// nothing while lookups are disabled) to keep this binary self-contained.
use std::fs;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_batch_stark::{ProverData, StarkGenericConfig, StarkInstance, prove_batch, verify_batch};
use p3_challenger::{HashChallenger, SerializingChallenger64};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_goldilocks::Goldilocks;
use p3_lookup::LookupAir;
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_sha256::Sha256;
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};
use p3_uni_stark::StarkConfig;
use p3_util::log2_strict_usize;

type Val = Goldilocks;
type Challenge = BinomialExtensionField<Val, 2>;
type ByteHash = Sha256;
type MyHash = SerializingHasher<ByteHash>;
type MyCompress = CompressionFunctionFromHasher<ByteHash, 2, 32>;
type ValMmcs = MerkleTreeMmcs<Val, u8, MyHash, MyCompress, 2, 32>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Challenger = SerializingChallenger64<Val, HashChallenger<u8, Sha256, 32>>;
type Dft = Radix2DitParallel<Val>;
type MyPcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
type MyConfig = StarkConfig<MyPcs, Challenge, Challenger>;

// ── Fibonacci AIR (2 columns, 3 public values) ───────────────────────────────

#[derive(Clone)]
struct FibonacciAir {}

impl<F> BaseAir<F> for FibonacciAir {
    fn width(&self) -> usize {
        2
    }
    fn num_public_values(&self) -> usize {
        3
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

fn fib_trace<F: PrimeField64>(a: u64, b: u64, n: usize) -> RowMajorMatrix<F> {
    assert!(n.is_power_of_two());
    let mut values = vec![F::ZERO; n * 2];
    values[0] = F::from_u64(a);
    values[1] = F::from_u64(b);
    for i in 1..n {
        values[i * 2] = values[(i - 1) * 2 + 1];
        values[i * 2 + 1] = values[(i - 1) * 2] + values[(i - 1) * 2 + 1];
    }
    RowMajorMatrix::new(values, 2)
}

// ── Multiplication AIR (reps*3 + 1 columns, no public values) ────────────────
// For each rep, 3 columns a, b, c with a*b = c and Fibonacci-style transitions.
// The extra last column is a permutation of the first column; it is only
// constrained by the local lookups, so it is dead weight while lookups are off,
// but it is kept so the trace shape matches fib_batch.rs.

#[derive(Clone)]
struct MulAir {
    reps: usize,
}

impl<F> BaseAir<F> for MulAir {
    fn width(&self) -> usize {
        self.reps * 3 + 1
    }
}

impl<AB: AirBuilder> Air<AB> for MulAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        let next = main.next_slice();
        for i in 0..self.reps {
            let s = i * 3;
            let a = local[s];
            let b = local[s + 1];
            let c = local[s + 2];
            builder.assert_eq(a * b, c);

            builder.when_transition().assert_eq(b, next[s]);
            builder.when_transition().assert_eq(a + b, next[s + 1]);
        }
    }
}

fn mul_trace<F: Field>(rows: usize, reps: usize) -> RowMajorMatrix<F> {
    assert!(rows.is_power_of_two());
    let w = reps * 3 + 1;
    let mut v = F::zero_vec(rows * w);
    let last_idx = w - 1;

    for rep in 0..reps {
        let mut a = F::ZERO;
        let mut b = F::ONE;
        for i in 0..rows {
            let idx = i * w + rep * 3;
            v[idx] = a;
            v[idx + 1] = b;
            v[idx + 2] = v[idx] * v[idx + 1];
            if i != rows - 1 {
                v[i * w + last_idx] = b;
            }
            let tmp = a + b;
            a = b;
            b = tmp;
        }
    }
    RowMajorMatrix::new(v, w)
}

// ── Enum wrapper so both AIRs fit in one `&[A]` slice ─────────────────────────

#[derive(Clone)]
enum BatchAir {
    Mul(MulAir),
    Fib(FibonacciAir),
}

impl<F> BaseAir<F> for BatchAir {
    fn width(&self) -> usize {
        match self {
            Self::Mul(a) => <MulAir as BaseAir<F>>::width(a),
            Self::Fib(a) => <FibonacciAir as BaseAir<F>>::width(a),
        }
    }

    fn num_public_values(&self) -> usize {
        match self {
            Self::Mul(a) => <MulAir as BaseAir<F>>::num_public_values(a),
            Self::Fib(a) => <FibonacciAir as BaseAir<F>>::num_public_values(a),
        }
    }
}

impl<AB: AirBuilder> Air<AB> for BatchAir {
    fn eval(&self, builder: &mut AB) {
        match self {
            Self::Mul(a) => a.eval(builder),
            Self::Fib(a) => a.eval(builder),
        }
    }
}

// No lookups: the default LookupAir methods register nothing, so
// commitments.permutation stays None and verify_batch takes the no-lookup path.
impl<F: Field> LookupAir<F> for BatchAir {}

// ── Main ─────────────────────────────────────────────────────────────────────

fn main() {
    let hash = MyHash::new(Sha256 {});
    let compress = MyCompress::new(Sha256 {});
    // cap_height = 0: single 32-byte root, matching the Aiken mmcs.ak assumption.
    let val_mmcs = ValMmcs::new(hash, compress, 0);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::default();
    let fri_params = FriParameters {
        log_blowup: 8,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: 22,
        commit_proof_of_work_bits: 16,
        query_proof_of_work_bits: 16,
        mmcs: challenge_mmcs,
    };
    let pcs = MyPcs::new(dft, val_mmcs, fri_params);
    let challenger = Challenger::from_hasher(vec![], Sha256 {});
    let config = MyConfig::new(pcs, challenger);

    let reps = 2;
    let log_n = 13;
    let n = 1 << log_n;

    let mul_trace = mul_trace::<Val>(n, reps);
    let fib_trace = fib_trace::<Val>(0, 1, n);
    // Take the expected last-row value straight from the trace: u64 Fibonacci
    // overflows long before n = 1024, the field value is what the constraint sees.
    let fib_last = fib_trace.row_slice(n - 1).unwrap()[1];
    let pvs: Vec<Vec<Val>> = vec![vec![], vec![Val::ZERO, Val::ONE, fib_last]];

    let mut airs = vec![
        BatchAir::Mul(MulAir { reps }),
        BatchAir::Fib(FibonacciAir {}),
    ];

    let is_zk = config.is_zk();
    let log_degrees: Vec<usize> = vec![mul_trace.height(), fib_trace.height()]
        .into_iter()
        .map(|height| log2_strict_usize(height) + is_zk)
        .collect();

    let out_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "batch_proof.json".to_string());

    eprintln!("Generating batch proof...");
    let start = std::time::Instant::now();
    let prover_data = ProverData::from_airs_and_degrees(&config, &mut airs, &log_degrees);
    let traces = [&mul_trace, &fib_trace];
    let instances = StarkInstance::new_multiple(&airs, &traces, &pvs, &prover_data.common);
    let proof = prove_batch(&config, &instances, &prover_data);
    println!("Proving time = {:?}", start.elapsed());

    let start = std::time::Instant::now();
    let prover_data = ProverData::from_airs_and_degrees(&config, &mut airs, &proof.degree_bits);
    verify_batch(&config, &airs, &proof, &pvs, &prover_data.common).expect("verification failed");
    println!("Verifying time = {:?}", start.elapsed());

    let proof_bytes = postcard::to_allocvec(&proof).expect("Failed to serialize proof");
    println!("Proof size: {} bytes", proof_bytes.len());
    println!("Proof degree_bits: {:?}", proof.degree_bits);

    eprintln!("Done. Serializing to JSON...");

    // Wrap proof + public values together: unlike the uni-stark exporter, the
    // batch public values (fib_last at n = 1024) are not hardcodable downstream.
    let json = serde_json::json!({
        "proof": serde_json::to_value(&proof).expect("JSON serialization failed"),
        "public_values": serde_json::to_value(&pvs).expect("JSON serialization failed"),
    });
    fs::write(&out_path, serde_json::to_string(&json).unwrap())
        .expect("Failed to write proof file");
    eprintln!("Proof written to {}", out_path);
}
