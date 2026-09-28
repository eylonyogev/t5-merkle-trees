//! Bounded paired-construction timing sweep; see OPTIMIZED_BENCHMARKS.md.
//!
//! CSV is emitted on stdout; configuration and skipped cases go to stderr.

use std::{
    env,
    hint::black_box,
    time::{Duration, Instant},
};

use binary_merkle_tree::{
    Blake3, Digest, LeafMode, LeafPlan, MerkleTree, OptimizedHash, OptimizedMerkleTree,
    ResearchHash, Sha3_256, Sha256,
};

struct Config {
    total_logs: Vec<u32>,
    width_logs: Vec<u32>,
    hashes: Vec<String>,
    schemes: Vec<String>,
    operations: Vec<String>,
    samples: usize,
    duration: Duration,
    max_digest_bytes: usize,
    allow_large: bool,
}

impl Config {
    fn from_env() -> Self {
        let full = flag("MERKLE_FULL", false);
        let total_default = if full { (20..=26).collect() } else { vec![20] };
        let width_default = if full {
            (0..=14).collect()
        } else {
            vec![0, 4, 6, 8, 10, 14]
        };
        let samples = number("MERKLE_SWEEP_SAMPLES", 5);
        assert!(samples >= 5, "MERKLE_SWEEP_SAMPLES must be at least 5");
        let milliseconds = number("MERKLE_SWEEP_MS", 80);
        assert!(milliseconds > 0, "MERKLE_SWEEP_MS must be positive");
        let hashes = list("MERKLE_HASHES", &["sha256", "sha3_256", "blake3"]);
        assert!(
            hashes
                .iter()
                .all(|h| ["sha256", "sha3_256", "blake3"].contains(&h.as_str())),
            "unknown MERKLE_HASHES entry"
        );
        let mut scheme_names = vec!["baseline"];
        scheme_names.extend(LeafMode::ALL.into_iter().map(LeafMode::name));
        let schemes = list("MERKLE_SCHEMES", &scheme_names);
        assert!(
            schemes.iter().all(|s| scheme_names.contains(&s.as_str())),
            "unknown MERKLE_SCHEMES entry; allowed: {scheme_names:?}"
        );
        let operations = list("MERKLE_OPERATIONS", &["commit", "verify"]);
        assert!(
            operations
                .iter()
                .all(|op| ["commit", "verify"].contains(&op.as_str())),
            "MERKLE_OPERATIONS accepts commit,verify"
        );
        Self {
            total_logs: logs("MERKLE_TOTAL_LOGS", &total_default, 26),
            width_logs: logs("MERKLE_WIDTH_LOGS", &width_default, 14),
            hashes,
            schemes,
            operations,
            samples,
            duration: Duration::from_millis(milliseconds as u64),
            max_digest_bytes: number("MERKLE_MAX_DIGEST_MIB", 256)
                .checked_mul(1 << 20)
                .expect("memory cap overflow"),
            allow_large: flag("MERKLE_ALLOW_LARGE", false),
        }
    }

    fn selected(&self, scheme: &str) -> bool {
        self.schemes.iter().any(|s| s == scheme)
    }
    fn measures(&self, operation: &str) -> bool {
        self.operations.iter().any(|s| s == operation)
    }
}

fn flag(name: &str, default: bool) -> bool {
    env::var(name).map_or(default, |value| match value.as_str() {
        "1" | "true" => true,
        "0" | "false" => false,
        _ => panic!("{name} must be 0, 1, false, or true"),
    })
}
fn number(name: &str, default: usize) -> usize {
    env::var(name).map_or(default, |value| {
        value
            .parse()
            .unwrap_or_else(|_| panic!("{name} must be an integer"))
    })
}
fn list(name: &str, default: &[&str]) -> Vec<String> {
    let result: Vec<_> = env::var(name).map_or_else(
        |_| default.iter().map(|s| (*s).to_owned()).collect(),
        |value| value.split(',').map(|s| s.trim().to_owned()).collect(),
    );
    assert!(
        !result.is_empty() && result.iter().all(|s| !s.is_empty()),
        "{name} must not be empty"
    );
    result
}
fn logs(name: &str, default: &[u32], maximum: u32) -> Vec<u32> {
    let Ok(value) = env::var(name) else {
        return default.to_vec();
    };
    let mut result: Vec<u32> = value
        .split(',')
        .map(|s| {
            let log = s
                .trim()
                .parse()
                .unwrap_or_else(|_| panic!("{name} must contain integer exponents"));
            assert!(log <= maximum, "{name} values must be at most {maximum}");
            log
        })
        .collect();
    result.sort_unstable();
    result.dedup();
    result
}

fn matrix(total: usize) -> Vec<u32> {
    let mut state = 0x6a09_e667_f3bc_c909_u64;
    (0..total)
        .map(|_| {
            state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut mixed = state;
            mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            (mixed ^ (mixed >> 31)) as u32
        })
        .collect()
}

struct Estimate {
    median: f64,
    p10: f64,
    p90: f64,
    iterations: usize,
}

/// Calibrate outside the samples, then time fixed batches. The timer overhead is
/// amortized for verification; slow commits still receive at least five samples.
fn measure(config: &Config, mut operation: impl FnMut()) -> Estimate {
    let mut calibration_iterations = 1_usize;
    let calibration = loop {
        let start = Instant::now();
        for _ in 0..calibration_iterations {
            operation();
        }
        let elapsed = start.elapsed();
        if elapsed >= Duration::from_millis(1) || calibration_iterations >= 1_048_576 {
            break elapsed.as_nanos().max(1) as f64 / calibration_iterations as f64;
        }
        calibration_iterations *= 2;
    };
    let target = config.duration.as_nanos() as f64 / config.samples as f64;
    let iterations = (target / calibration).round().clamp(1.0, 1_048_576.0) as usize;
    let mut samples = Vec::with_capacity(config.samples);
    for _ in 0..config.samples {
        let start = Instant::now();
        for _ in 0..iterations {
            operation();
        }
        samples.push(start.elapsed().as_nanos() as f64 / iterations as f64);
    }
    samples.sort_unstable_by(f64::total_cmp);
    let percentile = |p: f64| {
        let index = p * (samples.len() - 1) as f64;
        let low = index.floor() as usize;
        let high = index.ceil() as usize;
        samples[low] + (samples[high] - samples[low]) * index.fract()
    };
    Estimate {
        median: percentile(0.5),
        p10: percentile(0.1),
        p90: percentile(0.9),
        iterations,
    }
}

struct Case<'a> {
    hash: &'a str,
    scheme: &'a str,
    total_log: u32,
    width_log: u32,
    leaf_native: u64,
    leaf_abstract: u64,
}

fn emit<H: OptimizedHash>(config: &Config, case: &Case<'_>, operation: &str, estimate: Estimate) {
    let total = 1_usize << case.total_log;
    let width = 1_usize << case.width_log;
    let leaves = total / width;
    let height = case.total_log - case.width_log;
    let digest_bytes = (2 * leaves - 1) * 32;
    let (native_calls, abstract_calls, input_bytes) = if operation == "commit" {
        (
            case.leaf_native * leaves as u64 + (leaves - 1) as u64,
            case.leaf_abstract * leaves as u64,
            total * 4,
        )
    } else {
        (
            case.leaf_native + height as u64,
            case.leaf_abstract,
            width * 4,
        )
    };
    println!(
        "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{:.3},{:.3},{:.3}",
        case.hash,
        case.scheme,
        operation,
        case.total_log,
        case.width_log,
        total,
        width,
        leaves,
        total * 4,
        input_bytes,
        digest_bytes,
        height * 32,
        H::PRIMITIVE_NAME,
        native_calls,
        abstract_calls,
        config.samples,
        estimate.iterations,
        estimate.median,
        estimate.p10,
        estimate.p90
    );
}

struct Query {
    index: usize,
    siblings: Vec<Digest>,
}
fn queries(leaves: usize, mut open: impl FnMut(usize) -> Vec<Digest>) -> Vec<Query> {
    (0..leaves.min(256))
        .map(|query| {
            let index = query.wrapping_mul(0x9e37_79b9).wrapping_add(0x85eb_ca6b) & (leaves - 1);
            Query {
                index,
                siblings: open(index),
            }
        })
        .collect()
}

fn baseline<H: ResearchHash>(
    config: &Config,
    hash: &str,
    data: &[u32],
    total_log: u32,
    width_log: u32,
) -> Digest {
    let width = 1 << width_log;
    let case = Case {
        hash,
        scheme: "baseline",
        total_log,
        width_log,
        leaf_native: H::standard_leaf_calls(width * 4),
        leaf_abstract: 0,
    };
    if config.measures("commit") {
        let estimate = measure(config, || {
            black_box(MerkleTree::<H>::commit_u32(black_box(data), black_box(width)).unwrap());
        });
        emit::<H>(config, &case, "commit", estimate);
    }
    let tree = MerkleTree::<H>::commit_u32(data, width).unwrap();
    let commitment = tree.commitment();
    if config.measures("verify") {
        let queries = queries(tree.leaf_count(), |i| tree.open(i).unwrap().siblings);
        let mut next = 0;
        let estimate = measure(config, || {
            let query = &queries[next];
            next = (next + 1) % queries.len();
            let start = query.index * width;
            black_box(&commitment)
                .verify_u32(
                    black_box(query.index),
                    black_box(&data[start..start + width]),
                    black_box(&query.siblings),
                )
                .unwrap();
        });
        emit::<H>(config, &case, "verify", estimate);
    }
    tree.root()
}

fn optimized<H: ResearchHash>(
    config: &Config,
    case: &Case<'_>,
    data: &[u32],
    mode: LeafMode,
    baseline_root: Option<Digest>,
) {
    let width = 1 << case.width_log;
    if config.measures("commit") {
        let estimate = measure(config, || {
            black_box(
                OptimizedMerkleTree::<H>::commit_u32(
                    black_box(data),
                    black_box(width),
                    black_box(mode),
                )
                .unwrap(),
            );
        });
        emit::<H>(config, case, "commit", estimate);
    }
    let tree = OptimizedMerkleTree::<H>::commit_u32(data, width, mode).unwrap();
    if matches!(mode, LeafMode::Standard) {
        assert_eq!(
            Some(tree.root()),
            baseline_root,
            "standard roots must match the pinned baseline"
        );
    }
    let commitment = tree.commitment();
    let queries = queries(tree.leaf_count(), |i| tree.open(i).unwrap().siblings);
    // Check every prepared opening, even when timing only commitment.
    for query in &queries {
        let start = query.index * width;
        commitment
            .verify_u32(query.index, &data[start..start + width], &query.siblings)
            .unwrap();
    }
    if config.measures("verify") {
        let mut next = 0;
        let estimate = measure(config, || {
            let query = &queries[next];
            next = (next + 1) % queries.len();
            let start = query.index * width;
            black_box(&commitment)
                .verify_u32(
                    black_box(query.index),
                    black_box(&data[start..start + width]),
                    black_box(&query.siblings),
                )
                .unwrap();
        });
        emit::<H>(config, case, "verify", estimate);
    }
}

fn run<H: ResearchHash>(config: &Config, hash: &str) {
    for &total_log in &config.total_logs {
        let mut data = None;
        for &width_log in &config.width_logs {
            if width_log > total_log {
                continue;
            }
            let digest_bytes = ((2_usize << (total_log - width_log)) - 1) * 32;
            if !config.allow_large && digest_bytes > config.max_digest_bytes {
                eprintln!(
                    "skip {hash}/n2^{total_log}/w2^{width_log}: {digest_bytes} digest bytes exceed cap"
                );
                continue;
            }
            let data = data.get_or_insert_with(|| matrix(1 << total_log));
            let baseline_root = if config.selected("baseline") {
                eprintln!("{hash}/baseline/n2^{total_log}/w2^{width_log}");
                Some(baseline::<H>(config, hash, data, total_log, width_log))
            } else if config.selected(LeafMode::Standard.name()) {
                Some(
                    MerkleTree::<H>::commit_u32(data, 1 << width_log)
                        .unwrap()
                        .root(),
                )
            } else {
                None
            };
            for mode in LeafMode::ALL {
                if !config.selected(mode.name()) {
                    continue;
                }
                let leaf_bytes = 4_usize << width_log;
                let plan = match LeafPlan::new::<H>(mode, leaf_bytes) {
                    Ok(plan) => plan,
                    Err(error) => {
                        eprintln!(
                            "skip {hash}/{}/n2^{total_log}/w2^{width_log}: {error}",
                            mode.name()
                        );
                        continue;
                    }
                };
                let case = Case {
                    hash,
                    scheme: mode.name(),
                    total_log,
                    width_log,
                    leaf_native: plan.native_calls::<H>(),
                    leaf_abstract: plan.abstract_calls(),
                };
                eprintln!("{hash}/{}/n2^{total_log}/w2^{width_log}", mode.name());
                optimized::<H>(config, &case, data, mode, baseline_root);
            }
        }
    }
}

fn main() {
    let config = Config::from_env();
    eprintln!(
        "perf_sweep architecture={} os={} parallel={} rayon_threads={} samples={} target_ms={} max_digest_mib={} allow_large={}",
        env::consts::ARCH,
        env::consts::OS,
        cfg!(feature = "parallel"),
        env::var("RAYON_NUM_THREADS").unwrap_or_else(|_| "automatic".into()),
        config.samples,
        config.duration.as_millis(),
        config.max_digest_bytes >> 20,
        config.allow_large
    );
    println!(
        "hash,scheme,operation,total_log,width_log,total_elements,elements_per_leaf,leaves,matrix_bytes,operation_input_bytes,digest_bytes,path_bytes,primitive,native_calls,abstract_leaf_calls,samples,iterations_per_sample,median_ns,p10_ns,p90_ns"
    );
    if config.hashes.iter().any(|h| h == "sha256") {
        run::<Sha256>(&config, "sha256");
    }
    if config.hashes.iter().any(|h| h == "sha3_256") {
        run::<Sha3_256>(&config, "sha3_256");
    }
    if config.hashes.iter().any(|h| h == "blake3") {
        run::<Blake3>(&config, "blake3");
    }
}
