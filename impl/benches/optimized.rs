//! Comparisons against the unchanged Plonky3 adaptation; see OPTIMIZED_BENCHMARKS.md.

use std::{cell::OnceCell, env, hint::black_box, time::Duration};

use binary_merkle_tree::{
    Blake3, Digest, LeafMode, LeafPlan, MerkleTree, OptimizedMerkleTree, ResearchHash, Sha3_256,
    Sha256,
};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

struct Config {
    totals: Vec<u32>,
    widths: Vec<u32>,
    max_digest_bytes: usize,
    allow_large: bool,
}
impl Config {
    fn from_env() -> Self {
        let full = flag("MERKLE_FULL");
        let totals = if full { (20..=26).collect() } else { vec![20] };
        let widths = if full {
            (0..=14).collect()
        } else {
            vec![0, 4, 6, 8, 10, 14]
        };
        Self {
            totals: logs("MERKLE_TOTAL_LOGS", &totals, 26),
            widths: logs("MERKLE_WIDTH_LOGS", &widths, 14),
            max_digest_bytes: env::var("MERKLE_MAX_DIGEST_MIB")
                .map_or(256, |v| {
                    v.parse::<usize>().expect("invalid MERKLE_MAX_DIGEST_MIB")
                })
                .checked_mul(1 << 20)
                .expect("digest cap overflow"),
            allow_large: flag("MERKLE_ALLOW_LARGE"),
        }
    }
}
fn flag(name: &str) -> bool {
    env::var(name).is_ok_and(|value| match value.as_str() {
        "1" | "true" => true,
        "0" | "false" => false,
        _ => panic!("{name} must be 0, 1, false, or true"),
    })
}
fn logs(name: &str, default: &[u32], maximum: u32) -> Vec<u32> {
    let Ok(value) = env::var(name) else {
        return default.to_vec();
    };
    let mut result: Vec<u32> = value
        .split(',')
        .map(|value| {
            let log = value
                .trim()
                .parse()
                .unwrap_or_else(|_| panic!("invalid {name}"));
            assert!(log <= maximum, "{name} values must be at most {maximum}");
            log
        })
        .collect();
    result.sort_unstable();
    result.dedup();
    result
}
fn selected(name: &str, value: &str) -> bool {
    env::var(name).map_or(true, |values| {
        values.split(',').any(|entry| entry.trim() == value)
    })
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
struct Query {
    index: usize,
    siblings: Vec<Digest>,
}
fn queries(leaves: usize, mut open: impl FnMut(usize) -> Vec<Digest>) -> Vec<Query> {
    (0..leaves.min(256))
        .map(|q| {
            let index = q.wrapping_mul(0x9e37_79b9).wrapping_add(0x85eb_ca6b) & (leaves - 1);
            Query {
                index,
                siblings: open(index),
            }
        })
        .collect()
}

fn bench_suite<H: ResearchHash>(criterion: &mut Criterion, hash: &str, config: &Config) {
    if !selected("MERKLE_HASHES", hash) {
        return;
    }
    for operation in ["commit", "verify"] {
        if !selected("MERKLE_OPERATIONS", operation) {
            continue;
        }
        let mut group = criterion.benchmark_group(format!("experiment_{operation}/{hash}"));
        for &total_log in &config.totals {
            let total = 1_usize << total_log;
            let data = OnceCell::new();
            for &width_log in &config.widths {
                if width_log > total_log {
                    continue;
                }
                let width = 1_usize << width_log;
                let leaves = total / width;
                if !config.allow_large && (2 * leaves - 1) * 32 > config.max_digest_bytes {
                    continue;
                }
                group.throughput(if operation == "commit" {
                    Throughput::Bytes((total * 4) as u64)
                } else {
                    Throughput::Elements(1)
                });
                for mode in std::iter::once(None).chain(LeafMode::ALL.into_iter().map(Some)) {
                    let scheme = mode.map_or("baseline", LeafMode::name);
                    if !selected("MERKLE_SCHEMES", scheme) {
                        continue;
                    }
                    if mode.is_some_and(|mode| LeafPlan::new::<H>(mode, width * 4).is_err()) {
                        continue;
                    }
                    let mut baseline_fixture = None;
                    let mut optimized_fixture = None;
                    let mut query_fixture = None;
                    group.bench_function(
                        BenchmarkId::new(scheme, format!("n2^{total_log}/w2^{width_log}")),
                        |bencher| {
                            let data = data.get_or_init(|| matrix(total));
                            match (operation, mode) {
                                ("commit", None) => bencher.iter(|| {
                                    black_box(
                                        MerkleTree::<H>::commit_u32(
                                            black_box(data),
                                            black_box(width),
                                        )
                                        .unwrap(),
                                    );
                                }),
                                ("commit", Some(mode)) => bencher.iter(|| {
                                    black_box(
                                        OptimizedMerkleTree::<H>::commit_u32(
                                            black_box(data),
                                            black_box(width),
                                            black_box(mode),
                                        )
                                        .unwrap(),
                                    );
                                }),
                                ("verify", None) => {
                                    let tree = baseline_fixture.get_or_insert_with(|| {
                                        MerkleTree::<H>::commit_u32(data, width).unwrap()
                                    });
                                    let queries = query_fixture.get_or_insert_with(|| {
                                        queries(leaves, |i| tree.open(i).unwrap().siblings)
                                    });
                                    let commitment = tree.commitment();
                                    let mut next = 0;
                                    bencher.iter(|| {
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
                                }
                                ("verify", Some(mode)) => {
                                    let tree = optimized_fixture.get_or_insert_with(|| {
                                        OptimizedMerkleTree::<H>::commit_u32(data, width, mode)
                                            .unwrap()
                                    });
                                    let queries = query_fixture.get_or_insert_with(|| {
                                        queries(leaves, |i| tree.open(i).unwrap().siblings)
                                    });
                                    let commitment = tree.commitment();
                                    let mut next = 0;
                                    bencher.iter(|| {
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
                                }
                                _ => unreachable!(),
                            }
                        },
                    );
                }
            }
        }
        group.finish();
    }
}

fn bench_leaves<H: ResearchHash>(criterion: &mut Criterion, hash: &str) {
    if !selected("MERKLE_HASHES", hash) || !selected("MERKLE_OPERATIONS", "leaf") {
        return;
    }
    let mut group = criterion.benchmark_group(format!("experiment_leaf/{hash}"));
    // Paper-native records: T5 = five blocks; T8 = eight; the height-three
    // ABR3 gadget consumes eleven blocks. Other widths expose practical padding.
    for width in [1, 16, 40, 64, 88, 256, 16_384] {
        let bytes: Vec<_> = matrix(width)
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        group.throughput(Throughput::Bytes(bytes.len() as u64));
        if selected("MERKLE_SCHEMES", "baseline") {
            group.bench_function(
                BenchmarkId::new("baseline", format!("u32_{width}")),
                |bencher| {
                    bencher.iter(|| black_box(H::hash_leaf(black_box(&bytes))));
                },
            );
        }
        for mode in LeafMode::ALL {
            if !selected("MERKLE_SCHEMES", mode.name()) {
                continue;
            }
            let Ok(plan) = LeafPlan::new::<H>(mode, bytes.len()) else {
                continue;
            };
            group.bench_function(
                BenchmarkId::new(mode.name(), format!("u32_{width}")),
                |bencher| {
                    bencher.iter(|| black_box(plan.hash::<H>(black_box(&bytes))));
                },
            );
        }
    }
    group.finish();
}

fn benchmarks(criterion: &mut Criterion) {
    let config = Config::from_env();
    bench_leaves::<Sha256>(criterion, "sha256");
    bench_leaves::<Sha3_256>(criterion, "sha3_256");
    bench_leaves::<Blake3>(criterion, "blake3");
    bench_suite::<Sha256>(criterion, "sha256", &config);
    bench_suite::<Sha3_256>(criterion, "sha3_256", &config);
    bench_suite::<Blake3>(criterion, "blake3", &config);
}
criterion_group! {
    name = optimized;
    config = Criterion::default().sample_size(10).warm_up_time(Duration::from_millis(200)).measurement_time(Duration::from_secs(1));
    targets = benchmarks
}
criterion_main!(optimized);
