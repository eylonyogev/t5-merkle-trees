//! Matrix-shaped Merkle benchmarks; configuration and interpretation: BENCHMARKS.md.

use std::{borrow::Cow, cell::OnceCell, env, hint::black_box, time::Duration};

use binary_merkle_tree::{Blake3, Digest, HashFunction, MerkleTree, Sha3_256, Sha256};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use p3_matrix::dense::RowMajorMatrixView;
use p3_merkle_tree::MerkleTree as Plonky3Tree;

#[derive(Clone, Copy)]
enum Operation {
    Commit,
    CommitPlonky3,
    Verify,
    Open,
    OpenInto,
}

impl Operation {
    const ALL: [Self; 5] = [
        Self::Commit,
        Self::CommitPlonky3,
        Self::Verify,
        Self::Open,
        Self::OpenInto,
    ];

    fn name(self) -> &'static str {
        match self {
            Self::Commit => "commit",
            Self::CommitPlonky3 => "commit_plonky3",
            Self::Verify => "verify",
            Self::Open => "open",
            Self::OpenInto => "open_into",
        }
    }

    fn throughput(self, total_elements: usize) -> Throughput {
        match self {
            Self::Commit | Self::CommitPlonky3 => Throughput::Bytes((total_elements * 4) as u64),
            Self::Verify | Self::Open | Self::OpenInto => Throughput::Elements(1),
        }
    }
}

struct Config {
    total_logs: Vec<u32>,
    width_logs: Vec<u32>,
}

impl Config {
    fn from_env() -> Self {
        let full = bool_env("MERKLE_FULL").unwrap_or(false);
        let total_default: Vec<u32> = if full { (20..=26).collect() } else { vec![20] };
        let width_default: Vec<u32> = if full {
            (0..=14).collect()
        } else {
            vec![0, 4, 8, 14]
        };
        Self {
            total_logs: log_list("MERKLE_TOTAL_LOGS", &total_default, 20, 26),
            width_logs: log_list("MERKLE_WIDTH_LOGS", &width_default, 0, 14),
        }
    }
}

fn bool_env(name: &str) -> Option<bool> {
    env::var(name).ok().map(|value| match value.as_str() {
        "1" | "true" => true,
        "0" | "false" => false,
        _ => panic!("{name} must be 0, 1, false, or true"),
    })
}

fn log_list(name: &str, default: &[u32], minimum: u32, maximum: u32) -> Vec<u32> {
    let Ok(value) = env::var(name) else {
        return default.to_vec();
    };
    let mut values: Vec<u32> = value
        .split(',')
        .map(|part| {
            let log: u32 = part.trim().parse().unwrap_or_else(|_| {
                panic!("{name} must be a comma-separated list of integer exponents")
            });
            assert!(
                (minimum..=maximum).contains(&log),
                "{name} values must be in {minimum}..={maximum}"
            );
            log
        })
        .collect();
    values.sort_unstable();
    values.dedup();
    values
}

fn matrix(total_elements: usize) -> Vec<u32> {
    // Fixed SplitMix64 stream: reproducible, nonconstant data, no RNG dependency.
    let mut state = 0x6a09_e667_f3bc_c909_u64;
    (0..total_elements)
        .map(|_| {
            state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut mixed = state;
            mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            (mixed ^ (mixed >> 31)) as u32
        })
        .collect()
}

fn u32_bytes(input: &[u32]) -> Cow<'_, [u8]> {
    #[cfg(target_endian = "little")]
    {
        Cow::Borrowed(bytemuck::cast_slice(input))
    }
    #[cfg(target_endian = "big")]
    {
        Cow::Owned(input.iter().flat_map(|value| value.to_le_bytes()).collect())
    }
}

struct Query {
    index: usize,
    siblings: Vec<Digest>,
}

fn query_index(query: usize, leaf_count: usize) -> usize {
    // An odd stride permutes the power-of-two index space before repeating.
    query.wrapping_mul(0x9e37_79b9).wrapping_add(0x85eb_ca6b) & (leaf_count - 1)
}

fn queries<H: HashFunction>(tree: &MerkleTree<H>, leaf_count: usize) -> Vec<Query> {
    (0..leaf_count.min(256))
        .map(|query| {
            let index = query_index(query, leaf_count);
            let mut siblings = Vec::new();
            tree.open_into(index, &mut siblings).unwrap();
            Query { index, siblings }
        })
        .collect()
}

fn bench_hasher<H: HashFunction>(criterion: &mut Criterion, name: &str, config: &Config) {
    for operation in Operation::ALL {
        let mut group = criterion.benchmark_group(format!("{}/{name}", operation.name()));
        for &total_log in &config.total_logs {
            let total_elements = 1_usize << total_log;
            // Laziness matters: a Criterion CLI filter must not build excluded matrices/trees.
            let data = OnceCell::new();
            for &width_log in &config.width_logs {
                let width = 1_usize << width_log;
                let leaf_count = total_elements / width;
                let mut tree_fixture = None;
                let mut query_fixture = None;
                let mut siblings = Vec::with_capacity((total_log - width_log) as usize);
                group.throughput(operation.throughput(total_elements));
                group.bench_function(
                    BenchmarkId::new(format!("n2^{total_log}"), format!("w2^{width_log}")),
                    |bencher| {
                        let data = data.get_or_init(|| matrix(total_elements));
                        if matches!(operation, Operation::Commit) {
                            bencher.iter(|| {
                                let tree = MerkleTree::<H>::commit_u32(
                                    black_box(data.as_slice()),
                                    black_box(width),
                                )
                                .unwrap();
                                // The allocated tree is also dropped within the timed iteration.
                                black_box(tree);
                            });
                            return;
                        }

                        if matches!(operation, Operation::CommitPlonky3) {
                            // Both implementations borrow their input and allocate/drop digest
                            // layers during timing. On little-endian hosts, neither copies u32s.
                            let bytes = u32_bytes(data);
                            let leaf_hasher = H::leaf_hasher();
                            let compressor = H::node_compressor();
                            bencher.iter(|| {
                                let tree = Plonky3Tree::<u8, u8, _, 2, 32>::new::<u8, u8, _, _>(
                                    black_box(&leaf_hasher),
                                    black_box(&compressor),
                                    vec![RowMajorMatrixView::new(
                                        black_box(bytes.as_ref()),
                                        black_box(width * 4),
                                    )],
                                );
                                black_box(tree);
                            });
                            return;
                        }

                        // Allocation, initial construction, and proof preparation are untimed.
                        let tree = tree_fixture.get_or_insert_with(|| {
                            MerkleTree::<H>::commit_u32(data, width).unwrap()
                        });
                        match operation {
                            Operation::Commit | Operation::CommitPlonky3 => unreachable!(),
                            Operation::Verify => {
                                let queries =
                                    query_fixture.get_or_insert_with(|| queries(tree, leaf_count));
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
                                            black_box(query.siblings.as_slice()),
                                        )
                                        .unwrap();
                                });
                            }
                            Operation::Open => {
                                let mut next = 0;
                                bencher.iter(|| {
                                    let index = query_index(next, leaf_count);
                                    next = next.wrapping_add(1);
                                    black_box(tree.open(black_box(index)).unwrap());
                                });
                            }
                            Operation::OpenInto => {
                                let mut next = 0;
                                bencher.iter(|| {
                                    let index = query_index(next, leaf_count);
                                    next = next.wrapping_add(1);
                                    tree.open_into(black_box(index), black_box(&mut siblings))
                                        .unwrap();
                                    black_box(siblings.as_slice());
                                });
                            }
                        }
                    },
                );
            }
        }
        group.finish();
    }
}

fn bench_hash_operations<H: HashFunction>(criterion: &mut Criterion, name: &str) {
    // Include both sides of SHA-256 padding, SHA3-256 rate, and BLAKE3 block/chunk boundaries.
    let widths = [1, 13, 14, 15, 16, 31, 32, 33, 34, 255, 256, 257, 16_384];
    let mut leaves = criterion.benchmark_group(format!("hash_leaf_u32/{name}"));
    for width in widths {
        let data = matrix(width);
        leaves.throughput(Throughput::Bytes((width * 4) as u64));
        leaves.bench_with_input(
            BenchmarkId::from_parameter(width),
            &data,
            |bencher, data| {
                bencher.iter(|| black_box(H::hash_leaf_u32(black_box(data.as_slice()))));
            },
        );
    }
    leaves.finish();

    let mut parents = criterion.benchmark_group(format!("hash_nodes/{name}"));
    let left = [0x5a; 32];
    let right = [0xc3; 32];
    parents.throughput(Throughput::Bytes(64));
    parents.bench_function("digest_pair", |bencher| {
        bencher.iter(|| black_box(H::hash_nodes(black_box(&left), black_box(&right))));
    });
    parents.finish();
}

fn benchmarks(criterion: &mut Criterion) {
    let config = Config::from_env();
    bench_hash_operations::<Sha256>(criterion, "sha256");
    bench_hash_operations::<Sha3_256>(criterion, "sha3_256");
    bench_hash_operations::<Blake3>(criterion, "blake3");
    bench_hasher::<Sha256>(criterion, "sha256", &config);
    bench_hasher::<Sha3_256>(criterion, "sha3_256", &config);
    bench_hasher::<Blake3>(criterion, "blake3", &config);
}

criterion_group! {
    name = merkle;
    config = Criterion::default()
        .sample_size(10)
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(2));
    targets = benchmarks
}
criterion_main!(merkle);
