# Binary Merkle trees: Plonky3 baseline and compression experiments

`MerkleTree` is the unchanged reference described below. `OptimizedMerkleTree`
adds SIMD batching, coarser parallel scheduling, contiguous storage and explicit
whole-leaf compression modes. `LeafMode::Standard` preserves baseline roots;
T5, T8, ABR3 and SHA-256 T253 are separate experimental constructions.
Start with [EXPERIMENTS.md](EXPERIMENTS.md),
[OPTIMIZED_BENCHMARKS.md](OPTIMIZED_BENCHMARKS.md), and
[RESULTS.md](RESULTS.md) for the implementation, comparisons and measured results.

## Preserved reference implementation

A single-matrix, binary specialization of **Plonky3 0.6.3**, pinned to upstream
revision `02bb3950cbb8ff030219d7d9f1673dfe575cc371`. This replaces the original
custom tagged-hash implementation. The tree-building loops retain Plonky3's
leaf-first digest layers, allocation policy, scalar byte hashing, and
`p3-maybe-rayon` parallel scheduling. See [UPSTREAM.md](UPSTREAM.md) for provenance
and the exact scope of the simplification.

SHA-256 and BLAKE3 use the actual pinned Plonky3 hash/compression implementations.
NIST SHA3-256 uses a small adapter implementing the same Plonky3 traits. All three
configurations are checked against the actual upstream Merkle implementation;
benchmarks include an upstream comparison using identical inputs and primitives.

```sh
cd impl
cargo test --locked
RAYON_NUM_THREADS=4 cargo run --release --locked --example smoke -- 20 8
RAYON_NUM_THREADS=4 cargo bench --locked --bench merkle -- '^commit'
```

The lockfile and exact Plonky3 dependency versions make the reference reproducible.
The crate uses Rust 2024 and is tested with the toolchain recorded in [BASELINE.md](BASELINE.md).

## Use

```rust
use binary_merkle_tree::{Commitment, MerkleTree, Sha256};

// Inside a function returning Result<(), binary_merkle_tree::Error>:
let matrix: Vec<u32> = (0..1 << 20).collect();
let width = 256;
let tree = MerkleTree::<Sha256>::commit_u32(&matrix, width)?;
let index = 19;
let proof = tree.open(index)?;
let row = &matrix[index * width..(index + 1) * width];

// These dimensions and the suite are authenticated by the surrounding protocol.
let commitment = Commitment::<Sha256>::from_root(tree.root(), 4096, width * 4)?;
commitment.verify_u32(index, row, &proof.siblings)?;
```

Use `Sha3_256` or `Blake3` in place of `Sha256`. `commit_bytes` and `verify_bytes`
accept fixed-size byte records; `open_into` lets a caller reuse its proof buffer.
The caller retains the original matrix to answer openings. The tree only retains
its digests and dimensions. Single-proof verification allocates no heap memory.

## Exact hash constructions

| Suite | Leaf | Parent |
| --- | --- | --- |
| `Sha256` | Standard SHA-256 of the row bytes | One unpadded SHA-256 compression of `left || right`, starting from the standard IV; Plonky3 `Sha256Compress` |
| `Sha3_256` | NIST SHA3-256 of the row bytes | NIST SHA3-256 of `left || right`, through `CompressionFunctionFromHasher` |
| `Blake3` | Standard unkeyed BLAKE3 of the row bytes | Standard unkeyed BLAKE3 of `left || right`, through `CompressionFunctionFromHasher` |

All digests are 32 bytes. No leaf or node domain prefixes are added. The SHA-256
parent is **not** the full SHA-256 hash of a 64-byte message. NIST SHA3-256 is
**not** Keccak-256: the SHA3 adapter intentionally preserves the originally
requested hash instead of substituting Plonky3's native Keccak hash.

`u32` elements are encoded in little-endian order without field-modulus checks or
reduction. On little-endian hosts the input is borrowed as bytes. The leaf count
must be a nonzero power of two and every leaf has the same positive width; widths
need not themselves be powers of two. No implicit input padding is added. A
one-leaf root is its leaf hash. An authentication path contains exactly
`log2(leaf_count)` sibling digests in bottom-up order.

**The hash suite, leaf count, width, root, and queried index must be fixed or
authenticated by the protocol.** These untagged upstream constructions do not
encode matrix geometry in the root. In particular, a BLAKE3 or SHA3 internal node
also has the form of a hash of a 64-byte record; accepting a prover-chosen tree
height would defeat the intended position/shape checks. Verification validates
index, record length, and exact proof length against the trusted context before
hashing. No wire-format parser is provided.

Roots and proofs from the previous tagged implementation are incompatible.
`CommitOptions`, allocation-reusing recommits, and custom multiproofs remain
absent from the baseline, which exposes only the single-matrix binary construction.
The new optimized tree separately offers allocation-reusing recommits.
Upstream has additional MMCS and pruned-proof functionality outside this scope.

## What this baseline does and does not optimize

The tree is a simplified version of Plonky3's **scalar byte-hash configuration**:
`P = PW = u8`, packing width 1, binary arity 2. SHA-256 and BLAKE3 retain whatever
hardware acceleration their upstream backends provide. This is not Plonky3's
packed Poseidon/field-hash configuration, and the byte wrappers do not batch
independent messages into SIMD lanes.

Each level gets a zero-initialized digest vector, then hashes/compresses in
parallel using upstream's scheduling interface. The baseline has no custom work
thresholds, subtree scheduling, hash batching, or special buffer reuse. These
remain isolated from the new optimized implementation. Removing generic multi-matrix and
arity machinery can change timings, so benchmark parity is measured rather than
assumed. The verification wrapper retains strict validation and uses upstream's
bulk leaf-hashing path (`hash_iter_slices`) followed by the same compressor.

`RAYON_NUM_THREADS` controls the worker count. `--no-default-features` compiles
both the local implementation and the upstream reference with serial iteration.
Use matching build flags, features, and thread counts for comparisons.

For `N` elements, `W` elements per leaf, and `L = N/W` leaves, digest payload
storage is `32(2L - 1)` bytes, plus `O(log L)` vector headers and allocator overhead.
The caller's input needs another `4N` bytes:

| Elements | Width | Leaves | Input | Digests (approx.) |
| --- | --- | --- | --- | --- |
| `2^20` | `1` | `2^20` | 4 MiB | 64 MiB |
| `2^26` | `1` | `2^26` | 256 MiB | 4 GiB |
| `2^26` | `256` | `2^18` | 256 MiB | 16 MiB |
| `2^26` | `16384` | `2^12` | 256 MiB | 256 KiB |

## Benchmarking and further experiments

[BENCHMARKS.md](BENCHMARKS.md) describes the deterministic Criterion matrix sweep,
upstream comparison, throughput units, hash-boundary microbenchmarks, and saved
baseline commands. [BASELINE.md](BASELINE.md) records current validation and
selected measured comparisons; it supersedes the old custom-tree measurements.

`HashFunction` exposes separate `LeafHasher` and `NodeCompressor` types implementing
Plonky3's `CryptographicHasher` and `PseudoCompressionFunction`. Experiments can
change one primitive while keeping the tree and reference harness fixed. New
compression constructions must be treated as new suites with their own root
semantics and security assumptions. A change in hash/compression count should be
reported separately from an implementation optimization preserving roots.

```sh
cargo test --locked
cargo test --locked --no-default-features
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo fmt --check
```

The tests cover agreement with pinned Plonky3 roots and authentication paths,
cross-verification, independent hash fixtures, little-endian encoding, boundary
sizes, singleton trees, and malformed/tampered openings. The local crate forbids
unsafe Rust. Upstream-derived code is used under its MIT license; see
[LICENSE-MIT](LICENSE-MIT).
