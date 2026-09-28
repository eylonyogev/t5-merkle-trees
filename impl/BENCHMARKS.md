# Merkle benchmark protocol

Run from `impl/`. The Criterion harness measures a row-major matrix of `N`
32-bit elements with `W` elements in each leaf. A case named
`commit/sha256/n2^20/w2^8` commits 4 MiB of input in 4,096 leaves of 1 KiB each.
Data comes from a fixed deterministic generator and is prepared outside timing.
The baseline construction and provenance are documented in [README.md](README.md).

```sh
cargo bench --bench merkle
```

The default matrix suite uses `N = 2^20`, `W = 1, 16, 256, 16384`, and all three
hashes. It includes 60 matrix benchmarks and 42 hash microbenchmarks, and normally
takes several minutes. Each case uses 10 samples, 500 ms of warmup, and at least
two seconds of measurement. Criterion increases measurement time when operations
are slow. Its command-line options can override these settings.

## What is measured

| Benchmark | Timed work | Throughput unit |
| --- | --- | --- |
| `commit` | Build this simplified Plonky3 tree from borrowed u32 input and drop it | Input bytes/s |
| `commit_plonky3` | Build the pinned upstream Plonky3 tree from the same borrowed input bytes and drop it | Input bytes/s |
| `verify` | Verify one complete leaf and its authentication path against a previously constructed commitment | Proofs/s |
| `open` | Extract one authentication path, allocate the result, and drop it | Proofs/s |
| `open_into` | Extract one authentication path into a preallocated buffer | Proofs/s |
| `hash_leaf_u32` | Hash one canonically encoded u32 leaf | Leaf payload bytes/s |
| `hash_nodes` | Compress one pair of 32-byte digests using the selected construction | Digest payload bytes/s |

Criterion prints `elem/s` for verification and extraction; one element means one
opened leaf, not one field element. Commit throughput counts `4N` input bytes,
excluding intermediate digests, allocations, and memory traffic. Latency is
reported for every benchmark. To express commit throughput in field elements/s,
divide bytes/s by four.

Initial tree construction for queries, matrix generation, proof preparation, and
proof-buffer reservation are outside timed regions. Both commitment benchmarks
include fresh digest-layer allocation and deallocation. Inputs and outputs pass
through `black_box`. Allocation reuse and multiproofs were removed to keep the
baseline focused on Plonky3's ordinary tree construction and individual openings.

Verification cycles over 256 deterministic paths, or all leaves when fewer than
256 exist. Those paths are prepared once, so this is a warm-fixture verification
benchmark with no proof parsing, networking, or tree reads. Both extraction
benchmarks walk an odd-stride permutation of all leaf indices; they do not
repeatedly extract just the leftmost path. These measure sequential query handling.

## Comparing with pinned upstream Plonky3

`commit_plonky3` calls the unmodified `p3-merkle-tree` 0.6.3 implementation with a
single borrowed byte matrix, binary arity, scalar packing, and exactly the same
leaf hasher and parent compressor as `commit`. The byte matrix has `4W` columns,
encoding each u32 in little-endian order. SHA-256 uses Plonky3's SHA-256 hasher
and raw one-block `Sha256Compress`; BLAKE3 uses Plonky3's BLAKE3 hasher with
`CompressionFunctionFromHasher`; SHA3-256 uses our NIST SHA3-256 adapter on both
sides. No leaf or parent domain prefix is present.

On little-endian hosts, both paths borrow the original u32 allocation without
copying its bytes. Upstream retains a matrix view plus small general-purpose
metadata allocations; the simplified implementation retains only digest layers.
Both include their own tree allocations and drop costs. Upstream's construction
supports multiple matrices and mixed heights; its extra bookkeeping is part of
the reference measurement. This comparison measures the effect of simplifying
the same construction. It does not compare with every Plonky3 hash, field, packing,
or MMCS configuration.

On big-endian hosts, `commit_plonky3` prepares canonical bytes outside timing,
whereas `commit` includes u32 conversion. Do not interpret their latency ratio as
a matched implementation comparison there without moving both to pre-encoded
byte inputs. The hash microbenchmarks continue to include canonical u32 encoding.

For example, compare both implementations on the same matrix shapes and pool:

```sh
RAYON_NUM_THREADS=4 MERKLE_TOTAL_LOGS=20 MERKLE_WIDTH_LOGS=0,8,14 \
  cargo bench --bench merkle -- '^commit(_plonky3)?/sha256/'
```

The standalone tree's verification and proof-extraction benchmarks have no
upstream timing counterpart; agreement with upstream roots is a correctness
check, not a claim about upstream verification speed.

## Selecting workloads

`MERKLE_TOTAL_LOGS` and `MERKLE_WIDTH_LOGS` accept comma-separated base-two
exponents. Valid ranges are 20–26 and 0–14, respectively. They form a Cartesian
product. A Criterion regex selects operations, hashes, and individual shapes.
Matrix and tree fixtures are initialized lazily, so selecting one case does not
construct the other trees.

```sh
# All commit sizes at a fixed 256-element row width, for SHA-256 only.
MERKLE_TOTAL_LOGS=20,21,22,23,24,25,26 MERKLE_WIDTH_LOGS=8 \
  cargo bench --bench merkle -- '^commit/sha256/'

# Verification for small and large matrices across selected row widths.
MERKLE_TOTAL_LOGS=20,26 MERKLE_WIDTH_LOGS=0,4,8,14 \
  cargo bench --bench merkle -- '^verify/'

# All requested shapes: 7 totals × 15 widths × 3 hashes × 5 operations.
MERKLE_FULL=1 cargo bench --bench merkle

# A quick correctness and timing smoke check, without Criterion statistics.
cargo run --release --example smoke -- 20 8

# Exercise every registered default benchmark once, without timing analysis.
cargo bench --bench merkle -- --test
```

Explicit exponent lists override the corresponding `MERKLE_FULL=1` defaults.
The full sweep is an extended experiment, not a normal development check. At
`N = 2^26`, `W = 1`, digest layers occupy approximately 4 GiB and input takes
256 MiB, plus allocator and runtime overhead. A benchmark keeps at most one tree
fixture alive at a time; a timed commitment does not coexist with another tree
fixture. Avoid configurations that cause swapping. Wider leaves reduce digest
storage in inverse proportion to `W`.

## Parallelism and repeatability

The default `parallel` Cargo feature enables Plonky3's `p3-maybe-rayon` parallel
iterators for both tree implementations. `RAYON_NUM_THREADS` fixes the pool size.
Use `--no-default-features` to select the sequential iterator implementation on
both sides; a one-thread Rayon pool still measures parallel-iterator scheduling.
The old `MERKLE_PARALLEL` runtime switch is no longer supported.

```sh
cargo bench --no-default-features --bench merkle -- '^commit(_plonky3)?/'
RAYON_NUM_THREADS=4 cargo bench --bench merkle -- '^commit(_plonky3)?/'
```

Use the same feature flags and thread count before and after a code change.
Benchmark names deliberately stay stable across parallelism changes, so keep
baselines distinct. Record the CPU, OS, Rust version, feature flags, thread count,
exponent lists, dependency lockfile, and compiler flags alongside results. Use a
quiet machine, avoid thermal throttling, and run both sides with the same power
settings.

```sh
# Before making an optimization:
RAYON_NUM_THREADS=4 cargo bench --bench merkle -- \
  '^commit/sha256/' --save-baseline before

# After making it, with the same input, build flags, and thread settings:
RAYON_NUM_THREADS=4 cargo bench --bench merkle -- \
  '^commit/sha256/' --baseline before
```

Criterion writes estimates and comparison data under `target/criterion/`.
Increasing `--measurement-time` and `--sample-size` helps when differences are
small. A local experiment can use `RUSTFLAGS="-C target-cpu=native"` on both
sides; record that choice because those results depend on the host CPU. Previous
Criterion results from the tagged custom implementation are incompatible with
this construction: use fresh baseline names.

## Planning compression-call optimizations

For `L = N/W` leaves, a full binary tree performs `L` leaf hashes and `L - 1`
parent compressions. A single verification performs one leaf hash and `log2(L)`
parent compressions. Those counts are a starting point for attributing time, not
a count of internal compression-function calls: padding, backend block size, and
BLAKE3's internal tree affect the latter.

The `hash_leaf_u32` microbenchmarks use widths 1, 13, 14, 15, 16, 31, 32, 33, 34,
255, 256, 257, and 16,384 elements. SHA-256 changes from one padded block at width
13 to two at width 14; SHA3-256 crosses its 136-byte rate between widths 33 and
34; and BLAKE3 crosses a 1,024-byte chunk between widths 256 and 257. Leaf
messages have no extra prefix. `hash_nodes` isolates one fixed digest pair:
SHA-256 uses one raw compression call, while SHA3-256 and BLAKE3 perform ordinary
hashes of 64 bytes. Filter these independently:

```sh
cargo bench --bench merkle -- '^hash_(leaf_u32|nodes)/'
```

Keep root semantics and the security boundary explicit when changing the hash
construction. Compare commitment and verification separately: an improvement on
large leaves can disappear when parent hashing dominates, and a faster commitment
construction can make verification slower. For exact compression counts, add
backend instrumentation or use a documented analytical model in addition to
wall-clock measurements.
