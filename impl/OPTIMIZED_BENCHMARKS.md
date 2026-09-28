# Optimization experiment protocol

The original [Plonky3 benchmark](BENCHMARKS.md) and [recorded baseline](BASELINE.md)
remain unchanged. `benches/optimized.rs` and `examples/perf_sweep.rs` compare the
same local Plonky3 adaptation with the optimized tree and experimental leaf
constructions. The baseline and optimized `standard` mode have identical roots.
Other modes define different leaf hash functions and therefore different roots.

The comparison uses the same deterministic, nonconstant, row-major u32 input,
little-endian encoding, width, binary upper tree, and 32-byte authentication
paths. Input generation is outside timing. Commit measurements include fresh
tree allocation and deallocation; they do not retain a second tree fixture.
Verification measures complete leaf hashing plus the ordinary authentication
path. Byte verification and little-endian u32 verification allocate nothing;
on big-endian hosts the optimized u32 adapter allocates canonical bytes inside
timing. Verification rotates through 256 prepared
paths, or all paths for smaller trees. These are warm fixtures without parsing,
networking, or proof extraction costs.

## Short CSV sweep

Run from `impl/`:

```sh
RAYON_NUM_THREADS=4 cargo run --release --locked --example perf_sweep > sweep.csv
```

The default sweep covers `2^20` elements, widths `1,16,64,256,1024,16384`, all
three hashes, the unchanged baseline, and all supported experimental modes.
Each case produces separate commit and verify rows. Status and metadata are
printed to stderr, keeping stdout valid CSV. Unsupported mode/backend pairs
are skipped with an explanation.

Each operation is calibrated outside measurement, then sampled in five timed
batches. The default target is 80 ms per operation across those batches. Slow
operations still receive five samples, so this is a target rather than a strict
time limit. Rows contain median, interpolated 10th and 90th percentiles, sample
count, and iterations per sample. These percentiles describe the small set of
batch averages; they are not confidence intervals or individual-operation tail
latencies. Treat small differences as provisional and confirm them with
Criterion and repeated independent runs.

Useful controls:

| Environment variable | Default | Meaning |
| --- | --- | --- |
| `MERKLE_TOTAL_LOGS` | `20` | Comma-separated exponents for element count; 0–26 accepted for small smoke runs |
| `MERKLE_WIDTH_LOGS` | `0,4,6,8,10,14` | Comma-separated exponents for elements per leaf, 0–14 |
| `MERKLE_HASHES` | `sha256,sha3_256,blake3` | Hash backend filter |
| `MERKLE_SCHEMES` | All | `baseline,standard,fixed-md,t5,t8,abr3,t253,abr-wide,t277,shake128,sponge-dm272` |
| `MERKLE_OPERATIONS` | `commit,verify` | Operation filter |
| `MERKLE_SWEEP_MS` | `80` | Target measured milliseconds per operation |
| `MERKLE_SWEEP_SAMPLES` | `5` | Number of batches; minimum five |
| `MERKLE_MAX_DIGEST_MIB` | `256` | Skip shapes whose tree digest payload exceeds this limit |
| `MERKLE_ALLOW_LARGE` | `0` | Explicitly override the digest memory guard |
| `MERKLE_FULL` | `0` | Default to all total exponents 20–26 and width exponents 0–14 |

Explicit exponent lists override `MERKLE_FULL` defaults. Widths exceeding the
total element count are skipped. The memory guard excludes input storage and
allocator/runtime overhead; it is not an operating-system memory limit. The
largest requested shape, `N=2^26,W=1`, requires approximately 4 GiB of digest
storage plus 256 MiB of input, and is never run by default.

```sh
# Main comparison at the paper's eight-block record size and neighboring widths.
RAYON_NUM_THREADS=4 MERKLE_TOTAL_LOGS=20 MERKLE_WIDTH_LOGS=4,6,8,14 \
  cargo run --release --locked --example perf_sweep > representative.csv

# Scaling up to the largest input while keeping tree memory bounded.
RAYON_NUM_THREADS=4 MERKLE_TOTAL_LOGS=20,24,26 MERKLE_WIDTH_LOGS=8,14 \
  MERKLE_OPERATIONS=commit cargo run --release --locked --example perf_sweep > scaling.csv

# Higher precision for the same-root implementation comparison.
RAYON_NUM_THREADS=4 MERKLE_SCHEMES=baseline,standard MERKLE_SWEEP_MS=500 \
  MERKLE_SWEEP_SAMPLES=15 cargo run --release --locked --example perf_sweep > standard.csv

# Full requested grid, subject to the default memory guard.
RAYON_NUM_THREADS=4 MERKLE_FULL=1 \
  cargo run --release --locked --example perf_sweep > full.csv
```

The sweep runs the baseline first, followed by modes in `LeafMode::ALL` order,
within each shape. This keeps the input and shape comparable but does not
randomize away thermal drift. Repeat focused comparisons on a quiet machine,
and use independent runs when effects are small. The output records compiled
architecture, OS, parallel feature, and requested Rayon thread count on stderr;
record CPU model, Rust version, git revision, `Cargo.lock`, power state, and
`RUSTFLAGS` with published measurements. Do not compare runs with different
thread pools or compiler target features without labeling them.

## Counts and interpretation

CSV includes two distinct work counts:

- `native_calls`: the analytical number of SHA-256 compression calls, Keccak
  permutations, or BLAKE3 compression calls for the selected backend and mode.
  A commit is `leaves * native_leaf_calls + leaves - 1`; verification is
  `native_leaf_calls + log2(leaves)`. Each unchanged upper-tree parent requires
  one native call with these backends.
- `abstract_leaf_calls`: the leaf construction's abstract compression calls,
  summed over all leaves for commitment or one leaf for verification. Zero for
  ordinary standard hashing, including the short-input fallback of `t253`, means
  “not applicable”; it does not mean the hash
  performs no work. The common upper tree is excluded from this column.

Counts are a documented analytical model, not hardware performance counters.

The new `abr-wide` mode is supported by SHA-256 and BLAKE3; `t277` by
BLAKE3; `shake128` and `sponge-dm272` by the SHA3 backend. Each still uses
the original binary parent function for its backend. New public-width plans
are prepared outside hashing, just like the existing leaf plans. Unsupported
mode/backend pairs are rejected or skipped by the benchmark harness.

For the selected least-call candidates, `scripts/run_lowcall.py` runs backend
processes sequentially and records source/binary SHA-256 fingerprints, compiler
version, environment, exact commands and raw batch timing percentiles alongside
each CSV. It never overlaps benchmark jobs. See [LOWCALL_RESULTS.md](LOWCALL_RESULTS.md)
for the measured implementation and reproduction commands.

SIMD batching changes elapsed time without changing these logical counts.
Calls to different primitives, or different roles within a construction, need
not cost the same. In particular, fewer calls to an abstract wide compression
function can still require more native hash work than standard SHA3 or BLAKE3.
Wall-clock latency determines whether a construction wins on a given shape.

`matrix_bytes` is always the entire input allocation. `operation_input_bytes`
is the full matrix for commit and one disclosed leaf for verify. Digest payload
and authentication path bytes are reported separately. Compare like-for-like
rows: hash, total count, width, operation, thread pool, and compiler flags must
match. Throughput is `operation_input_bytes / time`; a single verification is
one opened row, not one field element.

## Criterion confirmation and natural record widths

```sh
RAYON_NUM_THREADS=4 MERKLE_WIDTH_LOGS=6,8,14 \
  cargo bench --locked --bench optimized -- '^experiment_(commit|verify)/sha256/'

# Same-root implementation comparison for every backend.
RAYON_NUM_THREADS=4 MERKLE_SCHEMES=baseline,standard \
  cargo bench --locked --bench optimized -- '^experiment_(commit|verify)/'

# Direct leaf hash timings, including natural paper dimensions.
RAYON_NUM_THREADS=4 cargo bench --locked --bench optimized -- '^experiment_leaf/'

# Build/run all selected benchmark cases once, without timing analysis.
MERKLE_TOTAL_LOGS=12 MERKLE_WIDTH_LOGS=0,4,6,8,10 \
  cargo bench --locked --bench optimized -- --test
```

Criterion defaults to ten samples, 200 ms warmup, and one second of measurement.
Filters keep expensive fixtures lazy. The new harness shares hash, scheme,
shape, and memory controls with the sweep. Its `MERKLE_OPERATIONS` additionally
accepts `leaf` for direct leaf microbenchmarks. Leaf microbenchmarks use widths
`1,16,40,64,88,256,16384`: 40 u32 elements form the five-block T5 input, 64 form
the eight-block T8 input, and 88 form the eleven-block ABR3 input. Matrix sweeps
retain the user's requested power-of-two widths. Planning, input generation,
and canonical encoding are outside direct leaf timing; hashing is inside it.

Use `--no-default-features` for serial iterators, or `RAYON_NUM_THREADS=1` to
measure a one-thread parallel runtime. Both are useful and have different
scheduling costs. Keep original baseline results under separate Criterion
baseline names; the original `merkle` harness remains available to compare the
unchanged local tree directly with pinned upstream Plonky3.
