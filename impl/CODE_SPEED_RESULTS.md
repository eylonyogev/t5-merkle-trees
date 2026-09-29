# SHA-256 leaf batching: implementation speedup

Standard SHA-256 commitments are **1.12–1.46× faster** in the measured
four-worker cases on this Apple M3. The change preserves the existing leaf
digests, parent compression, roots, proofs, and primitive-call counts.
It applies to `OptimizedMerkleTree` with `LeafMode::Standard`; it does not
accelerate the T5/T8/ABR-wide constructions or single-opening verification.

The implementation batches two independent leaf hashes through the existing
AArch64 SHA2 kernel. Each lane has its own standard IV and chaining state,
receives normal SHA-256 padding and length encoding, and emits big-endian words.
An odd last leaf uses the existing scalar hash. Scratch space is bounded,
with no per-batch heap allocation or new unsafe code. Runtime feature detection
selects this path only on little-endian AArch64 with SHA2; other targets retain
the previous scalar implementation. Other architectures were not benchmarked.

## Measurements

Measured on September 29, 2026: Apple M3, 8 cores, 24 GiB RAM,
macOS 27.0.1, Rust 1.96.0 / LLVM 22.1.2. Both executables used the same lockfile,
release profile (thin LTO, one codegen unit), default `parallel` feature, and
four Rayon workers, without custom `RUSTFLAGS`. The linker used the installed
Command Line Tools via `DEVELOPER_DIR=/Library/Developer/CommandLineTools`.

“Before” is the previously optimized implementation at
`cb64a21ea636bb99e5ea590782af74b2480f4a02`, rebuilt locally with the same toolchain.
“After” differs in `src/optimized_hash.rs` only. These comparisons do not reuse
the older M4 Max measurements in `LOWCALL_RESULTS.md`.

Each cell below is the median of four independent process medians. Each process
uses seven calibrated batch averages per case, targeting 300 ms per case.
Before/after process order alternates between passes; cases within a process
have fixed order. Processes run sequentially, with no concurrent builds or
tests. Fresh commits include digest allocation and destruction; matrix
generation is outside timing. Timing spread is not a confidence interval.

| Input | Bytes per leaf | Before (ms) | After (ms) | Speedup | Paired-run range |
| --- | ---: | ---: | ---: | ---: | ---: |
| 4 MiB | 4 | 14.282 | 10.641 | 1.34× | 1.33–1.38× |
| 4 MiB | 64 | 1.188 | 1.057 | 1.12× | 1.06–1.12× |
| 4 MiB | 256 | 0.653 | 0.552 | 1.18× | 1.17–1.19× |
| 4 MiB | 1,024 | 0.526 | 0.407 | 1.29× | 1.27–1.30× |
| 4 MiB | 65,536 | 0.491 | 0.337 | 1.46× | 1.45–1.73× |
| 64 MiB | 64 | 17.653 | 15.546 | 1.14× | 1.12–1.14× |
| 64 MiB | 256 | 9.317 | 7.551 | 1.23× | 1.23–1.24× |
| 64 MiB | 1,024 | 7.613 | 5.525 | 1.38× | 1.37–1.38× |
| 64 MiB | 65,536 | 7.026 | 4.821 | 1.46× | 1.45–1.46× |

The 64 MiB / 4-byte-leaf case exceeds the harness's 256 MiB digest-storage cap
and is skipped. Verification speedup ratios in this sweep are 0.996–1.002×;
the change does not affect that path.

A separate two-pass control sweep measures all three backends with standard,
T5, T8, and supported ABR-wide modes at 256-byte and 64 KiB leaves. Excluding
the intended standard SHA-256 commitment improvement, ratios are approximately
0.985–1.030×. Those small differences are not claimed as improvements.

Exploratory parent batching showed no consistent gain. Increasing the leaf-job
cap and parent-job size from 256 to 1,024 slowed several cases, so the final
change retains the original scheduling and parent implementation.

## Worker count

On this M3, eight workers are faster than four in the three additional sampled
cases. The table shows final-code commitment latency for 4 MiB inputs. One,
two, and eight workers use two process passes targeting 200 ms per case; the
four-worker row comes from the main sweep above. This is a local tuning result,
not a portable worker-count default.

| Workers | 4-byte leaves (ms) | 256-byte leaves (ms) | 64 KiB leaves (ms) |
| ---: | ---: | ---: | ---: |
| 1 | 37.075 | 1.752 | 1.111 |
| 2 | 19.278 | 0.940 | 0.589 |
| 4 | 10.641 | 0.552 | 0.337 |
| 8 | 8.406 | 0.468 | 0.256 |

Set `RAYON_NUM_THREADS=8` before starting the program to use that worker count.
The leaf-batching change also improves all sampled one-, two-, and eight-worker
cases compared with the old executable at the same worker count.
Raw CSVs and adjacent JSON metadata are saved for
[one](results/code-speed-workers-1.csv),
[two](results/code-speed-workers-2.csv), and
[eight](results/code-speed-workers-8.csv) workers. Reproduce these with
`--threads 1` (or `2`/`8`) plus `--widths 0,6,14 --totals 20
--operations commit --runs 2 --ms 200`.

## Validation and reproduction

Both the default parallel build and `--no-default-features` pass all 76 unit
and integration tests plus one doctest. Existing differential tests cover
SHA-256 padding boundaries, multiple blocks, empty and odd batches, all paths
in small trees, parallel chunk boundaries, recommits, and upstream Plonky3
compatibility. Formatting and Clippy also pass:

```sh
cargo fmt --manifest-path impl/Cargo.toml --check
cargo test --release --locked --manifest-path impl/Cargo.toml
cargo test --release --locked --manifest-path impl/Cargo.toml --no-default-features
cargo clippy --release --locked --manifest-path impl/Cargo.toml --all-targets --all-features -- -D warnings
```

Build `perf_sweep` separately at the before revision and in the final working
tree, using identical Rust 1.96.0 toolchains and build settings:

```sh
cargo build --release --locked --manifest-path impl/Cargo.toml --example perf_sweep
```

Save the two executables under distinct paths, then run the checked-in runner:

```sh
python3 impl/scripts/compare_binaries.py \
  --before /tmp/t5-before --after /tmp/t5-after \
  --output /tmp/code-speed-sha256 --cpu-model 'your CPU model'
```

The defaults reproduce the main sweep, including four workers and four passes.
For the control sweep add `--hashes sha256,sha3_256,blake3
--schemes standard,t5,t8,abr-wide --widths 6,14 --totals 20 --runs 2 --ms 180`.
Width and total exponents count `u32` elements, so leaf bytes are
`4 * 2^width_log` and input bytes are `4 * 2^total_log`.

Raw results: [main CSV](results/code-speed-sha256.csv),
[main protocol](results/code-speed-sha256.json),
[control CSV](results/code-speed-controls.csv),
[control protocol](results/code-speed-controls.json), and
[source, toolchain and executable fingerprints](results/code-speed-source.json).
