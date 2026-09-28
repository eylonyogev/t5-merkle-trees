# Experimental leaf optimization pass

This pass adds native SHA-256 instruction interleaving, fused T253 and BLAKE3 T8 kernels, four-message BLAKE3 NEON, cross-stage batching for single-leaf verification, direct SHA3 state packing, and task sizes that keep SIMD lanes populated. Compression roles, padding, leaf digests and Merkle roots are unchanged. The optimized `standard` tree remains the comparison point.

Measured on arm64 macOS with four Rayon threads, the gains are substantial in some cases. Improving an experimental implementation does not mean that it beats standard hashing. At `2^26` elements and 16,384 u32 per leaf:

- **SHA-256 T253:** commit 16.22 ms versus 26.04 ms standard (**1.61×**); verification 15.46 µs versus 23.65 µs (**1.53×**).
- **BLAKE3 T8:** commit 22.77 ms versus 28.78 ms standard (**1.26×**); verification 33.00 µs versus 27.88 µs (**0.84×**).
- **SHA3-256 T8:** commit 62.33 ms versus 34.47 ms standard (**0.55×**); verification 62.99 µs versus 67.41 µs (**1.07×**).

T5 is faster than its previous implementation on the measured wide-leaf cases, but still loses to optimized standard hashing. Its concrete native call count is higher for all three backends. No experimental mode wins on every measured shape and operation.

[New comparison and before/after plots](results/newpass-plots/README.md) include the negative results. The [earlier report](RESULTS.md) and [earlier plots](results/plots/README.md) remain historical records.

## Improvement from this implementation pass

These rows compare each experimental construction with its own previous implementation at `N=2^20`, width 16,384 u32 (64 KiB per leaf). They do **not** use standard hashing as the denominator.

| Hash / construction | Before commit ms | After commit ms | Commit gain | Before verify µs | After verify µs | Verify gain |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| SHA-256 T5 | 0.648 | 0.605 | 1.07× | 36.015 | 31.693 | 1.14× |
| SHA-256 T8 | 0.723 | 0.622 | 1.16× | 42.339 | 35.402 | 1.20× |
| SHA-256 T253 | 0.325 | 0.271 | 1.20× | 18.188 | 14.770 | 1.23× |
| SHA3-256 T5 | 1.896 | 1.729 | 1.10× | 154.098 | 104.338 | 1.48× |
| SHA3-256 T8 | 1.110 | 0.995 | 1.12× | 88.277 | 62.508 | 1.41× |
| BLAKE3 T5 | 1.263 | 0.758 | 1.67× | 76.793 | 55.614 | 1.38× |
| BLAKE3 T8 | 0.741 | 0.384 | 1.93× | 44.290 | 32.305 | 1.37× |

## Comparison with optimized standard

The larger input has `2^26` u32 elements (256 MiB). Speedup is standard time divided by experimental time: below 1× means the experimental construction is slower. Each backend uses the standard measurements from the same binary and sweep.

| Hash / construction | u32 / leaf | Commit ms | vs standard | Verify µs | vs standard |
| --- | ---: | ---: | ---: | ---: | ---: |
| SHA-256 T5 | 256 | 36.413 | 0.75× | 1.067 | 0.85× |
| SHA-256 T5 | 16,384 | 34.795 | 0.75× | 33.274 | 0.71× |
| SHA-256 T8 | 256 | 43.877 | 0.62× | 1.204 | 0.75× |
| SHA-256 T8 | 16,384 | 38.478 | 0.68× | 37.105 | 0.64× |
| SHA-256 T253 | 256 | 18.291 | 1.48× | 0.782 | 1.16× |
| SHA-256 T253 | 16,384 | 16.217 | 1.61× | 15.461 | 1.53× |
| SHA3-256 T5 | 256 | 112.781 | 0.36× | 4.163 | 0.83× |
| SHA3-256 T5 | 16,384 | 107.842 | 0.32× | 105.026 | 0.64× |
| SHA3-256 T8 | 256 | 73.140 | 0.56× | 3.870 | 0.89× |
| SHA3-256 T8 | 16,384 | 62.326 | 0.55× | 62.993 | 1.07× |
| BLAKE3 T5 | 256 | 48.441 | 0.59× | 1.895 | 0.95× |
| BLAKE3 T5 | 16,384 | 46.046 | 0.63× | 55.683 | 0.50× |
| BLAKE3 T8 | 256 | 27.234 | 1.04× | 1.627 | 1.11× |
| BLAKE3 T8 | 16,384 | 22.768 | 1.26× | 33.002 | 0.84× |

A 1.26× speedup means about 21% less elapsed time. BLAKE3 T8 now wins commitment at the measured medium and wide widths, while its wide-leaf verification still loses to standard BLAKE3. SHA3 T8's approximately 7% wide-leaf verification gain is modest; its commitment remains slower.

Native calls per 64 KiB leaf, unchanged by this pass:

| Backend | Standard | T5 | T8 | T253 |
| --- | ---: | ---: | ---: | ---: |
| SHA-256 compressions | 1,025 | 1,536 | 1,758 | 890 |
| SHA3 permutations | 482 | 1,536 | 879 | — |
| BLAKE3 compressions | 1,087 | 1,536 | 879 | — |

The upper binary tree is common to all modes. Kernel scheduling and SIMD change time per logical call; they do not change these analytical counts.

## Direct-leaf confirmation

The longer Criterion run confirms the wide-leaf results without tree allocation or parallel task scheduling. Selected final leaf-only timings (64 KiB), with Criterion's individual 95% intervals:

| Backend / mode | Leaf µs [95% interval] | Speedup vs standard |
| --- | ---: | ---: |
| SHA-256 standard | 22.843 [22.606, 23.308] | 1.00× |
| SHA-256 T253 | 14.549 [14.451, 14.664] | 1.57× |
| SHA3-256 standard | 65.929 [65.662, 66.220] | 1.00× |
| SHA3-256 T8 | 61.490 [61.326, 61.720] | 1.07× |
| BLAKE3 standard | 26.358 [26.267, 26.536] | 1.00× |
| BLAKE3 T8 | 31.323 [31.186, 31.423] | 0.84× |

Full direct-leaf data: [before](results/newpass-leaf-before.csv) and [after](results/newpass-leaf-after.csv). The intervals do not describe the speedup ratio or variability across independent runs.

## Data and source provenance

The final report uses [before N20](results/newpass-before.csv), [after N20](results/newpass-after.csv), and [after N26](results/newpass-scaling.csv). The complete before/after N20 grids contain 192 rows each; N26 has 64 rows. Every supported mode is retained, including fixed-MD and ABR3, even though the plots focus on the requested T5/T8/T253.

A final small-record BLAKE3 correction was measured separately after the first full sweep. SHA-256 and SHA3 rows retain the validated full-sweep binary; all BLAKE3 rows, including its standard reference, come from the corrected binary. The [final metadata](results/newpass-after-metadata.txt) records exact commands and per-backend binary/source provenance. The complete pre-correction snapshots remain under `*-before-short-fix.*`. No unmeasured timings or interpolated values are inserted.

The initial three-width snapshot and intermediate candidate sweeps remain available under `newpass-before-initial.*` and `newpass-candidate*.csv`. These document discarded regressions and tuning, but are not used for final ratios.

The final scalar path for single-stage BLAKE3 T8 removed a reproducible short-leaf verification regression: at width 16, the old implementation took 1.083 µs, the pre-correction implementation 1.140 µs, and the corrected implementation 1.050 µs. The corresponding corrected standard reference was 0.967 µs.

Small changes deserve caution. The unchanged SHA-256 standard one-element commitment initially moved by 7%, then by only 1% in a longer focused rerun. A suspected SHA-256 fixed-MD short-verification regression disappeared in that rerun. Such fluctuations are why the report distinguishes large sustained gains from small differences near 1×.

## Measurement protocol

The before-pass release `perf_sweep` and Criterion executables were copied
before source edits. Their SHA-256 digests, the corresponding source digests,
Cargo lockfile digest, git revision, and Rust version are recorded in
[before metadata](results/newpass-before-metadata.txt). Measurements use arm64
macOS, four Rayon threads, the default parallel feature, thin LTO and one
codegen unit, with no custom compiler flags.

The matrix sweep measures fresh commitment, including digest allocation and
deallocation, and complete single-opening verification, including leaf
hashing. Deterministic input generation and preparation of up to 256 proof
paths are outside timing. Every prepared opening is verified; standard roots
are checked against the pinned Plonky3 adaptation.

Each matrix point is the median of seven timed batch averages, targeting
150 ms total per point. Raw CSV also records batch-average p10/p90, iterations,
shape, memory payload and analytical native compression counts. Before and
after sweeps run separately and cases run in fixed order: frequency, thermal
state and background work can move timings. Small differences near 1× should
not be interpreted as established improvements. The plots have no ratio
confidence intervals.

Direct-leaf Criterion timings exclude `LeafPlan` creation and measure only
hashing. Each uses ten samples, 200 ms warmup and at least one second of
measurement. CSV contains the regression-slope estimate, or mean when
Criterion selects flat sampling, and its 95% confidence interval. Those
intervals describe individual estimates, not the ratio or variability across
independent runs.

## Reproduction

From `impl/`, after building the desired source version:

```sh
cargo build --release --locked --example perf_sweep --bench optimized

RAYON_NUM_THREADS=4 MERKLE_TOTAL_LOGS=20 MERKLE_WIDTH_LOGS=0,4,6,8,10,14 \
  MERKLE_SCHEMES=standard,fixed-md,t5,t8,abr3,t253 \
  MERKLE_SWEEP_MS=150 MERKLE_SWEEP_SAMPLES=7 \
  target/release/examples/perf_sweep > newpass-after.csv

RAYON_NUM_THREADS=4 MERKLE_TOTAL_LOGS=26 MERKLE_WIDTH_LOGS=8,14 \
  MERKLE_SCHEMES=standard,fixed-md,t5,t8,abr3,t253 \
  MERKLE_SWEEP_MS=150 MERKLE_SWEEP_SAMPLES=7 \
  target/release/examples/perf_sweep > newpass-scaling.csv

RAYON_NUM_THREADS=4 MERKLE_OPERATIONS=leaf MERKLE_SCHEMES=standard,t5,t8,t253 \
  cargo bench --locked --bench optimized -- \
  '^experiment_leaf/(sha256|sha3_256|blake3)/(standard|t5|t8|t253)/u32_(64|16384)$' \
  --save-baseline newpass-after
```

From the repository root, regenerate plots from checked-in CSV:

```sh
uv run impl/scripts/plot_newpass.py
```

[EXPERIMENTS.md](EXPERIMENTS.md) defines the constructions and their security
scope. Fewer abstract calls do not necessarily mean fewer native compression
calls, and fewer native calls do not ensure faster execution. In particular,
SHA-256 T8's domain-separated wide oracle requires two native compressions,
and SHA3's ordinary sponge absorbs more input per permutation than the
experimental adapters.

## Validation

The frozen source passed 59 tests plus one doctest with default features and
again with `--no-default-features` ([validation log](results/newpass-validation.txt)): 29 unit tests, 11 independent reference
tests, three compatibility tests, 13 optimized tree tests, and three Plonky3
conformance tests. The compatibility corpus includes 640 digests generated by
the previous implementation, including construction boundaries and partial
stages. New primitive kernels are compared against independent scalar
compression routines; paired and batched leaf outputs are checked against
single-leaf outputs.

All-target/all-feature Clippy passes with warnings denied, and formatting
checks pass. A separate build forces the Keccak software backend and passes
all 16 compatibility and optimized tree tests:

```sh
RUSTFLAGS='--cfg keccak_backend="soft"' \
  CARGO_TARGET_DIR=/private/tmp/merkle-experimental-optimization-pass/keccak-soft \
  cargo test --locked --offline --test leaf_compatibility --test optimized
```

Performance was measured only on arm64 macOS. The portable fallback tests do
not constitute x86 performance measurements.
