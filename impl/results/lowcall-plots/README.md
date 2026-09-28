# Implemented low-call constructions: measured results

These figures compare each implemented leaf mode with the **optimized standard tree of the same backend**. Both use the same binary-parent implementation. Roots change when a nonstandard leaf mode is selected. SHAKE128 is the standard XOF with a 32-byte output.

Speedup is `standard median_ns / variant median_ns`; values below 1× are slower. Timing ratios are measured performance, not ratios of compression counts. No measured cases, including regressions, are omitted.

Environment: Apple M4 Max, arm64 macOS, four Rayon threads for commitment. Verification measures one complete leaf opening. Each case has seven calibrated batch samples targeting 150 ms total sampling; calibration and integer batch sizes can change the actual duration. Sweeps use fixed case order. No confidence intervals are inferred from percentile bands; small ratios near 1× can reflect measurement noise.

## Figures and source data

- [N = 2²⁰, 4 MiB: all 15 widths](vs-optimized-n20.png) ([SVG](vs-optimized-n20.svg)); [300 timing rows](../lowcall-n20.csv).
- [N = 2²⁴, 64 MiB](vs-optimized-n24.png) ([SVG](vs-optimized-n24.svg)).
- [N = 2²⁶, 256 MiB](vs-optimized-n26.png) ([SVG](vs-optimized-n26.svg)); [160 timing rows across both larger sizes](../lowcall-scaling.csv).
- [Exact timing and native-call ratios](lowcall-ratios.csv).

Dashed colored series are the prior T253/T8 comparisons. Hollow T253 markers use its standard-hash fallback below 253 bytes. The horizontal dashed line is 1×.

## Representative 256 MiB matrices

Times below are medians; displayed speedups are rounded, while the CSV retains the full computed ratio. Counts are logical native calls, regardless of SIMD batching. SHA-256/BLAKE3 count compression calls; the Keccak backend counts full 24-round permutations. These primitive counts are not interchangeable measures of CPU cost.

### 256 u32 elements per leaf (1,024 bytes)

| Backend | Leaf mode | Calls / leaf | Commit (ms) | Commit speedup | Verify (µs) | Verify speedup |
|---|---|---:|---:|---:|---:|---:|
| SHA-256 | Optimized standard | 17 | 27.4872 | 1.000× | 0.8686 | 1.000× |
| SHA-256 | T253 (previous) | 14 | 18.3854 | 1.495× | 0.7538 | 1.152× |
| SHA-256 | ABR-wide | 14 | 17.2489 | 1.594× | 0.7344 | 1.183× |
| BLAKE3 | Optimized standard | 16 | 28.6107 | 1.000× | 1.7949 | 1.000× |
| BLAKE3 | T8 (previous) | 15 | 27.2233 | 1.051× | 1.6255 | 1.104× |
| BLAKE3 | T277 | 13 | 25.7690 | 1.110× | 1.8348 | 0.978× |
| BLAKE3 | ABR-wide | 13 | 26.1418 | 1.094× | 1.7921 | 1.002× |
| Keccak / SHA3-256 | Optimized standard | 8 | 41.0453 | 1.000× | 3.4389 | 1.000× |
| Keccak / SHA3-256 | SHAKE128 | 7 | 36.9129 | 1.112× | 3.3725 | 1.020× |
| Keccak / SHA3-256 | SPONGE-DM272 | 7 | 38.6407 | 1.062× | 3.4508 | 0.997× |

### 16,384 u32 elements per leaf (65,536 bytes)

| Backend | Leaf mode | Calls / leaf | Commit (ms) | Commit speedup | Verify (µs) | Verify speedup |
|---|---|---:|---:|---:|---:|---:|
| SHA-256 | Optimized standard | 1,025 | 25.9592 | 1.000× | 22.5407 | 1.000× |
| SHA-256 | T253 (previous) | 890 | 16.1773 | 1.605× | 15.1536 | 1.487× |
| SHA-256 | ABR-wide | 854 | 14.3000 | 1.815× | 14.2999 | 1.576× |
| BLAKE3 | Optimized standard | 1,087 | 28.8421 | 1.000× | 27.9560 | 1.000× |
| BLAKE3 | T8 (previous) | 879 | 22.8014 | 1.265× | 33.4078 | 0.837× |
| BLAKE3 | T277 | 803 | 21.4327 | 1.346× | 30.0732 | 0.930× |
| BLAKE3 | ABR-wide | 774 | 20.6110 | 1.399× | 25.5104 | 1.096× |
| Keccak / SHA3-256 | Optimized standard | 482 | 34.6345 | 1.000× | 65.9552 | 1.000× |
| Keccak / SHA3-256 | SHAKE128 | 391 | 27.7976 | 1.246× | 55.5203 | 1.188× |
| Keccak / SHA3-256 | SPONGE-DM272 | 395 | 29.2745 | 1.183× | 58.2446 | 1.132× |

For L leaves and c native calls per leaf, full commitment uses `L*c + L - 1` calls and one verification uses `c + log2(L)`. The exact operation counts, including all binary parents, are in the ratio CSV.

## Validation and reproduction

```sh
uv run impl/scripts/plot_lowcall.py
```

The generator checks unique complete grids (10 backend/mode combinations, two operations, 15 widths at N20; four widths at each of N24/N26), finite positive timings, percentile ordering, seven samples, matrix geometry, matching comparators, standard-hash native counts, and identical per-leaf counts across commit/verify and matrix sizes. It does not rerun benchmarks.

Validated 460 raw timings and exported 322 variant/comparator ratios. Rendered using Matplotlib 3.10.9.

[Construction definitions and security distinctions](../../NEXT_CONSTRUCTIONS.md) remain separate from these performance measurements. Lower counts and successful correctness tests are not cryptographic security proofs.
