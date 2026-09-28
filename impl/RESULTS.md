# Optimization measurements

The root-compatible `standard` optimized tree committed faster than the unchanged
Plonky3 adaptation in all 24 final sampled hash/shape combinations: **1.11–1.47×
for SHA-256, 2.05–2.39× for SHA3-256, and 1.99–2.92× for BLAKE3**. These are
measured local medians, not a claim about every requested shape or platform.
Selected longer Criterion measurements confirm the commitment gains.
Verification gains depend on the hash and width; wide standard leaves often
leave verification approximately unchanged.

The SHA-256-specific `t253` construction added commitment and verification gains
on wide leaves compared with the already optimized standard tree. Generic T5,
T8, and ABR3 did not beat optimized standard commitment in this sweep, including
the final SIMD batching of experimental SHA3 calls. Both positive and negative
results are retained: fewer abstract oracle calls need not mean less native
work or lower latency.

## Method and scope

- arm64 macOS, Rust 1.96.0 (`ac68faa20`, 2026-05-25), default parallel feature,
  four Rayon threads, thin LTO, one codegen unit, no custom compiler flags.
- Baseline: the unchanged single-matrix Plonky3 0.6.3 adaptation in this repo,
  scalar byte packing and original leaf-hasher adapter. This experiment does
  not time a second direct upstream implementation. [BASELINE.md](BASELINE.md)
  records the earlier direct comparison with pinned upstream and its scope.
- Identical deterministic u32 input and matrix shape; fresh tree allocation and
  deallocation are timed. Input generation is outside timing.
- Single verification discloses the complete leaf and cycles through up to 256
  prepared paths. Proof extraction and parsing are outside timing.
- Final sweeps: seven batch-average samples per operation, targeting 150 ms in
  total. Slow operations still receive seven samples. Sweep tables report the
  median. Raw CSV also contains 10th/90th percentiles and iterations per batch.
- Criterion confirmation: ten samples, 200 ms warmup, at least one second of
  measurement per case; regression-slope point estimate, or mean for flat
  sampling. The reported 95% intervals describe individual timing estimates,
  not the speedup ratio or variability across separate runs.
- Cases run in fixed order. Frequency, temperature, and background load can
  affect comparisons between runs. Small differences need more repetition;
  short sweeps have no statistical confidence intervals.

Final data: [representative CSV](results/representative-final.csv),
[representative metadata](results/representative-final.txt),
[scaling CSV](results/scaling-final.csv),
[scaling metadata](results/scaling-final.txt),
[Criterion estimates and 95% intervals](results/criterion-confirmation.csv), and
[Criterion log](results/criterion-confirmation.txt). Source snapshots and binary
SHA-256 digests are in the metadata. Earlier `*-initial.csv` files retain the
pre-SHA3-experimental-batching measurements for comparison; tables below use the
final files.

The final representative sweep covers `2^20` elements at widths
`1,16,64,256,1024,16384`, every hash, and every supported mode. Final scaling
covers `2^26` elements at widths `256,16384` with baseline, standard, T8, and
SHA-256 T253. Criterion confirms selected `2^20` cases at widths `64,16384`.
The full Cartesian grid was not run. The largest narrow-leaf shape remains
guarded because it needs approximately 4 GiB of digests plus 256 MiB of input.
No x86 measurements were performed.

## Root-compatible commitment

For `2^20` u32 elements (4 MiB), selected final sweep medians are:

| Hash | u32 / leaf | Baseline ms | Standard optimized ms | Speedup |
| --- | ---: | ---: | ---: | ---: |
| SHA-256 | 1 | 20.771 | 14.160 | 1.47× |
| SHA-256 | 64 | 0.776 | 0.587 | 1.32× |
| SHA-256 | 256 | 0.618 | 0.488 | 1.27× |
| SHA-256 | 16,384 | 0.497 | 0.423 | 1.18× |
| SHA3-256 | 1 | 92.387 | 38.661 | 2.39× |
| SHA3-256 | 64 | 2.226 | 0.980 | 2.27× |
| SHA3-256 | 256 | 1.548 | 0.742 | 2.09× |
| SHA3-256 | 16,384 | 1.198 | 0.557 | 2.15× |
| BLAKE3 | 1 | 45.270 | 22.548 | 2.01× |
| BLAKE3 | 64 | 1.481 | 0.614 | 2.41× |
| BLAKE3 | 256 | 1.118 | 0.513 | 2.18× |
| BLAKE3 | 16,384 | 0.988 | 0.467 | 2.12× |

For `2^26` u32 elements (256 MiB):

| Hash | u32 / leaf | Baseline ms | Standard optimized ms | Speedup |
| --- | ---: | ---: | ---: | ---: |
| SHA-256 | 256 | 33.624 | 27.533 | 1.22× |
| SHA-256 | 16,384 | 28.875 | 26.028 | 1.11× |
| SHA3-256 | 256 | 90.941 | 40.800 | 2.23× |
| SHA3-256 | 16,384 | 73.510 | 34.373 | 2.14× |
| BLAKE3 | 256 | 63.384 | 28.664 | 2.21× |
| BLAKE3 | 16,384 | 59.870 | 28.825 | 2.08× |

Speedup is baseline time divided by optimized time. Standard mode preserves
roots and authentication paths. Direct slice hashing, independent-message
SHA3/BLAKE3 batching, and tree scheduling/storage changes improve throughput
without reducing its native compression-call count.

The longer Criterion run confirms the same-root commitment result at `2^20`:

| Hash | u32 / leaf | Baseline ms [95% CI] | Standard ms [95% CI] | Speedup |
| --- | ---: | ---: | ---: | ---: |
| SHA-256 | 64 | 0.748 [0.744, 0.751] | 0.586 [0.585, 0.587] | 1.28× |
| SHA-256 | 16,384 | 0.500 [0.495, 0.503] | 0.424 [0.424, 0.426] | 1.18× |
| SHA3-256 | 64 | 2.233 [2.216, 2.267] | 0.997 [0.994, 1.002] | 2.24× |
| SHA3-256 | 16,384 | 1.197 [1.194, 1.201] | 0.557 [0.556, 0.558] | 2.15× |
| BLAKE3 | 64 | 1.461 [1.456, 1.466] | 0.605 [0.603, 0.608] | 2.41× |
| BLAKE3 | 16,384 | 0.975 [0.974, 0.976] | 0.463 [0.463, 0.463] | 2.11× |

## SHA-256 compression reduction

Comparing T253 with the already optimized standard tree isolates the leaf
construction's contribution while holding upper-tree implementation fixed.
T253 changes roots and requires its mode to be authenticated as protocol
context. See [EXPERIMENTS.md](EXPERIMENTS.md) for the exact construction,
encoding, domain separation, and research/security scope.

| Total u32 | u32 / leaf | Standard commit ms | T253 commit ms | Commit speedup | Standard verify µs | T253 verify µs | Verify speedup |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `2^20` | 64 | 0.587 | 0.554 | 1.06× | 0.499 | 0.512 | 0.97× |
| `2^20` | 256 | 0.488 | 0.401 | 1.22× | 0.705 | 0.632 | 1.11× |
| `2^20` | 1,024 | 0.448 | 0.352 | 1.27× | 1.695 | 1.356 | 1.25× |
| `2^20` | 16,384 | 0.423 | 0.324 | 1.31× | 22.726 | 16.786 | 1.35× |
| `2^26` | 256 | 27.533 | 22.377 | 1.23× | 0.889 | 0.826 | 1.08× |
| `2^26` | 16,384 | 26.028 | 19.324 | 1.35× | 22.700 | 17.177 | 1.32× |

At `2^26` elements and width 16,384, T253's 19.324 ms commit is
1.49× faster than the unchanged baseline's 28.875 ms; its
17.177 µs verification is 1.33× faster than the baseline's
22.771 µs. The table uses the stronger optimized-standard comparator.

Analytical native SHA-256 compression calls per leaf:

| u32 / leaf | Standard | T253 |
| --- | ---: | ---: |
| 64 | 5 | 4 |
| 256 | 17 | 14 |
| 1,024 | 65 | 56 |
| 16,384 | 1,025 | 890 |

For `L` leaves, the common upper tree adds `L-1` calls per commitment and
`log2(L)` per verification. Counts include the actual input-size handling.
SIMD, instruction overlap, encoding, and memory costs also affect elapsed time.
Short-leaf verification differences varied across runs; the wide-leaf gain was
consistent. Criterion's SHA-256 verification estimates at `2^20` were:

| u32 / leaf | Standard verify µs [95% CI] | T253 verify µs [95% CI] | Speedup |
| ---: | ---: | ---: | ---: |
| 64 | 0.555 [0.543, 0.561] | 0.500 [0.499, 0.501] | 1.11× |
| 16,384 | 22.545 [22.488, 22.608] | 17.211 [17.071, 17.346] | 1.31× |

## Verification and other constructions

Standard single-opening medians at `2^26` elements:

| Hash | u32 / leaf | Baseline µs | Standard optimized µs | Speedup |
| --- | ---: | ---: | ---: | ---: |
| SHA-256 | 256 | 0.891 | 0.889 | 1.00× |
| SHA-256 | 16,384 | 22.771 | 22.700 | 1.00× |
| SHA3-256 | 256 | 4.078 | 3.405 | 1.20× |
| SHA3-256 | 16,384 | 65.764 | 65.148 | 1.01× |
| BLAKE3 | 256 | 2.357 | 1.795 | 1.31× |
| BLAKE3 | 16,384 | 28.214 | 27.279 | 1.03× |

SHA-256 standard verification is essentially unchanged here. Shorter SHA3 and
BLAKE3 leaves benefit from faster parent hashing. When wide-leaf hashing
dominates, the sweep gains are small; some Criterion points differ noticeably
from these short-run medians, so within-run confidence intervals should not be
read as covering all between-run variability.

The generic experiments explain why abstract and native calls are separated.
A 256-byte SHA-256 leaf (`W=64`) needs five native compressions under standard
hashing. T8 uses three abstract calls but six native compressions with the
concrete wide-oracle adapter, and loses to optimized standard commitment.
SHA3's 136-byte rate makes ordinary leaf hashing especially competitive.
Padding short records to a gadget's natural size can also waste work.

BLAKE3 T8 has a limited verification benefit. At `N=2^20,W=64`, final sweep
medians were 0.941 µs for T8 and
0.991 µs for optimized standard;
Criterion measured 0.951 [0.949, 0.954] µs versus
1.050 [1.007, 1.139] µs (95% intervals). At `W=256`, the
sweep measured 1.444 versus
1.450 µs. Commitment was slower:
0.833 versus
0.614 ms at `W=64`, and
0.901 versus
0.513 ms at `W=256`. These results do not
support replacing standard BLAKE3 for all workloads.

No universal experimental mode is selected from this sweep. Standard preserves
root compatibility; experimental choices should be evaluated on the actual
commit/verification workload. Reproduction commands, CSV definitions, memory
controls, and Criterion filters are in
[OPTIMIZED_BENCHMARKS.md](OPTIMIZED_BENCHMARKS.md).

## Validation

- All 47 unit/integration tests and one doctest pass with default parallel
  features and with `--no-default-features`.
- All-target Clippy passes with warnings denied (`-D warnings`).
- All 323 selected new benchmark smoke cases passed
  ([log](results/benchmark-smoke.txt)).
- Every prepared optimized opening in both final sweeps was verified; standard
  roots were also checked against the unchanged baseline.
- `cargo fmt --check` and `git diff --check` pass.
