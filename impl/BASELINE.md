# Plonky3 0.6.3 baseline

This report supersedes the previous tagged custom-tree measurements. The hash
constructions, storage layout, and measured operations have changed; compare
future work against this baseline rather than the old recommit/multiproof results.

## Environment and method

- Date: 2026-09-28; local arm64 Darwin 24.6.0 host.
- Rust 1.96.0 (`ac68faa20`); checked-in `Cargo.lock`; no custom `RUSTFLAGS`.
- Plonky3 0.6.3, revision `02bb3950cbb8ff030219d7d9f1673dfe575cc371`.
- Default `parallel` feature, four Rayon threads, thin LTO, one codegen unit.
- `2^20` u32 elements (4 MiB), with widths 1, 256, and 16,384.
- Criterion: 10 samples, 500 ms warmup, at least 2 s measurement per case.
- Point estimate: regression slope, or mean when Criterion used flat sampling.
- Both implementations borrow the input and allocate/drop the tree inside timing.
- Identical leaf hashers and parent compressors, scalar byte packing, binary arity.
- Benchmark processes ran sequentially; input generation was outside timing.

## Matched commitment measurements

| Hash | Elements/leaf | Simplified (ms) | Upstream (ms) | Simplified / upstream |
| --- | ---: | ---: | ---: | ---: |
| SHA-256 | 1 | 22.832 | 21.167 | 1.079 |
| SHA-256 | 256 | 0.616 | 0.589 | 1.046 |
| SHA-256 | 16,384 | 0.495 | 0.473 | 1.045 |
| SHA3-256 adapter | 1 | 88.339 | 88.169 | 1.002 |
| SHA3-256 adapter | 256 | 1.442 | 1.428 | 1.010 |
| SHA3-256 adapter | 16,384 | 1.116 | 1.103 | 1.011 |
| BLAKE3 | 1 | 44.803 | 47.974 | 0.934 |
| BLAKE3 | 256 | 1.091 | 1.088 | 1.003 |
| BLAKE3 | 16,384 | 0.976 | 0.963 | 1.014 |

A ratio below 1 means the simplified version took less time. These selected
cases are within about 8% of the upstream implementation, with differences in
both directions. They establish a comparable local starting point, not exact
performance identity or a claim about every Plonky3 configuration. SHA3 uses the
same local NIST adapter in both trees; it is not upstream Keccak-256.

```sh
cd impl
RAYON_NUM_THREADS=4 MERKLE_TOTAL_LOGS=20 MERKLE_WIDTH_LOGS=0,8,14 \
  cargo bench --locked --bench merkle -- \
  '^commit(_plonky3)?/' --save-baseline plonky3-v063
```

Criterion samples, confidence intervals, and reports remain in the ignored
`target/criterion/` directory under baseline `plonky3-v063`. Use a new baseline
name for future changes so this reference is retained.

## Validation

- 14 integration tests and one doctest pass with default parallel features and
  with `--no-default-features`.
- Direct tests check all three suites against unmodified Plonky3 MMCS: roots,
  every sibling in the tested paths, and verification in both directions.
- Independent fixtures and recursive models cover canonical encoding, leaf-size
  and hash boundaries, all requested width exponents, and invalid/tampered proofs.
- All-target Clippy with warnings denied passes.
- All 102 default Criterion benchmark cases pass in smoke (`--test`) mode.
- A release smoke run commits `2^26` elements with `2^14` elements per leaf and
  checks valid and invalid openings for all three suites.

The complete Cartesian sweep through `2^26` elements was not run. See
[BENCHMARKS.md](BENCHMARKS.md) for workload controls and memory requirements.
The largest narrow-leaf tree still needs approximately 4 GiB of digest storage.
