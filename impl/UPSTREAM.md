# Plonky3 provenance and baseline scope

This crate specializes the published `p3-merkle-tree = 0.6.3` source, whose
`.cargo_vcs_info.json` identifies revision:

```text
02bb3950cbb8ff030219d7d9f1673dfe575cc371
```

This is an intentionally fixed reference release, not a claim to track the
latest Plonky3 release. Direct `p3-*` dependencies are pinned with `=0.6.3`, and
`Cargo.lock` fixes the complete dependency graph.

## Source mapping

- [`merkle-tree/src/merkle_tree.rs`](https://github.com/Plonky3/Plonky3/blob/02bb3950cbb8ff030219d7d9f1673dfe575cc371/merkle-tree/src/merkle_tree.rs):
  `MerkleTree::new`, `first_digest_layer`, and `compress` are specialized in
  local `src/lib.rs` to a single matrix, binary arity, scalar byte packing, and a
  power-of-two number of rows. The digest layers and per-layer loops are retained.
- [`merkle-tree/src/mmcs/batch.rs`](https://github.com/Plonky3/Plonky3/blob/02bb3950cbb8ff030219d7d9f1673dfe575cc371/merkle-tree/src/mmcs/batch.rs):
  the ordinary sibling path, bulk leaf hashing, and ordered parent compression
  are used by the simplified opening/verification wrapper.
- [`sha256/src/lib.rs`](https://github.com/Plonky3/Plonky3/blob/02bb3950cbb8ff030219d7d9f1673dfe575cc371/sha256/src/lib.rs):
  actual `Sha256` and `Sha256Compress` are imported, not reimplemented.
- [`blake3/src/lib.rs`](https://github.com/Plonky3/Plonky3/blob/02bb3950cbb8ff030219d7d9f1673dfe575cc371/blake3/src/lib.rs)
  and [`symmetric/src/compression.rs`](https://github.com/Plonky3/Plonky3/blob/02bb3950cbb8ff030219d7d9f1673dfe575cc371/symmetric/src/compression.rs):
  actual `Blake3` and `CompressionFunctionFromHasher` are imported.
- [`maybe-rayon`](https://github.com/Plonky3/Plonky3/tree/02bb3950cbb8ff030219d7d9f1673dfe575cc371/maybe-rayon):
  the actual feature-selected sequential/parallel iterator interface is used.

## Deliberate simplifications and adaptations

- One fixed-width byte matrix; u32 rows are a canonical little-endian convenience
  interface. Raw words are not field-reduced or encoded via a particular field type.
- Binary arity, a root commitment (cap height zero), and power-of-two row count.
  Matrix sorting, mixed-height injection, padding, arity schedules, and caps are omitted.
- `P = PW = u8` makes the packing width one. Packed/unpacked conversions become
  scalar digest assignments; no claim of cross-message SIMD is made.
- The input matrix is borrowed during construction and not retained. Opening
  returns only the sibling path; the caller supplies and retains row values.
- No hiding salts, serialization, tracing, pruned/multiproofs, or recommit API.
- Input validation returns errors rather than panicking. Allocation uses
  `try_reserve_exact` followed by zero initialization, retaining upstream's
  per-level zeroed storage behavior while reporting allocator failures when possible.
- A small NIST SHA3-256 adapter is local because upstream's Keccak-256 is a
  different hash. Its buffered iterator implementation follows the SHA-256 and
  BLAKE3 wrappers, and the very same adapter is passed to upstream in comparisons.
- The verifier checks trusted geometry, then follows the same bulk leaf-hash and
  ordered parent-compression path. It exposes only a single opening at a time.

The previous custom 0x00/0x01 framing and flat digest allocation are removed.
Hash constructions are documented in [README.md](README.md). In particular,
matching upstream's untagged hash format requires trusted fixed shape metadata.

## How the reference is kept honest

Tests instantiate actual `p3_merkle_tree::MerkleTreeMmcs` with the same byte
matrix, hasher, compressor, binary arity, and zero-height cap, then compare roots,
paths, and verification in both directions. Benchmarks also instantiate the actual
upstream `MerkleTree` on a borrowed byte-matrix view. Local and upstream commit
measurements both include digest allocation and destruction and exclude input
generation/conversion. They run with the same parallel feature and worker pool.

This establishes a concrete upstream reference, while leaving a short local tree
implementation available for future experiments. Root agreement is a correctness
check, not proof of equal speed; the side-by-side benchmark measures that separately.

## License

Plonky3 is dual licensed under MIT OR Apache-2.0. This adaptation uses the MIT
option and retains the upstream copyright and license in [LICENSE-MIT](LICENSE-MIT).
This license applies to the Rust implementation directory, not to the manuscript.
