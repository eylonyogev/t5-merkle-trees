# Optimized trees and whole-leaf experiments

The pinned Plonky3 specialization remains `MerkleTree`. The separate
`OptimizedMerkleTree` uses contiguous leaf-first digest storage, coarse Rayon
jobs, serial upper levels, complete-slice leaf hashing, and independent-message
SIMD. `LeafMode::Standard` has exactly the baseline roots and authentication
paths. Other modes change the leaf hash but retain the same binary parent
function and ordinary whole-leaf authentication path.

```rust
use binary_merkle_tree::{LeafMode, OptimizedMerkleTree, Sha256};
// Inside a function returning Result<(), binary_merkle_tree::Error>:
let data: Vec<u32> = (0..1 << 20).collect();
let tree = OptimizedMerkleTree::<Sha256>::commit_u32(&data, 256, LeafMode::T253)?;
let proof = tree.open(19)?;
tree.commitment().verify_u32(19, &data[19 * 256..20 * 256], &proof.siblings)?;
```

The protocol authenticates the hash suite, mode, root, leaf count, width and
queried index. Widths are positive and fixed; leaf counts are powers of two.
Every opening discloses the **entire record**. No specialized partial opening
inside a record is supported. Zero-filled tails are unambiguous only within
the authenticated fixed input length. Modes are selected explicitly, never
according to runtime hardware or measured performance.

## Constructions

All words below are 32 bytes. Abstract h2 consumes 64 bytes and h3 consumes
96. Separate roles distinguish functions within and between constructions.

| Mode | First-stage bytes | Later-stage fresh bytes | Abstract calls/stage |
| --- | ---: | ---: | --- |
| `FixedMd` | 64 | 64 | 1 h3 |
| `T5` | 160 | 128 | 3 h2 |
| `T8` | 256 | 224 | 3 h3 |
| `Abr3` | 352 | 320 | 7 h2 |
| `T253`, SHA-256 only | 253 | 221 | 3 restricted native calls, plus tail |

FixedMd chains a zero-initialized state with 64 fresh bytes each step, using
h3. It is a comparison construction, not standard padded SHA-256.

The [T5 paper](https://eprint.iacr.org/2021/373.pdf) by Dodis, Khovratovich,
Mouha and Nandi defines `a=h1(x1,x2)`, `b=h2(x3,x4)`, and
`T5=h3(a XOR x5,b XOR x5) XOR x5`. Its wider-input generalization, used as T8 in
the repo note, sets `a=h1(z1,z2,z3)`, `b=h2(z4,z5,z6)`, then
`T8=h3(a XOR z7,b XOR z7,z8) XOR z7`. Subsequent stages put the previous digest
in the shared XOR slot. Incomplete stages are zero-filled.

The linked [ABR correction paper](https://cs.nyu.edu/~dodis/ps/ABR.pdf) by Dhar,
Dodis and Nandi proves the height-three, 11-word case, identifies gaps in the
general-height proof, and attacks specialized local openings. Abr3 uses that
fixed gadget: four bottom functions consume eight words; two middle nodes and
the root consume the final three. Each internal node computes
`f(L XOR m,R XOR m) XOR R`, with a distinct function for every vertex. Longer
leaves chain fixed gadgets, inserting the previous digest as the first input
word. This does not assert security of arbitrary-height ABR.

## Concrete primitives

The papers analyze independent ideal functions. These concrete SHA/BLAKE
adapters are research instantiations under additional primitive assumptions;
the papers do not prove their concrete security.

- **SHA-256:** h2 uses distinct fixed chaining values and one raw compression.
  h3 uses full SHA-256 of a 17-byte role/arity tag followed by 96 input bytes,
  costing **two** compressions. A 96-byte input already fills SHA-256's 32-byte
  chaining value plus 64-byte block. XORing a role IV into arbitrary input state
  would not domain-separate the functions, because those domains coincide.
- **SHA3-256:** the 17-byte tag plus 64 or 96 bytes fits the 136-byte rate.
  Each oracle costs one Keccak-f[1600] permutation with NIST SHA3 padding.
  Standard hashing of a 256-byte leaf costs two permutations; T8 costs three.
- **BLAKE3:** research oracles use raw one-block compression with explicit
  role/arity counters and `KEYED_HASH | CHUNK_START | CHUNK_END` flags, without
  `ROOT`. h3 takes its chaining value from the final 32 input bytes and its
  block from the first 64; h2 fixes the chaining value to zero. These functions
  use BLAKE3 compression but are not standard unkeyed BLAKE3 hashes.

`src/experimental.rs` specifies the construction schedules and stage placement.
The modules in `src/experimental/` define each backend's role encoding,
endianness, tags, counters, padding and flags.

### T253: restricted T8 for SHA-256

T253 reserves one chaining-value byte for a fixed role and leaves 31 variable
bytes. A 95-byte primitive input supplies the 64-byte block and these 31 bytes.
Role bytes A1/A2/A3 give disjoint raw-compression domains. The gadget consumes
two 95-byte inputs, a 32-byte shared XOR word and a final 31-byte input, totaling
253 bytes, with T8's XOR wiring. Subsequent stages put the previous digest in
the shared slot and consume 221 fresh bytes. Residual bytes use raw SHA-256
chaining from the final digest, zero-filling the final 64-byte block.

For fixed width `B >= 253`, the plan takes `k=floor((B-32)/221)` stages and
`ceil((B-32-221k)/64)` tail calls. This minimizes their total
`3k+ceil((B-32-221k)/64)` over positive feasible k: removing a gadget adds three
or four tail calls. Below 253 bytes it uses standard SHA-256. At 256, 512 and
1024 bytes, counts are 4, 7 and 14, versus standard SHA-256's 5, 9 and 17.
This is a new restricted experiment, not exact T8 or standardized SHA-256; it
needs independent cryptographic review before protocol deployment.

## Costs and implementation

LeafPlan prepares the schedule once per width and hashes with bounded stack
scratch. It reports abstract gadget calls and analytical native primitive
calls separately. For a standard leaf of `B > 0` bytes:

| Hash | Native leaf calls | Binary parent calls |
| --- | --- | ---: |
| SHA-256 | `floor(B/64)+1+[B mod 64 >= 56]` | 1 |
| SHA3-256 | `floor(B/136)+1` | 1 |
| BLAKE3 | `ceil(B/64)+ceil(B/1024)-1` | 1 |

Commit costs `L*leaf_calls+L-1` and verification `leaf_calls+log2(L)`, for L
leaves. SIMD changes time, not the logical count. Abstract-call count zero for
standard hashing means not applicable, not zero work. These are analytical
counts, not hardware counters.

Standard hashing batches SHA3 via `keccak::ParState1600`, including two messages
on the AArch64 SHA3 backend with portable fallback, and BLAKE3 through native
hash_many kernels. Full BLAKE3 leaf slices expose its wide-input chunk SIMD,
which the baseline's 512-byte updates conceal. SHA-256 uses its native hardware
backend. Experimental backends additionally use:

- **SHA-256:** direct two-block encoding for h3, interleaved independent
  compressions with AArch64 SHA2 instructions, a fused T253 gadget that retains
  intermediate words in vector registers, and native-word chaining for T253
  tails.
- **SHA3:** one backend dispatch per leaf or batch, direct tagged-state
  encoding, and two-record batching. Single-record T5/T8 verification overlaps
  independent branches of the next gadget with the current gadget's final
  permutation. The dependent chain still runs in order.
- **BLAKE3:** four-record NEON compression with independently variable chaining
  values and counters. Fused four-record T8 keeps intermediate digests and the
  chaining state in vector form across stages. Uniform-role, fixed-CV calls
  also use upstream hash_many.
  Single-record T5/T8 verification precomputes independent branches in bounded
  windows before completing the dependent chain. One-stage leaves use small
  gadget buffers; one or two leftover compressions use upstream single-message
  calls. Parallel jobs contain at least four records to keep the four-lane
  kernel occupied.

Complete stages borrow input directly where possible; only incomplete stages
need zero-filled scratch. These changes preserve every mode's previous digest,
domain separation and logical compression count. CPU-specific kernels have
runtime feature checks and portable fallbacks. The crate denies unsafe Rust
except in the isolated `blake3_simd.rs` and `sha256_simd.rs` modules, whose safe
interfaces check sizes before entering bounded architecture intrinsics. BLAKE3
is pinned to 1.8.5 because its public platform API is unstable.

Storage is still `32(2L-1)` digest bytes. Contiguity reduces allocation count,
not digest count. Recommit methods reuse storage for exactly the same geometry
and mode. Fresh commit benchmarks include allocation and drop; reuse is not
silently credited as a hash optimization. Verification allocates no heap memory
on little-endian hosts; u32 conversion on big-endian hosts uses a byte buffer.

See [OPTIMIZED_BENCHMARKS.md](OPTIMIZED_BENCHMARKS.md) for commands and methodology,
[RESULTS.md](RESULTS.md) for the initial comparison, and
[NEWPASS_RESULTS.md](NEWPASS_RESULTS.md) for the subsequent implementation
optimizations and updated comparisons with optimized standard hashing.
