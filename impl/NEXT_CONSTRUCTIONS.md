# Candidates for reducing native compression calls

Research snapshot: 28 September 2026. These are analytical counts, **not
measured speedups**. A subsequent implementation adds SHA-256 ABR-wide,
BLAKE3 ABR-wide/T277 and the SHAKE128/SPONGE-DM272 leaf modes: see the
[exact implemented encodings](EXPERIMENTS.md) and
[performance report](LOWCALL_RESULTS.md). Other proposals remain unimplemented;
implementation does not change their proof status. Existing modes preserve
their roots. The target is a 32-byte digest and complete
openings of fixed-width records. Width, mode, tree shape and queried index must
be authenticated by the surrounding protocol.

## Security status: the assumptions are not interchangeable

**No: these candidates are not all secure under only collision resistance of
the underlying compression function.** Ordinary collision resistance forbids
finding equal outputs on distinct inputs. An independent ideal random-function
model additionally specifies how every output behaves, including across
related inputs and roles. An ideal public permutation model also exposes the
inverse and has its own proofs. Domain tags separate inputs; they do not by
themselves prove that a concrete primitive behaves ideally.

This distinction is essential for the call savings. The
[Chakraborty–Nandi lower-bound paper](https://eprint.iacr.org/2024/1095.pdf),
Section 4 and Appendix 8.1, explicitly shows that T5 and ABR do not preserve
collision resistance for arbitrary collision-resistant compressors. Its
linear-mode lower bound explains why extra assumptions are needed to beat
ordinary MD/Merkle call counts at a fixed compression interface. This is not
an attack on our concrete SHA/BLAKE instantiations.

| Construction | Assumption / established result | Status of our proposal |
| --- | --- | --- |
| T5/T8; T253, T255bits, T277 adaptations | Published T analysis models role oracles as independent ideal random functions; plain compressor CR is insufficient | Wider T framework is published. Concrete raw adapters, domain allocation and hybrid schedules need a complete specification and review. Current T253 also has an unrestricted raw-MD tail, whose input domain overlaps restricted gadget domains. |
| Widened ABR3: ABR569 / ABR625 | Corrected ordinary ABR3 result is in the independent-random-function model, with polynomial loss | Widening reduction below is a new sketch. Do not describe these curves as established secure instantiations. |
| T520 | Prepend/map/chop has a published single-prefix ideal-permutation analysis; T then needs suitable joint role oracles | Joint role simulation and composition for this exact mode remain unfinished. |
| SPONGE-DM c272 / c320 | Published ideal-permutation collision, preimage and second-preimage analysis | Proposed parameters fit that framework; concrete full-round Keccak security is an assumption. |
| SHAKE128, 32-byte output | Standardized sponge with conventional ideal-permutation analysis | 128-bit classical collision and preimage targets, rather than SHA3-256's 256-bit preimage target. |
| PA199 with fixed-width MD | Published PA collision resistance in the ideal-permutation model; fixed-width MD preserves compressor CR | Supports binding under that model. PA is not a random-oracle substitute, so this does not justify a T-over-PA mode. |
| Raw fixed-width SHA-256 MD | Fixed-length MD preserves collision resistance of the full variable-state compressor | Includes fixed trusted width, injective final padding and fixed initialization; full SHA-256 hash security alone is not the required compressor assumption. |
| Injective short leaves / ordinary wider-arity tree | Fixed-shape whole-leaf binding reduces to CR of the actual leaf and parent maps | No leaf hash needed at <=32 bytes; a raw BLAKE3 ternary map is a research compressor, not a standard 96-byte BLAKE3 hash. |

All of these statements concern **classical** security. For the current API,
complete-leaf collision resistance plus collision resistance of the binary
parent yields position binding by tracing two conflicting openings to a
collision. That does not establish every extractability or random-oracle
property a surrounding proof system might require, or a quantum security bound.

Nor does a 256-bit output guarantee 256-bit preimage resistance. The T5 paper
gives a generic preimage attack around `2^(2n/3)` queries, approximately
`2^171` for n=256. The corrected ABR3 bound is of birthday type with a substantial
polynomial factor; it is not a tight concrete 128-bit guarantee. The proposed
widening reduction preserves that limitation. The counts below do not certify
that all candidates satisfy the same security definition or strength.

## Most useful candidates

The table uses the largest requested leaf: 16,384 u32 elements = 65,536 bytes.
Savings compare with the optimized standard mode of the same backend. A native
call means one SHA-256/BLAKE3 compression or one full, 24-round Keccak-f[1600]
permutation; these units do not have equal execution times.

| Backend | Leaf construction | Calls | Fewer than standard | Status |
| --- | --- | ---: | ---: | --- |
| SHA-256 | Standard | 1,025 | — | Implemented |
| SHA-256 | Current T253 | 890 | 13.2% | Implemented research mode |
| SHA-256 | Widened ABR3, 95-byte oracle | 854 | 16.7% | New adaptation; reduction sketch below |
| BLAKE3 | Standard | 1,087 | — | Implemented |
| BLAKE3 | Current T8 | 879 | 19.1% | Implemented research mode |
| BLAKE3 | T277 with MD tail | 803 | 26.1% | New adapter of generalized T |
| BLAKE3 | Widened ABR3, 103-byte oracle | 774 | 28.8% | New adapter and reduction |
| Keccak | SHA3-256 | 482 | — | Implemented |
| Keccak | SHAKE128, 32-byte output | 391 | 18.9% | Standardized; different preimage target |
| Keccak | SPONGE-DM, capacity 272 bits | 395 | 18.0% | Published generic construction; proposed parameters |
| Keccak | SPONGE-DM, capacity 320 bits | 410 | 14.9% | Lane-aligned alternative |
| Keccak | T520 with MD tail | 403 | 16.4% | Derived candidate; joint adapter analysis needed |

[The CSV](results/candidate-compression-counts.csv) covers every requested
power-of-two width. [Plots and exact tables](results/candidate-compression-count-plots/README.md)
show native counts and ratios to each standard backend, including fixed-width
raw MD and PA199 comparisons. Regenerate and validate them with:

```sh
python3 impl/scripts/candidate_compression_counts.py
uv run impl/scripts/plot_candidate_compression_counts.py
```

For the unchanged binary upper tree with L leaves, commitment costs
`L * leaf_calls + L - 1`; one complete-leaf verification costs
`leaf_calls + log2(L)`. Thus leaf savings translate directly into saved calls,
but percentage savings for the complete operation also include the upper tree.

## Generalized T: the input capacity is the key parameter

Section 6 of the [T5 paper](https://eprint.iacr.org/2021/373.pdf) allows wider
oracles by adding independent input to each of its three functions. For an
`m`-byte input and 32-byte output, the resulting gadget consumes `3m - 32`
bytes in three calls, or `3m - 64` fresh bytes when chained through its shared
XOR word. Our T253 is the case `m = 95`; BLAKE3 T8 already uses `m = 96`.
Here, names such as **T277** and **T520** are working names for their first-stage
byte capacities, not names claimed from the literature.

For a candidate oracle with one-call cost, let `D = 3m - 64` and `t = m - 32`.
A plan with k positive T stages and a residual MD tail costs

```
3k + ceil(max(0, B - 32 - kD) / t).
```

A final gadget may be zero-padded because B is fixed and trusted. A separate
direct-head/MD-only plan handles small B. The companion script exhaustively
chooses the least-call plan over these choices; it does not silently substitute
standard hashing. The new `AbrWide` and `T277` Rust modes implement this public,
width-dependent schedule with the same tie-breaking rule; older `T253` and
`T8` retain their original schedules. Terminal zero padding is only injective
within the specified width.

For SHA-256 in particular, the proposed MD tail must serialize the entire
32-byte state and `m-32` fresh bytes into the restricted oracle input. It cannot
reserve a role byte by discarding a byte of the chaining state. Current T253's
unrestricted 64-byte raw-MD tail is a different adapter.

### BLAKE3: use seven counter bytes as additional payload

The [official BLAKE3 specification](https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.tex)
provides a 32-byte chaining value, a 64-byte block and a 64-bit counter, besides
length and flags. Reserve one counter byte for the oracle role, use the other
seven as message, and fix block length and flags. This gives `m = 103`:

```
first T stage:       3 * 103 - 32 = 277 bytes
later fresh input:   3 * 103 - 64 = 245 bytes
MD tail:            103 - 32     =  71 bytes/call
```

At 64 KiB, the least-padding optimum uses 266 gadgets followed by five
tail calls: **803**. The 267-gadget/two-tail schedule has the same cost but
more padding. The role byte must distinguish gadget,
head and tail functions and avoid existing mode namespaces. The remaining
counter bits are input data, not a sequential chunk index.

This assumes appropriate ideal behavior of raw BLAKE3 compression with a
variable counter and variable chaining value. It is not standard BLAKE3, and
the security of standard BLAKE3 alone is insufficient to justify the adapter.
The existing variable-counter SIMD kernel makes it a practical experiment.

Even without widening, replacing T8's padded final gadget with an MD tail
helps: at 512 bytes, its count drops from 9 to 7; at 64 KiB, from 879 to 878.

### SHA-256: reclaim some role bits

If a standalone suite needs only three gadget roles and one shared MD role,
reserve two bits instead of a whole byte in the 768-bit compression input.
Then `m=766` bits, the first gadget holds 2,042 bits, and subsequent gadgets
absorb 1,786 fresh bits. The count model gives **881** calls at 64 KiB, versus
890 for current T253. This is a small additional gain and requires bit packing,
so widened ABR3 is the more interesting count experiment. The CSV calls this
capacity model `t255bits-hybrid`; it is not a finished domain allocation across
all other modes of the repository.

## Widened ABR3: a further research candidate

The [corrected ABR analysis](https://cs.nyu.edu/~dodis/ps/ABR.pdf) establishes
the height-three, seven-oracle gadget; it does not establish arbitrary-height
ABR or the widened adapter below. We use only its collision-resistance result
for complete gadget inputs, not its specialized local openings.

Give each of the seven oracles `delta = m - 64` additional independent input
bytes. Counting the original eleven 32-byte words and the seven extensions
gives:

```
first gadget:       352 + 7delta = 7m - 96 bytes
later fresh input:                 7m - 128 bytes
cost:                             7 calls
```

Thus SHA-256 with `m=95` gives 569/537-byte first/later capacities; BLAKE3 with
`m=103` gives 625/593. The latter uses 110 full gadgets plus four 71-byte tail
calls at 64 KiB, for **774** calls. SHA-256 can pad its 122nd gadget and use
**854** calls. These count improvements are conditional on the widened
construction and concrete adapters meeting the intended assumptions.

There is also a scheduling opportunity: put the previous digest into the
**root's shared message word**. All six non-root calls then depend only on
fresh input, leaving one serial root call per gadget. The current Abr3 mode
puts the chaining value into a bottom input. Moving it changes the hash, but
does not change capacity or call count.

### Proposed classical collision reduction

This is a new proof sketch developed during this investigation, not a theorem
attributed to the ABR authors. Let the output size be n bits and model each
wide role as an independent random function on `(x,y,z)`, where x and y have
n bits and z is the extra input. Reduce to seven independent narrow ABR
oracles on pairs of n-bit strings.

For each role, injectively map every distinct queried `(x,y,z)` to a pair
`(u,v)` satisfying `u XOR v = x XOR y`. Allocate a previously unused pair
in that XOR class without looking at its oracle output, and return the narrow
oracle's value. Repeat queries reuse the mapping. Each class contains `2^n`
pairs, so allocation succeeds below that many queries per role. Fresh pairs
produce precisely the independent uniform outputs required by the wide model.

Write `u = x XOR r` and `v = y XOR r`. A wide internal node evaluates
`h(a XOR s, b XOR s, z) XOR b`. Replace its message word by `s XOR r` in
the narrow gadget. Its children, narrow oracle output and right-child
feed-forward agree, so its result agrees. At the bottom, use the mapped pair
as the two narrow message words.

The complete-message transformation is injective: equal transformed bottom
pairs identify equal wide query records. Inductively, equal transformed child
messages give equal child outputs; equal transformed internal shared words
then give equal narrow query pairs. Injectivity of the query table recovers
the same wide records and the original shared words and extra inputs.
Consequently, a wide collision produces a distinct-input narrow collision.

Complete both output-message evaluations before performing the transformation;
this adds at most 14 queries total, or two per role. Apply the corrected ABR3
bound with this additional query cost and require fewer than `2^n` queries
per role. For a chained leaf, first extract a collision in a single wide
gadget or tail from the equal-length chain, then apply this reduction. Mapping
an entire chain directly would not preserve its chaining words.

This sketch addresses classical collision resistance under independent random
functions. It does not give indifferentiability, quantum-query security,
specialized ABR local-opening security, or a proof for concrete SHA/BLAKE
compression. Formalizing and independently reviewing this argument precedes
relying on the widened gadget in a protocol.

## Keccak: different modes are more promising than ordinary T8

SHA3-256 absorbs 136 bytes per permutation. A chained T gadget absorbs
`m - 64/3` fresh bytes per call. Even filling an oracle to 136 bytes does not
beat SHA3-256; one needs `m > 157 1/3`. The ordinary tagged SHA3 adapter
therefore cannot deliver the desired gain just by accepting slightly more data.

### SHAKE128 and SPONGE-DM

[FIPS 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf) defines
SHAKE128 with a 168-byte rate. A 32-byte output gives a straightforward
128-bit collision target, but only a 128-bit preimage target. It uses
`floor(B/168)+1` permutations here; SHAKE256 retains SHA3-256's 136-byte rate.

[SPONGE-DM, CRYPTO 2026](https://eprint.iacr.org/2025/963), replaces each
absorption permutation P by `P(x) XOR x` and uses ordinary permutations when
squeezing. Its ideal-permutation bounds give collision exponent
`min(n/2,c/2)`, preimage exponent n, and second-preimage exponent
`min(n,c-log2(alpha))`, for at most alpha absorbed blocks. These are generic
bounds; a concrete Keccak instance remains a cryptographic assumption.

Our suggested parameters are `b=1600`, `n=256`, `c=c'=272`, `r=r'=1328` bits.
The 32-byte output fits in the first output block. A fixed 17-byte domain
prefix and `pad10*1` give `floor((B+17)/166)+1` calls. At 64 KiB this is
395; `272-log2(395)>256`, so the generic second-preimage exponent remains
256 at our maximum leaf size. The lane-aligned alternative `c=320`, rate
160 bytes, uses 410 calls. Full-state feed-forward is required for these
bounds; keeping only capacity feed-forward does not inherit them.

### A direct Keccak analogue: T520

[Dodis, Reyzin, Rivest and Shen, FSE 2009](https://people.csail.mit.edu/rivest/pubs/DRRS09.pdf)
analyze the prepend/map/chop construction `h_Q(x)=Trunc256(P(Q || x))`.
A 16-byte fixed prefix leaves 184 input bytes in a 200-byte Keccak state.
Distinct fixed prefixes would encode roles. Under the ideal-permutation
framework this is a plausible 128-bit-target adapter, giving a 520-byte
first T stage, 488-byte later stages, and 152-byte MD tails: 403 calls at
64 KiB. Joint simulation of the role prefixes must be accounted for; merely
citing the single-prefix theorem is not a completed proof of the whole mode.

Do not instead truncate `P(x)` on unrestricted 200-byte inputs: access to
the inverse permutation makes finding collisions easy. Nor does every
collision-resistant compression function automatically satisfy T's stronger
oracle assumptions.

### Permutation feed-forward compression (PA)

The [PA/PAX paper, USENIX Security 2026](https://www.usenix.org/system/files/usenixsecurity26-andreeva.pdf)
proves collision resistance for `Trunc256(P(x) XOR x)` in the ideal-permutation
model, including inverse queries. Restricting a 200-byte input to one role
byte plus 199 variable bytes gives a fixed-width MD candidate absorbing
167 fresh bytes per call: 393 calls at 64 KiB from a fixed initial state.
This is another useful binding-only candidate. PA is not indifferentiable
from a random oracle, so plugging it into T and claiming the T theorem would
be unjustified. It is included as `pa199-fixedwidth` in the candidate grid.

## Other changes that save calls

**Small leaves: injective encoding.** For fixed B <= 32, encode the entire
leaf into 32 bytes with zero extension and perform no leaf compression.
Under trusted shape and complete openings, disagreement must then collide
in a parent. Commitment calls fall from `2L-1` to `L-1`; verification saves
one call. This supplies binding, not a pseudorandom or hiding leaf digest.

**Fixed-width SHA-256 without terminal length padding.** A domain/width
specific initial state and fixed number of data blocks permit a raw-MD mode
with `ceil(B/64)` online calls. At B=64,128,256 this gives 1,2,4 instead of
2,3,5. Any initialization compression is a separately reported setup cost
amortized over equal-width leaves. This changes the hash and requires a
specified fixed-width/domain construction. A related proposal is discussed
by [Khovratovich](https://ethresear.ch/t/post-poseidon-hash-function-variants-for-ethereum/26071).
It is a useful comparison baseline, especially where current T253 falls back
to standard SHA-256. The upper SHA-256 parent already costs one call.

**Wider upper trees.** Four 32-byte digests plus a one-byte tag fit in a
single SHA3-256 rate block including padding. A complete four-ary tree uses
`(L-1)/3` parent calls and `log4(L)` verification calls, compared with `L-1`
and `log2(L)`. Authentication paths contain 1.5 times as many sibling digests.
The current 17-byte research tag would not fit: this requires a new short
parent domain encoding. The research BLAKE3 96-byte raw oracle similarly
permits three-child parents under its ideal-compression assumption,
approximately halving internal calls with about 26% more proof digests.
Standard BLAKE3 hashing of 96 bytes costs two calls and does not give this
one-call parent. Non-power-of-arity leaf counts need an explicit mixed
arity shape and domain specification. These alter the binary-tree API.

## Suggested order of experiments

1. Add SHAKE128 as a standardized comparison and prototype SPONGE-DM with
   capacities 272 and 320, keeping full Keccak rounds.
2. Add a fully specified T277 adapter and width-dependent tail planner for
   BLAKE3; benchmark both commit batches and a single complete-leaf opening.
3. Formalize the widened ABR3 reduction, then prototype 95- and 103-byte
   adapters with the chaining word at the root.
4. Evaluate injective small leaves and a quaternary Keccak upper tree where
   proof-size tradeoffs are acceptable.

Count reductions are not uniform across widths, and a count-minimizing plan
need not minimize time. Serialization, XOR feed-forward, batching, SIMD lane
utilization and dependency depth all remain benchmark variables. Reduced-round
functions such as TurboSHAKE address a different cost axis and should not be
credited as fewer full Keccak-f[1600] calls in this comparison.
