//! Experimental whole-record leaf hashes, with ordinary binary Merkle parents.
//!
//! These modes change the commitment scheme, not merely its implementation.
//! The verifier must authenticate the mode, byte width, encoding and tree shape.
//! Zero padding below is injective only within that fixed public byte width.
//! Every opening discloses the entire record: no ABR/T5 partial openings are used.
//!
//! T5/T8 follow Sections 4/6 of <https://eprint.iacr.org/2021/373.pdf>.
//! ABR uses only the eleven-input, height-three construction from Definition 6
//! and Theorem 15 of <https://cs.nyu.edu/~dodis/ps/ABR.pdf>. Its final feed-forward
//! is the right child, unlike T5's final feed-forward of the shared message.
//! Repeating this fixed gadget is ordinary fixed-format composition, not a
//! claim about the unresolved security of arbitrary-height ABR.
//!
//! The papers analyze independent ideal compression functions. Concrete SHA-2,
//! SHA-3 and BLAKE3 instantiations below remain research constructions requiring
//! cryptographic review. They are not standard SHA-256/SHA3-256/BLAKE3 hashes.

use crate::{Blake3, Digest, Error, OptimizedHash, Sha3_256, Sha256};
#[cfg(test)]
use sha3::Digest as _;

mod blake3_backend;
mod sha256_backend;
mod sha3_backend;
mod wide;

#[cfg(test)]
use blake3_backend::blake3_counter;
#[cfg(test)]
use sha256_backend::{sha256_95, sha256_compress};

/// A fixed, public whole-record hashing rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeafMode {
    /// The original hash, with exactly the original commitment roots.
    Standard,
    /// Fixed-length MD using a domain-separated 96-to-32-byte oracle.
    FixedMd,
    /// Five digest blocks in three 64-to-32-byte oracle calls.
    T5,
    /// Eight digest blocks in three 96-to-32-byte oracle calls.
    T8,
    /// Eleven digest blocks in seven 64-to-32-byte oracle calls.
    Abr3,
    /// SHA-256-only, 253-byte restriction of T8 with genuine role separation.
    T253,
    /// Widened height-three ABR: SHA-256 uses 95-byte oracles, BLAKE3 103.
    /// This is a research adaptation with a provisional ideal-function proof.
    AbrWide,
    /// BLAKE3-only, counter-payload T gadget with a fixed-width MD tail.
    T277,
    /// SHA3 backend: standard SHAKE128 with a 32-byte output.
    Shake128,
    /// SHA3 backend: full-round SPONGE-DM with 272-bit capacity and 17-byte tag.
    SpongeDm272,
}

impl LeafMode {
    pub const ALL: [Self; 10] = [
        Self::Standard,
        Self::FixedMd,
        Self::T5,
        Self::T8,
        Self::Abr3,
        Self::T253,
        Self::AbrWide,
        Self::T277,
        Self::Shake128,
        Self::SpongeDm272,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::FixedMd => "fixed-md",
            Self::T5 => "t5",
            Self::T8 => "t8",
            Self::Abr3 => "abr3",
            Self::T253 => "t253",
            Self::AbrWide => "abr-wide",
            Self::T277 => "t277",
            Self::Shake128 => "shake128",
            Self::SpongeDm272 => "sponge-dm272",
        }
    }
}

/// Primitive interfaces for experimental leaf constructions.
///
/// Roles must be separated, including across the two arities. The built-in
/// BLAKE3 adapter stores the arity in counter bits 48..55, so its role must
/// be less than `2^48`. All built-in constructions use small constants.
pub trait ResearchHash: OptimizedHash {
    /// Preferred minimum number of rows per parallel job. Batched backends
    /// still accept partial groups; this keeps ordinary jobs from underfilling
    /// their SIMD kernels when records are large.
    const LEAF_BATCH_SIZE: usize = 2;

    fn oracle2(role: u64, input: &[u8; 64]) -> Digest;
    fn oracle3(role: u64, input: &[u8; 96]) -> Digest;

    /// Two independent calls, possibly with different domain roles. Backends
    /// may evaluate them with SIMD; the abstract and native call counts remain
    /// unchanged.
    #[inline]
    fn oracle2_pair(roles: [u64; 2], inputs: [&[u8; 64]; 2]) -> [Digest; 2] {
        core::array::from_fn(|i| Self::oracle2(roles[i], inputs[i]))
    }

    #[inline]
    fn oracle3_pair(roles: [u64; 2], inputs: [&[u8; 96]; 2]) -> [Digest; 2] {
        core::array::from_fn(|i| Self::oracle3(roles[i], inputs[i]))
    }

    fn oracle2_calls() -> u64;
    fn oracle3_calls() -> u64;

    /// Hash one complete record after the public width has been checked.
    /// Backends can fuse gadget stages and keep dispatch or SIMD state local.
    fn hash_leaf_planned(plan: &LeafPlan, input: &[u8]) -> Digest {
        plan.hash_generic::<Self>(input)
    }

    /// Backend hook used by [`LeafPlan::hash_many`]. The caller checks shapes;
    /// the default preserves scalar evaluation for custom research backends.
    fn hash_leaves_planned(plan: &LeafPlan, input: &[u8], output: &mut [Digest]) {
        for (row, digest) in input.chunks_exact(plan.leaf_bytes()).zip(output) {
            *digest = plan.hash::<Self>(row);
        }
    }

    fn supports_t253() -> bool {
        false
    }

    /// Evaluate the preplanned SHA-256 restriction. Other suites reject it.
    fn hash_t253(_input: &[u8], _stages: usize) -> Digest {
        unreachable!("T253 is supported only by SHA-256")
    }

    /// Payload capacity of the backend's one-call wide research oracle.
    fn wide_oracle_bytes(_mode: LeafMode) -> Option<usize> {
        None
    }

    fn supports_sponge_modes() -> bool {
        false
    }

    fn hash_wide(_plan: &LeafPlan, _input: &[u8]) -> Digest {
        unreachable!("unsupported wide research mode")
    }

    fn hash_sponge(_plan: &LeafPlan, _input: &[u8]) -> Digest {
        unreachable!("unsupported sponge research mode")
    }
}

/// Width-dependent parameters prepared once, before hashing matrix rows.
///
/// Hashing uses bounded stack scratch and no allocation. The plan is reusable
/// across backends for the original generic modes. Backend-specific plans
/// reject unsupported or differently sized adapters at the hashing boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LeafPlan {
    mode: LeafMode,
    leaf_bytes: usize,
    stages: usize,
    remainder: usize,
    wide: Option<wide::WidePlan>,
}

impl LeafPlan {
    pub fn new<H: ResearchHash>(mode: LeafMode, leaf_bytes: usize) -> Result<Self, Error> {
        if leaf_bytes == 0 {
            return Err(Error::InvalidLeafSize);
        }
        if mode == LeafMode::T253 && !H::supports_t253() {
            return Err(Error::UnsupportedMode);
        }
        let wide = match mode {
            LeafMode::AbrWide | LeafMode::T277 => {
                let bytes = H::wide_oracle_bytes(mode).ok_or(Error::UnsupportedMode)?;
                if leaf_bytes > isize::MAX as usize {
                    return Err(Error::InvalidLeafSize);
                }
                let kind = if mode == LeafMode::AbrWide {
                    wide::WideKind::Abr3
                } else {
                    wide::WideKind::T
                };
                Some(wide::WidePlan::new(kind, leaf_bytes, bytes))
            }
            LeafMode::Shake128 | LeafMode::SpongeDm272 if !H::supports_sponge_modes() => {
                return Err(Error::UnsupportedMode);
            }
            _ => None,
        };
        let mut remainder = 0;
        let stages = match mode {
            LeafMode::Standard => 0,
            LeafMode::FixedMd => leaf_bytes.div_ceil(64),
            LeafMode::T5 => stage_count(leaf_bytes, 160, 128),
            LeafMode::T8 => stage_count(leaf_bytes, 256, 224),
            LeafMode::Abr3 => stage_count(leaf_bytes, 352, 320),
            LeafMode::T253 if leaf_bytes < 253 => 0,
            LeafMode::T253 => {
                // Removing a gadget replaces three calls by 3 or 4 tail
                // calls, because 221/64 is between 3 and 4. Therefore the
                // largest possible k minimizes 3k+ceil((B-32-221k)/64),
                // and also implements the larger-k tie break without search.
                let stages = (leaf_bytes - 32) / 221;
                remainder = (leaf_bytes - 32) % 221;
                stages
            }
            LeafMode::AbrWide | LeafMode::T277 | LeafMode::Shake128 | LeafMode::SpongeDm272 => 0,
        };
        Ok(Self {
            mode,
            leaf_bytes,
            stages,
            remainder,
            wide,
        })
    }

    pub const fn mode(&self) -> LeafMode {
        self.mode
    }

    pub const fn leaf_bytes(&self) -> usize {
        self.leaf_bytes
    }

    /// Calls to the selected abstract oracle, before its concrete cost.
    /// Standard, SHAKE/SPONGE-DM and T253's short-input fallback report zero
    /// because they do not use a gadget oracle. Zero does not mean free: use
    /// `native_calls` to count its compression/permutation work.
    /// T253 counts its native compression invocations, including its MD tail.
    pub fn abstract_calls(&self) -> u64 {
        match self.mode {
            LeafMode::Standard => 0,
            LeafMode::FixedMd => self.stages as u64,
            LeafMode::T5 | LeafMode::T8 => 3 * self.stages as u64,
            LeafMode::Abr3 => 7 * self.stages as u64,
            LeafMode::T253 if self.stages == 0 => 0,
            LeafMode::T253 => 3 * self.stages as u64 + self.remainder.div_ceil(64) as u64,
            LeafMode::AbrWide | LeafMode::T277 => self.wide.as_ref().unwrap().calls(),
            LeafMode::Shake128 | LeafMode::SpongeDm272 => 0,
        }
    }

    /// Actual compression/permutation calls, including concrete oracle padding.
    pub fn native_calls<H: ResearchHash>(&self) -> u64 {
        self.assert_backend::<H>();
        match self.mode {
            LeafMode::Standard => H::standard_leaf_calls(self.leaf_bytes),
            LeafMode::FixedMd | LeafMode::T8 => self.abstract_calls() * H::oracle3_calls(),
            LeafMode::T5 | LeafMode::Abr3 => self.abstract_calls() * H::oracle2_calls(),
            LeafMode::T253 if self.stages == 0 => H::standard_leaf_calls(self.leaf_bytes),
            LeafMode::T253 => self.abstract_calls(),
            LeafMode::AbrWide | LeafMode::T277 => self.abstract_calls(),
            LeafMode::Shake128 => (self.leaf_bytes / 168) as u64 + 1,
            LeafMode::SpongeDm272 => {
                // Avoid overflowing for widths close to usize::MAX.
                (self.leaf_bytes / 166) as u64 + ((self.leaf_bytes % 166 + 17) / 166) as u64 + 1
            }
        }
    }

    fn assert_backend<H: ResearchHash>(&self) {
        assert!(
            self.mode != LeafMode::T253 || H::supports_t253(),
            "T253 requires SHA-256"
        );
        if let Some(plan) = self.wide {
            assert_eq!(
                H::wide_oracle_bytes(self.mode),
                Some(plan.oracle_bytes),
                "wide plan requires its original backend"
            );
        }
        assert!(
            !matches!(self.mode, LeafMode::Shake128 | LeafMode::SpongeDm272)
                || H::supports_sponge_modes(),
            "sponge mode requires the SHA3 backend"
        );
    }

    /// Hash exactly one record of the planned public width.
    ///
    /// # Panics
    /// Panics if the input has another width or the backend does not support
    /// the planned mode and its concrete oracle capacity.
    #[inline]
    pub fn hash<H: ResearchHash>(&self, input: &[u8]) -> Digest {
        assert_eq!(
            input.len(),
            self.leaf_bytes,
            "leaf must match its planned width"
        );
        self.assert_backend::<H>();
        H::hash_leaf_planned(self, input)
    }

    /// Scalar construction specification, also the default for custom suites.
    fn hash_generic<H: ResearchHash>(&self, input: &[u8]) -> Digest {
        match self.mode {
            LeafMode::Standard => H::hash_leaf_fast(input),
            LeafMode::FixedMd => fixed_md::<H>(input),
            LeafMode::T5 => chained_t5::<H>(input),
            LeafMode::T8 => chained_t8::<H>(input),
            LeafMode::Abr3 => chained::<352>(input, 320, abr3::<H>),
            LeafMode::T253 => {
                assert!(H::supports_t253(), "T253 requires SHA-256");
                H::hash_t253(input, self.stages)
            }
            LeafMode::AbrWide | LeafMode::T277 => H::hash_wide(self, input),
            LeafMode::Shake128 | LeafMode::SpongeDm272 => H::hash_sponge(self, input),
        }
    }

    /// Hash complete rows using bounded stack scratch and no worker threads.
    /// Built-in backends batch independent records or gadget branches when
    /// supported by the selected CPU.
    ///
    /// # Panics
    /// Panics if the input and output shapes disagree or the backend does not
    /// support the planned mode and its concrete oracle capacity.
    pub fn hash_many<H: ResearchHash>(&self, input: &[u8], output: &mut [Digest]) {
        assert_eq!(
            Some(input.len()),
            output.len().checked_mul(self.leaf_bytes),
            "leaf batch must match its planned shape"
        );
        self.assert_backend::<H>();
        if self.mode == LeafMode::Standard {
            H::hash_leaves_fast(input, self.leaf_bytes, output);
        } else {
            H::hash_leaves_planned(self, input, output);
        }
    }
}

fn stage_count(bytes: usize, first: usize, subsequent: usize) -> usize {
    1 + bytes.saturating_sub(first).div_ceil(subsequent)
}

const MD_ROLE: u64 = 1;
const T5_ROLES: [u64; 3] = [10, 11, 12];
const T8_ROLES: [u64; 3] = [20, 21, 22];
const ABR_ROLES: [u64; 7] = [30, 31, 32, 33, 34, 35, 36];

#[inline]
fn xor(left: Digest, right: &Digest) -> Digest {
    core::array::from_fn(|i| left[i] ^ right[i])
}

#[inline]
fn fixed_md<H: ResearchHash>(input: &[u8]) -> Digest {
    let mut state = [0; 32];
    for chunk in input.chunks(64) {
        let mut message = [0; 96];
        message[..32].copy_from_slice(&state);
        message[32..32 + chunk.len()].copy_from_slice(chunk);
        state = H::oracle3(MD_ROLE, &message);
    }
    state
}

/// Gadget chaining: T5/T8 place state in their shared XOR slot; ABR places it
/// in the first bottom-node input. Every stage evaluates the complete gadget.
#[inline]
fn chained<const BYTES: usize>(
    input: &[u8],
    fresh: usize,
    gadget: fn(&[u8; BYTES]) -> Digest,
) -> Digest {
    let first = input.len().min(BYTES);
    let mut message = [0; BYTES];
    let mut state = if first == BYTES {
        gadget(input[..BYTES].try_into().unwrap())
    } else {
        message[..first].copy_from_slice(input);
        gadget(&message)
    };
    for chunk in input[first..].chunks(fresh) {
        // A complete stage overwrites every byte. Only the final short stage
        // needs explicit padding, independent of data from its predecessor.
        if chunk.len() < fresh {
            message.fill(0);
        }
        if BYTES == 352 {
            message[..32].copy_from_slice(&state);
            message[32..32 + chunk.len()].copy_from_slice(chunk);
        } else {
            let shared = if BYTES == 160 { 128 } else { 192 };
            let before_shared = chunk.len().min(shared);
            message[..before_shared].copy_from_slice(&chunk[..before_shared]);
            message[shared..shared + 32].copy_from_slice(&state);
            if chunk.len() > shared {
                message[shared + 32..shared + 32 + chunk.len() - shared]
                    .copy_from_slice(&chunk[shared..]);
            }
        }
        state = gadget(&message);
    }
    state
}

#[inline]
fn t5<H: ResearchHash>(message: &[u8; 160]) -> Digest {
    t5_parts::<H>(
        message[..64].try_into().unwrap(),
        message[64..128].try_into().unwrap(),
        message[128..160].try_into().unwrap(),
    )
}

#[inline]
fn t5_parts<H: ResearchHash>(a: &[u8; 64], b: &[u8; 64], shared: &Digest) -> Digest {
    let [left, right] = H::oracle2_pair([T5_ROLES[0], T5_ROLES[1]], [a, b]);
    let mut root = [0; 64];
    root[..32].copy_from_slice(&xor(left, shared));
    root[32..].copy_from_slice(&xor(right, shared));
    xor(H::oracle2(T5_ROLES[2], &root), shared)
}

#[inline]
fn t8<H: ResearchHash>(message: &[u8; 256]) -> Digest {
    t8_parts::<H>(
        message[..96].try_into().unwrap(),
        message[96..192].try_into().unwrap(),
        message[192..224].try_into().unwrap(),
        message[224..].try_into().unwrap(),
    )
}

#[inline]
fn t8_parts<H: ResearchHash>(
    a: &[u8; 96],
    b: &[u8; 96],
    shared: &Digest,
    extra: &Digest,
) -> Digest {
    let [left, right] = H::oracle3_pair([T8_ROLES[0], T8_ROLES[1]], [a, b]);
    let mut root = [0; 96];
    root[..32].copy_from_slice(&xor(left, shared));
    root[32..64].copy_from_slice(&xor(right, shared));
    root[64..].copy_from_slice(extra);
    xor(H::oracle3(T8_ROLES[2], &root), shared)
}

// Complete stages borrow fresh input directly instead of copying a padded
// whole gadget. Only the final incomplete stage uses a scratch buffer.
#[inline]
fn chained_t5<H: ResearchHash>(input: &[u8]) -> Digest {
    if input.len() < 160 {
        let mut padded = [0; 160];
        padded[..input.len()].copy_from_slice(input);
        return t5::<H>(&padded);
    }
    let mut state = t5::<H>(input[..160].try_into().unwrap());
    let mut chunks = input[160..].chunks_exact(128);
    for chunk in &mut chunks {
        state = t5_parts::<H>(
            chunk[..64].try_into().unwrap(),
            chunk[64..].try_into().unwrap(),
            &state,
        );
    }
    if !chunks.remainder().is_empty() {
        let mut tail = [0; 128];
        tail[..chunks.remainder().len()].copy_from_slice(chunks.remainder());
        state = t5_parts::<H>(
            tail[..64].try_into().unwrap(),
            tail[64..].try_into().unwrap(),
            &state,
        );
    }
    state
}

#[inline]
fn chained_t8<H: ResearchHash>(input: &[u8]) -> Digest {
    if input.len() < 256 {
        let mut padded = [0; 256];
        padded[..input.len()].copy_from_slice(input);
        return t8::<H>(&padded);
    }
    let mut state = t8::<H>(input[..256].try_into().unwrap());
    let mut chunks = input[256..].chunks_exact(224);
    for chunk in &mut chunks {
        state = t8_parts::<H>(
            chunk[..96].try_into().unwrap(),
            chunk[96..192].try_into().unwrap(),
            &state,
            chunk[192..].try_into().unwrap(),
        );
    }
    if !chunks.remainder().is_empty() {
        let mut tail = [0; 224];
        tail[..chunks.remainder().len()].copy_from_slice(chunks.remainder());
        state = t8_parts::<H>(
            tail[..96].try_into().unwrap(),
            tail[96..192].try_into().unwrap(),
            &state,
            tail[192..].try_into().unwrap(),
        );
    }
    state
}

#[inline]
fn abr_node<H: ResearchHash>(role: u64, left: Digest, right: Digest, shared: &Digest) -> Digest {
    let mut message = [0; 64];
    message[..32].copy_from_slice(&xor(left, shared));
    message[32..].copy_from_slice(&xor(right, shared));
    xor(H::oracle2(role, &message), &right)
}

#[inline]
fn abr3<H: ResearchHash>(message: &[u8; 352]) -> Digest {
    let [bottom0, bottom1] = H::oracle2_pair(
        [ABR_ROLES[0], ABR_ROLES[1]],
        [
            message[..64].try_into().unwrap(),
            message[64..128].try_into().unwrap(),
        ],
    );
    let [bottom2, bottom3] = H::oracle2_pair(
        [ABR_ROLES[2], ABR_ROLES[3]],
        [
            message[128..192].try_into().unwrap(),
            message[192..256].try_into().unwrap(),
        ],
    );
    let [left, right] = abr_node_pair::<H>(
        [ABR_ROLES[4], ABR_ROLES[5]],
        [bottom0, bottom2],
        [bottom1, bottom3],
        [
            message[256..288].try_into().unwrap(),
            message[288..320].try_into().unwrap(),
        ],
    );
    abr_node::<H>(
        ABR_ROLES[6],
        left,
        right,
        message[320..352].try_into().unwrap(),
    )
}

#[inline]
fn abr_node_pair<H: ResearchHash>(
    roles: [u64; 2],
    left: [Digest; 2],
    right: [Digest; 2],
    shared: [&Digest; 2],
) -> [Digest; 2] {
    let messages: [[u8; 64]; 2] = core::array::from_fn(|i| {
        let mut message = [0; 64];
        message[..32].copy_from_slice(&xor(left[i], shared[i]));
        message[32..].copy_from_slice(&xor(right[i], shared[i]));
        message
    });
    let digests = H::oracle2_pair(roles, [&messages[0], &messages[1]]);
    core::array::from_fn(|i| xor(digests[i], &right[i]))
}

/// Prefix is part of the experimental suite definition. It also separates the
/// oracle arities. Seventeen bytes leave both SHA-256 widths within two blocks,
/// and both SHA3 widths within a single 136-byte rate block.
fn prefix(arity: u8, role: u64) -> [u8; 17] {
    let mut bytes = [0; 17];
    bytes[..8].copy_from_slice(b"MTLFv001");
    bytes[8] = arity;
    bytes[9..].copy_from_slice(&role.to_le_bytes());
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(bytes: usize) -> Vec<u8> {
        (0..bytes)
            .map(|i| i.wrapping_mul(73).wrapping_add(i / 7) as u8)
            .collect()
    }

    // Deliberately separate, block-oriented specification. Production code
    // works on byte offsets; this one pads/concatenates Vecs and indexes blocks.
    fn reference_gadget<H: ResearchHash>(mode: LeafMode, bytes: &[u8]) -> Digest {
        let blocks: Vec<Digest> = bytes
            .chunks_exact(32)
            .map(|b| b.try_into().unwrap())
            .collect();
        let call2 = |role, x: Digest, y: Digest| {
            let bytes = [x.as_slice(), y.as_slice()].concat();
            H::oracle2(role, bytes.as_slice().try_into().unwrap())
        };
        let call3 = |role, x: Digest, y: Digest, z: Digest| {
            let bytes = [x.as_slice(), y.as_slice(), z.as_slice()].concat();
            H::oracle3(role, bytes.as_slice().try_into().unwrap())
        };
        match mode {
            LeafMode::T5 => {
                let a = call2(10, blocks[0], blocks[1]);
                let b = call2(11, blocks[2], blocks[3]);
                xor(
                    call2(12, xor(a, &blocks[4]), xor(b, &blocks[4])),
                    &blocks[4],
                )
            }
            LeafMode::T8 => {
                let a = call3(20, blocks[0], blocks[1], blocks[2]);
                let b = call3(21, blocks[3], blocks[4], blocks[5]);
                xor(
                    call3(22, xor(a, &blocks[6]), xor(b, &blocks[6]), blocks[7]),
                    &blocks[6],
                )
            }
            LeafMode::Abr3 => {
                let mut values: Vec<Digest> = (0..4)
                    .map(|i| call2(30 + i as u64, blocks[2 * i], blocks[2 * i + 1]))
                    .collect();
                let mut msg = 8;
                let mut role = 34;
                while values.len() > 1 {
                    values = values
                        .chunks_exact(2)
                        .map(|pair| {
                            let out = xor(
                                call2(role, xor(pair[0], &blocks[msg]), xor(pair[1], &blocks[msg])),
                                &pair[1],
                            );
                            msg += 1;
                            role += 1;
                            out
                        })
                        .collect();
                }
                values[0]
            }
            _ => unreachable!(),
        }
    }

    fn reference<H: ResearchHash>(mode: LeafMode, input: &[u8]) -> Digest {
        if mode == LeafMode::Standard {
            return H::hash_leaf_fast(input);
        }
        if mode == LeafMode::FixedMd {
            let mut state = [0; 32];
            for chunk in input.chunks(64) {
                let mut bytes = state.to_vec();
                bytes.extend_from_slice(chunk);
                bytes.resize(96, 0);
                state = H::oracle3(1, bytes.as_slice().try_into().unwrap());
            }
            return state;
        }
        let width = match mode {
            LeafMode::T5 => 160,
            LeafMode::T8 => 256,
            LeafMode::Abr3 => 352,
            _ => unreachable!(),
        };
        let first = input.len().min(width);
        let mut first_input = input[..first].to_vec();
        first_input.resize(width, 0);
        let mut state = reference_gadget::<H>(mode, &first_input);
        for chunk in input[first..].chunks(width - 32) {
            let mut bytes = chunk.to_vec();
            bytes.resize(width - 32, 0);
            let insertion = match mode {
                LeafMode::T5 => 128,
                LeafMode::T8 => 192,
                LeafMode::Abr3 => 0,
                _ => unreachable!(),
            };
            bytes.splice(insertion..insertion, state);
            state = reference_gadget::<H>(mode, &bytes);
        }
        state
    }

    fn check_reference<H: ResearchHash>() {
        for width in [
            1, 4, 31, 32, 63, 64, 65, 127, 128, 159, 160, 161, 192, 223, 224, 253, 255, 256, 257,
            288, 289, 351, 352, 353, 480, 481, 512, 672, 673, 1024, 4096,
        ] {
            let input = data(width);
            for mode in [
                LeafMode::Standard,
                LeafMode::FixedMd,
                LeafMode::T5,
                LeafMode::T8,
                LeafMode::Abr3,
            ] {
                let plan = LeafPlan::new::<H>(mode, width).unwrap();
                assert_eq!(
                    plan.hash::<H>(&input),
                    reference::<H>(mode, &input),
                    "{mode:?}, width={width}"
                );
                // Every byte of the disclosed record must affect its digest.
                for index in [0, width / 2, width - 1] {
                    let mut changed = input.clone();
                    changed[index] ^= 1;
                    assert_ne!(plan.hash::<H>(&input), plan.hash::<H>(&changed));
                }
            }
        }
    }

    #[test]
    fn sha256_matches_formula() {
        check_reference::<Sha256>();
    }
    #[test]
    fn sha3_matches_formula() {
        check_reference::<Sha3_256>();
    }
    #[test]
    fn blake3_matches_formula() {
        check_reference::<Blake3>();
    }

    #[test]
    fn independent_oracle_pairs_preserve_inputs_and_domain_roles() {
        fn check<H: ResearchHash>() {
            let bytes = data(192);
            let input2 = [
                bytes[..64].try_into().unwrap(),
                bytes[64..128].try_into().unwrap(),
            ];
            let input3 = [
                bytes[..96].try_into().unwrap(),
                bytes[96..].try_into().unwrap(),
            ];
            for roles in [[0, 0], [10, 11], [20, 21], [35, 34], [65535, 1]] {
                assert_eq!(
                    H::oracle2_pair(roles, input2),
                    core::array::from_fn(|i| H::oracle2(roles[i], input2[i]))
                );
                assert_eq!(
                    H::oracle3_pair(roles, input3),
                    core::array::from_fn(|i| H::oracle3(roles[i], input3[i]))
                );
            }
        }
        check::<Sha256>();
        check::<Sha3_256>();
        check::<Blake3>();
    }

    #[test]
    fn sha3_batched_records_match_independent_scalar_specification() {
        for width in [
            1, 4, 31, 32, 63, 64, 65, 127, 128, 159, 160, 161, 192, 223, 224, 255, 256, 257, 287,
            288, 289, 351, 352, 353, 479, 480, 481, 511, 512, 672, 673, 1024, 4096,
        ] {
            for mode in [
                LeafMode::Standard,
                LeafMode::FixedMd,
                LeafMode::T5,
                LeafMode::T8,
                LeafMode::Abr3,
            ] {
                let plan = LeafPlan::new::<Sha3_256>(mode, width).unwrap();
                for count in [0, 1, 2, 3, 4, 5, 9] {
                    let input = data(count * width);
                    let mut output = vec![[0; 32]; count];
                    plan.hash_many::<Sha3_256>(&input, &mut output);
                    for (row, digest) in input.chunks_exact(width).zip(output) {
                        assert_eq!(
                            digest,
                            reference::<Sha3_256>(mode, row),
                            "{mode:?}, width={width}, count={count}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    #[should_panic(expected = "leaf batch must match its planned shape")]
    fn rejects_partial_planned_batch() {
        LeafPlan::new::<Sha3_256>(LeafMode::T8, 256)
            .unwrap()
            .hash_many::<Sha3_256>(&[0; 511], &mut [[0; 32]; 2]);
    }

    #[test]
    #[should_panic(expected = "T253 requires SHA-256")]
    fn rejects_cross_backend_t253_batch() {
        LeafPlan::new::<Sha256>(LeafMode::T253, 256)
            .unwrap()
            .hash_many::<Sha3_256>(&[0; 512], &mut [[0; 32]; 2]);
    }

    #[test]
    fn primitive_roles_are_distinct() {
        fn check<H: ResearchHash>() {
            for role in 0..40 {
                assert_ne!(H::oracle2(role, &[0; 64]), H::oracle2(role + 1, &[0; 64]));
                assert_ne!(H::oracle3(role, &[0; 96]), H::oracle3(role + 1, &[0; 96]));
                assert_ne!(H::oracle2(role, &[0; 64]), H::oracle3(role, &[0; 96]));
            }
        }
        check::<Sha256>();
        check::<Sha3_256>();
        check::<Blake3>();
        for role in [0xa1, 0xa2] {
            assert_ne!(
                sha256_95(role, &[0; 64], &[0; 31]),
                sha256_95(role + 1, &[0; 64], &[0; 31])
            );
        }
    }

    #[test]
    fn blake3_raw_oracles_match_public_hazmat() {
        use blake3::hazmat::HasherExt;
        for role in [0, 1, 10, 36, 65535] {
            let bytes = data(96);
            for arity in [2, 3] {
                let key: Digest = if arity == 2 {
                    [0; 32]
                } else {
                    bytes[64..].try_into().unwrap()
                };
                let mut hasher = blake3::Hasher::new_keyed(&key);
                hasher.set_input_offset(blake3_counter(arity, role) * 1024);
                hasher.update(&bytes[..64]);
                let actual = if arity == 2 {
                    Blake3::oracle2(role, bytes[..64].try_into().unwrap())
                } else {
                    Blake3::oracle3(role, bytes.as_slice().try_into().unwrap())
                };
                assert_eq!(actual, hasher.finalize_non_root());
                assert_eq!(blake3_counter(arity, role) >> 48, u64::from(arity));
                assert_eq!(blake3_counter(arity, role) & ((1 << 48) - 1), role);
            }
        }
    }

    #[test]
    fn primitive_counts_and_t253_planning() {
        for (mode, width, abstract_calls, sha256_calls) in [
            (LeafMode::FixedMd, 64, 1, 2),
            (LeafMode::FixedMd, 65, 2, 4),
            (LeafMode::T5, 160, 3, 3),
            (LeafMode::T5, 161, 6, 6),
            (LeafMode::T8, 256, 3, 6),
            (LeafMode::T8, 257, 6, 12),
            (LeafMode::Abr3, 352, 7, 7),
            (LeafMode::Abr3, 353, 14, 14),
        ] {
            let plan = LeafPlan::new::<Sha256>(mode, width).unwrap();
            assert_eq!(plan.abstract_calls(), abstract_calls);
            assert_eq!(plan.native_calls::<Sha256>(), sha256_calls);
            assert_eq!(plan.native_calls::<Sha3_256>(), abstract_calls);
            assert_eq!(plan.native_calls::<Blake3>(), abstract_calls);
        }
        for width in 253..4096 {
            let plan = LeafPlan::new::<Sha256>(LeafMode::T253, width).unwrap();
            let expected = (1..=(width - 32) / 221)
                .map(|k| 3 * k + (width - 32 - 221 * k).div_ceil(64))
                .min()
                .unwrap();
            assert_eq!(plan.native_calls::<Sha256>(), expected as u64);
        }
        for (width, calls) in [
            (252, 5),
            (253, 3),
            (254, 4),
            (256, 4),
            (474, 6),
            (475, 7),
            (512, 7),
            (1024, 14),
        ] {
            assert_eq!(
                LeafPlan::new::<Sha256>(LeafMode::T253, width)
                    .unwrap()
                    .native_calls::<Sha256>(),
                calls
            );
        }
    }

    #[test]
    fn t253_matches_explicit_layout_and_uses_every_byte() {
        for width in [1, 64, 252, 253, 254, 256, 317, 318, 474, 475, 512, 1024] {
            let input = data(width);
            let plan = LeafPlan::new::<Sha256>(LeafMode::T253, width).unwrap();
            let actual = plan.hash::<Sha256>(&input);
            if width < 253 {
                assert_eq!(actual, Sha256::hash_leaf_fast(&input));
            } else {
                let primitive = |role: u8, bytes: &[u8]| {
                    let mut iv = vec![role];
                    iv.extend_from_slice(&bytes[64..95]);
                    sha256_compress(
                        iv.as_slice().try_into().unwrap(),
                        bytes[..64].try_into().unwrap(),
                    )
                };
                let gadget = |bytes: &[u8]| {
                    let a = primitive(0xa1, &bytes[..95]);
                    let b = primitive(0xa2, &bytes[95..190]);
                    let m: &Digest = bytes[190..222].try_into().unwrap();
                    let mut final_input = xor(a, m).to_vec();
                    final_input.extend_from_slice(&xor(b, m));
                    final_input.extend_from_slice(&bytes[222..253]);
                    xor(primitive(0xa3, &final_input), m)
                };
                let mut reference = gadget(&input[..253]);
                let mut consumed = 253;
                for _ in 1..plan.stages {
                    let mut bytes = input[consumed..consumed + 221].to_vec();
                    bytes.splice(190..190, reference);
                    reference = gadget(&bytes);
                    consumed += 221;
                }
                for chunk in input[consumed..].chunks(64) {
                    let mut bytes = chunk.to_vec();
                    bytes.resize(64, 0);
                    reference = sha256_compress(&reference, bytes.as_slice().try_into().unwrap());
                }
                assert_eq!(actual, reference, "width={width}");
            }
            for index in 0..width {
                let mut changed = input.clone();
                changed[index] ^= 1;
                assert_ne!(
                    actual,
                    plan.hash::<Sha256>(&changed),
                    "width={width}, changed={index}"
                );
            }
        }
    }

    #[test]
    fn rejects_empty_or_unsupported_plans() {
        assert_eq!(
            LeafPlan::new::<Sha256>(LeafMode::T5, 0),
            Err(Error::InvalidLeafSize)
        );
        assert_eq!(
            LeafPlan::new::<Blake3>(LeafMode::T253, 256),
            Err(Error::UnsupportedMode)
        );
        assert_eq!(
            LeafPlan::new::<Sha3_256>(LeafMode::T253, 256),
            Err(Error::UnsupportedMode)
        );
    }

    #[test]
    #[should_panic(expected = "leaf must match its planned width")]
    fn rejects_wrong_width() {
        LeafPlan::new::<Sha256>(LeafMode::T8, 256)
            .unwrap()
            .hash::<Sha256>(&[0; 255]);
    }
}
