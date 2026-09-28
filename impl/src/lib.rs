//! A single-matrix, binary specialization of Plonky3 0.6.3's Merkle tree.
//!
//! The leaf-first vector of digest layers, per-layer allocation, row hashing and
//! compression loops follow upstream with scalar byte packing (`P = PW = u8`).
//! See `UPSTREAM.md` for the pinned revision and the precise simplifications.
//!
//! Leaves contain canonical little-endian u32 encodings, with no domain prefix.
//! SHA-256 uses Plonky3's unpadded parent compressor; SHA3-256 and BLAKE3 hash
//! the concatenated 64-byte child digests. These roots differ from version 0.1.
//! The protocol must authenticate the suite, leaf count, width, and queried index.
//!
//! [`OptimizedMerkleTree`] separately provides batched hashing and coarse parallel
//! scheduling. [`LeafMode::Standard`] preserves the baseline roots; other modes
//! are experimental whole-record constructions and additionally require an
//! authenticated mode. See `EXPERIMENTS.md` for definitions and assumptions.
//!
//! ```
//! use binary_merkle_tree::{MerkleTree, Sha256};
//! let matrix: Vec<u32> = (0..1024).collect();
//! let tree = MerkleTree::<Sha256>::commit_u32(&matrix, 16)?;
//! let proof = tree.open(7)?;
//! tree.commitment().verify_u32(7, &matrix[112..128], &proof.siblings)?;
//! # Ok::<(), binary_merkle_tree::Error>(())
//! ```
//
// Tree construction adapted from Plonky3, Copyright (c) 2022 The Plonky3 Authors.
// Licensed under MIT; see LICENSE-MIT and UPSTREAM.md.

#![forbid(unsafe_code)]

mod hash;
pub use hash::{Blake3, Digest, HashFunction, Sha3_256, Sha256};
mod optimized_hash;
pub use optimized_hash::OptimizedHash;
mod experimental;
pub use experimental::{LeafMode, LeafPlan, ResearchHash};
mod optimized;
pub use optimized::{OptimizedCommitment, OptimizedMerkleTree};

use p3_maybe_rayon::prelude::*;
use p3_symmetric::{CryptographicHasher, PseudoCompressionFunction};
use std::{fmt, marker::PhantomData};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    EmptyInput,
    InvalidLeafSize,
    InvalidShape,
    SizeOverflow,
    IndexOutOfBounds,
    InvalidProofLength,
    RootMismatch,
    AllocationFailed,
    UnsupportedMode,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::EmptyInput => "a tree must contain at least one leaf",
            Self::InvalidLeafSize => "leaf size must be positive and match the commitment",
            Self::InvalidShape => "input must contain a power-of-two number of complete leaves",
            Self::SizeOverflow => "tree dimensions exceed addressable storage",
            Self::IndexOutOfBounds => "leaf index is out of bounds",
            Self::InvalidProofLength => "proof has a missing or surplus sibling digest",
            Self::RootMismatch => "opening does not match the committed root",
            Self::AllocationFailed => "unable to allocate tree or proof storage",
            Self::UnsupportedMode => "leaf construction is not available for this hash suite",
        })
    }
}
impl std::error::Error for Error {}

/// An ordinary binary authentication path, ordered from leaf to root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleProof {
    pub siblings: Vec<Digest>,
}

/// The verifier's authenticated suite, root and matrix geometry.
///
/// Geometry is public protocol context, not hashed into the root. In particular,
/// these upstream-compatible untagged constructions are not a commitment to a
/// variable-shape collection: do not accept shape metadata from the prover.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Commitment<H: HashFunction> {
    root: Digest,
    leaf_count: usize,
    leaf_bytes: usize,
    marker: PhantomData<H>,
}

impl<H: HashFunction> Commitment<H> {
    pub fn from_root(root: Digest, leaf_count: usize, leaf_bytes: usize) -> Result<Self, Error> {
        validate_dimensions(leaf_count, leaf_bytes)?;
        Ok(Self {
            root,
            leaf_count,
            leaf_bytes,
            marker: PhantomData,
        })
    }

    pub fn root(&self) -> Digest {
        self.root
    }
    pub fn leaf_count(&self) -> usize {
        self.leaf_count
    }
    pub fn leaf_bytes(&self) -> usize {
        self.leaf_bytes
    }
    pub fn height(&self) -> usize {
        self.leaf_count.ilog2() as usize
    }

    /// Verify a fixed-size leaf against the trusted context without allocation.
    /// Like upstream MMCS verification, the leaf uses `hash_iter_slices`.
    pub fn verify_bytes(
        &self,
        index: usize,
        leaf: &[u8],
        siblings: &[Digest],
    ) -> Result<(), Error> {
        self.validate_opening(index, leaf.len(), siblings.len())?;
        let digest = H::leaf_hasher().hash_iter_slices([leaf]);
        self.verify_digest(index, digest, siblings)
    }

    pub fn verify_u32(&self, index: usize, leaf: &[u32], siblings: &[Digest]) -> Result<(), Error> {
        #[cfg(target_endian = "little")]
        {
            self.verify_bytes(index, bytemuck::cast_slice(leaf), siblings)
        }
        #[cfg(target_endian = "big")]
        {
            let bytes = leaf.len().checked_mul(4).ok_or(Error::SizeOverflow)?;
            self.validate_opening(index, bytes, siblings.len())?;
            self.verify_digest(index, H::hash_leaf_u32(leaf), siblings)
        }
    }

    fn validate_opening(&self, index: usize, bytes: usize, siblings: usize) -> Result<(), Error> {
        if index >= self.leaf_count {
            return Err(Error::IndexOutOfBounds);
        }
        if bytes != self.leaf_bytes {
            return Err(Error::InvalidLeafSize);
        }
        if siblings != self.height() {
            return Err(Error::InvalidProofLength);
        }
        Ok(())
    }

    fn verify_digest(
        &self,
        mut index: usize,
        mut digest: Digest,
        siblings: &[Digest],
    ) -> Result<(), Error> {
        let compressor = H::node_compressor();
        for &sibling in siblings {
            let children = if index & 1 == 0 {
                [digest, sibling]
            } else {
                [sibling, digest]
            };
            digest = compressor.compress(children);
            index >>= 1;
        }
        // Root and path are public values, so constant-time equality is unnecessary.
        if digest == self.root {
            Ok(())
        } else {
            Err(Error::RootMismatch)
        }
    }
}

/// Prover state with Plonky3's per-level, leaf-first digest storage.
///
/// Input data is borrowed during construction and not retained. The caller must
/// keep it to answer openings. Scheduling uses `p3-maybe-rayon`, just as upstream:
/// default features enable parallelism; `--no-default-features` selects serial.
#[derive(Debug)]
pub struct MerkleTree<H: HashFunction> {
    digest_layers: Vec<Vec<Digest>>,
    commitment: Commitment<H>,
}

impl<H: HashFunction> MerkleTree<H> {
    pub fn commit_bytes(input: &[u8], leaf_bytes: usize) -> Result<Self, Error> {
        let count = input_shape(input.len(), leaf_bytes)?;
        let hasher = H::leaf_hasher();
        Self::build(count, leaf_bytes, |index| {
            let row = &input[index * leaf_bytes..(index + 1) * leaf_bytes];
            // Upstream first_digest_layer with one matrix and packing width 1.
            hasher.hash_iter(row.iter().copied())
        })
    }

    /// Commit row-major raw u32 elements, encoded little-endian without reduction.
    pub fn commit_u32(input: &[u32], elements_per_leaf: usize) -> Result<Self, Error> {
        let count = input_shape(input.len(), elements_per_leaf)?;
        let bytes = elements_per_leaf
            .checked_mul(4)
            .ok_or(Error::SizeOverflow)?;
        #[cfg(target_endian = "little")]
        {
            let _ = count;
            Self::commit_bytes(bytemuck::cast_slice(input), bytes)
        }
        #[cfg(target_endian = "big")]
        {
            Self::build(count, bytes, |index| {
                H::hash_leaf_u32(&input[index * elements_per_leaf..(index + 1) * elements_per_leaf])
            })
        }
    }

    pub fn root(&self) -> Digest {
        self.commitment.root
    }
    pub fn commitment(&self) -> Commitment<H> {
        self.commitment
    }
    pub fn leaf_count(&self) -> usize {
        self.commitment.leaf_count
    }
    pub fn leaf_bytes(&self) -> usize {
        self.commitment.leaf_bytes
    }
    pub fn height(&self) -> usize {
        self.commitment.height()
    }
    pub fn node_count(&self) -> usize {
        self.digest_layers.iter().map(Vec::len).sum()
    }
    /// Digest payload bytes, excluding per-level Vec headers and allocator overhead.
    pub fn storage_bytes(&self) -> usize {
        self.node_count() * size_of::<Digest>()
    }

    pub fn open(&self, index: usize) -> Result<MerkleProof, Error> {
        let mut siblings = Vec::new();
        self.open_into(index, &mut siblings)?;
        Ok(MerkleProof { siblings })
    }

    /// Copy an ordinary Plonky3-compatible path; an invalid index leaves `siblings` unchanged.
    pub fn open_into(&self, mut index: usize, siblings: &mut Vec<Digest>) -> Result<(), Error> {
        if index >= self.leaf_count() {
            return Err(Error::IndexOutOfBounds);
        }
        siblings.clear();
        siblings
            .try_reserve(self.height())
            .map_err(|_| Error::AllocationFailed)?;
        for layer in &self.digest_layers[..self.height()] {
            siblings.push(layer[index ^ 1]);
            index >>= 1;
        }
        Ok(())
    }

    fn build(
        count: usize,
        bytes: usize,
        hash_row: impl Fn(usize) -> Digest + Sync,
    ) -> Result<Self, Error> {
        validate_dimensions(count, bytes)?;
        let node_count = count
            .checked_mul(2)
            .and_then(|n| n.checked_sub(1))
            .ok_or(Error::SizeOverflow)?;
        let storage_bytes = node_count
            .checked_mul(size_of::<Digest>())
            .ok_or(Error::SizeOverflow)?;
        if storage_bytes > isize::MAX as usize {
            return Err(Error::SizeOverflow);
        }

        // Plonky3 first_digest_layer, specialized to P = PW = u8 (packing width 1).
        let mut first_layer = zeroed_layer(count)?;
        first_layer
            .par_chunks_exact_mut(1)
            .enumerate()
            .for_each(|(index, out)| {
                out[0] = hash_row(index);
            });
        let mut digest_layers = Vec::new();
        digest_layers
            .try_reserve_exact(count.ilog2() as usize + 1)
            .map_err(|_| Error::AllocationFailed)?;
        digest_layers.push(first_layer);
        while digest_layers.last().unwrap().len() > 1 {
            let parents = compress_layer::<H>(digest_layers.last().unwrap())?;
            digest_layers.push(parents);
        }
        let root = digest_layers.last().unwrap()[0];
        let commitment = Commitment {
            root,
            leaf_count: count,
            leaf_bytes: bytes,
            marker: PhantomData,
        };
        Ok(Self {
            digest_layers,
            commitment,
        })
    }
}

// Plonky3 `compress`, specialized to binary arity, scalar byte packing, no
// matrix injection and power-of-two height. Keep per-level allocation and the
// upstream parallel loop so optimizations can be measured against this baseline.
fn compress_layer<H: HashFunction>(children: &[Digest]) -> Result<Vec<Digest>, Error> {
    let mut parents = zeroed_layer(children.len() / 2)?;
    let compressor = H::node_compressor();
    parents
        .par_chunks_exact_mut(1)
        .enumerate()
        .for_each(|(index, out)| {
            out[0] = compressor.compress([children[2 * index], children[2 * index + 1]]);
        });
    Ok(parents)
}

fn zeroed_layer(length: usize) -> Result<Vec<Digest>, Error> {
    let mut layer = Vec::new();
    layer
        .try_reserve_exact(length)
        .map_err(|_| Error::AllocationFailed)?;
    layer.resize(length, [0; 32]);
    Ok(layer)
}

fn input_shape(length: usize, width: usize) -> Result<usize, Error> {
    if width == 0 {
        return Err(Error::InvalidLeafSize);
    }
    if length == 0 {
        return Err(Error::EmptyInput);
    }
    if !length.is_multiple_of(width) || !(length / width).is_power_of_two() {
        return Err(Error::InvalidShape);
    }
    Ok(length / width)
}

fn validate_dimensions(leaves: usize, bytes: usize) -> Result<(), Error> {
    if bytes == 0 {
        return Err(Error::InvalidLeafSize);
    }
    if leaves == 0 {
        return Err(Error::EmptyInput);
    }
    if !leaves.is_power_of_two() {
        return Err(Error::InvalidShape);
    }
    let input_bytes = leaves.checked_mul(bytes).ok_or(Error::SizeOverflow)?;
    if input_bytes > isize::MAX as usize {
        return Err(Error::SizeOverflow);
    }
    Ok(())
}
