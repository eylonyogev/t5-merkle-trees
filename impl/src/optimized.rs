//! A separately measurable optimization of the pinned Plonky3 baseline.

use crate::{Digest, Error, LeafMode, LeafPlan, MerkleProof, ResearchHash};
use p3_maybe_rayon::prelude::*;
use std::marker::PhantomData;

/// Authenticated context for an optimized tree, including its leaf construction.
///
/// The caller must obtain the hash suite, mode, geometry and index from trusted
/// protocol context. Experimental modes change roots; `Standard` is compatible
/// with the pinned Plonky3 baseline. Every opening discloses the entire leaf.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OptimizedCommitment<H: ResearchHash> {
    root: Digest,
    leaf_count: usize,
    plan: LeafPlan,
    marker: PhantomData<H>,
}

impl<H: ResearchHash> OptimizedCommitment<H> {
    pub fn from_root(
        root: Digest,
        leaf_count: usize,
        leaf_bytes: usize,
        mode: LeafMode,
    ) -> Result<Self, Error> {
        crate::validate_dimensions(leaf_count, leaf_bytes)?;
        Ok(Self {
            root,
            leaf_count,
            plan: LeafPlan::new::<H>(mode, leaf_bytes)?,
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
        self.plan.leaf_bytes()
    }
    pub fn mode(&self) -> LeafMode {
        self.plan.mode()
    }
    pub fn height(&self) -> usize {
        self.leaf_count.ilog2() as usize
    }
    pub fn leaf_plan(&self) -> LeafPlan {
        self.plan
    }

    /// Verify an ordinary byte-record authentication path without allocating.
    pub fn verify_bytes(
        &self,
        index: usize,
        leaf: &[u8],
        siblings: &[Digest],
    ) -> Result<(), Error> {
        if index >= self.leaf_count {
            return Err(Error::IndexOutOfBounds);
        }
        if leaf.len() != self.leaf_bytes() {
            return Err(Error::InvalidLeafSize);
        }
        if siblings.len() != self.height() {
            return Err(Error::InvalidProofLength);
        }
        let mut digest = self.plan.hash::<H>(leaf);
        let mut position = index;
        for sibling in siblings {
            digest = if position & 1 == 0 {
                H::hash_node_fast(&digest, sibling)
            } else {
                H::hash_node_fast(sibling, &digest)
            };
            position >>= 1;
        }
        if digest == self.root {
            Ok(())
        } else {
            Err(Error::RootMismatch)
        }
    }

    pub fn verify_u32(&self, index: usize, leaf: &[u32], siblings: &[Digest]) -> Result<(), Error> {
        #[cfg(target_endian = "little")]
        {
            self.verify_bytes(index, bytemuck::cast_slice(leaf), siblings)
        }
        #[cfg(target_endian = "big")]
        {
            self.verify_bytes(index, &encode_le(leaf)?, siblings)
        }
    }
}

/// Binary tree with contiguous leaf-first storage, batched hashing and coarse
/// parallel jobs. Input data is borrowed during construction, not retained.
///
/// `Standard` preserves baseline roots. Other modes implement whole-record
/// compression experiments described in `EXPERIMENTS.md`.
#[derive(Debug)]
pub struct OptimizedMerkleTree<H: ResearchHash> {
    digests: Vec<Digest>,
    commitment: OptimizedCommitment<H>,
}

impl<H: ResearchHash> OptimizedMerkleTree<H> {
    pub fn commit_bytes(input: &[u8], leaf_bytes: usize, mode: LeafMode) -> Result<Self, Error> {
        let count = crate::input_shape(input.len(), leaf_bytes)?;
        let commitment = OptimizedCommitment::from_root([0; 32], count, leaf_bytes, mode)?;
        let nodes = count
            .checked_mul(2)
            .and_then(|n| n.checked_sub(1))
            .ok_or(Error::SizeOverflow)?;
        let bytes = nodes
            .checked_mul(size_of::<Digest>())
            .ok_or(Error::SizeOverflow)?;
        if bytes > isize::MAX as usize {
            return Err(Error::SizeOverflow);
        }
        let mut tree = Self {
            digests: crate::zeroed_layer(nodes)?,
            commitment,
        };
        tree.fill(input);
        Ok(tree)
    }

    pub fn commit_u32(
        input: &[u32],
        elements_per_leaf: usize,
        mode: LeafMode,
    ) -> Result<Self, Error> {
        crate::input_shape(input.len(), elements_per_leaf)?;
        let leaf_bytes = elements_per_leaf
            .checked_mul(4)
            .ok_or(Error::SizeOverflow)?;
        #[cfg(target_endian = "little")]
        {
            Self::commit_bytes(bytemuck::cast_slice(input), leaf_bytes, mode)
        }
        #[cfg(target_endian = "big")]
        {
            Self::commit_bytes(&encode_le(input)?, leaf_bytes, mode)
        }
    }

    /// Reuse digest storage for another matrix of exactly the same shape and
    /// mode. A rejected input leaves the previous commitment and paths intact.
    pub fn recommit_bytes(&mut self, input: &[u8]) -> Result<(), Error> {
        if input.len() != self.leaf_count() * self.leaf_bytes() {
            return Err(Error::InvalidShape);
        }
        self.fill(input);
        Ok(())
    }

    pub fn recommit_u32(&mut self, input: &[u32]) -> Result<(), Error> {
        #[cfg(target_endian = "little")]
        {
            self.recommit_bytes(bytemuck::cast_slice(input))
        }
        #[cfg(target_endian = "big")]
        {
            self.recommit_bytes(&encode_le(input)?)
        }
    }

    pub fn root(&self) -> Digest {
        self.commitment.root
    }
    pub fn commitment(&self) -> OptimizedCommitment<H> {
        self.commitment
    }
    pub fn leaf_count(&self) -> usize {
        self.commitment.leaf_count()
    }
    pub fn leaf_bytes(&self) -> usize {
        self.commitment.leaf_bytes()
    }
    pub fn mode(&self) -> LeafMode {
        self.commitment.mode()
    }
    pub fn height(&self) -> usize {
        self.commitment.height()
    }
    pub fn node_count(&self) -> usize {
        self.digests.len()
    }
    /// Digest payload bytes, excluding the Vec header and allocator overhead.
    pub fn storage_bytes(&self) -> usize {
        self.digests.len() * size_of::<Digest>()
    }

    pub fn open(&self, index: usize) -> Result<MerkleProof, Error> {
        let mut siblings = Vec::new();
        self.open_into(index, &mut siblings)?;
        Ok(MerkleProof { siblings })
    }

    pub fn open_into(&self, mut index: usize, siblings: &mut Vec<Digest>) -> Result<(), Error> {
        if index >= self.leaf_count() {
            return Err(Error::IndexOutOfBounds);
        }
        siblings.clear();
        siblings
            .try_reserve(self.height())
            .map_err(|_| Error::AllocationFailed)?;
        let mut start = 0;
        let mut count = self.leaf_count();
        while count > 1 {
            siblings.push(self.digests[start + (index ^ 1)]);
            start += count;
            count >>= 1;
            index >>= 1;
        }
        Ok(())
    }

    fn fill(&mut self, input: &[u8]) {
        let plan = self.commitment.plan;
        let count = self.leaf_count();
        // Enough bytes per job to amortize Rayon, while retaining independent
        // messages in each job for SIMD. Large records still have many jobs.
        let chunk = (65_536 / self.leaf_bytes())
            .clamp(2, 256)
            .max(H::LEAF_BATCH_SIZE.min(256));
        let leaves = &mut self.digests[..count];
        if count >= 2 * chunk && input.len() >= 65_536 {
            leaves
                .par_chunks_mut(chunk)
                .enumerate()
                .for_each(|(i, out)| {
                    let start = i * chunk * plan.leaf_bytes();
                    hash_leaves::<H>(
                        &plan,
                        &input[start..start + out.len() * plan.leaf_bytes()],
                        out,
                    );
                });
        } else {
            hash_leaves::<H>(&plan, input, leaves);
        }

        let mut start = 0;
        let mut width = count;
        while width > 1 {
            let (earlier, later) = self.digests.split_at_mut(start + width);
            let children = &earlier[start..];
            let parents = &mut later[..width / 2];
            if parents.len() >= 1024 {
                parents
                    .par_chunks_mut(256)
                    .enumerate()
                    .for_each(|(i, out)| {
                        let begin = 2 * i * 256;
                        H::hash_nodes_fast(&children[begin..begin + 2 * out.len()], out);
                    });
            } else {
                H::hash_nodes_fast(children, parents);
            }
            start += width;
            width >>= 1;
        }
        self.commitment.root = self.digests[self.digests.len() - 1];
    }
}

fn hash_leaves<H: ResearchHash>(plan: &LeafPlan, input: &[u8], output: &mut [Digest]) {
    plan.hash_many::<H>(input, output);
}

#[cfg(target_endian = "big")]
fn encode_le(input: &[u32]) -> Result<Vec<u8>, Error> {
    let length = input.len().checked_mul(4).ok_or(Error::SizeOverflow)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| Error::AllocationFailed)?;
    for word in input {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    Ok(bytes)
}
