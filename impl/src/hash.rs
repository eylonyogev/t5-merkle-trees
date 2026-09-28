//! Plonky3's byte-oriented hash suites and a NIST SHA3-256 adapter.
//!
//! Leaves have no domain prefix. SHA-256 parents use one unpadded compression
//! from the SHA-256 IV; SHA3-256 and BLAKE3 parents hash the 64 child-digest bytes.
//! The matrix shape is part of the commitment context, not encoded in its root.

use p3_symmetric::{CompressionFunctionFromHasher, CryptographicHasher, PseudoCompressionFunction};
use sha3::Digest as _;

/// A 256-bit digest; all built-in suites use the full 32-byte output.
pub type Digest = [u8; 32];

/// Statically dispatched Plonky3 hash suite for byte matrices.
///
/// The associated types are the actual Plonky3 hasher/compressor interfaces so
/// the same configuration can be passed to the upstream Merkle implementation.
/// These byte hashers use one scalar byte per input item, not packed SIMD lanes.
/// Changing either primitive changes the commitment scheme and its roots.
/// Implement experiments through the associated primitive types: the tree calls
/// those directly. The convenience methods below must agree with those primitives.
pub trait HashFunction: Copy + Send + Sync + 'static {
    const NAME: &'static str;

    type LeafHasher: CryptographicHasher<u8, Digest> + Send + Sync;
    type NodeCompressor: PseudoCompressionFunction<Digest, 2> + Send + Sync;

    fn leaf_hasher() -> Self::LeafHasher;
    fn node_compressor() -> Self::NodeCompressor;

    /// Follow Plonky3's scalar matrix-row hashing path, including its buffered
    /// iterator adapter. Benchmarks therefore include the same adapter cost.
    #[inline]
    fn hash_leaf(bytes: &[u8]) -> Digest {
        Self::leaf_hasher().hash_iter(bytes.iter().copied())
    }

    /// Hash the exact little-endian byte encoding of the elements.
    #[inline]
    fn hash_leaf_u32(elements: &[u32]) -> Digest {
        #[cfg(target_endian = "little")]
        {
            Self::hash_leaf(bytemuck::cast_slice(elements))
        }
        #[cfg(target_endian = "big")]
        {
            Self::leaf_hasher().hash_iter(elements.iter().flat_map(|element| element.to_le_bytes()))
        }
    }

    #[inline]
    fn hash_nodes(left: &Digest, right: &Digest) -> Digest {
        Self::node_compressor().compress([*left, *right])
    }
}

/// Standard SHA-256 leaves and Plonky3's single, unpadded SHA-256 parent compression.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sha256;

impl HashFunction for Sha256 {
    const NAME: &'static str = "sha256";

    type LeafHasher = p3_sha256::Sha256;
    type NodeCompressor = p3_sha256::Sha256Compress;

    #[inline]
    fn leaf_hasher() -> Self::LeafHasher {
        p3_sha256::Sha256
    }

    #[inline]
    fn node_compressor() -> Self::NodeCompressor {
        p3_sha256::Sha256Compress
    }
}

/// NIST SHA3-256 for both leaves and concatenated child digests.
///
/// Plonky3's Keccak hasher is a different function. This adapter preserves the
/// requested NIST SHA3 padding and is usable directly with upstream Plonky3.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sha3_256;

impl CryptographicHasher<u8, Digest> for Sha3_256 {
    fn hash_iter<I>(&self, input: I) -> Digest
    where
        I: IntoIterator<Item = u8>,
    {
        // Match the buffering strategy in p3-sha256 and p3-blake3 0.6.3.
        let mut hasher = sha3::Sha3_256::new();
        p3_util::apply_to_chunks::<512, _, _>(input, |bytes| hasher.update(bytes));
        hasher.finalize().into()
    }

    fn hash_iter_slices<'a, I>(&self, input: I) -> Digest
    where
        I: IntoIterator<Item = &'a [u8]>,
    {
        let mut hasher = sha3::Sha3_256::new();
        for bytes in input {
            hasher.update(bytes);
        }
        hasher.finalize().into()
    }
}

impl HashFunction for Sha3_256 {
    const NAME: &'static str = "sha3-256";

    type LeafHasher = Self;
    type NodeCompressor = CompressionFunctionFromHasher<Self, 2, 32>;

    #[inline]
    fn leaf_hasher() -> Self::LeafHasher {
        Self
    }

    #[inline]
    fn node_compressor() -> Self::NodeCompressor {
        CompressionFunctionFromHasher::new(Self)
    }
}

/// Plonky3's standard unkeyed BLAKE3 for leaves and concatenated child digests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Blake3;

impl HashFunction for Blake3 {
    const NAME: &'static str = "blake3";

    type LeafHasher = p3_blake3::Blake3;
    type NodeCompressor = CompressionFunctionFromHasher<p3_blake3::Blake3, 2, 32>;

    #[inline]
    fn leaf_hasher() -> Self::LeafHasher {
        p3_blake3::Blake3
    }

    #[inline]
    fn node_compressor() -> Self::NodeCompressor {
        CompressionFunctionFromHasher::new(p3_blake3::Blake3)
    }
}
