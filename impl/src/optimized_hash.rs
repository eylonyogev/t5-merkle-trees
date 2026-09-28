//! Root-preserving hashing shortcuts for the optimized tree.
//!
//! Each batch is evaluated on one thread. The tree controls Rayon work granularity;
//! these routines use the primitive's independent-message SIMD where available.
//! BLAKE3's `platform` interface is explicitly unstable upstream, so its dependency
//! is pinned and its use is confined to this module.

use crate::{Blake3, Digest, HashFunction, Sha3_256, Sha256};
use keccak::{Backend, BackendClosure, ParState1600};
use sha3::Digest as _;

/// Root-preserving implementation options for a [`HashFunction`].
///
/// Custom suites can supply the two scalar operations and inherit scalar batching.
/// The batches do not start threads and preserve input order.
pub trait OptimizedHash: HashFunction {
    /// Unit counted by [`Self::standard_leaf_calls`].
    const PRIMITIVE_NAME: &'static str;

    fn hash_leaf_fast(bytes: &[u8]) -> Digest;

    /// Hash complete, equally sized rows into `output` without allocation.
    ///
    /// # Panics
    /// Panics if `leaf_bytes` is zero or the input and output shapes disagree.
    fn hash_leaves_fast(input: &[u8], leaf_bytes: usize, output: &mut [Digest]) {
        check_leaf_batch(input, leaf_bytes, output.len());
        for (row, digest) in input.chunks_exact(leaf_bytes).zip(output) {
            *digest = Self::hash_leaf_fast(row);
        }
    }

    fn hash_node_fast(left: &Digest, right: &Digest) -> Digest {
        Self::hash_nodes(left, right)
    }

    /// Hash consecutive child pairs into `output` without allocation.
    ///
    /// # Panics
    /// Panics unless `children.len() == 2 * output.len()`.
    fn hash_nodes_fast(children: &[Digest], output: &mut [Digest]) {
        check_node_batch(children, output.len());
        for (pair, digest) in children.chunks_exact(2).zip(output) {
            *digest = Self::hash_node_fast(&pair[0], &pair[1]);
        }
    }

    /// Actual primitive calls required by the standard leaf hash, including
    /// padding and BLAKE3's internal chunk tree. SIMD changes throughput, not this
    /// count. Merkle-tree parent calls are accounted for separately.
    fn standard_leaf_calls(bytes: usize) -> u64;
}

impl OptimizedHash for Sha256 {
    const PRIMITIVE_NAME: &'static str = "SHA-256 compression";

    #[inline]
    fn hash_leaf_fast(bytes: &[u8]) -> Digest {
        sha2::Sha256::digest(bytes).into()
    }

    fn standard_leaf_calls(bytes: usize) -> u64 {
        (bytes / 64) as u64 + 1 + u64::from(bytes % 64 >= 56)
    }
}

impl OptimizedHash for Sha3_256 {
    const PRIMITIVE_NAME: &'static str = "Keccak-f[1600] permutation";

    #[inline]
    fn hash_leaf_fast(bytes: &[u8]) -> Digest {
        sha3::Sha3_256::digest(bytes).into()
    }

    fn hash_leaves_fast(input: &[u8], leaf_bytes: usize, output: &mut [Digest]) {
        check_leaf_batch(input, leaf_bytes, output.len());
        if output.is_empty() {
            return;
        }
        keccak::Keccak::new().with_backend(Sha3Batch {
            input,
            leaf_bytes,
            output,
        });
    }

    #[inline]
    fn hash_node_fast(left: &Digest, right: &Digest) -> Digest {
        Self::hash_leaf_fast(&join_digests(left, right))
    }

    fn hash_nodes_fast(children: &[Digest], output: &mut [Digest]) {
        check_node_batch(children, output.len());
        Self::hash_leaves_fast(bytemuck::cast_slice(children), 64, output);
    }

    fn standard_leaf_calls(bytes: usize) -> u64 {
        (bytes / SHA3_RATE) as u64 + 1
    }
}

impl OptimizedHash for Blake3 {
    const PRIMITIVE_NAME: &'static str = "BLAKE3 compression";

    #[inline]
    fn hash_leaf_fast(bytes: &[u8]) -> Digest {
        // A complete slice exposes all chunks to BLAKE3's own SIMD scheduler.
        // The upstream byte iterator instead feeds 512-byte updates.
        blake3::hash(bytes).into()
    }

    fn hash_leaves_fast(input: &[u8], leaf_bytes: usize, output: &mut [Digest]) {
        check_leaf_batch(input, leaf_bytes, output.len());
        match leaf_bytes {
            64 => blake3_hash_many::<64>(input, output),
            128 => blake3_hash_many::<128>(input, output),
            256 => blake3_hash_many::<256>(input, output),
            512 => blake3_hash_many::<512>(input, output),
            1024 => blake3_hash_many::<1024>(input, output),
            _ => {
                for (row, digest) in input.chunks_exact(leaf_bytes).zip(output) {
                    *digest = Self::hash_leaf_fast(row);
                }
            }
        }
    }

    #[inline]
    fn hash_node_fast(left: &Digest, right: &Digest) -> Digest {
        Self::hash_leaf_fast(&join_digests(left, right))
    }

    fn hash_nodes_fast(children: &[Digest], output: &mut [Digest]) {
        check_node_batch(children, output.len());
        blake3_hash_many::<64>(bytemuck::cast_slice(children), output);
    }

    fn standard_leaf_calls(bytes: usize) -> u64 {
        let blocks = bytes.div_ceil(64).max(1) as u64;
        let chunks = bytes.div_ceil(1024).max(1) as u64;
        blocks + chunks - 1
    }
}

#[inline]
fn check_leaf_batch(input: &[u8], leaf_bytes: usize, output_len: usize) {
    assert!(leaf_bytes != 0, "leaf byte count must be positive");
    assert_eq!(
        Some(input.len()),
        output_len.checked_mul(leaf_bytes),
        "leaf batch input and output shapes must agree"
    );
}

#[inline]
fn check_node_batch(children: &[Digest], output_len: usize) {
    assert_eq!(
        Some(children.len()),
        output_len.checked_mul(2),
        "node batch must have two children per output"
    );
}

#[inline]
fn join_digests(left: &Digest, right: &Digest) -> [u8; 64] {
    let mut input = [0; 64];
    input[..32].copy_from_slice(left);
    input[32..].copy_from_slice(right);
    input
}

const SHA3_RATE: usize = 136;

struct Sha3Batch<'a> {
    input: &'a [u8],
    leaf_bytes: usize,
    output: &'a mut [Digest],
}

impl BackendClosure for Sha3Batch<'_> {
    fn call_once<B: Backend>(self) {
        let mut states = ParState1600::<B>::default();
        let lanes = states.len();
        let permute = B::get_par_f1600();
        let full_bytes = self.leaf_bytes / SHA3_RATE * SHA3_RATE;
        let remainder = self.leaf_bytes % SHA3_RATE;

        for (rows, output) in self
            .input
            .chunks(self.leaf_bytes.saturating_mul(lanes))
            .zip(self.output.chunks_mut(lanes))
        {
            states.fill([0; 25]);
            for block_start in (0..full_bytes).step_by(SHA3_RATE) {
                for (state, row) in states.iter_mut().zip(rows.chunks_exact(self.leaf_bytes)) {
                    xor_sha3_block(state, &row[block_start..block_start + SHA3_RATE]);
                }
                permute(&mut states);
            }

            for (state, row) in states.iter_mut().zip(rows.chunks_exact(self.leaf_bytes)) {
                xor_sha3_block(state, &row[full_bytes..]);
                // SHA3 suffix 0x06, including the case where suffix and final
                // padding bit occupy the same byte. A full rate block always
                // receives an additional, empty padded block.
                state[remainder / 8] ^= 0x06_u64 << (8 * (remainder % 8));
                state[16] ^= 0x80_u64 << 56;
            }
            permute(&mut states);

            for (state, digest) in states.iter().zip(output) {
                for (word, bytes) in state[..4].iter().zip(digest.chunks_exact_mut(8)) {
                    bytes.copy_from_slice(&word.to_le_bytes());
                }
            }
        }
    }
}

#[inline]
fn xor_sha3_block(state: &mut [u64; 25], block: &[u8]) {
    let mut words = block.chunks_exact(8);
    for (word, bytes) in state.iter_mut().zip(words.by_ref()) {
        *word ^= u64::from_le_bytes(bytes.try_into().unwrap());
    }
    let remainder = words.remainder();
    if !remainder.is_empty() {
        let word = &mut state[block.len() / 8];
        for (shift, &byte) in remainder.iter().enumerate() {
            *word ^= u64::from(byte) << (8 * shift);
        }
    }
}

/// Hash independent full-block messages within one BLAKE3 chunk. ROOT belongs
/// on the *last* block only; placing it in `flags` would corrupt multi-block
/// hashes. The input counter remains zero for every independent message.
fn blake3_hash_many<const BYTES: usize>(input: &[u8], output: &mut [Digest]) {
    const WIDTH: usize = blake3::platform::MAX_SIMD_DEGREE;
    const CHUNK_START: u8 = 1;
    const CHUNK_END: u8 = 2;
    const ROOT: u8 = 8;
    let platform = blake3::platform::Platform::detect();
    let dummy = [0; BYTES];
    let mut inputs = [&dummy; WIDTH];
    for (rows, digests) in input.chunks(BYTES * WIDTH).zip(output.chunks_mut(WIDTH)) {
        for (target, row) in inputs.iter_mut().zip(rows.chunks_exact(BYTES)) {
            *target = row.try_into().unwrap();
        }
        platform.hash_many(
            &inputs[..digests.len()],
            &p3_sha256::H256_256,
            0,
            blake3::IncrementCounter::No,
            0,
            CHUNK_START,
            CHUNK_END | ROOT,
            bytemuck::cast_slice_mut(digests),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| i.wrapping_mul(193).wrapping_add(i / 23) as u8)
            .collect()
    }

    fn check_suite<H: OptimizedHash>(reference: impl Fn(&[u8]) -> Digest) {
        let widths = [
            0, 1, 4, 7, 8, 31, 32, 55, 56, 63, 64, 65, 95, 96, 127, 128, 135, 136, 137, 255, 256,
            271, 272, 273, 511, 512, 513, 1023, 1024, 1025, 2048, 4096, 65_536,
        ];
        for width in widths {
            let bytes = data(width);
            assert_eq!(
                H::hash_leaf_fast(&bytes),
                reference(&bytes),
                "width={width}"
            );
            assert_eq!(H::hash_leaf_fast(&bytes), H::hash_leaf(&bytes));
            if width == 0 {
                continue;
            }
            // Empty batches, partially occupied vectors, whole vectors and
            // multiple vectors exercise every backend's tail handling.
            for count in [0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17] {
                let input = data(width * count);
                let mut output = vec![[0; 32]; count];
                H::hash_leaves_fast(&input, width, &mut output);
                for (row, digest) in input.chunks_exact(width).zip(output) {
                    assert_eq!(digest, reference(row), "width={width}, count={count}");
                }
            }
        }

        for count in [0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 65] {
            let children: Vec<Digest> = data(count * 64)
                .chunks_exact(32)
                .map(|bytes| bytes.try_into().unwrap())
                .collect();
            let mut output = vec![[0; 32]; count];
            H::hash_nodes_fast(&children, &mut output);
            for (pair, digest) in children.chunks_exact(2).zip(output) {
                assert_eq!(digest, H::hash_nodes(&pair[0], &pair[1]));
                assert_eq!(digest, H::hash_node_fast(&pair[0], &pair[1]));
            }
        }
    }

    #[test]
    fn sha256_matches_standard_and_upstream() {
        check_suite::<Sha256>(|bytes| sha2::Sha256::digest(bytes).into());
    }

    #[test]
    fn sha3_matches_standard_and_upstream() {
        check_suite::<Sha3_256>(|bytes| sha3::Sha3_256::digest(bytes).into());
    }

    #[test]
    fn blake3_matches_standard_and_upstream() {
        check_suite::<Blake3>(|bytes| blake3::hash(bytes).into());
    }

    #[test]
    fn primitive_counts_include_padding_and_chunk_tree() {
        for (bytes, sha256, sha3, blake3) in [
            (0, 1, 1, 1),
            (55, 1, 1, 1),
            (56, 2, 1, 1),
            (64, 2, 1, 1),
            (65, 2, 1, 2),
            (135, 3, 1, 3),
            (136, 3, 2, 3),
            (256, 5, 2, 4),
            (1024, 17, 8, 16),
            (1025, 17, 8, 18),
            (2048, 33, 16, 33),
            (65_536, 1025, 482, 1087),
        ] {
            assert_eq!(Sha256::standard_leaf_calls(bytes), sha256);
            assert_eq!(Sha3_256::standard_leaf_calls(bytes), sha3);
            assert_eq!(Blake3::standard_leaf_calls(bytes), blake3);
        }
    }

    #[test]
    #[should_panic(expected = "leaf byte count must be positive")]
    fn rejects_zero_width() {
        Sha256::hash_leaves_fast(&[], 0, &mut []);
    }

    #[test]
    #[should_panic(expected = "leaf batch input and output shapes must agree")]
    fn rejects_partial_row() {
        Sha3_256::hash_leaves_fast(&[0; 65], 64, &mut [[0; 32]]);
    }

    #[test]
    #[should_panic(expected = "node batch must have two children per output")]
    fn rejects_odd_children() {
        Blake3::hash_nodes_fast(&[[0; 32]; 3], &mut [[0; 32]]);
    }
}
