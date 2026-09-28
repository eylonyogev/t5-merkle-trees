//! Direct conformance with the pinned, unmodified Plonky3 implementation.
//!
//! Byte matrices deliberately use canonical little-endian u32 encodings, rather
//! than Plonky3 field hash adapters (which define a different commitment scheme).

use binary_merkle_tree::{Blake3, HashFunction, MerkleTree, Sha3_256, Sha256};
use p3_commit::{BatchOpeningRef, Mmcs};
use p3_matrix::{Dimensions, dense::RowMajorMatrixView};
use p3_merkle_tree::MerkleTreeMmcs;

type Upstream<H> = MerkleTreeMmcs<
    u8,
    u8,
    <H as HashFunction>::LeafHasher,
    <H as HashFunction>::NodeCompressor,
    2,
    32,
>;

fn check_matrix<H: HashFunction>(bytes: &[u8], width: usize) {
    let height = bytes.len() / width;
    let mmcs = Upstream::<H>::new(H::leaf_hasher(), H::node_compressor(), 0);
    let matrix = RowMajorMatrixView::new(bytes, width);
    let dimensions = [Dimensions { width, height }];
    let (upstream_root, upstream_tree) = mmcs.commit_matrix(matrix);
    let tree = MerkleTree::<H>::commit_bytes(bytes, width).unwrap();
    assert_eq!(upstream_root.num_roots(), 1);
    assert_eq!(tree.root(), upstream_root[0]);

    for index in 0..height {
        let upstream_opening = mmcs.open_batch(index, &upstream_tree);
        let proof = tree.open(index).unwrap();
        let leaf = &bytes[index * width..(index + 1) * width];
        assert_eq!(upstream_opening.opened_values, vec![leaf.to_vec()]);
        assert_eq!(proof.siblings, upstream_opening.opening_proof);

        // Our verifier accepts an upstream path against an upstream root.
        tree.commitment()
            .verify_bytes(index, leaf, &upstream_opening.opening_proof)
            .unwrap();
        // Upstream accepts our path with identical public dimensions and root.
        mmcs.verify_batch(
            &upstream_root,
            &dimensions,
            index,
            BatchOpeningRef::new(&upstream_opening.opened_values, &proof.siblings),
        )
        .unwrap();
    }
}

fn check_suite<H: HashFunction>() {
    for leaf_count in [1, 2, 4, 8, 32, 64] {
        for width in [1, 3, 16, 34, 257] {
            let words: Vec<_> = (0..leaf_count * width)
                .map(|index| (index as u32).wrapping_mul(0x9e37_79b9).rotate_left(11))
                .collect();
            let bytes: Vec<_> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
            let tree = MerkleTree::<H>::commit_u32(&words, width).unwrap();
            let byte_tree = MerkleTree::<H>::commit_bytes(&bytes, width * 4).unwrap();
            assert_eq!(tree.root(), byte_tree.root());
            check_matrix::<H>(&bytes, width * 4);
        }
    }
    // Exercise byte widths across all three hash functions' block boundaries.
    for width in [
        1, 3, 55, 56, 63, 64, 65, 135, 136, 137, 511, 512, 513, 1023, 1024, 1025, 65536,
    ] {
        let bytes: Vec<_> = (0..width * 2)
            .map(|index| (index * 29 + 41) as u8)
            .collect();
        check_matrix::<H>(&bytes, width);
    }
}

#[test]
fn sha256_roots_paths_and_verifiers_match_plonky3() {
    check_suite::<Sha256>();
}

#[test]
fn sha3_roots_paths_and_verifiers_match_plonky3() {
    check_suite::<Sha3_256>();
}

#[test]
fn blake3_roots_paths_and_verifiers_match_plonky3() {
    check_suite::<Blake3>();
}
