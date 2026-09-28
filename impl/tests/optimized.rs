//! Differential and adversarial tests for the optimized tree. Standard mode
//! must preserve the pinned Plonky3 baseline's roots and authentication paths.

use binary_merkle_tree::{
    Blake3, Error, LeafMode, MerkleTree, OptimizedCommitment, OptimizedMerkleTree, ResearchHash,
    Sha3_256, Sha256,
};

fn bytes(length: usize) -> Vec<u8> {
    (0..length)
        .map(|index| index.wrapping_mul(37).wrapping_add(index / 251) as u8)
        .collect()
}

fn words(length: usize) -> Vec<u32> {
    (0..length)
        .map(|index| (index as u32).wrapping_mul(0x9e37_79b9).rotate_left(13))
        .collect()
}

fn encode(input: &[u32]) -> Vec<u8> {
    input.iter().flat_map(|word| word.to_le_bytes()).collect()
}

fn standard_differential<H: ResearchHash>() {
    for leaf_count in [1_usize, 2, 4, 8, 32] {
        for width in [
            1, 3, 4, 7, 31, 32, 55, 56, 63, 64, 65, 95, 96, 127, 128, 135, 136, 137, 255, 256, 271,
            272, 511, 512, 513, 1023, 1024, 1025, 65_536,
        ] {
            let input = bytes(leaf_count * width);
            let baseline = MerkleTree::<H>::commit_bytes(&input, width).unwrap();
            let tree =
                OptimizedMerkleTree::<H>::commit_bytes(&input, width, LeafMode::Standard).unwrap();
            let imported = OptimizedCommitment::<H>::from_root(
                tree.root(),
                leaf_count,
                width,
                LeafMode::Standard,
            )
            .unwrap();
            assert_eq!(tree.root(), baseline.root());
            assert_eq!(tree.height(), leaf_count.ilog2() as usize);
            assert_eq!(tree.node_count(), 2 * leaf_count - 1);
            assert_eq!(tree.storage_bytes(), (2 * leaf_count - 1) * 32);
            assert_eq!(imported.mode(), LeafMode::Standard);
            for index in 0..leaf_count {
                let proof = tree.open(index).unwrap();
                assert_eq!(proof, baseline.open(index).unwrap());
                let leaf = &input[index * width..(index + 1) * width];
                imported.verify_bytes(index, leaf, &proof.siblings).unwrap();
                baseline
                    .commitment()
                    .verify_bytes(index, leaf, &proof.siblings)
                    .unwrap();
                let mut reused = vec![[99; 32]; 17];
                tree.open_into(index, &mut reused).unwrap();
                assert_eq!(reused, proof.siblings);
            }
        }
    }
}

#[test]
fn standard_sha256_preserves_roots_and_all_paths() {
    standard_differential::<Sha256>();
}

#[test]
fn standard_sha3_preserves_roots_and_all_paths() {
    standard_differential::<Sha3_256>();
}

#[test]
fn standard_blake3_preserves_roots_and_all_paths() {
    standard_differential::<Blake3>();
}

fn canonical_u32<H: ResearchHash>() {
    for exponent in 0..=14 {
        let width = 1 << exponent;
        let input = words(4 * width);
        let canonical = encode(&input);
        let tree = OptimizedMerkleTree::<H>::commit_u32(&input, width, LeafMode::Standard).unwrap();
        let byte_tree =
            OptimizedMerkleTree::<H>::commit_bytes(&canonical, width * 4, LeafMode::Standard)
                .unwrap();
        let baseline = MerkleTree::<H>::commit_u32(&input, width).unwrap();
        assert_eq!(tree.root(), byte_tree.root());
        assert_eq!(tree.root(), baseline.root());
        for index in 0..4 {
            let proof = tree.open(index).unwrap();
            tree.commitment()
                .verify_u32(
                    index,
                    &input[index * width..(index + 1) * width],
                    &proof.siblings,
                )
                .unwrap();
        }
    }
}

#[test]
fn requested_matrix_widths_preserve_canonical_encoding() {
    canonical_u32::<Sha256>();
    canonical_u32::<Sha3_256>();
    canonical_u32::<Blake3>();
}

fn parallel_shapes<H: ResearchHash>() {
    for count in [512, 1024, 2048, 4096, 8192] {
        for width in [4, 64] {
            let input = bytes(count * width);
            let baseline = MerkleTree::<H>::commit_bytes(&input, width).unwrap();
            let tree =
                OptimizedMerkleTree::<H>::commit_bytes(&input, width, LeafMode::Standard).unwrap();
            assert_eq!(tree.root(), baseline.root());
            for index in [0, 1, 127, 128, 255, 256, count / 2, count - 2, count - 1] {
                assert_eq!(tree.open(index).unwrap(), baseline.open(index).unwrap());
            }
        }
    }
}

#[test]
fn parallel_chunk_boundaries_preserve_paths() {
    parallel_shapes::<Sha256>();
    parallel_shapes::<Sha3_256>();
    parallel_shapes::<Blake3>();
}

fn malformed_openings<H: ResearchHash>(mode: LeafMode, width: usize) {
    let input = bytes(8 * width);
    let tree = OptimizedMerkleTree::<H>::commit_bytes(&input, width, mode).unwrap();
    let commitment = tree.commitment();
    let proof = tree.open(5).unwrap();
    let leaf = &input[5 * width..6 * width];
    let mut altered = leaf.to_vec();
    altered[width / 2] ^= 1;
    assert_eq!(
        commitment.verify_bytes(5, &altered, &proof.siblings),
        Err(Error::RootMismatch)
    );
    for index in [0, 4, 6, 7] {
        assert_eq!(
            commitment.verify_bytes(index, leaf, &proof.siblings),
            Err(Error::RootMismatch)
        );
    }
    for level in 0..proof.siblings.len() {
        let mut altered = proof.siblings.clone();
        altered[level][level] ^= 1;
        assert_eq!(
            commitment.verify_bytes(5, leaf, &altered),
            Err(Error::RootMismatch)
        );
    }
    let mut surplus = proof.siblings.clone();
    surplus.push([0; 32]);
    assert_eq!(
        commitment.verify_bytes(5, leaf, &surplus),
        Err(Error::InvalidProofLength)
    );
    assert_eq!(
        commitment.verify_bytes(5, leaf, &proof.siblings[1..]),
        Err(Error::InvalidProofLength)
    );
    assert_eq!(
        commitment.verify_bytes(5, &leaf[1..], &proof.siblings),
        Err(Error::InvalidLeafSize)
    );
    for invalid in [8, usize::MAX] {
        assert_eq!(
            commitment.verify_bytes(invalid, leaf, &proof.siblings),
            Err(Error::IndexOutOfBounds)
        );
        let mut buffer = vec![[77; 32]; 9];
        assert_eq!(
            tree.open_into(invalid, &mut buffer),
            Err(Error::IndexOutOfBounds)
        );
        assert_eq!(buffer, vec![[77; 32]; 9]);
        assert_eq!(tree.open(invalid).err(), Some(Error::IndexOutOfBounds));
    }
    let mut bad_root = tree.root();
    bad_root[31] ^= 1;
    assert_eq!(
        OptimizedCommitment::<H>::from_root(bad_root, 8, width, mode)
            .unwrap()
            .verify_bytes(5, leaf, &proof.siblings),
        Err(Error::RootMismatch)
    );
    assert_eq!(
        OptimizedCommitment::<H>::from_root(tree.root(), 4, width, mode)
            .unwrap()
            .verify_bytes(1, leaf, &proof.siblings),
        Err(Error::InvalidProofLength)
    );
}

#[test]
fn standard_rejects_malformed_and_tampered_openings() {
    malformed_openings::<Sha256>(LeafMode::Standard, 12);
    malformed_openings::<Sha3_256>(LeafMode::Standard, 12);
    malformed_openings::<Blake3>(LeafMode::Standard, 12);
}

#[test]
fn invalid_shapes_and_overflow_are_rejected_before_allocation() {
    for (input, width, error) in [
        (&[][..], 1, Error::EmptyInput),
        (&[1][..], 0, Error::InvalidLeafSize),
        (&[1, 2, 3][..], 1, Error::InvalidShape),
        (&[1, 2, 3][..], 2, Error::InvalidShape),
    ] {
        assert_eq!(
            OptimizedMerkleTree::<Blake3>::commit_bytes(input, width, LeafMode::Standard).err(),
            Some(error)
        );
    }
    for (count, width, error) in [
        (0, 4, Error::EmptyInput),
        (3, 4, Error::InvalidShape),
        (1, 0, Error::InvalidLeafSize),
        (2, usize::MAX, Error::SizeOverflow),
        (1, isize::MAX as usize + 1, Error::SizeOverflow),
        (1 << (usize::BITS - 1), 1, Error::SizeOverflow),
    ] {
        assert_eq!(
            OptimizedCommitment::<Blake3>::from_root([0; 32], count, width, LeafMode::Standard)
                .err(),
            Some(error)
        );
    }
    assert_eq!(
        OptimizedMerkleTree::<Blake3>::commit_u32(&[], 1, LeafMode::Standard).err(),
        Some(Error::EmptyInput)
    );
    assert_eq!(
        OptimizedMerkleTree::<Blake3>::commit_u32(&[1, 2], 0, LeafMode::Standard).err(),
        Some(Error::InvalidLeafSize)
    );
    assert_eq!(
        OptimizedMerkleTree::<Blake3>::commit_u32(&[1], usize::MAX, LeafMode::Standard).err(),
        Some(Error::InvalidShape)
    );
}

fn recommit<H: ResearchHash>(mode: LeafMode, width: usize) {
    let mut input = words(32 * width);
    let mut tree = OptimizedMerkleTree::<H>::commit_u32(&input, width, mode).unwrap();
    let original_root = tree.root();
    let original_proof = tree.open(11).unwrap();
    let original_bytes = encode(&input);
    assert!(
        tree.recommit_bytes(&original_bytes[..original_bytes.len() - 1])
            .is_err()
    );
    assert!(tree.recommit_u32(&input[..input.len() - 1]).is_err());
    assert_eq!(tree.root(), original_root);
    assert_eq!(tree.open(11).unwrap(), original_proof);
    for value in &mut input {
        *value = value.rotate_right(7) ^ 0x1234_5678;
    }
    tree.recommit_u32(&input).unwrap();
    let expected = OptimizedMerkleTree::<H>::commit_u32(&input, width, mode).unwrap();
    assert_ne!(tree.root(), original_root);
    assert_eq!(tree.root(), expected.root());
    for index in 0..32 {
        assert_eq!(tree.open(index).unwrap(), expected.open(index).unwrap());
        tree.commitment()
            .verify_u32(
                index,
                &input[index * width..(index + 1) * width],
                &tree.open(index).unwrap().siblings,
            )
            .unwrap();
    }
    tree.recommit_bytes(&original_bytes).unwrap();
    assert_eq!(tree.root(), original_root);
    assert_eq!(tree.open(11).unwrap(), original_proof);
}

#[test]
fn recommit_preserves_shape_and_rebuilds_every_layer() {
    recommit::<Sha256>(LeafMode::Standard, 16);
    recommit::<Sha3_256>(LeafMode::Standard, 34);
    recommit::<Blake3>(LeafMode::Standard, 256);
}

const EXPERIMENTAL_MODES: [LeafMode; 4] = [
    LeafMode::FixedMd,
    LeafMode::T5,
    LeafMode::T8,
    LeafMode::Abr3,
];

fn experimental_roundtrip<H: ResearchHash>(modes: &[LeafMode]) {
    for &mode in modes {
        for width in [
            1, 31, 32, 63, 64, 65, 127, 128, 159, 160, 161, 252, 253, 254, 255, 256, 257, 287, 288,
            351, 352, 353, 473, 474, 475, 480, 1024, 4096,
        ] {
            for count in [1, 2, 8] {
                let input = bytes(count * width);
                let tree = OptimizedMerkleTree::<H>::commit_bytes(&input, width, mode).unwrap();
                let commitment =
                    OptimizedCommitment::<H>::from_root(tree.root(), count, width, mode).unwrap();
                assert_eq!(commitment.mode(), mode);
                let standard =
                    OptimizedMerkleTree::<H>::commit_bytes(&input, width, LeafMode::Standard)
                        .unwrap();
                let wrong_mode = OptimizedCommitment::<H>::from_root(
                    tree.root(),
                    count,
                    width,
                    LeafMode::Standard,
                )
                .unwrap();
                for index in 0..count {
                    let proof = tree.open(index).unwrap();
                    let leaf = &input[index * width..(index + 1) * width];
                    commitment
                        .verify_bytes(index, leaf, &proof.siblings)
                        .unwrap();
                    let mut altered = leaf.to_vec();
                    altered[width - 1] ^= 0x80;
                    assert_eq!(
                        commitment.verify_bytes(index, &altered, &proof.siblings),
                        Err(Error::RootMismatch),
                        "{mode:?}, width={width}"
                    );
                    // Some strategies intentionally use the standard hash for
                    // short records. Mode metadata is trusted protocol context;
                    // roots need not distinguish modes taking the same path.
                    if count == 1 && tree.root() != standard.root() {
                        assert_eq!(
                            wrong_mode.verify_bytes(index, leaf, &proof.siblings),
                            Err(Error::RootMismatch)
                        );
                    }
                    if width.is_multiple_of(4) {
                        let word_leaf: Vec<_> = leaf
                            .chunks_exact(4)
                            .map(|word| u32::from_le_bytes(word.try_into().unwrap()))
                            .collect();
                        commitment
                            .verify_u32(index, &word_leaf, &proof.siblings)
                            .unwrap();
                    }
                }
            }
        }
        malformed_openings::<H>(mode, 352);
        recommit::<H>(mode, 96);
    }
}

#[test]
fn experimental_sha256_openings_and_recommit() {
    experimental_roundtrip::<Sha256>(&EXPERIMENTAL_MODES);
    experimental_roundtrip::<Sha256>(&[LeafMode::T253]);
}

#[test]
fn experimental_sha3_openings_and_recommit() {
    experimental_roundtrip::<Sha3_256>(&EXPERIMENTAL_MODES);
}

#[test]
fn experimental_blake3_openings_and_recommit() {
    experimental_roundtrip::<Blake3>(&EXPERIMENTAL_MODES);
}

#[test]
fn sha256_specific_mode_rejects_other_suites() {
    assert_eq!(
        OptimizedMerkleTree::<Sha3_256>::commit_bytes(&bytes(256), 256, LeafMode::T253).err(),
        Some(Error::UnsupportedMode)
    );
    assert_eq!(
        OptimizedMerkleTree::<Blake3>::commit_bytes(&bytes(256), 256, LeafMode::T253).err(),
        Some(Error::UnsupportedMode)
    );
    assert_eq!(
        OptimizedCommitment::<Sha3_256>::from_root([0; 32], 1, 256, LeafMode::T253).err(),
        Some(Error::UnsupportedMode)
    );
    assert_eq!(
        OptimizedCommitment::<Blake3>::from_root([0; 32], 1, 256, LeafMode::T253).err(),
        Some(Error::UnsupportedMode)
    );
}

#[test]
fn single_leaf_has_an_empty_proof_and_still_checks_shape() {
    let tree =
        OptimizedMerkleTree::<Blake3>::commit_bytes(&[1, 2, 3], 3, LeafMode::Standard).unwrap();
    assert!(tree.open(0).unwrap().siblings.is_empty());
    tree.commitment().verify_bytes(0, &[1, 2, 3], &[]).unwrap();
    assert_eq!(
        tree.commitment().verify_bytes(0, &[1, 2, 3], &[[0; 32]]),
        Err(Error::InvalidProofLength)
    );
    assert_eq!(
        tree.commitment().verify_u32(0, &[0x0003_0201], &[]),
        Err(Error::InvalidLeafSize)
    );
}
