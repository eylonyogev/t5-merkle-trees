//! Public-API coverage for the new whole-record modes. Backend modules contain
//! independent primitive and scalar-reference checks; these check composition.
use binary_merkle_tree::{
    Blake3, Error, LeafMode, LeafPlan, OptimizedCommitment, OptimizedMerkleTree, ResearchHash,
    Sha3_256, Sha256,
};

fn data(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i.wrapping_mul(179) ^ (i >> 3) ^ (i >> 11)) as u8)
        .collect()
}

fn check<H: ResearchHash>(modes: &[LeafMode]) {
    for &mode in modes {
        for width in [
            1, 4, 32, 64, 95, 96, 103, 149, 150, 166, 167, 168, 256, 277, 278, 512, 569, 570, 625,
            626, 1024, 4096, 65_536,
        ] {
            // 8 rows exercise SIMD batches and their Merkle composition.
            let input = data(8 * width);
            let plan = LeafPlan::new::<H>(mode, width).unwrap();
            let mut leaves = [[0; 32]; 8];
            plan.hash_many::<H>(&input, &mut leaves);
            let tree = OptimizedMerkleTree::<H>::commit_bytes(&input, width, mode).unwrap();
            let context = OptimizedCommitment::<H>::from_root(tree.root(), 8, width, mode).unwrap();
            for index in [0, 3, 7] {
                let leaf = &input[index * width..(index + 1) * width];
                assert_eq!(leaves[index], plan.hash::<H>(leaf));
                let proof = tree.open(index).unwrap();
                context.verify_bytes(index, leaf, &proof.siblings).unwrap();
                let mut changed = leaf.to_vec();
                changed[width - 1] ^= 1;
                assert_eq!(
                    context.verify_bytes(index, &changed, &proof.siblings),
                    Err(Error::RootMismatch)
                );
                let mut bad_path = proof.siblings.clone();
                bad_path[0][0] ^= 1;
                assert_eq!(
                    context.verify_bytes(index, leaf, &bad_path),
                    Err(Error::RootMismatch)
                );
                let mut wrong_root = tree.root();
                wrong_root[31] ^= 1;
                let wrong =
                    OptimizedCommitment::<H>::from_root(wrong_root, 8, width, mode).unwrap();
                assert_eq!(
                    wrong.verify_bytes(index, leaf, &proof.siblings),
                    Err(Error::RootMismatch)
                );
            }
        }
        for log in 0..=14 {
            let width = 1 << log;
            let words: Vec<u32> = (0..4 * width)
                .map(|i| (i as u32).wrapping_mul(0x9e37_79b9))
                .collect();
            let encoded: Vec<_> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
            let mut tree = OptimizedMerkleTree::<H>::commit_u32(&words, width, mode).unwrap();
            let byte_tree =
                OptimizedMerkleTree::<H>::commit_bytes(&encoded, 4 * width, mode).unwrap();
            assert_eq!(tree.root(), byte_tree.root());
            for index in [0, 3] {
                let proof = tree.open(index).unwrap();
                tree.commitment()
                    .verify_u32(
                        index,
                        &words[index * width..(index + 1) * width],
                        &proof.siblings,
                    )
                    .unwrap();
            }
            let mut changed = words.clone();
            changed[width] ^= 17;
            tree.recommit_u32(&changed).unwrap();
            let fresh = OptimizedMerkleTree::<H>::commit_u32(&changed, width, mode).unwrap();
            assert_eq!(tree.root(), fresh.root());
            assert_ne!(tree.root(), byte_tree.root());
        }
    }
}

#[test]
fn sha256_wide_records() {
    check::<Sha256>(&[LeafMode::AbrWide]);
}

#[test]
fn blake3_wide_records() {
    check::<Blake3>(&[LeafMode::AbrWide, LeafMode::T277]);
}

#[test]
fn keccak_records() {
    check::<Sha3_256>(&[LeafMode::Shake128, LeafMode::SpongeDm272]);
}

#[test]
fn counts_match_the_independently_generated_candidate_grid() {
    let source = include_str!("../results/candidate-compression-counts.csv");
    let mut checked = 0;
    for line in source.lines().skip(1) {
        let columns: Vec<_> = line.split(',').collect();
        let width = columns[5].parse::<usize>().unwrap();
        let expected = columns[6].parse::<u64>().unwrap();
        let actual = match (columns[0], columns[2]) {
            ("sha256", "abr569-hybrid") => LeafPlan::new::<Sha256>(LeafMode::AbrWide, width)
                .unwrap()
                .native_calls::<Sha256>(),
            ("blake3", "abr625-hybrid") => LeafPlan::new::<Blake3>(LeafMode::AbrWide, width)
                .unwrap()
                .native_calls::<Blake3>(),
            ("blake3", "t277-hybrid") => LeafPlan::new::<Blake3>(LeafMode::T277, width)
                .unwrap()
                .native_calls::<Blake3>(),
            ("sha3_256", "shake128") => LeafPlan::new::<Sha3_256>(LeafMode::Shake128, width)
                .unwrap()
                .native_calls::<Sha3_256>(),
            ("sha3_256", "spongedm-c272-prefix17") => {
                LeafPlan::new::<Sha3_256>(LeafMode::SpongeDm272, width)
                    .unwrap()
                    .native_calls::<Sha3_256>()
            }
            _ => continue,
        };
        assert_eq!(
            actual, expected,
            "{} {} width={width}",
            columns[0], columns[2]
        );
        checked += 1;
    }
    assert_eq!(checked, 75);
}

#[test]
fn incompatible_backends_are_rejected() {
    for mode in [LeafMode::Shake128, LeafMode::SpongeDm272] {
        assert_eq!(
            LeafPlan::new::<Sha256>(mode, 1024),
            Err(Error::UnsupportedMode)
        );
        assert_eq!(
            LeafPlan::new::<Blake3>(mode, 1024),
            Err(Error::UnsupportedMode)
        );
    }
    for mode in [LeafMode::AbrWide, LeafMode::T277] {
        assert_eq!(
            LeafPlan::new::<Sha3_256>(mode, 1024),
            Err(Error::UnsupportedMode)
        );
    }
    assert_eq!(
        LeafPlan::new::<Sha256>(LeafMode::T277, 1024),
        Err(Error::UnsupportedMode)
    );
    let plan = LeafPlan::new::<Sha256>(LeafMode::AbrWide, 4).unwrap();
    assert!(std::panic::catch_unwind(|| plan.hash::<Blake3>(&[0; 4])).is_err());
    let plan = LeafPlan::new::<Sha3_256>(LeafMode::Shake128, 4).unwrap();
    assert!(
        std::panic::catch_unwind(|| plan.hash_many::<Blake3>(&[0; 4], &mut [[0; 32]])).is_err()
    );
}

#[test]
fn empty_batches_do_not_overflow_a_large_public_width() {
    let width = 1usize << (usize::BITS - 2);
    for mode in [LeafMode::AbrWide, LeafMode::T277] {
        let plan = LeafPlan::new::<Blake3>(mode, width).unwrap();
        plan.hash_many::<Blake3>(&[], &mut []);
    }
    LeafPlan::new::<Sha256>(LeafMode::AbrWide, width)
        .unwrap()
        .hash_many::<Sha256>(&[], &mut []);
    for mode in [LeafMode::Shake128, LeafMode::SpongeDm272] {
        LeafPlan::new::<Sha3_256>(mode, width)
            .unwrap()
            .hash_many::<Sha3_256>(&[], &mut []);
    }
}
