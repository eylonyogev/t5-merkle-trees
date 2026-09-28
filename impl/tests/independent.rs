//! Independent recursive trees, fixed cryptographic vectors, and adversarial
//! openings. Upstream Plonky3 interoperability is tested in `plonky3.rs`.

use binary_merkle_tree::{
    Blake3, Commitment, Digest, Error, HashFunction, MerkleTree, Sha3_256, Sha256,
};
use sha2::Digest as _;

trait Oracle: HashFunction {
    fn standard_hash(message: &[u8]) -> Digest;

    fn reference_parent(left: &Digest, right: &Digest) -> Digest {
        let mut message = left.to_vec();
        message.extend_from_slice(right);
        Self::standard_hash(&message)
    }
}

impl Oracle for Sha256 {
    fn standard_hash(message: &[u8]) -> Digest {
        sha2::Sha256::digest(message).into()
    }

    fn reference_parent(left: &Digest, right: &Digest) -> Digest {
        // Deliberately bypass p3-sha256 and the library's HashFunction adapter.
        let mut state = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];
        let mut block = [0; 64];
        block[..32].copy_from_slice(left);
        block[32..].copy_from_slice(right);
        sha2::block_api::compress256(&mut state, &[block]);
        let mut digest = [0; 32];
        for (bytes, word) in digest.chunks_exact_mut(4).zip(state) {
            bytes.copy_from_slice(&word.to_be_bytes());
        }
        digest
    }
}
impl Oracle for Sha3_256 {
    fn standard_hash(message: &[u8]) -> Digest {
        sha3::Sha3_256::digest(message).into()
    }
}
impl Oracle for Blake3 {
    fn standard_hash(message: &[u8]) -> Digest {
        *blake3::hash(message).as_bytes()
    }
}

fn decode_hex(hex: &str) -> Digest {
    assert_eq!(hex.len(), 64);
    std::array::from_fn(|index| u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap())
}

fn reference_root<H: Oracle>(data: &[u8], width: usize) -> Digest {
    if data.len() == width {
        return H::standard_hash(data);
    }
    let (left, right) = data.split_at(data.len() / 2);
    H::reference_parent(
        &reference_root::<H>(left, width),
        &reference_root::<H>(right, width),
    )
}

fn reference_path<H: Oracle>(data: &[u8], width: usize, index: usize) -> Vec<Digest> {
    if data.len() == width {
        return Vec::new();
    }
    let (left, right) = data.split_at(data.len() / 2);
    let half = left.len() / width;
    let (mut path, sibling) = if index < half {
        (reference_path::<H>(left, width, index), right)
    } else {
        (reference_path::<H>(right, width, index - half), left)
    };
    path.push(reference_root::<H>(sibling, width));
    path
}

fn words(length: usize) -> Vec<u32> {
    (0..length)
        .map(|index| (index as u32).wrapping_mul(0x9e37_79b9).rotate_left(13))
        .collect()
}

fn encode(data: &[u32]) -> Vec<u8> {
    data.iter().flat_map(|word| word.to_le_bytes()).collect()
}

#[test]
fn fixed_external_hash_vectors() {
    // SHA-256/SHA3 fixtures generated with Python hashlib. The raw SHA-256
    // parent fixture uses an independent Python implementation of the 64 rounds,
    // checked against hashlib on the padded, one-block "abc" known-answer test.
    let leaf = [0, u32::MAX, 0x1234_5678];
    let left = std::array::from_fn(|index| index as u8);
    let right = std::array::from_fn(|index| (index + 32) as u8);
    assert_eq!(
        Sha256::hash_leaf(&[]),
        decode_hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    );
    assert_eq!(
        Sha3_256::hash_leaf(&[]),
        decode_hex("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a")
    );
    assert_eq!(
        Blake3::hash_leaf(&[]),
        decode_hex("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262")
    );
    assert_eq!(
        Sha256::hash_leaf_u32(&leaf),
        decode_hex("bd3e331ac95ef6f89afcef3dd0b8df31cb04a18842afd2aafed480efc192371b")
    );
    assert_eq!(
        Sha3_256::hash_leaf_u32(&leaf),
        decode_hex("da9cb165719b373b8cec5e7a4f8ae859e715da4301fa91f394182b1d7fc62453")
    );
    assert_eq!(
        Sha256::hash_nodes(&left, &right),
        decode_hex("fc99a2df88f42a7a7bb9d18033cdc6a20256755f9d5b9a5044a9cc315abe84a7")
    );
    assert_eq!(
        Sha3_256::hash_nodes(&left, &right),
        decode_hex("c8ad478f4e1dd9d47dfc3b985708d92db1f8db48fe9cddd459e63c321f490402")
    );
}

#[test]
fn fixed_external_matrix_vectors() {
    let matrix = [
        0,
        1,
        u32::MAX,
        0x1234_5678,
        256,
        65536,
        13,
        89,
        144,
        0x8000_0000,
        42,
        31,
    ];
    assert_eq!(
        MerkleTree::<Sha256>::commit_u32(&matrix, 3).unwrap().root(),
        decode_hex("04af3217c3ceb3450c3f9cd7107c9147861d6fbc820645a9a345c59add3cb296")
    );
    assert_eq!(
        MerkleTree::<Sha3_256>::commit_u32(&matrix, 3)
            .unwrap()
            .root(),
        decode_hex("f8b51e9a0c4f9fb9ba58095c66d99cded78915bf7fb791b82ca8c149e01f131c")
    );
}

fn check_reference<H: Oracle>() {
    for leaf_count in [1, 2, 4, 8, 32] {
        for width in [1, 3, 17, 64, 255] {
            let matrix = words(leaf_count * width);
            let bytes = encode(&matrix);
            let tree = MerkleTree::<H>::commit_u32(&matrix, width).unwrap();
            let byte_tree = MerkleTree::<H>::commit_bytes(&bytes, width * 4).unwrap();
            let imported = Commitment::<H>::from_root(tree.root(), leaf_count, width * 4).unwrap();
            assert_eq!(tree.root(), reference_root::<H>(&bytes, width * 4));
            assert_eq!(tree.root(), byte_tree.root());
            assert_eq!(tree.leaf_count(), leaf_count);
            assert_eq!(tree.leaf_bytes(), width * 4);
            assert_eq!(tree.height(), leaf_count.ilog2() as usize);
            assert_eq!(tree.node_count(), 2 * leaf_count - 1);
            assert_eq!(tree.storage_bytes(), (2 * leaf_count - 1) * 32);
            for index in 0..leaf_count {
                let proof = tree.open(index).unwrap();
                assert_eq!(
                    proof.siblings,
                    reference_path::<H>(&bytes, width * 4, index)
                );
                assert_eq!(proof, byte_tree.open(index).unwrap());
                assert_eq!(proof.siblings.len(), imported.height());
                imported
                    .verify_u32(
                        index,
                        &matrix[index * width..(index + 1) * width],
                        &proof.siblings,
                    )
                    .unwrap();
                imported
                    .verify_bytes(
                        index,
                        &bytes[index * width * 4..(index + 1) * width * 4],
                        &proof.siblings,
                    )
                    .unwrap();
            }
        }
    }
}

#[test]
fn sha256_matches_recursive_oracle() {
    check_reference::<Sha256>();
}
#[test]
fn sha3_matches_recursive_oracle() {
    check_reference::<Sha3_256>();
}
#[test]
fn blake3_matches_recursive_oracle() {
    check_reference::<Blake3>();
}

fn check_hash_boundaries<H: Oracle>() {
    for length in [
        0, 1, 54, 55, 56, 62, 63, 64, 65, 126, 127, 128, 134, 135, 136, 137, 511, 512, 513, 1022,
        1023, 1024, 1025, 65536,
    ] {
        let bytes: Vec<_> = (0..length).map(|index| (index * 19 + 23) as u8).collect();
        assert_eq!(H::hash_leaf(&bytes), H::standard_hash(&bytes));
    }
    for width in [
        1, 3, 15, 16, 17, 33, 34, 35, 127, 128, 129, 255, 256, 257, 16384,
    ] {
        let data = words(width);
        assert_eq!(H::hash_leaf_u32(&data), H::hash_leaf(&encode(&data)));
    }
    let left = [1; 32];
    let right = [2; 32];
    assert_eq!(
        H::hash_nodes(&left, &right),
        H::reference_parent(&left, &right)
    );
    assert_ne!(H::hash_nodes(&left, &right), H::hash_nodes(&right, &left));
}

#[test]
fn hash_padding_and_chunk_boundaries() {
    check_hash_boundaries::<Sha256>();
    check_hash_boundaries::<Sha3_256>();
    check_hash_boundaries::<Blake3>();
}

#[test]
fn plonky3_hash_constructions_have_no_domain_prefix() {
    let left = [1; 32];
    let right = [2; 32];
    let payload: Vec<_> = left.into_iter().chain(right).collect();
    assert_ne!(
        Sha256::hash_leaf(&payload),
        Sha256::hash_nodes(&left, &right)
    );
    assert_eq!(
        Sha3_256::hash_leaf(&payload),
        Sha3_256::hash_nodes(&left, &right)
    );
    assert_eq!(
        Blake3::hash_leaf(&payload),
        Blake3::hash_nodes(&left, &right)
    );
    // A one-leaf tree uses no parent compression and its proof is empty.
    let tree = MerkleTree::<Blake3>::commit_bytes(&payload, 64).unwrap();
    assert_eq!(tree.root(), Blake3::hash_leaf(&payload));
    assert!(tree.open(0).unwrap().siblings.is_empty());
    tree.commitment().verify_bytes(0, &payload, &[]).unwrap();
}

fn check_adversarial_openings<H: Oracle>() {
    let matrix = words(8 * 3);
    let tree = MerkleTree::<H>::commit_u32(&matrix, 3).unwrap();
    let commitment = tree.commitment();
    let proof = tree.open(5).unwrap();
    let leaf = &matrix[15..18];
    let mut altered_leaf = leaf.to_vec();
    altered_leaf[1] ^= 1;
    assert_eq!(
        commitment.verify_u32(5, &altered_leaf, &proof.siblings),
        Err(Error::RootMismatch)
    );
    for index in 0..8 {
        if index != 5 {
            assert_eq!(
                commitment.verify_u32(index, leaf, &proof.siblings),
                Err(Error::RootMismatch)
            );
        }
    }
    for level in 0..proof.siblings.len() {
        let mut altered = proof.siblings.clone();
        altered[level][0] ^= 1;
        assert_eq!(
            commitment.verify_u32(5, leaf, &altered),
            Err(Error::RootMismatch)
        );
    }
    let mut surplus = proof.siblings.clone();
    surplus.push([0; 32]);
    assert_eq!(
        commitment.verify_u32(5, leaf, &surplus),
        Err(Error::InvalidProofLength)
    );
    assert_eq!(
        commitment.verify_u32(5, leaf, &proof.siblings[1..]),
        Err(Error::InvalidProofLength)
    );
    assert_eq!(
        commitment.verify_u32(5, &leaf[..2], &proof.siblings),
        Err(Error::InvalidLeafSize)
    );
    assert_eq!(
        commitment.verify_u32(8, leaf, &proof.siblings),
        Err(Error::IndexOutOfBounds)
    );
    assert_eq!(
        commitment.verify_u32(usize::MAX, leaf, &proof.siblings),
        Err(Error::IndexOutOfBounds)
    );
    let mut root = tree.root();
    root[31] ^= 1;
    assert_eq!(
        Commitment::<H>::from_root(root, 8, 12)
            .unwrap()
            .verify_u32(5, leaf, &proof.siblings),
        Err(Error::RootMismatch)
    );
    assert_eq!(
        Commitment::<H>::from_root(tree.root(), 4, 12)
            .unwrap()
            .verify_u32(1, leaf, &proof.siblings),
        Err(Error::InvalidProofLength)
    );
    assert_eq!(
        Commitment::<H>::from_root(tree.root(), 8, 16)
            .unwrap()
            .verify_u32(5, leaf, &proof.siblings),
        Err(Error::InvalidLeafSize)
    );
    let mut buffer = vec![[77; 32]; 9];
    assert_eq!(tree.open_into(8, &mut buffer), Err(Error::IndexOutOfBounds));
    assert_eq!(buffer, vec![[77; 32]; 9]);
    tree.open_into(5, &mut buffer).unwrap();
    assert_eq!(buffer, proof.siblings);
}

#[test]
fn rejects_tampering_and_malformed_proofs() {
    check_adversarial_openings::<Sha256>();
    check_adversarial_openings::<Sha3_256>();
    check_adversarial_openings::<Blake3>();
}

#[test]
fn rejects_invalid_shapes_and_overflowing_metadata() {
    assert_eq!(
        MerkleTree::<Blake3>::commit_bytes(&[], 1).unwrap_err(),
        Error::EmptyInput
    );
    assert_eq!(
        MerkleTree::<Blake3>::commit_bytes(&[1], 0).unwrap_err(),
        Error::InvalidLeafSize
    );
    assert_eq!(
        MerkleTree::<Blake3>::commit_bytes(&[1, 2, 3], 1).unwrap_err(),
        Error::InvalidShape
    );
    assert_eq!(
        MerkleTree::<Blake3>::commit_bytes(&[1, 2, 3], 2).unwrap_err(),
        Error::InvalidShape
    );
    assert_eq!(
        MerkleTree::<Blake3>::commit_u32(&[], 1).unwrap_err(),
        Error::EmptyInput
    );
    assert_eq!(
        MerkleTree::<Blake3>::commit_u32(&[1, 2], 0).unwrap_err(),
        Error::InvalidLeafSize
    );
    assert_eq!(
        MerkleTree::<Blake3>::commit_u32(&[1, 2], 3).unwrap_err(),
        Error::InvalidShape
    );
    assert_eq!(
        MerkleTree::<Blake3>::commit_u32(&[1], usize::MAX).unwrap_err(),
        Error::InvalidShape
    );
    assert_eq!(
        Commitment::<Blake3>::from_root([0; 32], 0, 4),
        Err(Error::EmptyInput)
    );
    assert_eq!(
        Commitment::<Blake3>::from_root([0; 32], 3, 4),
        Err(Error::InvalidShape)
    );
    assert_eq!(
        Commitment::<Blake3>::from_root([0; 32], 1, 0),
        Err(Error::InvalidLeafSize)
    );
    assert_eq!(
        Commitment::<Blake3>::from_root([0; 32], 2, usize::MAX),
        Err(Error::SizeOverflow)
    );
    assert_eq!(
        Commitment::<Blake3>::from_root([0; 32], 1, isize::MAX as usize + 1),
        Err(Error::SizeOverflow)
    );
    assert_eq!(
        Commitment::<Blake3>::from_root([0; 32], 1 << (usize::BITS - 1), 1),
        Err(Error::SizeOverflow)
    );
}

#[test]
fn byte_leaves_need_not_be_u32_aligned() {
    for leaf_bytes in [1, 3, 5, 55, 56, 63, 64, 65, 135, 136, 137, 1023, 1024, 1025] {
        let bytes: Vec<_> = (0..leaf_bytes * 8)
            .map(|index| (index * 37 + 19) as u8)
            .collect();
        let tree = MerkleTree::<Blake3>::commit_bytes(&bytes, leaf_bytes).unwrap();
        assert_eq!(tree.root(), reference_root::<Blake3>(&bytes, leaf_bytes));
        for index in 0..8 {
            let proof = tree.open(index).unwrap();
            tree.commitment()
                .verify_bytes(
                    index,
                    &bytes[index * leaf_bytes..(index + 1) * leaf_bytes],
                    &proof.siblings,
                )
                .unwrap();
        }
    }
    let tree = MerkleTree::<Blake3>::commit_bytes(&[1, 2, 3], 3).unwrap();
    assert_eq!(
        tree.commitment().verify_u32(0, &[0x0003_0201], &[]),
        Err(Error::InvalidLeafSize)
    );
}

#[test]
fn requested_width_range_is_supported() {
    fn check<H: Oracle>() {
        for exponent in 0..=14 {
            let width = 1 << exponent;
            let matrix = words(4 * width);
            let tree = MerkleTree::<H>::commit_u32(&matrix, width).unwrap();
            assert_eq!(
                tree.root(),
                reference_root::<H>(&encode(&matrix), 4 * width)
            );
            tree.commitment()
                .verify_u32(3, &matrix[3 * width..], &tree.open(3).unwrap().siblings)
                .unwrap();
        }
    }
    check::<Sha256>();
    check::<Sha3_256>();
    check::<Blake3>();
}
