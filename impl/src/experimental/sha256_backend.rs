use super::*;

impl ResearchHash for Sha256 {
    #[inline]
    fn oracle2(role: u64, input: &[u8; 64]) -> Digest {
        // Fixed, distinct CVs provide genuinely disjoint native compression
        // domains. In particular this is not a role XORed into variable input.
        let mut iv = [0; 32];
        iv[..17].copy_from_slice(&prefix(2, role));
        sha256_compress(&iv, input)
    }

    #[inline]
    fn oracle3(role: u64, input: &[u8; 96]) -> Digest {
        // The fixed 17 + 96 byte encoding always occupies exactly two SHA-256
        // blocks. Build them directly instead of buffering two updates and
        // running a generic finalizer for every experimental oracle call.
        let blocks = oracle3_blocks(role, input);
        let mut state = p3_sha256::H256_256;
        sha2::block_api::compress256(&mut state, &blocks);
        encode_state(state)
    }

    #[inline]
    fn oracle2_pair(roles: [u64; 2], inputs: [&[u8; 64]; 2]) -> [Digest; 2] {
        let mut states = core::array::from_fn(|i| {
            let mut iv = [0; 32];
            iv[..17].copy_from_slice(&prefix(2, roles[i]));
            decode_state(&iv)
        });
        crate::sha256_simd::compress_pair(&mut states, inputs);
        states.map(encode_state)
    }

    #[inline]
    fn oracle3_pair(roles: [u64; 2], inputs: [&[u8; 96]; 2]) -> [Digest; 2] {
        let blocks = [
            oracle3_blocks(roles[0], inputs[0]),
            oracle3_blocks(roles[1], inputs[1]),
        ];
        let mut states = [p3_sha256::H256_256; 2];
        for (left, right) in blocks[0].iter().zip(&blocks[1]) {
            crate::sha256_simd::compress_pair(&mut states, [left, right]);
        }
        states.map(encode_state)
    }

    fn oracle2_calls() -> u64 {
        1
    }
    fn oracle3_calls() -> u64 {
        2
    }
    fn supports_t253() -> bool {
        true
    }

    fn hash_t253(input: &[u8], stages: usize) -> Digest {
        if stages == 0 {
            return Self::hash_leaf_fast(input);
        }
        let mut state = t253_gadget(
            input[..95].try_into().unwrap(),
            input[95..190].try_into().unwrap(),
            input[190..222].try_into().unwrap(),
            input[222..253].try_into().unwrap(),
        );
        let mut offset = 253;
        for _ in 1..stages {
            state = t253_gadget(
                input[offset..offset + 95].try_into().unwrap(),
                input[offset + 95..offset + 190].try_into().unwrap(),
                &state,
                input[offset + 190..offset + 221].try_into().unwrap(),
            );
            offset += 221;
        }
        // Preserve the native CV words across consecutive tail compressions.
        // The tail is fixed-format zero padding, not SHA-256 length padding.
        let (blocks, remainder) = input[offset..].as_chunks::<64>();
        if blocks.is_empty() && remainder.is_empty() {
            return state;
        }
        let mut words = decode_state(&state);
        if !blocks.is_empty() {
            sha2::block_api::compress256(&mut words, blocks);
        }
        if !remainder.is_empty() {
            let mut block = [0; 64];
            block[..remainder.len()].copy_from_slice(remainder);
            sha2::block_api::compress256(&mut words, core::slice::from_ref(&block));
        }
        encode_state(words)
    }
}

#[inline]
fn oracle3_blocks(role: u64, input: &[u8; 96]) -> [[u8; 64]; 2] {
    let mut blocks = [[0; 64]; 2];
    blocks[0][..17].copy_from_slice(&prefix(3, role));
    blocks[0][17..].copy_from_slice(&input[..47]);
    blocks[1][..49].copy_from_slice(&input[47..]);
    blocks[1][49] = 0x80;
    blocks[1][56..].copy_from_slice(&(113_u64 * 8).to_be_bytes());
    blocks
}

#[inline]
pub(super) fn sha256_compress(iv: &Digest, block: &[u8; 64]) -> Digest {
    let mut state = decode_state(iv);
    sha2::block_api::compress256(&mut state, core::slice::from_ref(block));
    encode_state(state)
}

#[inline]
fn decode_state(iv: &Digest) -> [u32; 8] {
    core::array::from_fn(|i| u32::from_be_bytes(iv[i * 4..i * 4 + 4].try_into().unwrap()))
}

#[inline]
fn encode_state(state: [u32; 8]) -> Digest {
    let mut digest = [0; 32];
    for (bytes, word) in digest.chunks_exact_mut(4).zip(state) {
        bytes.copy_from_slice(&word.to_be_bytes());
    }
    digest
}

/// One native SHA-256 call on 95 freely chosen bytes. Three role bytes select
/// disjoint slices of the complete 96-byte SHA-256 compression input domain.
#[inline]
#[cfg(test)]
pub(super) fn sha256_95(role: u8, block: &[u8; 64], extra: &[u8; 31]) -> Digest {
    let mut iv = [0; 32];
    iv[0] = role;
    iv[1..].copy_from_slice(extra);
    sha256_compress(&iv, block)
}

#[inline]
pub(super) fn t253_gadget(
    left: &[u8; 95],
    right: &[u8; 95],
    shared: &Digest,
    extra: &[u8; 31],
) -> Digest {
    crate::sha256_simd::t253(left, right, shared, extra)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_two_block_encoding_matches_standard_sha256() {
        let input: [u8; 96] = core::array::from_fn(|i| (i * 179 + 21) as u8);
        for role in [0, 1, 10, 22, 36, u64::MAX, 0x1234_5678_9abc_def0] {
            let mut hasher = sha2::Sha256::new();
            hasher.update(prefix(3, role));
            hasher.update(input);
            let expected: Digest = hasher.finalize().into();
            assert_eq!(Sha256::oracle3(role, &input), expected);
        }
    }
}
