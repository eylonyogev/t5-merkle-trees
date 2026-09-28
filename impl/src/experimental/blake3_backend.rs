use super::*;
use crate::blake3_simd::{compress_many, compress_one};

const FLAGS: u8 = 16 | 1 | 2; // KEYED_HASH | CHUNK_START | CHUNK_END, no ROOT.

pub(super) fn blake3_counter(arity: u8, role: u64) -> u64 {
    assert!(
        role < (1 << 48),
        "BLAKE3 experimental role exceeds its namespace"
    );
    (u64::from(arity) << 48) | role
}

#[inline]
fn blake3_oracle(arity: u8, role: u64, key: &Digest, block: &[u8; 64]) -> Digest {
    compress_one(key, block, blake3_counter(arity, role), FLAGS)
}

impl ResearchHash for Blake3 {
    const LEAF_BATCH_SIZE: usize = 4;

    #[inline]
    fn oracle2(role: u64, input: &[u8; 64]) -> Digest {
        blake3_oracle(2, role, &[0; 32], input)
    }

    #[inline]
    fn oracle3(role: u64, input: &[u8; 96]) -> Digest {
        blake3_oracle(
            3,
            role,
            input[64..].try_into().unwrap(),
            input[..64].try_into().unwrap(),
        )
    }

    #[inline]
    fn oracle2_pair(roles: [u64; 2], inputs: [&[u8; 64]; 2]) -> [Digest; 2] {
        oracle2_many(roles, &[*inputs[0], *inputs[1]])
    }

    #[inline]
    fn oracle3_pair(roles: [u64; 2], inputs: [&[u8; 96]; 2]) -> [Digest; 2] {
        oracle3_many(roles, &[*inputs[0], *inputs[1]])
    }

    fn hash_leaf_planned(plan: &LeafPlan, input: &[u8]) -> Digest {
        match plan.mode() {
            // One gadget has no independent future stages to precompute. Its
            // small padding buffer avoids allocating/clearing pipeline scratch
            // for sixteen bottom calls when only two calls are required.
            LeafMode::T5 | LeafMode::T8 if plan.stages == 1 => plan.hash_generic::<Self>(input),
            LeafMode::T5 => pipeline::<160>(input, plan.stages),
            LeafMode::T8 => pipeline::<256>(input, plan.stages),
            LeafMode::Abr3 => chained::<352>(input, 320, abr_one),
            _ => plan.hash_generic::<Self>(input),
        }
    }

    fn hash_leaves_planned(plan: &LeafPlan, input: &[u8], output: &mut [Digest]) {
        let width = plan.leaf_bytes();
        if plan.mode() == LeafMode::Standard {
            Self::hash_leaves_fast(input, width, output);
            return;
        }
        assert!(plan.mode() != LeafMode::T253, "T253 requires SHA-256");
        for (rows, digests) in input
            .chunks(width.saturating_mul(4))
            .zip(output.chunks_mut(4))
        {
            if digests.len() == 1 {
                digests[0] = Self::hash_leaf_planned(plan, rows);
                continue;
            }
            // Unused lanes duplicate the first row, never read beyond input.
            let inputs = core::array::from_fn(|i| {
                let index = if i < digests.len() { i } else { 0 };
                &rows[index * width..(index + 1) * width]
            });
            let result = match plan.mode() {
                LeafMode::FixedMd => fixed_md_many(inputs),
                LeafMode::T5 => chained_many::<160>(inputs),
                LeafMode::T8 => chained_many::<256>(inputs),
                LeafMode::Abr3 => chained_many::<352>(inputs),
                LeafMode::Standard | LeafMode::T253 => unreachable!(),
            };
            digests.copy_from_slice(&result[..digests.len()]);
        }
    }

    fn oracle2_calls() -> u64 {
        1
    }
    fn oracle3_calls() -> u64 {
        1
    }
}

#[inline]
fn oracle2_many<const N: usize>(roles: [u64; N], blocks: &[[u8; 64]; N]) -> [Digest; N] {
    let mut out = [[0; 32]; N];
    if N != 0 && roles.iter().all(|role| *role == roles[0]) {
        // T5 and ABR batches share the zero CV and role. The upstream kernel
        // specializes that case and avoids loading/transposing variable CVs.
        let inputs: [&[u8; 64]; N] = core::array::from_fn(|i| &blocks[i]);
        blake3::platform::Platform::detect().hash_many(
            &inputs,
            &[0; 8],
            blake3_counter(2, roles[0]),
            blake3::IncrementCounter::No,
            16,
            1,
            2,
            bytemuck::cast_slice_mut(&mut out),
        );
        return out;
    }
    compress_many(
        &[[0; 32]; N],
        blocks,
        &roles.map(|r| blake3_counter(2, r)),
        FLAGS,
        &mut out,
    );
    out
}

#[inline]
fn oracle3_many<const N: usize>(roles: [u64; N], messages: &[[u8; 96]; N]) -> [Digest; N] {
    let keys: [Digest; N] = core::array::from_fn(|i| messages[i][64..].try_into().unwrap());
    let blocks: [[u8; 64]; N] = core::array::from_fn(|i| messages[i][..64].try_into().unwrap());
    let mut out = [[0; 32]; N];
    compress_many(
        &keys,
        &blocks,
        &roles.map(|r| blake3_counter(3, r)),
        FLAGS,
        &mut out,
    );
    out
}

fn fixed_md_many(inputs: [&[u8]; 4]) -> [Digest; 4] {
    let mut state = [[0; 32]; 4];
    for offset in (0..inputs[0].len()).step_by(64) {
        let count = (inputs[0].len() - offset).min(64);
        let messages = core::array::from_fn(|i| {
            let mut message = [0; 96];
            message[..32].copy_from_slice(&state[i]);
            message[32..32 + count].copy_from_slice(&inputs[i][offset..offset + count]);
            message
        });
        state = oracle3_many([MD_ROLE; 4], &messages);
    }
    state
}

/// Matching stages of four complete records use all four compression lanes.
fn chained_many<const BYTES: usize>(inputs: [&[u8]; 4]) -> [Digest; 4] {
    if BYTES == 256
        && let Some(output) = crate::blake3_simd::t8_four(inputs)
    {
        return output;
    }
    let first = inputs[0].len().min(BYTES);
    let mut messages = [[0; BYTES]; 4];
    for i in 0..4 {
        messages[i][..first].copy_from_slice(&inputs[i][..first]);
    }
    let mut state = gadget_many(&messages);
    let mut offset = first;
    while offset < inputs[0].len() {
        let count = (inputs[0].len() - offset).min(BYTES - 32);
        for i in 0..4 {
            // Full stages overwrite every byte; only the final partial stage
            // needs zeroing. This preserves the original zero-padded encoding.
            if count != BYTES - 32 {
                messages[i].fill(0);
            }
            let chunk = &inputs[i][offset..offset + count];
            if BYTES == 352 {
                messages[i][..32].copy_from_slice(&state[i]);
                messages[i][32..32 + count].copy_from_slice(chunk);
            } else {
                let shared = if BYTES == 160 { 128 } else { 192 };
                let before = count.min(shared);
                messages[i][..before].copy_from_slice(&chunk[..before]);
                messages[i][shared..shared + 32].copy_from_slice(&state[i]);
                if count > shared {
                    messages[i][shared + 32..shared + 32 + count - shared]
                        .copy_from_slice(&chunk[shared..]);
                }
            }
        }
        state = gadget_many(&messages);
        offset += count;
    }
    state
}

#[inline]
fn gadget_many<const BYTES: usize>(messages: &[[u8; BYTES]; 4]) -> [Digest; 4] {
    if BYTES == 160 {
        let left = oracle2_many(
            [T5_ROLES[0]; 4],
            &core::array::from_fn(|i| messages[i][..64].try_into().unwrap()),
        );
        let right = oracle2_many(
            [T5_ROLES[1]; 4],
            &core::array::from_fn(|i| messages[i][64..128].try_into().unwrap()),
        );
        let shared: [Digest; 4] =
            core::array::from_fn(|i| messages[i][128..160].try_into().unwrap());
        let roots = core::array::from_fn(|i| {
            let mut root = [0; 64];
            root[..32].copy_from_slice(&xor(left[i], &shared[i]));
            root[32..].copy_from_slice(&xor(right[i], &shared[i]));
            root
        });
        let out = oracle2_many([T5_ROLES[2]; 4], &roots);
        core::array::from_fn(|i| xor(out[i], &shared[i]))
    } else if BYTES == 256 {
        let left = oracle3_many(
            [T8_ROLES[0]; 4],
            &core::array::from_fn(|i| messages[i][..96].try_into().unwrap()),
        );
        let right = oracle3_many(
            [T8_ROLES[1]; 4],
            &core::array::from_fn(|i| messages[i][96..192].try_into().unwrap()),
        );
        let shared: [Digest; 4] =
            core::array::from_fn(|i| messages[i][192..224].try_into().unwrap());
        let roots = core::array::from_fn(|i| {
            let mut root = [0; 96];
            root[..32].copy_from_slice(&xor(left[i], &shared[i]));
            root[32..64].copy_from_slice(&xor(right[i], &shared[i]));
            root[64..].copy_from_slice(&messages[i][224..256]);
            root
        });
        let out = oracle3_many([T8_ROLES[2]; 4], &roots);
        core::array::from_fn(|i| xor(out[i], &shared[i]))
    } else {
        debug_assert_eq!(BYTES, 352);
        let bottom: [[Digest; 4]; 4] = core::array::from_fn(|j| {
            oracle2_many(
                [ABR_ROLES[j]; 4],
                &core::array::from_fn(|i| messages[i][64 * j..64 * (j + 1)].try_into().unwrap()),
            )
        });
        let left = abr_many(
            ABR_ROLES[4],
            bottom[0],
            bottom[1],
            core::array::from_fn(|i| messages[i][256..288].try_into().unwrap()),
        );
        let right = abr_many(
            ABR_ROLES[5],
            bottom[2],
            bottom[3],
            core::array::from_fn(|i| messages[i][288..320].try_into().unwrap()),
        );
        abr_many(
            ABR_ROLES[6],
            left,
            right,
            core::array::from_fn(|i| messages[i][320..352].try_into().unwrap()),
        )
    }
}

#[inline]
fn abr_many(role: u64, left: [Digest; 4], right: [Digest; 4], shared: [Digest; 4]) -> [Digest; 4] {
    let blocks = core::array::from_fn(|i| {
        let mut block = [0; 64];
        block[..32].copy_from_slice(&xor(left[i], &shared[i]));
        block[32..].copy_from_slice(&xor(right[i], &shared[i]));
        block
    });
    let out = oracle2_many([role; 4], &blocks);
    core::array::from_fn(|i| xor(out[i], &right[i]))
}

#[inline]
fn abr_one(message: &[u8; 352]) -> Digest {
    let bottom = oracle2_many(
        [ABR_ROLES[0], ABR_ROLES[1], ABR_ROLES[2], ABR_ROLES[3]],
        &core::array::from_fn(|i| message[i * 64..(i + 1) * 64].try_into().unwrap()),
    );
    let [left, right] = abr_node_pair::<Blake3>(
        [ABR_ROLES[4], ABR_ROLES[5]],
        [bottom[0], bottom[2]],
        [bottom[1], bottom[3]],
        [
            message[256..288].try_into().unwrap(),
            message[288..320].try_into().unwrap(),
        ],
    );
    abr_node::<Blake3>(
        ABR_ROLES[6],
        left,
        right,
        message[320..].try_into().unwrap(),
    )
}

/// Bottom calls do not depend on the preceding stage's root: precompute them
/// across up to eight stages, then evaluate the dependent roots in order. This
/// accelerates a single verification, where cross-record batching is absent.
fn pipeline<const BYTES: usize>(input: &[u8], stages: usize) -> Digest {
    const WINDOW: usize = 8;
    let fresh = BYTES - 32;
    let shared_offset = if BYTES == 160 { 128 } else { 192 };
    let oracle_bytes = shared_offset / 2;
    let roles = if BYTES == 160 { T5_ROLES } else { T8_ROLES };
    let arity = if BYTES == 160 { 2 } else { 3 };
    let mut state = [0; 32];
    for start in (0..stages).step_by(WINDOW) {
        let count = (stages - start).min(WINDOW);
        let mut blocks = [[0; 64]; WINDOW * 2];
        let mut keys = [[0; 32]; WINDOW * 2];
        let mut counters = [0; WINDOW * 2];
        let mut extras = [[0; 32]; WINDOW];
        for i in 0..count {
            let stage = start + i;
            let offset = if stage == 0 {
                0
            } else {
                BYTES + (stage - 1) * fresh
            };
            let available = (input.len() - offset).min(if stage == 0 { BYTES } else { fresh });
            for side in 0..2 {
                let begin = oracle_bytes * side;
                if available >= shared_offset {
                    // Almost all stages are complete. Fixed-size copies compile
                    // to vector loads/stores instead of a dynamic memcpy call
                    // for each 64-byte block and 32-byte CV.
                    blocks[2 * i + side]
                        .copy_from_slice(&input[offset + begin..offset + begin + 64]);
                    if BYTES == 256 {
                        keys[2 * i + side]
                            .copy_from_slice(&input[offset + begin + 64..offset + begin + 96]);
                    }
                } else {
                    let remaining = available.saturating_sub(begin);
                    let block_count = remaining.min(64);
                    if block_count != 0 {
                        blocks[2 * i + side][..block_count]
                            .copy_from_slice(&input[offset + begin..offset + begin + block_count]);
                    }
                    if BYTES == 256 && remaining > 64 {
                        let key_count = (remaining - 64).min(32);
                        keys[2 * i + side][..key_count].copy_from_slice(
                            &input[offset + begin + 64..offset + begin + 64 + key_count],
                        );
                    }
                }
                counters[2 * i + side] = blake3_counter(arity, roles[side]);
            }
            if BYTES == 256 {
                let extra_offset = if stage == 0 { 224 } else { 192 };
                let extra_count = available.saturating_sub(extra_offset).min(32);
                if extra_count == 32 {
                    extras[i]
                        .copy_from_slice(&input[offset + extra_offset..offset + extra_offset + 32]);
                } else if extra_count != 0 {
                    extras[i][..extra_count].copy_from_slice(
                        &input[offset + extra_offset..offset + extra_offset + extra_count],
                    );
                }
            }
        }
        let mut bottom = [[0; 32]; WINDOW * 2];
        compress_many(
            &keys[..2 * count],
            &blocks[..2 * count],
            &counters[..2 * count],
            FLAGS,
            &mut bottom[..2 * count],
        );
        for i in 0..count {
            if start + i == 0 {
                let available = input.len().saturating_sub(shared_offset).min(32);
                if available != 0 {
                    state[..available]
                        .copy_from_slice(&input[shared_offset..shared_offset + available]);
                }
            }
            let mut root = [0; 64];
            root[..32].copy_from_slice(&xor(bottom[2 * i], &state));
            root[32..].copy_from_slice(&xor(bottom[2 * i + 1], &state));
            let out = blake3_oracle(arity, roles[2], &extras[i], &root);
            state = xor(out, &state);
        }
    }
    state
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn row_batches_and_stage_pipeline_preserve_all_encodings() {
        let widths = [
            1, 4, 63, 64, 65, 127, 128, 159, 160, 161, 191, 192, 223, 224, 255, 256, 257, 351, 352,
            353, 479, 480, 481, 1024, 4096,
        ];
        for mode in [
            LeafMode::FixedMd,
            LeafMode::T5,
            LeafMode::T8,
            LeafMode::Abr3,
        ] {
            for width in widths {
                let plan = LeafPlan::new::<Blake3>(mode, width).unwrap();
                for count in [0, 1, 2, 3, 4, 5, 7, 8, 9] {
                    let input: Vec<u8> = (0..width * count)
                        .map(|i| (i * 131 + i / 19) as u8)
                        .collect();
                    let mut output = vec![[0; 32]; count];
                    plan.hash_many::<Blake3>(&input, &mut output);
                    for (row, got) in input.chunks_exact(width).zip(output) {
                        let expected = plan.hash_generic::<Blake3>(row);
                        assert_eq!(got, expected, "mode={mode:?}, width={width}, rows={count}");
                        assert_eq!(
                            plan.hash::<Blake3>(row),
                            expected,
                            "single mode={mode:?}, width={width}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn pipeline_multiple_windows_and_partial_last_stage() {
        for mode in [LeafMode::T5, LeafMode::T8] {
            for width in [2047, 2048, 2049, 16383, 16384, 16385, 65536] {
                let input: Vec<u8> = (0..width).map(|i| (i * 97 + i / 3) as u8).collect();
                let plan = LeafPlan::new::<Blake3>(mode, width).unwrap();
                assert_eq!(
                    plan.hash::<Blake3>(&input),
                    plan.hash_generic::<Blake3>(&input)
                );
            }
        }
    }
}
