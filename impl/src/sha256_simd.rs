//! Two independent SHA-256 compressions, interleaved with AArch64 SHA2.
//!
//! The safe entry checks CPU features before executing architecture intrinsics.
//! Other targets keep the RustCrypto compression implementation. No caller can
//! supply an invalid block or CV length, and all accesses are within fixed arrays.

#[inline]
pub(crate) fn compress_pair(states: &mut [[u32; 8]; 2], blocks: [&[u8; 64]; 2]) {
    #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
    if std::arch::is_aarch64_feature_detected!("sha2") {
        // SAFETY: runtime feature detection established SHA2 availability. Each
        // state and input block has the exact length required by the kernel.
        unsafe { aarch64::compress_pair(states, blocks) };
        return;
    }
    for i in 0..2 {
        sha2::block_api::compress256(&mut states[i], core::slice::from_ref(blocks[i]));
    }
}

/// Three T253 compressions, keeping intermediate CVs in vector registers on
/// supported CPUs. This retains the exact role bytes and feed-forward rule.
#[inline]
pub(crate) fn t253(
    left: &[u8; 95],
    right: &[u8; 95],
    shared: &[u8; 32],
    extra: &[u8; 31],
) -> [u8; 32] {
    #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
    if std::arch::is_aarch64_feature_detected!("sha2") {
        // SAFETY: feature availability is checked; fixed array types establish
        // all memory bounds needed by the fused kernel.
        return unsafe { aarch64::t253(left, right, shared, extra) };
    }
    t253_portable(left, right, shared, extra)
}

/// Fused SHA95 ABR3 chain. Returns None on CPUs without the SHA2 extension so
/// callers can retain the independent portable construction specification.
pub(crate) fn abr_wide(
    input: &[u8],
    stages: usize,
    tails: usize,
    md_head: bool,
) -> Option<[u8; 32]> {
    #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
    if std::arch::is_aarch64_feature_detected!("sha2") {
        // SAFETY: runtime feature check; the implementation bounds/pads every
        // message segment before performing its fixed-width vector accesses.
        return Some(unsafe { aarch64::abr_wide_rows([input], stages, tails, md_head)[0] });
    }
    let _ = (input, stages, tails, md_head);
    None
}

pub(crate) fn abr_wide_pair(
    input: [&[u8]; 2],
    stages: usize,
    tails: usize,
    md_head: bool,
) -> Option<[[u8; 32]; 2]> {
    #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
    if std::arch::is_aarch64_feature_detected!("sha2") {
        // SAFETY: as above, with independent rows in both native lanes.
        return Some(unsafe { aarch64::abr_wide_rows(input, stages, tails, md_head) });
    }
    let _ = (input, stages, tails, md_head);
    None
}

fn t253_portable(
    left: &[u8; 95],
    right: &[u8; 95],
    shared: &[u8; 32],
    extra: &[u8; 31],
) -> [u8; 32] {
    fn call(role: u8, block: &[u8; 64], extra: &[u8; 31]) -> [u8; 32] {
        let mut iv = [0; 32];
        iv[0] = role;
        iv[1..].copy_from_slice(extra);
        let mut state =
            core::array::from_fn(|i| u32::from_be_bytes(iv[i * 4..i * 4 + 4].try_into().unwrap()));
        sha2::block_api::compress256(&mut state, core::slice::from_ref(block));
        let mut digest = [0; 32];
        for (bytes, word) in digest.chunks_exact_mut(4).zip(state) {
            bytes.copy_from_slice(&word.to_be_bytes());
        }
        digest
    }
    let a = call(
        0xa1,
        left[..64].try_into().unwrap(),
        left[64..].try_into().unwrap(),
    );
    let b = call(
        0xa2,
        right[..64].try_into().unwrap(),
        right[64..].try_into().unwrap(),
    );
    let mut root = [0; 64];
    for i in 0..32 {
        root[i] = a[i] ^ shared[i];
        root[32 + i] = b[i] ^ shared[i];
    }
    let digest = call(0xa3, &root, extra);
    core::array::from_fn(|i| digest[i] ^ shared[i])
}

#[cfg(all(target_arch = "aarch64", target_endian = "little"))]
mod aarch64 {
    use core::arch::aarch64::*;

    // SHA-256 round constants from FIPS 180-4, section 4.2.2.
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    #[target_feature(enable = "sha2")]
    pub(super) unsafe fn compress_pair(states: &mut [[u32; 8]; 2], blocks: [&[u8; 64]; 2]) {
        // SAFETY: the safe wrapper establishes SHA2 support. Every vector load
        // and store below spans four u32s or sixteen bytes inside a fixed-size
        // array. AArch64 vector accesses do not require extra alignment.
        unsafe {
            let mut abcd = [
                vld1q_u32(states[0][..4].as_ptr()),
                vld1q_u32(states[1][..4].as_ptr()),
            ];
            let mut efgh = [
                vld1q_u32(states[0][4..].as_ptr()),
                vld1q_u32(states[1][4..].as_ptr()),
            ];
            let original_abcd = abcd;
            let original_efgh = efgh;
            let mut words: [[uint32x4_t; 4]; 2] = core::array::from_fn(|lane| {
                core::array::from_fn(|part| {
                    vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(blocks[lane][part * 16..].as_ptr())))
                })
            });

            // Each group advances both independent CVs by four rounds. Updating
            // both ABCD halves before EFGH exposes independent instructions to
            // the scheduler instead of waiting on one message's round chain.
            macro_rules! rounds {
                ($constant:expr, $word:expr) => {{
                    let constants = vld1q_u32(K[$constant..].as_ptr());
                    let message0 = vaddq_u32(words[0][$word], constants);
                    let message1 = vaddq_u32(words[1][$word], constants);
                    let previous = abcd;
                    abcd[0] = vsha256hq_u32(previous[0], efgh[0], message0);
                    abcd[1] = vsha256hq_u32(previous[1], efgh[1], message1);
                    efgh[0] = vsha256h2q_u32(efgh[0], previous[0], message0);
                    efgh[1] = vsha256h2q_u32(efgh[1], previous[1], message1);
                }};
            }
            macro_rules! expand_rounds {
                ($constant:expr, $a:expr, $b:expr, $c:expr, $d:expr) => {{
                    for lane in 0..2 {
                        words[lane][$a] = vsha256su1q_u32(
                            vsha256su0q_u32(words[lane][$a], words[lane][$b]),
                            words[lane][$c],
                            words[lane][$d],
                        );
                    }
                    rounds!($constant, $a);
                }};
            }
            rounds!(0, 0);
            rounds!(4, 1);
            rounds!(8, 2);
            rounds!(12, 3);
            for round in (16..64).step_by(16) {
                expand_rounds!(round, 0, 1, 2, 3);
                expand_rounds!(round + 4, 1, 2, 3, 0);
                expand_rounds!(round + 8, 2, 3, 0, 1);
                expand_rounds!(round + 12, 3, 0, 1, 2);
            }
            for lane in 0..2 {
                vst1q_u32(
                    states[lane][..4].as_mut_ptr(),
                    vaddq_u32(abcd[lane], original_abcd[lane]),
                );
                vst1q_u32(
                    states[lane][4..].as_mut_ptr(),
                    vaddq_u32(efgh[lane], original_efgh[lane]),
                );
            }
        }
    }

    #[target_feature(enable = "sha2")]
    pub(super) unsafe fn t253(
        left: &[u8; 95],
        right: &[u8; 95],
        shared: &[u8; 32],
        extra: &[u8; 31],
    ) -> [u8; 32] {
        // SAFETY: SHA2 was checked by the safe wrapper. All loads below have
        // at least sixteen available bytes, including 63..79 and 79..95 for
        // a bottom-node CV; the byte at offset 63 is replaced by the role.
        unsafe {
            let inputs = [left, right];
            let states = core::array::from_fn::<_, 2, _>(|lane| {
                let first = load_be(&inputs[lane][63..]);
                let word = vgetq_lane_u32::<0>(first);
                [
                    vsetq_lane_u32::<0>((word & 0x00ff_ffff) | ((0xa1 + lane as u32) << 24), first),
                    load_be(&inputs[lane][79..]),
                ]
            });
            let messages = core::array::from_fn::<_, 2, _>(|lane| {
                core::array::from_fn(|part| load_be(&inputs[lane][part * 16..]))
            });
            let bottom = compress_vectors(states, messages);
            let shared = [load_be(&shared[..16]), load_be(&shared[16..])];
            let root_message = [[
                veorq_u32(bottom[0][0], shared[0]),
                veorq_u32(bottom[0][1], shared[1]),
                veorq_u32(bottom[1][0], shared[0]),
                veorq_u32(bottom[1][1], shared[1]),
            ]];
            let mut iv = [0; 32];
            iv[0] = 0xa3;
            iv[1..].copy_from_slice(extra);
            let root =
                compress_vectors([[load_be(&iv[..16]), load_be(&iv[16..])]], root_message)[0];
            let mut digest = [0; 32];
            for part in 0..2 {
                vst1q_u8(
                    digest[part * 16..].as_mut_ptr(),
                    vrev32q_u8(vreinterpretq_u8_u32(veorq_u32(root[part], shared[part]))),
                );
            }
            digest
        }
    }

    type State = [uint32x4_t; 2];

    /// Load role||extra31 without building a temporary CV: the ignored byte at
    /// bytes[0] belongs to the preceding message field and is replaced by role.
    #[inline(always)]
    unsafe fn wide_cv(role: u8, bytes: &[u8]) -> State {
        unsafe {
            let first = load_be(bytes);
            [
                vsetq_lane_u32::<0>(
                    (vgetq_lane_u32::<0>(first) & 0x00ff_ffff) | ((role as u32) << 24),
                    first,
                ),
                load_be(&bytes[16..]),
            ]
        }
    }

    #[inline(always)]
    unsafe fn digest_words(bytes: &[u8]) -> State {
        unsafe { [load_be(bytes), load_be(&bytes[16..])] }
    }

    #[inline(always)]
    unsafe fn internal_words(left: State, right: State, shared: State) -> [uint32x4_t; 4] {
        unsafe {
            [
                veorq_u32(left[0], shared[0]),
                veorq_u32(left[1], shared[1]),
                veorq_u32(right[0], shared[0]),
                veorq_u32(right[1], shared[1]),
            ]
        }
    }

    #[inline(always)]
    unsafe fn feed_right(hash: State, right: State) -> State {
        unsafe { [veorq_u32(hash[0], right[0]), veorq_u32(hash[1], right[1])] }
    }

    /// Six non-root calls, with every independent pair interleaved. All
    /// intermediate words remain in native SHA registers, not byte digests.
    #[inline(always)]
    unsafe fn abr_prepare(input: &[u8]) -> (State, State) {
        unsafe {
            let bottom = |start: usize| {
                let states = core::array::from_fn(|i| {
                    wide_cv(0xd0 + (start + i) as u8, &input[(start + i) * 95 + 63..])
                });
                let words = core::array::from_fn::<_, 2, _>(|i| {
                    core::array::from_fn(|j| load_be(&input[(start + i) * 95 + j * 16..]))
                });
                compress_vectors(states, words)
            };
            let ab = bottom(0);
            let cd = bottom(2);
            let middle = compress_vectors(
                [wide_cv(0xd4, &input[411..]), wide_cv(0xd5, &input[474..])],
                [
                    internal_words(ab[0], ab[1], digest_words(&input[380..])),
                    internal_words(cd[0], cd[1], digest_words(&input[443..])),
                ],
            );
            (feed_right(middle[0], ab[1]), feed_right(middle[1], cd[1]))
        }
    }

    /// N is one or two. Bottom/middle branches always use two-way SHA2;
    /// dependent roots and MD tails additionally pair neighboring rows.
    #[target_feature(enable = "sha2")]
    pub(super) unsafe fn abr_wide_rows<const N: usize>(
        input: [&[u8]; N],
        stages: usize,
        tails: usize,
        md_head: bool,
    ) -> [[u8; 32]; N] {
        unsafe {
            let zero = vdupq_n_u32(0);
            let mut state = [[zero; 2]; N];
            let mut offset = 0;
            if md_head {
                let mut padded = [[0; 95]; N];
                for i in 0..N {
                    if input[i].len() < 95 {
                        padded[i][..input[i].len()].copy_from_slice(input[i]);
                    }
                }
                let heads: [&[u8]; N] = core::array::from_fn(|i| {
                    if input[i].len() >= 95 {
                        &input[i][..95]
                    } else {
                        &padded[i]
                    }
                });
                let states = core::array::from_fn(|i| wide_cv(0xd7, &heads[i][63..]));
                let words = core::array::from_fn(|i| {
                    core::array::from_fn(|j| load_be(&heads[i][j * 16..]))
                });
                state = compress_vectors(states, words);
                offset = 95;
            }
            let mut padded = [[0; 569]; N];
            for stage in 0..stages {
                let first = stage == 0;
                let capacity = if first { 569 } else { 537 };
                for i in 0..N {
                    let remaining = input[i].len().saturating_sub(offset);
                    if remaining > 0 && remaining < capacity {
                        padded[i][..remaining].copy_from_slice(&input[i][offset..]);
                    }
                }
                let messages: [&[u8]; N] = core::array::from_fn(|i| {
                    let remaining = input[i].len().saturating_sub(offset);
                    if remaining >= capacity {
                        &input[i][offset..offset + capacity]
                    } else {
                        &padded[i][..capacity]
                    }
                });
                let prepared: [(State, State); N] =
                    core::array::from_fn(|i| abr_prepare(messages[i]));
                let shared: [State; N] = core::array::from_fn(|i| {
                    if first {
                        digest_words(&messages[i][506..])
                    } else {
                        state[i]
                    }
                });
                let states: [State; N] = core::array::from_fn(|i| {
                    wide_cv(0xd6, &messages[i][if first { 537 } else { 505 }..])
                });
                let words = core::array::from_fn(|i| {
                    internal_words(prepared[i].0, prepared[i].1, shared[i])
                });
                let root = compress_vectors(states, words);
                state = core::array::from_fn(|i| feed_right(root[i], prepared[i].1));
                offset += capacity;
            }
            for _ in 0..tails {
                let mut padded = [[0; 63]; N];
                for i in 0..N {
                    let remaining = input[i].len().saturating_sub(offset);
                    if remaining > 0 && remaining < 63 {
                        padded[i][..remaining].copy_from_slice(&input[i][offset..]);
                    }
                }
                let messages: [&[u8]; N] = core::array::from_fn(|i| {
                    let remaining = input[i].len().saturating_sub(offset);
                    if remaining >= 63 {
                        &input[i][offset..offset + 63]
                    } else {
                        &padded[i]
                    }
                });
                let states = core::array::from_fn(|i| wide_cv(0xd7, &messages[i][31..]));
                let words = core::array::from_fn(|i| {
                    [
                        state[i][0],
                        state[i][1],
                        load_be(messages[i]),
                        load_be(&messages[i][16..]),
                    ]
                });
                state = compress_vectors(states, words);
                offset += 63;
            }
            core::array::from_fn(|i| {
                let mut result = [0; 32];
                for part in 0..2 {
                    vst1q_u8(
                        result[part * 16..].as_mut_ptr(),
                        vrev32q_u8(vreinterpretq_u8_u32(state[i][part])),
                    );
                }
                result
            })
        }
    }

    /// Caller supplies at least sixteen bytes and has enabled SHA2/NEON.
    #[inline(always)]
    unsafe fn load_be(bytes: &[u8]) -> uint32x4_t {
        unsafe { vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(bytes.as_ptr()))) }
    }

    /// One or two raw compressions on values already held as big-endian words.
    /// Inlining into the fused gadget avoids storing intermediate digests or
    /// reconstructing a 64-byte root message. Caller has enabled SHA2.
    #[inline(always)]
    unsafe fn compress_vectors<const LANES: usize>(
        states: [[uint32x4_t; 2]; LANES],
        mut words: [[uint32x4_t; 4]; LANES],
    ) -> [[uint32x4_t; 2]; LANES] {
        unsafe {
            let mut abcd: [uint32x4_t; LANES] = core::array::from_fn(|lane| states[lane][0]);
            let mut efgh: [uint32x4_t; LANES] = core::array::from_fn(|lane| states[lane][1]);
            macro_rules! rounds {
                ($constant:expr, $word:expr) => {{
                    let constants = vld1q_u32(K[$constant..].as_ptr());
                    let message: [uint32x4_t; LANES] =
                        core::array::from_fn(|lane| vaddq_u32(words[lane][$word], constants));
                    let previous = abcd;
                    for lane in 0..LANES {
                        abcd[lane] = vsha256hq_u32(previous[lane], efgh[lane], message[lane]);
                    }
                    for lane in 0..LANES {
                        efgh[lane] = vsha256h2q_u32(efgh[lane], previous[lane], message[lane]);
                    }
                }};
            }
            macro_rules! expand_rounds {
                ($constant:expr, $a:expr, $b:expr, $c:expr, $d:expr) => {{
                    for lane in 0..LANES {
                        words[lane][$a] = vsha256su1q_u32(
                            vsha256su0q_u32(words[lane][$a], words[lane][$b]),
                            words[lane][$c],
                            words[lane][$d],
                        );
                    }
                    rounds!($constant, $a);
                }};
            }
            rounds!(0, 0);
            rounds!(4, 1);
            rounds!(8, 2);
            rounds!(12, 3);
            for round in (16..64).step_by(16) {
                expand_rounds!(round, 0, 1, 2, 3);
                expand_rounds!(round + 4, 1, 2, 3, 0);
                expand_rounds!(round + 8, 2, 3, 0, 1);
                expand_rounds!(round + 12, 3, 0, 1, 2);
            }
            core::array::from_fn(|lane| {
                [
                    vaddq_u32(abcd[lane], states[lane][0]),
                    vaddq_u32(efgh[lane], states[lane][1]),
                ]
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn independent_compressions_match_upstream_for_arbitrary_cvs() {
        for seed in 0_u32..193 {
            let mut states: [[u32; 8]; 2] = core::array::from_fn(|lane| {
                core::array::from_fn(|word| {
                    seed.wrapping_mul(0x9e37_79b9)
                        .rotate_left((lane * 8 + word) as u32)
                        ^ (word + lane * 17) as u32
                })
            });
            let blocks: [[u8; 64]; 2] = core::array::from_fn(|lane| {
                core::array::from_fn(|i| (seed as usize * 31 + lane * 179 + i * 73 + i / 7) as u8)
            });
            let mut expected = states;
            for lane in 0..2 {
                sha2::block_api::compress256(
                    &mut expected[lane],
                    core::slice::from_ref(&blocks[lane]),
                );
            }
            compress_pair(&mut states, [&blocks[0], &blocks[1]]);
            assert_eq!(states, expected, "seed {seed}");
        }
    }

    #[test]
    fn fused_t253_matches_three_independent_compressions() {
        for seed in 0..193 {
            let left = core::array::from_fn(|i| (i * 17 + seed * 37 + i / 7) as u8);
            let right = core::array::from_fn(|i| (i * 179 + seed * 73 + i / 11) as u8);
            let shared = core::array::from_fn(|i| (i * 43 + seed * 61) as u8);
            let extra = core::array::from_fn(|i| (i * 173 + seed * 19) as u8);
            assert_eq!(
                t253(&left, &right, &shared, &extra),
                t253_portable(&left, &right, &shared, &extra),
                "seed {seed}"
            );
        }
    }
}
