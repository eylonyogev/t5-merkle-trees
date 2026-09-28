//! BLAKE3's seven-round compression with independent CVs and counters per lane.
//!
//! The upstream multi-message API takes one common CV. T8 needs a different CV
//! for every message. This small kernel supplies that missing operation while
//! retaining exactly the upstream compression function, including its flags.
//! All unsafe code is confined to AArch64 NEON loads/stores and intrinsics;
//! the public-to-the-crate boundary accepts only checked, complete arrays.

use crate::Digest;

/// Compress complete 64-byte messages with arbitrary independent chaining values.
pub(crate) fn compress_many(
    cvs: &[Digest],
    blocks: &[[u8; 64]],
    counters: &[u64],
    flags: u8,
    out: &mut [Digest],
) {
    assert_eq!(cvs.len(), blocks.len());
    assert_eq!(cvs.len(), counters.len());
    assert_eq!(cvs.len(), out.len());
    #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
    if std::arch::is_aarch64_feature_detected!("neon") {
        let full = cvs.len() / 4 * 4;
        for start in (0..full).step_by(4) {
            // SAFETY: NEON was detected, and checked slice lengths plus this
            // range produce four complete CVs, blocks, counters and outputs.
            let result = unsafe {
                neon::four(
                    cvs[start..start + 4].try_into().unwrap(),
                    blocks[start..start + 4].try_into().unwrap(),
                    counters[start..start + 4].try_into().unwrap(),
                    flags,
                )
            };
            out[start..start + 4].copy_from_slice(&result);
        }
        let remaining = cvs.len() - full;
        if remaining == 3 {
            let mut last_cvs = [[0; 32]; 4];
            let mut last_blocks = [[0; 64]; 4];
            let mut last_counters = [0; 4];
            last_cvs[..remaining].copy_from_slice(&cvs[full..]);
            last_blocks[..remaining].copy_from_slice(&blocks[full..]);
            last_counters[..remaining].copy_from_slice(&counters[full..]);
            // SAFETY: all arrays have four elements; NEON was detected above.
            let result = unsafe { neon::four(&last_cvs, &last_blocks, &last_counters, flags) };
            out[full..].copy_from_slice(&result[..remaining]);
        } else {
            // Two useful lanes did not amortize packing and padding on the
            // measured AArch64 target; the upstream single-message routine is
            // faster for one or two tails. Three lanes still benefit from SIMD.
            for i in full..cvs.len() {
                out[i] = portable(&cvs[i], &blocks[i], counters[i], flags);
            }
        }
        return;
    }
    for (((cv, block), counter), output) in cvs.iter().zip(blocks).zip(counters).zip(out) {
        *output = portable(cv, block, *counter, flags);
    }
}

/// Use upstream's optimized single-message implementation for dependent calls.
/// The portable AArch64 routine measured faster than an intra-message NEON
/// implementation here; across-message SIMD remains useful for full batches.
#[inline]
pub(crate) fn compress_one(cv: &Digest, block: &[u8; 64], counter: u64, flags: u8) -> Digest {
    portable(cv, block, counter, flags)
}

/// The wide experimental oracle uses the complete block and CV plus seven
/// counter bytes as payload. The final counter byte separates the oracle role.
/// Input order is block (64), CV (32), then little-endian counter payload (7).
#[inline]
pub(crate) fn compress_103_one(role: u8, input: &[u8; 103]) -> Digest {
    let mut counter = [0; 8];
    counter[..7].copy_from_slice(&input[96..]);
    counter[7] = role;
    compress_one(
        input[64..96].try_into().unwrap(),
        input[..64].try_into().unwrap(),
        u64::from_le_bytes(counter),
        19,
    )
}

/// Batch the wide oracle without first splitting/copying each message into
/// separate CV and block arrays. Full four-message groups use independent
/// counters and CVs in NEON; other targets retain identical scalar semantics.
pub(crate) fn compress_103_many(roles: &[u8], inputs: &[[u8; 103]], out: &mut [Digest]) {
    assert_eq!(roles.len(), inputs.len());
    assert_eq!(inputs.len(), out.len());
    #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
    if std::arch::is_aarch64_feature_detected!("neon") {
        let full = inputs.len() / 4 * 4;
        for start in (0..full).step_by(4) {
            // SAFETY: NEON was detected, and the checked lengths contain four
            // complete messages, role bytes, and destinations at this offset.
            let result = unsafe {
                neon::four_wide(
                    roles[start..start + 4].try_into().unwrap(),
                    inputs[start..start + 4].try_into().unwrap(),
                )
            };
            out[start..start + 4].copy_from_slice(&result);
        }
        for i in full..inputs.len() {
            out[i] = compress_103_one(roles[i], &inputs[i]);
        }
        return;
    }
    for ((role, input), output) in roles.iter().zip(inputs).zip(out) {
        *output = compress_103_one(*role, input);
    }
}

/// Fused T8 chaining for four records. Returning `None` selects the portable
/// backend on targets without this kernel. The fixed role namespace is exactly
/// the BLAKE3 experimental T8 definition, including its original zero padding.
pub(crate) fn t8_four(input: [&[u8]; 4]) -> Option<[Digest; 4]> {
    assert!(!input[0].is_empty());
    assert!(input.iter().all(|row| row.len() == input[0].len()));
    #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
    if std::arch::is_aarch64_feature_detected!("neon") {
        // SAFETY: NEON is available. The kernel uses checked slices and pads
        // partial stages into complete stack arrays before any vector load.
        return Some(unsafe { neon::t8_four(input) });
    }
    None
}

/// Fused T277/ABR625 stages and their domain-separated MD tails. The planner
/// selects the schedule once; this kernel keeps chaining digests in vectors
/// throughout the four independent records instead of storing/reloading them
/// at every oracle boundary.
pub(crate) fn wide_four(
    input: [&[u8]; 4],
    abr: bool,
    stages: usize,
    tails: usize,
    md_head: bool,
) -> Option<[Digest; 4]> {
    assert!(!input[0].is_empty());
    assert!(input.iter().all(|row| row.len() == input[0].len()));
    debug_assert_eq!(stages == 0, md_head);
    #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
    if std::arch::is_aarch64_feature_detected!("neon") {
        // SAFETY: NEON is available. Every vector read is from a checked input
        // subrange or complete zero-padded scratch, as in the existing T8 path.
        return Some(unsafe { neon::wide_four(input, abr, stages, tails, md_head) });
    }
    let _ = (abr, stages, tails, md_head);
    None
}

/// Fused lookahead for a single wide leaf. Four gadget stages expose their
/// independent branches to SIMD; only the final root of each stage remains
/// serial. Short leaves retain the scalar scheduler without SIMD setup cost.
pub(crate) fn wide_one(input: &[u8], abr: bool, stages: usize, tails: usize) -> Option<Digest> {
    if stages < 4 {
        return None;
    }
    #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
    if std::arch::is_aarch64_feature_detected!("neon") {
        // SAFETY: NEON is available, and the kernel uses checked slices plus
        // fixed-size zero-padded arrays for partial stages and MD tails.
        return Some(unsafe { neon::wide_one(input, abr, stages, tails) });
    }
    let _ = (input, abr, tails);
    None
}

#[cfg(all(target_arch = "aarch64", target_endian = "little"))]
#[inline]
fn wide_node_scalar(
    left: &Digest,
    right: &Digest,
    shared: &Digest,
    extra: &[u8],
    role: u8,
    abr: bool,
) -> Digest {
    debug_assert_eq!(extra.len(), 39);
    let mut block = [0; 64];
    for i in 0..32 {
        block[i] = left[i] ^ shared[i];
        block[32 + i] = right[i] ^ shared[i];
    }
    let mut counter = [0; 8];
    counter[..7].copy_from_slice(&extra[32..]);
    counter[7] = role;
    let out = compress_one(
        extra[..32].try_into().unwrap(),
        &block,
        u64::from_le_bytes(counter),
        19,
    );
    core::array::from_fn(|i| out[i] ^ if abr { right[i] } else { shared[i] })
}

#[inline]
fn portable(cv: &Digest, block: &[u8; 64], counter: u64, flags: u8) -> Digest {
    let mut words = blake3::platform::words_from_le_bytes_32(cv);
    // On x86, upstream selects its optimized single-message SIMD implementation.
    blake3::platform::Platform::detect().compress_in_place(&mut words, block, 64, counter, flags);
    let mut out = [0; 32];
    for (word, bytes) in words.iter().zip(out.chunks_exact_mut(4)) {
        bytes.copy_from_slice(&word.to_le_bytes());
    }
    out
}

#[cfg(all(target_arch = "aarch64", target_endian = "little"))]
mod neon {
    use super::Digest;
    use std::arch::aarch64::*;

    // Message schedules from the BLAKE3 specification, including all seven rounds.
    const SCHEDULE: [[usize; 16]; 7] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
        [3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1],
        [10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6],
        [12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4],
        [9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7],
        [11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13],
    ];

    #[inline(always)]
    unsafe fn mix(
        mut a: uint32x4_t,
        mut b: uint32x4_t,
        mut c: uint32x4_t,
        mut d: uint32x4_t,
        x: uint32x4_t,
        y: uint32x4_t,
    ) -> (uint32x4_t, uint32x4_t, uint32x4_t, uint32x4_t) {
        // SAFETY: callers execute only after checking NEON availability. These
        // intrinsics operate on registers; no pointer or alignment is involved.
        unsafe {
            a = vaddq_u32(vaddq_u32(a, b), x);
            d = veorq_u32(d, a);
            d = vreinterpretq_u32_u16(vrev32q_u16(vreinterpretq_u16_u32(d)));
            c = vaddq_u32(c, d);
            b = veorq_u32(b, c);
            b = vsriq_n_u32::<12>(vshlq_n_u32::<20>(b), b);
            a = vaddq_u32(vaddq_u32(a, b), y);
            d = veorq_u32(d, a);
            // A byte-table rotation is one instruction instead of two shifts.
            let rotate = vld1q_u8([1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12].as_ptr());
            d = vreinterpretq_u32_u8(vqtbl1q_u8(vreinterpretq_u8_u32(d), rotate));
            c = vaddq_u32(c, d);
            b = veorq_u32(b, c);
            b = vsriq_n_u32::<7>(vshlq_n_u32::<25>(b), b);
            (a, b, c, d)
        }
    }

    #[inline(always)]
    unsafe fn round<const R: usize>(v: &mut [uint32x4_t; 16], m: &[uint32x4_t; 16]) {
        let s = SCHEDULE[R];
        macro_rules! g {
            ($a:literal, $b:literal, $c:literal, $d:literal, $i:literal) => {
                // SAFETY: the calling kernel checked NEON; indices are fixed.
                (v[$a], v[$b], v[$c], v[$d]) =
                    unsafe { mix(v[$a], v[$b], v[$c], v[$d], m[s[$i]], m[s[$i + 1]]) };
            };
        }
        g!(0, 4, 8, 12, 0);
        g!(1, 5, 9, 13, 2);
        g!(2, 6, 10, 14, 4);
        g!(3, 7, 11, 15, 6);
        g!(0, 5, 10, 15, 8);
        g!(1, 6, 11, 12, 10);
        g!(2, 7, 8, 13, 12);
        g!(3, 4, 9, 14, 14);
    }

    #[inline(always)]
    unsafe fn transpose(v: [uint32x4_t; 4]) -> [uint32x4_t; 4] {
        // SAFETY: register-only NEON operations, checked by the calling kernel.
        unsafe {
            let a = vreinterpretq_u64_u32(vtrn1q_u32(v[0], v[1]));
            let b = vreinterpretq_u64_u32(vtrn2q_u32(v[0], v[1]));
            let c = vreinterpretq_u64_u32(vtrn1q_u32(v[2], v[3]));
            let d = vreinterpretq_u64_u32(vtrn2q_u32(v[2], v[3]));
            [
                vreinterpretq_u32_u64(vzip1q_u64(a, c)),
                vreinterpretq_u32_u64(vzip1q_u64(b, d)),
                vreinterpretq_u32_u64(vzip2q_u64(a, c)),
                vreinterpretq_u32_u64(vzip2q_u64(b, d)),
            ]
        }
    }

    #[inline(always)]
    unsafe fn compress_words(
        cv: &[uint32x4_t; 8],
        m: &[uint32x4_t; 16],
        counter_low: uint32x4_t,
        counter_high: uint32x4_t,
        flags: u8,
    ) -> [uint32x4_t; 8] {
        // SAFETY: register-only operations. The calling kernel enables NEON.
        unsafe {
            let mut v = [
                cv[0],
                cv[1],
                cv[2],
                cv[3],
                cv[4],
                cv[5],
                cv[6],
                cv[7],
                vdupq_n_u32(0x6a09e667),
                vdupq_n_u32(0xbb67ae85),
                vdupq_n_u32(0x3c6ef372),
                vdupq_n_u32(0xa54ff53a),
                counter_low,
                counter_high,
                vdupq_n_u32(64),
                vdupq_n_u32(u32::from(flags)),
            ];
            round::<0>(&mut v, m);
            round::<1>(&mut v, m);
            round::<2>(&mut v, m);
            round::<3>(&mut v, m);
            round::<4>(&mut v, m);
            round::<5>(&mut v, m);
            round::<6>(&mut v, m);
            core::array::from_fn(|i| veorq_u32(v[i], v[i + 8]))
        }
    }

    #[inline(always)]
    unsafe fn load_words<const WORDS: usize>(
        rows: [&[u8]; 4],
        offset: usize,
    ) -> [uint32x4_t; WORDS] {
        // SAFETY: every pointer comes from an explicitly checked 16-byte slice.
        // NEON loads support unaligned addresses. WORDS is always 8 or 16 here.
        unsafe {
            let mut words = [vdupq_n_u32(0); WORDS];
            for i in 0..WORDS / 4 {
                let start = offset + i * 16;
                let lanes = core::array::from_fn(|lane| {
                    vreinterpretq_u32_u8(vld1q_u8(rows[lane][start..start + 16].as_ptr()))
                });
                words[i * 4..i * 4 + 4].copy_from_slice(&transpose(lanes));
            }
            words
        }
    }

    #[inline(always)]
    unsafe fn store_words(words: &[uint32x4_t; 8]) -> [Digest; 4] {
        // SAFETY: stores each write a complete 16-byte half of a 32-byte array.
        unsafe {
            let mut out = [[0; 32]; 4];
            for i in 0..2 {
                let result = transpose(core::array::from_fn(|j| words[i * 4 + j]));
                for lane in 0..4 {
                    vst1q_u8(
                        out[lane][i * 16..].as_mut_ptr(),
                        vreinterpretq_u8_u32(result[lane]),
                    );
                }
            }
            out
        }
    }

    #[target_feature(enable = "neon")]
    pub(super) unsafe fn four(
        cvs: &[Digest; 4],
        blocks: &[[u8; 64]; 4],
        counters: &[u64; 4],
        flags: u8,
    ) -> [Digest; 4] {
        // SAFETY: all addresses below refer to complete 16-byte subranges of
        // fixed-size input/output arrays. NEON vld1/vst1 permit unaligned access.
        // The caller detected NEON and this function enables that CPU feature.
        unsafe {
            let m = load_words(core::array::from_fn(|i| blocks[i].as_slice()), 0);
            let cv = load_words(core::array::from_fn(|i| cvs[i].as_slice()), 0);
            let out = compress_words(
                &cv,
                &m,
                vld1q_u32(counters.map(|counter| counter as u32).as_ptr()),
                vld1q_u32(counters.map(|counter| (counter >> 32) as u32).as_ptr()),
                flags,
            );
            store_words(&out)
        }
    }

    #[target_feature(enable = "neon")]
    pub(super) unsafe fn four_wide(roles: &[u8; 4], inputs: &[[u8; 103]; 4]) -> [Digest; 4] {
        // SAFETY: fixed-size inputs contain every vector load. Counter loads
        // below use scalar byte reads, including the final three payload bytes,
        // so they never over-read the end of a 103-byte message.
        unsafe {
            let rows = core::array::from_fn(|i| inputs[i].as_slice());
            let low: [u32; 4] = core::array::from_fn(|i| {
                u32::from_le_bytes(inputs[i][96..100].try_into().unwrap())
            });
            let high: [u32; 4] = core::array::from_fn(|i| {
                u32::from_le_bytes([inputs[i][100], inputs[i][101], inputs[i][102], roles[i]])
            });
            let result = compress_words(
                &load_words(rows, 64),
                &load_words(rows, 0),
                vld1q_u32(low.as_ptr()),
                vld1q_u32(high.as_ptr()),
                19,
            );
            store_words(&result)
        }
    }

    #[inline(always)]
    unsafe fn counter_words(rows: [&[u8]; 4], offset: usize, role: u8) -> (uint32x4_t, uint32x4_t) {
        // SAFETY: load four complete scalar words from local arrays. Checked
        // slice/index access ensures exactly seven payload bytes are consumed.
        unsafe {
            let low: [u32; 4] = core::array::from_fn(|i| {
                u32::from_le_bytes(rows[i][offset..offset + 4].try_into().unwrap())
            });
            let high: [u32; 4] = core::array::from_fn(|i| {
                u32::from_le_bytes([
                    rows[i][offset + 4],
                    rows[i][offset + 5],
                    rows[i][offset + 6],
                    role,
                ])
            });
            (vld1q_u32(low.as_ptr()), vld1q_u32(high.as_ptr()))
        }
    }

    #[inline(always)]
    unsafe fn wide_oracle(rows: [&[u8]; 4], offset: usize, role: u8) -> [uint32x4_t; 8] {
        // SAFETY: callers provide a complete 103-byte oracle input in each row.
        unsafe {
            let (low, high) = counter_words(rows, offset + 96, role);
            compress_words(
                &load_words(rows, offset + 64),
                &load_words(rows, offset),
                low,
                high,
                19,
            )
        }
    }

    #[inline(always)]
    unsafe fn wide_node(
        left: &[uint32x4_t; 8],
        right: &[uint32x4_t; 8],
        shared: &[uint32x4_t; 8],
        rows: [&[u8]; 4],
        extra_offset: usize,
        role: u8,
        abr: bool,
    ) -> [uint32x4_t; 8] {
        // SAFETY: checked rows contain the 39-byte extra input. All other
        // operations act on NEON registers and the caller enabled NEON.
        unsafe {
            let mut block = [vdupq_n_u32(0); 16];
            for i in 0..8 {
                block[i] = veorq_u32(left[i], shared[i]);
                block[i + 8] = veorq_u32(right[i], shared[i]);
            }
            let (low, high) = counter_words(rows, extra_offset + 32, role);
            let out = compress_words(&load_words(rows, extra_offset), &block, low, high, 19);
            core::array::from_fn(|i| veorq_u32(out[i], if abr { right[i] } else { shared[i] }))
        }
    }

    #[target_feature(enable = "neon")]
    pub(super) unsafe fn wide_four(
        input: [&[u8]; 4],
        abr: bool,
        stages: usize,
        tails: usize,
        md_head: bool,
    ) -> [Digest; 4] {
        // SAFETY: the wrapper validated equal nonempty inputs and NEON. All
        // external reads below use checked slices; partial stages and tails
        // are copied into complete fixed-size zero-padded arrays before loads.
        unsafe {
            let mut state = [vdupq_n_u32(0); 8];
            let first_width = if abr { 625 } else { 277 };
            let md_role = if abr { 0xd7 } else { 0xc3 };
            let mut partial = [[0; 625]; 4];
            let mut offset = 0;
            if md_head {
                let available = input[0].len().min(103);
                let rows = if available == 103 {
                    core::array::from_fn(|i| &input[i][..103])
                } else {
                    for i in 0..4 {
                        partial[i][..available].copy_from_slice(&input[i][..available]);
                    }
                    core::array::from_fn(|i| &partial[i][..103])
                };
                state = wide_oracle(rows, 0, md_role);
                offset = available;
            }
            for stage in 0..stages {
                let first = stage == 0;
                let width = first_width - if first { 0 } else { 32 };
                let available = (input[0].len() - offset).min(width);
                let rows = if available == width {
                    core::array::from_fn(|i| &input[i][offset..offset + width])
                } else {
                    // Only the final stage can be partial. Scratch is still
                    // zero because a gadget schedule never has an MD head.
                    for i in 0..4 {
                        partial[i][..available]
                            .copy_from_slice(&input[i][offset..offset + available]);
                    }
                    core::array::from_fn(|i| &partial[i][..width])
                };
                if abr {
                    let a = wide_oracle(rows, 0, 0xd0);
                    let b = wide_oracle(rows, 103, 0xd1);
                    let left = wide_node(&a, &b, &load_words(rows, 412), rows, 444, 0xd4, true);
                    let c = wide_oracle(rows, 206, 0xd2);
                    let d = wide_oracle(rows, 309, 0xd3);
                    let right = wide_node(&c, &d, &load_words(rows, 483), rows, 515, 0xd5, true);
                    if first {
                        state = load_words(rows, 554);
                    }
                    state = wide_node(
                        &left,
                        &right,
                        &state,
                        rows,
                        if first { 586 } else { 554 },
                        0xd6,
                        true,
                    );
                } else {
                    let left = wide_oracle(rows, 0, 0xc0);
                    let right = wide_oracle(rows, 103, 0xc1);
                    if first {
                        state = load_words(rows, 206);
                    }
                    state = wide_node(
                        &left,
                        &right,
                        &state,
                        rows,
                        if first { 238 } else { 206 },
                        0xc2,
                        false,
                    );
                }
                offset += available;
            }
            let mut tail_scratch = [[0; 71]; 4];
            for _ in 0..tails {
                let available = (input[0].len() - offset).min(71);
                let rows = if available == 71 {
                    core::array::from_fn(|i| &input[i][offset..offset + 71])
                } else {
                    // Only the last tail can be partial, so scratch is zero.
                    for i in 0..4 {
                        tail_scratch[i][..available]
                            .copy_from_slice(&input[i][offset..offset + available]);
                    }
                    core::array::from_fn(|i| tail_scratch[i].as_slice())
                };
                let fresh: [uint32x4_t; 8] = load_words(rows, 0);
                let mut block = [vdupq_n_u32(0); 16];
                block[..8].copy_from_slice(&state);
                block[8..].copy_from_slice(&fresh);
                let (low, high) = counter_words(rows, 64, md_role);
                state = compress_words(&load_words(rows, 32), &block, low, high, 19);
                offset += available;
            }
            debug_assert_eq!(offset, input[0].len());
            store_words(&state)
        }
    }

    #[target_feature(enable = "neon")]
    pub(super) unsafe fn wide_one(input: &[u8], abr: bool, stages: usize, tails: usize) -> Digest {
        // SAFETY: the wrapper detected NEON. All loads below are checked input
        // subranges or padded fixed-size arrays, and unused SIMD lanes reuse
        // a complete active stage rather than reading beyond the input.
        unsafe {
            let fresh = if abr { 593 } else { 245 };
            let root_offset = if abr { 554 } else { 206 };
            let mut state = [0; 32];
            let mut partial = [[0; 625]; 4];
            let mut offset = 0;
            let mut stage = 0;
            while stage < stages {
                let count = (stages - stage).min(4);
                let starts: [usize; 4] = core::array::from_fn(|i| {
                    offset + i * fresh + usize::from(stage == 0 && i > 0) * 32
                });
                let widths: [usize; 4] =
                    core::array::from_fn(|i| fresh + usize::from(stage + i == 0) * 32);
                for i in 0..count {
                    let available = input.len().saturating_sub(starts[i]).min(widths[i]);
                    if available < widths[i] {
                        partial[i][..available]
                            .copy_from_slice(&input[starts[i]..starts[i] + available]);
                    }
                }
                let rows: [&[u8]; 4] = core::array::from_fn(|lane| {
                    let i = if lane < count { lane } else { 0 };
                    if input.len().saturating_sub(starts[i]) >= widths[i] {
                        &input[starts[i]..starts[i] + widths[i]]
                    } else {
                        &partial[i][..widths[i]]
                    }
                });
                let (left, right) = if abr {
                    let a = wide_oracle(rows, 0, 0xd0);
                    let b = wide_oracle(rows, 103, 0xd1);
                    let left = wide_node(&a, &b, &load_words(rows, 412), rows, 444, 0xd4, true);
                    let c = wide_oracle(rows, 206, 0xd2);
                    let d = wide_oracle(rows, 309, 0xd3);
                    let right = wide_node(&c, &d, &load_words(rows, 483), rows, 515, 0xd5, true);
                    (store_words(&left), store_words(&right))
                } else {
                    (
                        store_words(&wide_oracle(rows, 0, 0xc0)),
                        store_words(&wide_oracle(rows, 103, 0xc1)),
                    )
                };
                for i in 0..count {
                    let first = stage + i == 0;
                    if first {
                        state.copy_from_slice(&rows[i][root_offset..root_offset + 32]);
                    }
                    let extra_offset = root_offset + usize::from(first) * 32;
                    state = super::wide_node_scalar(
                        &left[i],
                        &right[i],
                        &state,
                        &rows[i][extra_offset..extra_offset + 39],
                        if abr { 0xd6 } else { 0xc2 },
                        abr,
                    );
                }
                offset = (offset + count * fresh + usize::from(stage == 0) * 32).min(input.len());
                stage += count;
            }
            for _ in 0..tails {
                let count = (input.len() - offset).min(71);
                let mut block = [0; 103];
                block[..32].copy_from_slice(&state);
                block[32..32 + count].copy_from_slice(&input[offset..offset + count]);
                state = super::compress_103_one(if abr { 0xd7 } else { 0xc3 }, &block);
                offset += count;
            }
            debug_assert_eq!(offset, input.len());
            state
        }
    }

    #[target_feature(enable = "neon")]
    pub(super) unsafe fn t8_four(input: [&[u8]; 4]) -> [Digest; 4] {
        // SAFETY: the safe wrapper validated equal, positive widths and NEON.
        // Every stage is either a checked full input slice or a padded stack
        // array. load_words performs an additional bound check per vector load.
        unsafe {
            let zero = vdupq_n_u32(0);
            let mut state = [zero; 8];
            let mut partial = [[0; 256]; 4];
            let mut offset = 0;
            while offset < input[0].len() {
                let first = offset == 0;
                let width = if first { 256 } else { 224 };
                let available = width.min(input[0].len() - offset);
                let rows: [&[u8]; 4] = if available == width {
                    core::array::from_fn(|i| &input[i][offset..offset + width])
                } else {
                    // A partial stage can only be the last one. The scratch is
                    // zero initialized once and has not been written earlier.
                    for i in 0..4 {
                        partial[i][..available]
                            .copy_from_slice(&input[i][offset..offset + available]);
                    }
                    core::array::from_fn(|i| &partial[i][..width])
                };
                if first {
                    state = load_words(rows, 192);
                }
                // Counters are (3 << 48) | role. The CV carries the third
                // 32-byte argument, exactly like the unfused oracle3 adapter.
                let left = compress_words(
                    &load_words(rows, 64),
                    &load_words(rows, 0),
                    vdupq_n_u32(20),
                    vdupq_n_u32(3 << 16),
                    19,
                );
                let right = compress_words(
                    &load_words(rows, 160),
                    &load_words(rows, 96),
                    vdupq_n_u32(21),
                    vdupq_n_u32(3 << 16),
                    19,
                );
                let mut root = [zero; 16];
                for i in 0..8 {
                    root[i] = veorq_u32(left[i], state[i]);
                    root[i + 8] = veorq_u32(right[i], state[i]);
                }
                let root = compress_words(
                    &load_words(rows, if first { 224 } else { 192 }),
                    &root,
                    vdupq_n_u32(22),
                    vdupq_n_u32(3 << 16),
                    19,
                );
                for i in 0..8 {
                    state[i] = veorq_u32(root[i], state[i]);
                }
                offset += available;
            }
            store_words(&state)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Build the upstream call independently of the production adapter: word
    // parsing, counter assembly and result serialization deliberately live in
    // this reference rather than going through compress_103_one.
    fn wide_reference(role: u8, input: &[u8; 103]) -> Digest {
        let mut cv = core::array::from_fn(|i| {
            u32::from_le_bytes(input[64 + 4 * i..68 + 4 * i].try_into().unwrap())
        });
        let counter = input[96..]
            .iter()
            .enumerate()
            .fold(u64::from(role) << 56, |value, (i, byte)| {
                value | (u64::from(*byte) << (8 * i))
            });
        blake3::platform::Platform::detect().compress_in_place(
            &mut cv,
            input[..64].try_into().unwrap(),
            64,
            counter,
            16 | 1 | 2,
        );
        let mut out = [0; 32];
        for (bytes, word) in out.chunks_exact_mut(4).zip(cv) {
            bytes.copy_from_slice(&word.to_le_bytes());
        }
        out
    }

    #[test]
    fn wide_oracle_uses_every_payload_and_role_byte() {
        let input = core::array::from_fn(|i| (i * 117 + 53) as u8);
        for role in [0, 1, 0xc0, 0xc1, 0xc2, 0xc3, 0xd0, 0xd6, 0xd7, 255] {
            let expected = wide_reference(role, &input);
            assert_eq!(compress_103_one(role, &input), expected);
            for i in 0..103 {
                let mut changed = input;
                changed[i] ^= 0x80;
                assert_eq!(
                    compress_103_one(role, &changed),
                    wide_reference(role, &changed)
                );
                assert_ne!(compress_103_one(role, &changed), expected, "byte={i}");
            }
            for bit in 0..8 {
                assert_ne!(compress_103_one(role ^ (1 << bit), &input), expected);
            }
        }
    }

    #[test]
    fn wide_batches_and_partial_lanes_match_upstream() {
        for count in 0..=17 {
            let inputs: Vec<[u8; 103]> = (0..count)
                .map(|row| core::array::from_fn(|i| (row * 57 + i * 117 + i / 7) as u8))
                .collect();
            let roles: Vec<u8> = (0..count).map(|i| (i * 29 + 0xc0) as u8).collect();
            let mut out = vec![[0; 32]; count];
            compress_103_many(&roles, &inputs, &mut out);
            for i in 0..count {
                assert_eq!(
                    out[i],
                    wide_reference(roles[i], &inputs[i]),
                    "rows={count}, lane={i}"
                );
            }
        }
    }

    #[test]
    fn independent_messages_match_upstream() {
        let mut state = 0x94d0_49bb_1331_11ebu64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for count in 0..=17 {
            let cvs: Vec<Digest> = (0..count)
                .map(|_| core::array::from_fn(|_| next() as u8))
                .collect();
            let blocks: Vec<[u8; 64]> = (0..count)
                .map(|_| core::array::from_fn(|_| next() as u8))
                .collect();
            let counters: Vec<u64> = (0..count).map(|_| next()).collect();
            for flags in [0, 1, 2, 3, 8, 11, 19, 35, 67, 255] {
                let mut output = vec![[0; 32]; count];
                compress_many(&cvs, &blocks, &counters, flags, &mut output);
                for i in 0..count {
                    let expected = portable(&cvs[i], &blocks[i], counters[i], flags);
                    assert_eq!(
                        output[i], expected,
                        "count={count}, lane={i}, flags={flags}"
                    );
                    assert_eq!(
                        compress_one(&cvs[i], &blocks[i], counters[i], flags),
                        expected
                    );
                }
            }
        }
    }

    #[test]
    #[should_panic(expected = "assertion `left == right` failed")]
    fn mismatched_batch_shape_is_rejected() {
        compress_many(&[[0; 32]], &[], &[], 19, &mut []);
    }
}
