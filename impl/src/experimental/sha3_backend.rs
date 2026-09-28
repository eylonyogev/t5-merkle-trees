//! Direct one-block SHA3 oracles and persistent two-message scheduling.
//!
//! Every oracle retains its original 17-byte prefix and SHA3 suffix. Packing
//! directly into Keccak lanes removes intermediate encoded messages. A single
//! backend selection serves an entire leaf batch or verification leaf.
//!
//! SHAKE128 is the standard XOF truncated to 32 bytes. SPONGE-DM272 uses
//! full-round Keccak-f[1600], a 166-byte rate, full-state Davies--Meyer
//! feed-forward during absorption, and a fixed 17-byte leaf domain prefix.

use super::*;
use keccak::{Backend, BackendClosure, ParFn1600, ParState1600};

impl ResearchHash for Sha3_256 {
    #[inline]
    fn oracle2(role: u64, input: &[u8; 64]) -> Digest {
        oracle_dispatch(2, [role; 2], [input; 2], 1)[0]
    }

    #[inline]
    fn oracle3(role: u64, input: &[u8; 96]) -> Digest {
        oracle_dispatch(3, [role; 2], [input; 2], 1)[0]
    }

    #[inline]
    fn oracle2_pair(roles: [u64; 2], inputs: [&[u8; 64]; 2]) -> [Digest; 2] {
        oracle_dispatch(2, roles, inputs, 2)
    }

    #[inline]
    fn oracle3_pair(roles: [u64; 2], inputs: [&[u8; 96]; 2]) -> [Digest; 2] {
        oracle_dispatch(3, roles, inputs, 2)
    }

    fn hash_leaf_planned(plan: &LeafPlan, input: &[u8]) -> Digest {
        if plan.mode() == LeafMode::Standard {
            return Self::hash_leaf_fast(input);
        }
        if matches!(plan.mode(), LeafMode::Shake128 | LeafMode::SpongeDm272) {
            return Self::hash_sponge(plan, input);
        }
        let mut output = [[0; 32]];
        keccak::Keccak::new().with_backend(LeafJob {
            plan,
            input,
            output: &mut output,
        });
        output[0]
    }

    fn hash_leaves_planned(plan: &LeafPlan, input: &[u8], output: &mut [Digest]) {
        if plan.mode() == LeafMode::Standard {
            Self::hash_leaves_fast(input, plan.leaf_bytes(), output);
            return;
        }
        if matches!(plan.mode(), LeafMode::Shake128 | LeafMode::SpongeDm272) {
            keccak::Keccak::new().with_backend(SpongeJob {
                plan,
                input,
                output,
            });
            return;
        }
        keccak::Keccak::new().with_backend(LeafJob {
            plan,
            input,
            output,
        });
    }

    fn oracle2_calls() -> u64 {
        1
    }
    fn oracle3_calls() -> u64 {
        1
    }

    fn supports_sponge_modes() -> bool {
        true
    }

    fn hash_sponge(plan: &LeafPlan, input: &[u8]) -> Digest {
        let mut output = [[0; 32]];
        keccak::Keccak::new().with_backend(SpongeJob {
            plan,
            input,
            output: &mut output,
        });
        output[0]
    }
}

// This is prefix(4, 80), independent of the existing SHA3 oracle roles.
const SPONGE_DM_PREFIX: [u8; 17] = *b"MTLFv001\x04\x50\0\0\0\0\0\0\0";

struct SpongeJob<'a> {
    plan: &'a LeafPlan,
    input: &'a [u8],
    output: &'a mut [Digest],
}

impl BackendClosure for SpongeJob<'_> {
    fn call_once<B: Backend>(self) {
        match self.plan.mode() {
            LeafMode::Shake128 => {
                sponge_batch::<B, 168, false>(self.input, self.plan.leaf_bytes(), self.output)
            }
            LeafMode::SpongeDm272 => {
                sponge_batch::<B, 166, true>(self.input, self.plan.leaf_bytes(), self.output)
            }
            _ => unreachable!("expected SHAKE128 or SPONGE-DM272"),
        }
    }
}

/// A scalar entry avoids paying for an unused second SIMD record during
/// verification and in an odd batch's final row.
#[inline]
fn sponge_single<const RATE: usize, const DM: bool>(
    input: &[u8],
    mut permute: impl FnMut(&mut [u64; 25]),
) -> Digest {
    let mut state = [0; 25];
    let mut offset = 0;
    let mut occupied = 0;
    if DM {
        xor_block(&mut state, &SPONGE_DM_PREFIX);
        occupied = SPONGE_DM_PREFIX.len();
        let take = input.len().min(RATE - occupied);
        xor_block_at(&mut state, &input[..take], occupied);
        occupied += take;
        offset = take;
        if occupied == RATE {
            sponge_permute::<DM>(&mut state, &mut permute);
            occupied = 0;
        }
    }
    while input.len() - offset >= RATE {
        xor_block(&mut state, &input[offset..offset + RATE]);
        sponge_permute::<DM>(&mut state, &mut permute);
        offset += RATE;
    }
    // A short prefixed message was already absorbed above. Otherwise this is
    // the ordinary final partial block, including an empty padding block.
    if occupied == 0 {
        xor_block(&mut state, &input[offset..]);
        occupied = input.len() - offset;
    }
    sponge_padding::<RATE, DM>(&mut state, occupied);
    sponge_permute::<DM>(&mut state, &mut permute);
    sponge_digest(&state)
}

fn sponge_batch<B: Backend, const RATE: usize, const DM: bool>(
    input: &[u8],
    width: usize,
    output: &mut [Digest],
) {
    let mut states = ParState1600::<B>::default();
    let lanes = states.len();
    let permute = B::get_par_f1600();
    for (rows, digests) in input
        .chunks(width.saturating_mul(lanes))
        .zip(output.chunks_mut(lanes))
    {
        if digests.len() == 1 {
            digests[0] = sponge_single::<RATE, DM>(rows, B::get_f1600());
            continue;
        }
        states.fill([0; 25]);
        let mut offset = 0;
        let mut occupied = 0;
        if DM {
            occupied = SPONGE_DM_PREFIX.len();
            let take = width.min(RATE - occupied);
            for (state, row) in states.iter_mut().zip(rows.chunks_exact(width)) {
                xor_block(state, &SPONGE_DM_PREFIX);
                xor_block_at(state, &row[..take], occupied);
            }
            occupied += take;
            offset = take;
            if occupied == RATE {
                sponge_permute_many::<B, DM>(&mut states, permute);
                occupied = 0;
            }
        }
        while width - offset >= RATE {
            for (state, row) in states.iter_mut().zip(rows.chunks_exact(width)) {
                xor_block(state, &row[offset..offset + RATE]);
            }
            sponge_permute_many::<B, DM>(&mut states, permute);
            offset += RATE;
        }
        if occupied == 0 {
            for (state, row) in states.iter_mut().zip(rows.chunks_exact(width)) {
                xor_block(state, &row[offset..]);
            }
            occupied = width - offset;
        }
        for state in states.iter_mut().take(digests.len()) {
            sponge_padding::<RATE, DM>(state, occupied);
        }
        sponge_permute_many::<B, DM>(&mut states, permute);
        for (state, digest) in states.iter().zip(digests) {
            *digest = sponge_digest(state);
        }
    }
}

#[inline]
fn sponge_permute<const DM: bool>(state: &mut [u64; 25], permute: &mut impl FnMut(&mut [u64; 25])) {
    if DM {
        let before = *state;
        permute(state);
        for (word, original) in state.iter_mut().zip(before) {
            *word ^= original;
        }
    } else {
        permute(state);
    }
}

#[inline]
fn sponge_permute_many<B: Backend, const DM: bool>(
    states: &mut ParState1600<B>,
    permute: ParFn1600<B>,
) {
    if DM {
        let before = states.clone();
        permute(states);
        for (state, original) in states.iter_mut().zip(before) {
            for (word, previous) in state.iter_mut().zip(original) {
                *word ^= previous;
            }
        }
    } else {
        permute(states);
    }
}

#[inline]
fn sponge_padding<const RATE: usize, const DM: bool>(state: &mut [u64; 25], occupied: usize) {
    let suffix = if DM { 0x01_u64 } else { 0x1f_u64 };
    state[occupied / 8] ^= suffix << (8 * (occupied % 8));
    state[(RATE - 1) / 8] ^= 0x80_u64 << (8 * ((RATE - 1) % 8));
}

#[inline]
fn sponge_digest(state: &[u64; 25]) -> Digest {
    let mut digest = [0; 32];
    for (word, bytes) in state[..4].iter().zip(digest.chunks_exact_mut(8)) {
        bytes.copy_from_slice(&word.to_le_bytes());
    }
    digest
}

/// Full blocks use word loads. In particular, rate 166 is twenty words and
/// two bytes, without a per-byte loop over the complete rate.
#[inline]
fn xor_block(state: &mut [u64; 25], block: &[u8]) {
    let mut words = block.chunks_exact(8);
    for (word, bytes) in state.iter_mut().zip(words.by_ref()) {
        *word ^= u64::from_le_bytes(bytes.try_into().unwrap());
    }
    for (i, &byte) in words.remainder().iter().enumerate() {
        state[block.len() / 8] ^= u64::from(byte) << (8 * i);
    }
}

/// Only the first SPONGE-DM block starts at a non-word-aligned offset.
#[inline]
fn xor_block_at(state: &mut [u64; 25], block: &[u8], offset: usize) {
    let displacement = offset % 8;
    let mut words = block.chunks_exact(8);
    for (index, bytes) in words.by_ref().enumerate() {
        let word = u64::from_le_bytes(bytes.try_into().unwrap());
        state[offset / 8 + index] ^= word << (8 * displacement);
        if displacement != 0 {
            state[offset / 8 + index + 1] ^= word >> (64 - 8 * displacement);
        }
    }
    let tail_offset = offset + block.len() / 8 * 8;
    for (index, &byte) in words.remainder().iter().enumerate() {
        let position = tail_offset + index;
        state[position / 8] ^= u64::from(byte) << (8 * (position % 8));
    }
}

struct OracleJob<'a, const N: usize> {
    arity: u8,
    roles: [u64; 2],
    inputs: [&'a [u8; N]; 2],
    count: usize,
    output: &'a mut [Digest; 2],
}

impl<const N: usize> BackendClosure for OracleJob<'_, N> {
    #[inline]
    fn call_once<B: Backend>(self) {
        *self.output = Engine::<B>::new().oracles(self.arity, self.roles, self.inputs, self.count);
    }
}

#[inline]
fn oracle_dispatch<const N: usize>(
    arity: u8,
    roles: [u64; 2],
    inputs: [&[u8; N]; 2],
    count: usize,
) -> [Digest; 2] {
    let mut output = [[0; 32]; 2];
    keccak::Keccak::new().with_backend(OracleJob {
        arity,
        roles,
        inputs,
        count,
        output: &mut output,
    });
    output
}

struct LeafJob<'a> {
    plan: &'a LeafPlan,
    input: &'a [u8],
    output: &'a mut [Digest],
}

impl BackendClosure for LeafJob<'_> {
    fn call_once<B: Backend>(self) {
        let mut engine = Engine::<B>::new();
        let width = self.plan.leaf_bytes();
        for (rows, digests) in self
            .input
            .chunks(width.saturating_mul(2))
            .zip(self.output.chunks_mut(2))
        {
            let inputs = [
                &rows[..width],
                if digests.len() == 2 {
                    &rows[width..]
                } else {
                    &rows[..width]
                },
            ];
            let pair = match (self.plan.mode(), digests.len()) {
                (LeafMode::T5, 1) => [engine.t_single::<64>(inputs[0], T5_ROLES); 2],
                (LeafMode::T8, 1) => [engine.t_single::<96>(inputs[0], T8_ROLES); 2],
                (LeafMode::T5, _) => engine.t_pair::<64>(inputs, T5_ROLES),
                (LeafMode::T8, _) => engine.t_pair::<96>(inputs, T8_ROLES),
                (LeafMode::FixedMd, _) => engine.fixed_md(inputs, digests.len()),
                (LeafMode::Abr3, 1) => [engine.abr_single(inputs[0]); 2],
                (LeafMode::Abr3, _) => engine.abr3(inputs, digests.len()),
                (
                    LeafMode::Standard
                    | LeafMode::T253
                    | LeafMode::AbrWide
                    | LeafMode::T277
                    | LeafMode::Shake128
                    | LeafMode::SpongeDm272,
                    _,
                ) => {
                    unreachable!("unsupported SHA3 research mode")
                }
            };
            digests.copy_from_slice(&pair[..digests.len()]);
        }
    }
}

struct Engine<B: Backend> {
    states: ParState1600<B>,
    permute: ParFn1600<B>,
}

impl<B: Backend> Engine<B> {
    #[inline]
    fn new() -> Self {
        Self {
            states: ParState1600::<B>::default(),
            permute: B::get_par_f1600(),
        }
    }

    /// The backend may expose one or several lanes. A scalar backend visits
    /// both independent messages in order; two-lane hardware handles one call.
    #[inline]
    fn oracles<const N: usize>(
        &mut self,
        arity: u8,
        roles: [u64; 2],
        inputs: [&[u8; N]; 2],
        count: usize,
    ) -> [Digest; 2] {
        let mut output = [[0; 32]; 2];
        let lanes = self.states.len();
        for start in (0..count).step_by(lanes) {
            let active = lanes.min(count - start);
            // Inactive lanes are independent and their output is discarded.
            // They need not be reset between calls.
            for lane in 0..active {
                self.states[lane] = oracle_state(arity, roles[start + lane], inputs[start + lane]);
            }
            (self.permute)(&mut self.states);
            for lane in 0..active {
                for (bytes, &word) in output[start + lane]
                    .chunks_exact_mut(8)
                    .zip(&self.states[lane][..4])
                {
                    bytes.copy_from_slice(&word.to_le_bytes());
                }
            }
        }
        output
    }

    #[inline]
    fn one<const N: usize>(&mut self, arity: u8, role: u64, input: &[u8; N]) -> Digest {
        self.oracles(arity, [role; 2], [input; 2], 1)[0]
    }

    fn fixed_md(&mut self, input: [&[u8]; 2], count: usize) -> [Digest; 2] {
        if count == 1 {
            // A strictly serial MD chain has no independent work for a second
            // lane. Use the scalar backend entry directly, without constructing
            // a duplicate record and the two-record scheduling scaffold.
            let permute = B::get_f1600();
            let mut digest = [0; 32];
            for chunk in input[0].chunks(64) {
                let mut message = [0; 96];
                message[..32].copy_from_slice(&digest);
                message[32..32 + chunk.len()].copy_from_slice(chunk);
                let mut state = oracle_state(3, MD_ROLE, &message);
                permute(&mut state);
                for (bytes, &word) in digest.chunks_exact_mut(8).zip(&state[..4]) {
                    bytes.copy_from_slice(&word.to_le_bytes());
                }
            }
            return [digest; 2];
        }
        let mut state = [[0; 32]; 2];
        for offset in (0..input[0].len()).step_by(64) {
            let take = 64.min(input[0].len() - offset);
            let messages: [[u8; 96]; 2] = core::array::from_fn(|i| {
                let mut message = [0; 96];
                message[..32].copy_from_slice(&state[i]);
                message[32..32 + take].copy_from_slice(&input[i][offset..offset + take]);
                message
            });
            state = self.oracles(3, [MD_ROLE; 2], [&messages[0], &messages[1]], count);
        }
        state
    }

    fn t_pair<const N: usize>(&mut self, input: [&[u8]; 2], roles: [u64; 3]) -> [Digest; 2] {
        let arity = if N == 64 { 2 } else { 3 };
        let stages = stage_count(input[0].len(), 3 * N - 32, 3 * N - 64);
        let mut shared = [[0; 32]; 2];
        for index in 0..stages {
            let messages = [
                Stage::<N>::load(input[0], index),
                Stage::<N>::load(input[1], index),
            ];
            if index == 0 {
                shared = [messages[0].shared, messages[1].shared];
            }
            let left = self.oracles(
                arity,
                [roles[0]; 2],
                [&messages[0].left, &messages[1].left],
                2,
            );
            let right = self.oracles(
                arity,
                [roles[1]; 2],
                [&messages[0].right, &messages[1].right],
                2,
            );
            let roots = core::array::from_fn::<_, 2, _>(|i| {
                messages[i].root(left[i], right[i], &shared[i])
            });
            let root = self.oracles(arity, [roles[2]; 2], [&roots[0], &roots[1]], 2);
            shared = core::array::from_fn(|i| xor(root[i], &shared[i]));
        }
        shared
    }

    /// A verification leaf has no independent neighboring record. For long
    /// T5/T8 leaves, pair a dependent root with a bottom node from a later stage.
    /// The schedule uses three two-lane rounds for two additional gadgets,
    /// retaining the exact dependency graph and all original oracle calls.
    fn t_single<const N: usize>(&mut self, input: &[u8], roles: [u64; 3]) -> Digest {
        let arity = if N == 64 { 2 } else { 3 };
        let stages = stage_count(input.len(), 3 * N - 32, 3 * N - 64);
        let mut current = Stage::<N>::load(input, 0);
        let mut shared = current.shared;
        let [mut left, mut right] = self.oracles(
            arity,
            [roles[0], roles[1]],
            [&current.left, &current.right],
            2,
        );
        let mut index = 0;
        while index + 2 < stages {
            let next = Stage::<N>::load(input, index + 1);
            let after = Stage::<N>::load(input, index + 2);
            let root = current.root(left, right, &shared);
            let [digest, next_left] =
                self.oracles(arity, [roles[2], roles[0]], [&root, &next.left], 2);
            shared = xor(digest, &shared);
            let [next_right, after_left] =
                self.oracles(arity, [roles[1], roles[0]], [&next.right, &after.left], 2);
            let root = next.root(next_left, next_right, &shared);
            let [digest, after_right] =
                self.oracles(arity, [roles[2], roles[1]], [&root, &after.right], 2);
            shared = xor(digest, &shared);
            current = after;
            left = after_left;
            right = after_right;
            index += 2;
        }
        let root = current.root(left, right, &shared);
        shared = xor(self.one(arity, roles[2], &root), &shared);
        if index + 1 < stages {
            current = Stage::<N>::load(input, index + 1);
            [left, right] = self.oracles(
                arity,
                [roles[0], roles[1]],
                [&current.left, &current.right],
                2,
            );
            let root = current.root(left, right, &shared);
            shared = xor(self.one(arity, roles[2], &root), &shared);
        }
        shared
    }

    fn abr3(&mut self, input: [&[u8]; 2], count: usize) -> [Digest; 2] {
        let mut messages = [[0; 352]; 2];
        let first = input[0].len().min(352);
        for i in 0..count {
            messages[i][..first].copy_from_slice(&input[i][..first]);
        }
        let mut state = self.abr_gadget(&messages, count);
        for offset in (first..input[0].len()).step_by(320) {
            let take = 320.min(input[0].len() - offset);
            for i in 0..count {
                if take < 320 {
                    messages[i].fill(0);
                }
                messages[i][..32].copy_from_slice(&state[i]);
                messages[i][32..32 + take].copy_from_slice(&input[i][offset..offset + take]);
            }
            state = self.abr_gadget(&messages, count);
        }
        state
    }

    fn abr_single(&mut self, input: &[u8]) -> Digest {
        let mut message = [0; 352];
        let first = input.len().min(352);
        message[..first].copy_from_slice(&input[..first]);
        let mut state = self.abr_single_gadget(&message);
        for offset in (first..input.len()).step_by(320) {
            let take = 320.min(input.len() - offset);
            if take < 320 {
                message.fill(0);
            }
            message[..32].copy_from_slice(&state);
            message[32..32 + take].copy_from_slice(&input[offset..offset + take]);
            state = self.abr_single_gadget(&message);
        }
        state
    }

    fn abr_single_gadget(&mut self, message: &[u8; 352]) -> Digest {
        let [bottom0, bottom1] = self.oracles::<64>(
            2,
            [ABR_ROLES[0], ABR_ROLES[1]],
            [
                message[..64].try_into().unwrap(),
                message[64..128].try_into().unwrap(),
            ],
            2,
        );
        let [bottom2, bottom3] = self.oracles::<64>(
            2,
            [ABR_ROLES[2], ABR_ROLES[3]],
            [
                message[128..192].try_into().unwrap(),
                message[192..256].try_into().unwrap(),
            ],
            2,
        );
        let [left, right] = self.abr_nodes(
            [ABR_ROLES[4], ABR_ROLES[5]],
            [bottom0, bottom2],
            [bottom1, bottom3],
            [
                message[256..288].try_into().unwrap(),
                message[288..320].try_into().unwrap(),
            ],
            2,
        );
        self.abr_nodes(
            [ABR_ROLES[6]; 2],
            [left; 2],
            [right; 2],
            [message[320..].try_into().unwrap(); 2],
            1,
        )[0]
    }

    fn abr_gadget(&mut self, messages: &[[u8; 352]; 2], count: usize) -> [Digest; 2] {
        let bottom: [[Digest; 2]; 4] = core::array::from_fn(|node| {
            self.oracles::<64>(
                2,
                [ABR_ROLES[node]; 2],
                core::array::from_fn(|i| {
                    messages[i][node * 64..(node + 1) * 64].try_into().unwrap()
                }),
                count,
            )
        });
        let left = self.abr_nodes(
            [ABR_ROLES[4]; 2],
            bottom[0],
            bottom[1],
            core::array::from_fn(|i| messages[i][256..288].try_into().unwrap()),
            count,
        );
        let right = self.abr_nodes(
            [ABR_ROLES[5]; 2],
            bottom[2],
            bottom[3],
            core::array::from_fn(|i| messages[i][288..320].try_into().unwrap()),
            count,
        );
        self.abr_nodes(
            [ABR_ROLES[6]; 2],
            left,
            right,
            core::array::from_fn(|i| messages[i][320..].try_into().unwrap()),
            count,
        )
    }

    fn abr_nodes(
        &mut self,
        roles: [u64; 2],
        left: [Digest; 2],
        right: [Digest; 2],
        shared: [&Digest; 2],
        count: usize,
    ) -> [Digest; 2] {
        let messages: [[u8; 64]; 2] = core::array::from_fn(|i| {
            let mut message = [0; 64];
            message[..32].copy_from_slice(&xor(left[i], shared[i]));
            message[32..].copy_from_slice(&xor(right[i], shared[i]));
            message
        });
        let digest = self.oracles(2, roles, [&messages[0], &messages[1]], count);
        core::array::from_fn(|i| xor(digest[i], &right[i]))
    }
}

/// Packing starts at byte 17, hence each little-endian input word straddles
/// two Keccak words at a one-byte displacement. The fixed input widths are
/// multiples of eight and end before the rate's final padding byte.
#[inline]
fn oracle_state<const N: usize>(arity: u8, role: u64, input: &[u8; N]) -> [u64; 25] {
    let mut state = [0; 25];
    state[0] = u64::from_le_bytes(*b"MTLFv001");
    state[1] = u64::from(arity) | (role << 8);
    state[2] = role >> 56;
    for (i, word) in input.chunks_exact(8).enumerate() {
        let word = u64::from_le_bytes(word.try_into().unwrap());
        state[2 + i] |= word << 8;
        state[3 + i] = word >> 56;
    }
    state[2 + N / 8] |= 0x06 << 8;
    state[16] = 0x8000_0000_0000_0000;
    state
}

/// One T5/T8 stage. Its bottom inputs and extra word are independent of all
/// preceding stages; only its shared word is replaced by the previous digest.
struct Stage<const N: usize> {
    left: [u8; N],
    right: [u8; N],
    shared: Digest,
    extra: Digest,
}

impl<const N: usize> Stage<N> {
    #[inline]
    fn load(input: &[u8], index: usize) -> Self {
        let first = 3 * N - 32;
        let fresh = first - 32;
        let offset = if index == 0 {
            0
        } else {
            first + (index - 1) * fresh
        };
        let bytes = &input[offset..];
        let complete = if index == 0 { first } else { fresh };
        if bytes.len() >= complete {
            // Fixed-size copies let complete stages avoid dynamic memcpy and
            // zero-filling. Only the final incomplete stage needs padding.
            return Self {
                left: bytes[..N].try_into().unwrap(),
                right: bytes[N..2 * N].try_into().unwrap(),
                shared: if index == 0 {
                    bytes[2 * N..2 * N + 32].try_into().unwrap()
                } else {
                    [0; 32]
                },
                extra: if N == 96 {
                    bytes[complete - 32..complete].try_into().unwrap()
                } else {
                    [0; 32]
                },
            };
        }
        let mut stage = Self {
            left: [0; N],
            right: [0; N],
            shared: [0; 32],
            extra: [0; 32],
        };
        copy_available(&mut stage.left, bytes, 0);
        copy_available(&mut stage.right, bytes, N);
        if index == 0 {
            copy_available(&mut stage.shared, bytes, 2 * N);
        }
        if N == 96 {
            copy_available(
                &mut stage.extra,
                bytes,
                2 * N + usize::from(index == 0) * 32,
            );
        }
        stage
    }

    #[inline]
    fn root(&self, left: Digest, right: Digest, shared: &Digest) -> [u8; N] {
        let mut root = [0; N];
        root[..32].copy_from_slice(&xor(left, shared));
        root[32..64].copy_from_slice(&xor(right, shared));
        if N == 96 {
            root[64..].copy_from_slice(&self.extra);
        }
        root
    }
}

#[inline]
fn copy_available(output: &mut [u8], input: &[u8], offset: usize) {
    if offset < input.len() {
        let take = output.len().min(input.len() - offset);
        output[..take].copy_from_slice(&input[offset..offset + take]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deliberately bytewise and materialized: independent of the production
    /// packing, streaming, parallel schedule and prefix boundary handling.
    fn sponge_reference(input: &[u8], dm: bool) -> Digest {
        let rate = if dm { 166 } else { 168 };
        let mut padded = Vec::new();
        if dm {
            padded.extend_from_slice(&prefix(4, 80));
        }
        padded.extend_from_slice(input);
        let suffix_at = padded.len();
        padded.resize((padded.len() / rate + 1) * rate, 0);
        padded[suffix_at] = if dm { 1 } else { 0x1f };
        *padded.last_mut().unwrap() |= 0x80;
        let mut state = [0; 25];
        for block in padded.chunks_exact(rate) {
            for (position, &byte) in block.iter().enumerate() {
                state[position / 8] ^= u64::from(byte) << (8 * (position % 8));
            }
            let before = state;
            keccak::Keccak::new().with_f1600(|permute| permute(&mut state));
            if dm {
                for position in 0..25 {
                    state[position] ^= before[position];
                }
            }
        }
        core::array::from_fn(|i| (state[i / 8] >> (8 * (i % 8))) as u8)
    }

    fn shake_reference(input: &[u8]) -> Digest {
        use sha3::digest::{ExtendableOutput, Update, XofReader};
        let mut hasher = sha3::Shake128::default();
        hasher.update(input);
        let mut digest = [0; 32];
        hasher.finalize_xof().read(&mut digest);
        digest
    }

    #[test]
    fn sponge_scalar_counts_and_padding_match_independent_references() {
        assert_eq!(SPONGE_DM_PREFIX, prefix(4, 80));
        let widths = (0..=512).chain([1024, 4096, 16_384, 65_536]);
        for width in widths {
            let input: Vec<u8> = (0..width).map(|i| (i * 177 + i / 13 + 19) as u8).collect();
            let mut shake = [0; 32];
            let mut dm = [0; 32];
            let mut shake_calls = 0;
            let mut dm_calls = 0;
            keccak::Keccak::new().with_f1600(|permute| {
                shake = sponge_single::<168, false>(&input, |state| {
                    shake_calls += 1;
                    permute(state);
                });
                dm = sponge_single::<166, true>(&input, |state| {
                    dm_calls += 1;
                    permute(state);
                });
            });
            assert_eq!(shake, shake_reference(&input), "SHAKE128 width {width}");
            assert_eq!(
                shake,
                sponge_reference(&input, false),
                "SHAKE128 width {width}"
            );
            assert_eq!(
                dm,
                sponge_reference(&input, true),
                "SPONGE-DM272 width {width}"
            );
            assert_eq!(shake_calls, width / 168 + 1);
            assert_eq!(dm_calls, (width + 17) / 166 + 1);
            if width > 0 {
                let shake_plan = LeafPlan::new::<Sha3_256>(LeafMode::Shake128, width).unwrap();
                let dm_plan = LeafPlan::new::<Sha3_256>(LeafMode::SpongeDm272, width).unwrap();
                assert_eq!(shake_plan.native_calls::<Sha3_256>(), shake_calls as u64);
                assert_eq!(dm_plan.native_calls::<Sha3_256>(), dm_calls as u64);
                assert_eq!(shake_plan.hash::<Sha3_256>(&input), shake);
                assert_eq!(dm_plan.hash::<Sha3_256>(&input), dm);
            }
        }
    }

    #[test]
    fn sponge_parallel_rows_and_all_benchmark_widths_match_scalar_reference() {
        let mut widths = vec![
            1, 7, 8, 9, 147, 148, 149, 150, 165, 166, 167, 168, 169, 313, 314, 315, 316, 331, 332,
            333, 334, 335, 336, 337,
        ];
        widths.extend((0..=14).map(|log| 4 << log));
        widths.sort_unstable();
        widths.dedup();
        for mode in [LeafMode::Shake128, LeafMode::SpongeDm272] {
            for &width in &widths {
                let input: Vec<u8> = (0..width * 5)
                    .map(|i| (i * 97 + i / width * 23 + i / 43) as u8)
                    .collect();
                let plan = LeafPlan::new::<Sha3_256>(mode, width).unwrap();
                let expected: Vec<Digest> = input
                    .chunks_exact(width)
                    .map(|row| sponge_reference(row, mode == LeafMode::SpongeDm272))
                    .collect();
                for rows in [0, 1, 2, 3, 5] {
                    let mut actual = vec![[0; 32]; rows];
                    plan.hash_many::<Sha3_256>(&input[..rows * width], &mut actual);
                    assert_eq!(
                        actual,
                        expected[..rows],
                        "{mode:?} width {width}, rows {rows}"
                    );
                }
                // Both modes must consume the last byte even across a rate
                // boundary, rather than accidentally dropping a short tail.
                let mut altered = input[..width].to_vec();
                altered[width - 1] ^= 0x80;
                assert_ne!(plan.hash::<Sha3_256>(&altered), expected[0]);
            }
        }
    }

    #[test]
    fn direct_oracles_match_standard_sha3_encoding() {
        let input: [u8; 96] = core::array::from_fn(|i| (i * 179 + 21) as u8);
        for role in [0, 1, 10, 22, 36, u64::MAX, 0x1234_5678_9abc_def0] {
            for arity in [2, 3] {
                let width = if arity == 2 { 64 } else { 96 };
                let mut hasher = sha3::Sha3_256::new();
                hasher.update(prefix(arity, role));
                hasher.update(&input[..width]);
                let expected: Digest = hasher.finalize().into();
                let actual = if arity == 2 {
                    Sha3_256::oracle2(role, input[..64].try_into().unwrap())
                } else {
                    Sha3_256::oracle3(role, &input)
                };
                assert_eq!(actual, expected);
            }
        }
    }

    #[test]
    fn persistent_batch_and_pipeline_match_scalar_graph_at_stage_boundaries() {
        for mode in [
            LeafMode::FixedMd,
            LeafMode::T5,
            LeafMode::T8,
            LeafMode::Abr3,
        ] {
            for width in [
                1, 63, 64, 65, 159, 160, 161, 255, 256, 257, 287, 288, 289, 351, 352, 353, 383,
                384, 385, 415, 416, 417, 479, 480, 481, 511, 512, 513, 671, 672, 673, 703, 704,
                705, 1024, 4096,
            ] {
                let input: Vec<u8> = (0..width * 3).map(|i| (i * 37 + i / 23) as u8).collect();
                let plan = LeafPlan::new::<Sha3_256>(mode, width).unwrap();
                let expected: Vec<Digest> = input
                    .chunks_exact(width)
                    .map(|row| plan.hash_generic::<Sha3_256>(row))
                    .collect();
                for (row, expected) in input.chunks_exact(width).zip(&expected) {
                    assert_eq!(
                        plan.hash::<Sha3_256>(row),
                        *expected,
                        "{mode:?}, width {width}"
                    );
                }
                let mut actual = [[0; 32]; 3];
                plan.hash_many::<Sha3_256>(&input, &mut actual);
                assert_eq!(
                    actual.as_slice(),
                    expected.as_slice(),
                    "{mode:?}, width {width}"
                );
            }
        }
    }
}
