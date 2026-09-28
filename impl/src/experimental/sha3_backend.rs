//! Direct one-block SHA3 oracles and persistent two-message scheduling.
//!
//! Every oracle retains its original 17-byte prefix and SHA3 suffix. Packing
//! directly into Keccak lanes removes intermediate encoded messages. A single
//! backend selection serves an entire leaf batch or verification leaf.

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
                (LeafMode::Standard | LeafMode::T253, _) => {
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
