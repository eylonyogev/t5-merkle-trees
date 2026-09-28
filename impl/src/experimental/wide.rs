//! Fixed-width wide T and ABR3 gadgets with disjoint MD tails.
//!
//! The planner is public-width dependent. A full first gadget carries one
//! additional digest-sized shared word; subsequent gadgets put the previous
//! output in the ROOT shared slot. Consequently every non-root call in a
//! gadget can be prepared before the preceding gadget finishes.

use super::Digest;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum WideKind {
    T,
    Abr3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct WidePlan {
    pub kind: WideKind,
    pub oracle_bytes: usize,
    pub stages: usize,
    pub tails: usize,
    pub md_head: bool,
}

impl WidePlan {
    pub fn new(kind: WideKind, leaf_bytes: usize, oracle_bytes: usize) -> Self {
        assert!(leaf_bytes > 0 && oracle_bytes >= 64);
        // u128 avoids overflowing even for an otherwise valid usize::MAX
        // public width; planning must never iterate in proportion to width.
        let bytes = leaf_bytes as u128;
        let m = oracle_bytes as u128;
        let cost = match kind {
            WideKind::T => 3,
            WideKind::Abr3 => 7,
        };
        let fresh = match kind {
            WideKind::T => 3 * m - 64,
            WideKind::Abr3 => 7 * m - 128,
        };
        let tail = m - 32;
        let md_tails = bytes.saturating_sub(m).div_ceil(tail);
        // (calls, padding, reverse stage count), exactly the analytical
        // generator's tie break. Distinct schedules with equal stage counts
        // describe the same encoding, so their textual kind is immaterial.
        let mut best = (1 + md_tails, m + md_tails * tail - bytes, 0, md_tails, true);
        let mut consider = |stages: u128, tails: u128| {
            let candidate = (
                cost * stages + tails,
                32 + stages * fresh + tails * tail - bytes,
                stages,
                tails,
                false,
            );
            if (candidate.0, candidate.1, core::cmp::Reverse(candidate.2))
                < (best.0, best.1, core::cmp::Reverse(best.2))
            {
                best = candidate;
            }
        };
        consider(bytes.saturating_sub(32).div_ceil(fresh).max(1), 0);
        let full = bytes.saturating_sub(32) / fresh;
        if full > 0 {
            // For complete gadgets, C(k) = ceil((B-32-delta*k)/tail),
            // where delta = fresh-cost*tail > 0. The largest k minimizes
            // calls; the FIRST k attaining that cost minimizes zero padding.
            let delta = fresh - cost * tail;
            let x = bytes - 32;
            let min_calls = (x - delta * full).div_ceil(tail);
            let stages = x.saturating_sub(min_calls * tail).div_ceil(delta).max(1);
            debug_assert!(stages <= full);
            consider(stages, (x - stages * fresh).div_ceil(tail));
        }
        Self {
            kind,
            oracle_bytes,
            stages: best.2.try_into().unwrap(),
            tails: best.3.try_into().unwrap(),
            md_head: best.4,
        }
    }

    pub fn calls(&self) -> u64 {
        let per_stage = match self.kind {
            WideKind::T => 3,
            WideKind::Abr3 => 7,
        };
        (self.stages as u64) * per_stage + self.tails as u64 + u64::from(self.md_head)
    }

    #[inline]
    fn fresh(&self) -> usize {
        match self.kind {
            WideKind::T => 3 * self.oracle_bytes - 64,
            WideKind::Abr3 => 7 * self.oracle_bytes - 128,
        }
    }

    #[inline]
    fn md_role(&self) -> u8 {
        match self.kind {
            WideKind::T => 0xc3,
            WideKind::Abr3 => 0xd7,
        }
    }
}

pub(super) trait WideOracle<const M: usize> {
    fn one(role: u8, input: &[u8; M]) -> Digest;

    #[inline]
    fn many<const N: usize>(roles: [u8; N], inputs: &[[u8; M]; N]) -> [Digest; N] {
        core::array::from_fn(|i| Self::one(roles[i], &inputs[i]))
    }
}

#[derive(Clone, Copy)]
struct Prepared<const M: usize> {
    left: Digest,
    right: Digest,
    shared: Digest,
    root: [u8; M],
}

/// Copy an optionally short final segment. All callers initialize their
/// destination to zero, so the omitted suffix is the specified zero padding.
#[inline]
fn copy_at(input: &[u8], offset: usize, output: &mut [u8]) {
    if offset < input.len() {
        let count = output.len().min(input.len() - offset);
        output[..count].copy_from_slice(&input[offset..offset + count]);
    }
}

#[inline]
fn mixed<const M: usize>(left: &Digest, right: &Digest, shared: &Digest) -> [u8; M] {
    let mut input = [0; M];
    for i in 0..32 {
        input[i] = left[i] ^ shared[i];
        input[32 + i] = right[i] ^ shared[i];
    }
    input
}

/// Prepare N independent gadgets, either neighboring rows or a lookahead
/// window within one row. Each invocation exposes a full SIMD group to the
/// backend; intermediate parents do not depend on the chain's root state.
#[inline]
fn prepare<O: WideOracle<M>, const M: usize, const N: usize>(
    kind: WideKind,
    inputs: [&[u8]; N],
    first: [bool; N],
) -> [Prepared<M>; N] {
    let role = match kind {
        WideKind::T => 0xc0,
        WideKind::Abr3 => 0xd0,
    };
    let bottom = |branch: usize| {
        let blocks = core::array::from_fn(|i| {
            let mut block = [0; M];
            copy_at(inputs[i], branch * M, &mut block);
            block
        });
        O::many([role + branch as u8; N], &blocks)
    };
    let a = bottom(0);
    let b = bottom(1);
    let (left, right, root_offset) = match kind {
        WideKind::T => (a, b, 2 * M),
        WideKind::Abr3 => {
            let c = bottom(2);
            let d = bottom(3);
            let parent = |role, left: &[Digest; N], right: &[Digest; N], offset| {
                let blocks = core::array::from_fn(|i| {
                    let mut shared = [0; 32];
                    copy_at(inputs[i], offset, &mut shared);
                    let mut block = mixed::<M>(&left[i], &right[i], &shared);
                    copy_at(inputs[i], offset + 32, &mut block[64..]);
                    block
                });
                let mut hashes = O::many([role; N], &blocks);
                for i in 0..N {
                    for j in 0..32 {
                        hashes[i][j] ^= right[i][j];
                    }
                }
                hashes
            };
            (
                parent(0xd4, &a, &b, 4 * M),
                parent(0xd5, &c, &d, 5 * M - 32),
                6 * M - 64,
            )
        }
    };
    core::array::from_fn(|i| {
        let mut shared = [0; 32];
        if first[i] {
            copy_at(inputs[i], root_offset, &mut shared);
        }
        let mut root = [0; M];
        copy_at(
            inputs[i],
            root_offset + usize::from(first[i]) * 32,
            &mut root[64..],
        );
        Prepared {
            left: left[i],
            right: right[i],
            shared,
            root,
        }
    })
}

#[inline]
fn finish<O: WideOracle<M>, const M: usize, const N: usize>(
    kind: WideKind,
    prepared: &mut [Prepared<M>; N],
    previous: &[Digest; N],
    first: [bool; N],
) -> [Digest; N] {
    let roots = core::array::from_fn(|i| {
        let shared = if first[i] {
            &prepared[i].shared
        } else {
            &previous[i]
        };
        for (j, shared_byte) in shared.iter().enumerate() {
            prepared[i].root[j] = prepared[i].left[j] ^ shared_byte;
            prepared[i].root[32 + j] = prepared[i].right[j] ^ shared_byte;
        }
        prepared[i].root
    });
    let role = match kind {
        WideKind::T => 0xc2,
        WideKind::Abr3 => 0xd6,
    };
    let mut result = O::many([role; N], &roots);
    for i in 0..N {
        let feed = match kind {
            WideKind::T if first[i] => &prepared[i].shared,
            WideKind::T => &previous[i],
            WideKind::Abr3 => &prepared[i].right,
        };
        for j in 0..32 {
            result[i][j] ^= feed[j];
        }
    }
    result
}

#[inline]
fn segment(input: &[u8], offset: usize, capacity: usize) -> &[u8] {
    &input[offset.min(input.len())..offset.saturating_add(capacity).min(input.len())]
}

/// Process several complete records together, including their dependent roots
/// and MD tails. No worker threads or heap scratch are used here.
#[inline]
fn rows<O: WideOracle<M>, const M: usize, const N: usize>(
    plan: &WidePlan,
    input: [&[u8]; N],
) -> [Digest; N] {
    let mut state = [[0; 32]; N];
    let mut offset = 0;
    if plan.md_head {
        let blocks = core::array::from_fn(|i| {
            let mut block = [0; M];
            copy_at(input[i], 0, &mut block);
            block
        });
        state = O::many([plan.md_role(); N], &blocks);
        offset = M;
    } else {
        for stage in 0..plan.stages {
            let capacity = plan.fresh() + usize::from(stage == 0) * 32;
            let mut prepared = prepare::<O, M, N>(
                plan.kind,
                core::array::from_fn(|i| segment(input[i], offset, capacity)),
                [stage == 0; N],
            );
            state = finish::<O, M, N>(plan.kind, &mut prepared, &state, [stage == 0; N]);
            offset += capacity;
        }
    }
    for _ in 0..plan.tails {
        let blocks = core::array::from_fn(|i| {
            let mut block = [0; M];
            block[..32].copy_from_slice(&state[i]);
            copy_at(input[i], offset, &mut block[32..]);
            block
        });
        state = O::many([plan.md_role(); N], &blocks);
        offset += M - 32;
    }
    state
}

pub(super) fn hash<O: WideOracle<M>, const M: usize>(plan: &WidePlan, input: &[u8]) -> Digest {
    debug_assert_eq!(M, plan.oracle_bytes);
    if plan.stages < 4 {
        return rows::<O, M, 1>(plan, [input])[0];
    }
    let mut state = [0; 32];
    let mut offset = 0;
    let mut stage = 0;
    while stage + 4 <= plan.stages {
        let first = core::array::from_fn(|i| stage + i == 0);
        let inputs = core::array::from_fn(|i| {
            let start = offset + i * plan.fresh() + usize::from(stage == 0 && i > 0) * 32;
            segment(input, start, plan.fresh() + usize::from(first[i]) * 32)
        });
        let mut prepared = prepare::<O, M, 4>(plan.kind, inputs, first);
        for i in 0..4 {
            state = finish::<O, M, 1>(
                plan.kind,
                core::array::from_mut(&mut prepared[i]),
                &[state],
                [first[i]],
            )[0];
        }
        offset += 4 * plan.fresh() + usize::from(stage == 0) * 32;
        stage += 4;
    }
    while stage < plan.stages {
        let mut prepared =
            prepare::<O, M, 1>(plan.kind, [segment(input, offset, plan.fresh())], [false]);
        state = finish::<O, M, 1>(plan.kind, &mut prepared, &[state], [false])[0];
        offset += plan.fresh();
        stage += 1;
    }
    for _ in 0..plan.tails {
        let mut block = [0; M];
        block[..32].copy_from_slice(&state);
        copy_at(input, offset, &mut block[32..]);
        state = O::one(plan.md_role(), &block);
        offset += M - 32;
    }
    state
}

pub(super) fn hash_many<O: WideOracle<M>, const M: usize>(
    plan: &WidePlan,
    input: &[u8],
    output: &mut [Digest],
) {
    debug_assert_eq!(M, plan.oracle_bytes);
    if output.is_empty() {
        return;
    }
    let width = input.len() / output.len();
    debug_assert_eq!(input.len(), width * output.len());
    let mut row = 0;
    while row + 4 <= output.len() {
        let inputs = core::array::from_fn(|i| &input[(row + i) * width..(row + i + 1) * width]);
        output[row..row + 4].copy_from_slice(&rows::<O, M, 4>(plan, inputs));
        row += 4;
    }
    if row + 2 <= output.len() {
        let inputs = core::array::from_fn(|i| &input[(row + i) * width..(row + i + 1) * width]);
        output[row..row + 2].copy_from_slice(&rows::<O, M, 2>(plan, inputs));
        row += 2;
    }
    if row < output.len() {
        output[row] = hash::<O, M>(plan, &input[row * width..]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest as _;
    use std::cell::Cell;

    thread_local! { static CALLS: Cell<u64> = const { Cell::new(0) }; }

    struct Counting;
    impl<const M: usize> WideOracle<M> for Counting {
        fn one(role: u8, input: &[u8; M]) -> Digest {
            CALLS.with(|calls| calls.set(calls.get() + 1));
            let mut hash = sha2::Sha256::new();
            hash.update([role]);
            hash.update(input);
            hash.finalize().into()
        }
    }

    /// Independent direct specification: materialize each complete gadget,
    /// reinsert the previous output at its root shared slot, then evaluate the
    /// three/seven calls in dependency order without the production scheduler.
    fn reference<const M: usize>(plan: &WidePlan, input: &[u8]) -> Digest {
        let mut state = [0; 32];
        let mut cursor = 0;
        if plan.md_head {
            let mut head = [0; M];
            let take = input.len().min(M);
            head[..take].copy_from_slice(&input[..take]);
            state = Counting::one(plan.md_role(), &head);
            cursor = take;
        }
        for stage in 0..plan.stages {
            let size = plan.fresh() + 32;
            let root_shared = match plan.kind {
                WideKind::T => 2 * M,
                WideKind::Abr3 => 6 * M - 64,
            };
            let mut message = vec![0; size];
            if stage == 0 {
                let take = size.min(input.len() - cursor);
                message[..take].copy_from_slice(&input[cursor..cursor + take]);
                cursor += take;
            } else {
                for (j, byte) in message.iter_mut().enumerate() {
                    if (root_shared..root_shared + 32).contains(&j) {
                        *byte = state[j - root_shared];
                    } else if cursor < input.len() {
                        *byte = input[cursor];
                        cursor += 1;
                    }
                }
            }
            let internal = |role, left: Digest, right: Digest, offset, feed_shared| {
                let shared = &message[offset..offset + 32];
                let mut block = [0; M];
                for i in 0..32 {
                    block[i] = left[i] ^ shared[i];
                    block[32 + i] = right[i] ^ shared[i];
                }
                block[64..].copy_from_slice(&message[offset + 32..offset + M - 32]);
                let mut result = Counting::one(role, &block);
                for i in 0..32 {
                    result[i] ^= if feed_shared { shared[i] } else { right[i] };
                }
                result
            };
            state = match plan.kind {
                WideKind::T => {
                    let left =
                        <Counting as WideOracle<M>>::one(0xc0, message[..M].try_into().unwrap());
                    let right = <Counting as WideOracle<M>>::one(
                        0xc1,
                        message[M..2 * M].try_into().unwrap(),
                    );
                    internal(0xc2, left, right, 2 * M, true)
                }
                WideKind::Abr3 => {
                    let bottom: [Digest; 4] = core::array::from_fn(|i| {
                        <Counting as WideOracle<M>>::one(
                            0xd0 + i as u8,
                            message[i * M..(i + 1) * M].try_into().unwrap(),
                        )
                    });
                    let left = internal(0xd4, bottom[0], bottom[1], 4 * M, false);
                    let right = internal(0xd5, bottom[2], bottom[3], 5 * M - 32, false);
                    internal(0xd6, left, right, 6 * M - 64, false)
                }
            };
        }
        for _ in 0..plan.tails {
            let mut block = [0; M];
            block[..32].copy_from_slice(&state);
            let take = (M - 32).min(input.len() - cursor);
            block[32..32 + take].copy_from_slice(&input[cursor..cursor + take]);
            cursor += take;
            state = Counting::one(plan.md_role(), &block);
        }
        assert_eq!(cursor, input.len());
        state
    }

    fn check_scheduler<const M: usize>() {
        for kind in [WideKind::T, WideKind::Abr3] {
            let first = if kind == WideKind::T {
                3 * M - 32
            } else {
                7 * M - 96
            };
            let fresh = first - 32;
            let mut widths = vec![1, 4, 32, M - 1, M, M + 1, 65536];
            for capacity in [first, first + fresh, first + 3 * fresh, first + 4 * fresh] {
                widths.extend([capacity - 1, capacity, capacity + 1]);
            }
            for width in widths {
                let plan = WidePlan::new(kind, width, M);
                let input: Vec<_> = (0..9 * width)
                    .map(|i| (i * 179 + i / 17 + 41) as u8)
                    .collect();
                let expected: Vec<_> = input
                    .chunks_exact(width)
                    .map(|row| reference::<M>(&plan, row))
                    .collect();
                for count in [1, 2, 3, 4, 5, 7, 8, 9] {
                    let mut actual = vec![[0; 32]; count];
                    CALLS.with(|calls| calls.set(0));
                    hash_many::<Counting, M>(&plan, &input[..count * width], &mut actual);
                    assert_eq!(
                        actual,
                        expected[..count],
                        "{kind:?} M={M}, width={width}, rows={count}"
                    );
                    assert_eq!(CALLS.with(Cell::get), plan.calls() * count as u64);
                }
                CALLS.with(|calls| calls.set(0));
                assert_eq!(hash::<Counting, M>(&plan, &input[..width]), expected[0]);
                assert_eq!(CALLS.with(Cell::get), plan.calls());
            }
        }
    }

    #[test]
    fn scheduler_matches_scalar_and_executes_exact_planned_calls() {
        check_scheduler::<95>();
        check_scheduler::<103>();
    }

    #[test]
    fn every_first_and_chained_gadget_byte_is_consumed() {
        for kind in [WideKind::T, WideKind::Abr3] {
            let first = if kind == WideKind::T { 277 } else { 625 };
            let width = 2 * first - 32;
            let plan = WidePlan::new(kind, width, 103);
            assert_eq!(plan.stages, 2);
            let mut input = vec![0; width];
            let original = hash::<Counting, 103>(&plan, &input);
            for i in 0..width {
                input[i] = 1;
                assert_ne!(
                    hash::<Counting, 103>(&plan, &input),
                    original,
                    "{kind:?} byte {i}"
                );
                input[i] = 0;
            }
        }
    }

    fn enumerated(kind: WideKind, bytes: usize, m: usize) -> WidePlan {
        let cost = if kind == WideKind::T { 3 } else { 7 };
        let fresh = if kind == WideKind::T {
            3 * m - 64
        } else {
            7 * m - 128
        };
        let tails = bytes.saturating_sub(m).div_ceil(m - 32);
        let mut best = (
            1 + tails,
            m + tails * (m - 32) - bytes,
            core::cmp::Reverse(0),
            tails,
            true,
        );
        for stages in 1..=bytes.saturating_sub(32).div_ceil(fresh).max(1) {
            let capacity = 32 + stages * fresh;
            let tails = bytes.saturating_sub(capacity).div_ceil(m - 32);
            let candidate = (
                cost * stages + tails,
                capacity + tails * (m - 32) - bytes,
                core::cmp::Reverse(stages),
                tails,
                false,
            );
            if candidate < best {
                best = candidate;
            }
        }
        WidePlan {
            kind,
            oracle_bytes: m,
            stages: best.2.0,
            tails: best.3,
            md_head: best.4,
        }
    }

    #[test]
    fn constant_time_planner_matches_exhaustive_schedules() {
        for m in [64, 95, 96, 103, 184] {
            for kind in [WideKind::T, WideKind::Abr3] {
                for bytes in 1..=8192 {
                    assert_eq!(
                        WidePlan::new(kind, bytes, m),
                        enumerated(kind, bytes, m),
                        "{kind:?}, {bytes}, {m}"
                    );
                }
                for bytes in [65536, usize::MAX / 2, usize::MAX] {
                    assert!(WidePlan::new(kind, bytes, m).calls() > 0);
                }
            }
        }
        assert_eq!(WidePlan::new(WideKind::T, 65536, 103).calls(), 803);
        assert_eq!(WidePlan::new(WideKind::Abr3, 65536, 95).calls(), 854);
        assert_eq!(WidePlan::new(WideKind::Abr3, 65536, 103).calls(), 774);
    }
}
