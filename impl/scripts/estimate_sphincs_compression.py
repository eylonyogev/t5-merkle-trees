#!/usr/bin/env python3
"""Estimate compression-only SPHINCS+/SLH-DSA gains; no security or timing claim.

Standard FIPS 205 parameters, w=16, simple SHA2/SHAKE instantiations.
SHA2 seed-block midstates are precomputed, as in the reference implementation.
Signing fuses WOTS signing into full leaf generation, avoiding duplicate chains.
Message hashing, RNG, packing, XORs, and memory costs are excluded.
Verification averages uniform message digits, computing checksum cost exactly.

Two candidate models:
  direct: T5/T8 built from standard addressed 2-/3-block tweakable hashes;
          three such hashes per gadget, chained and padded to fixed width.
  raw-wide SHA2: hypothetical one-compression role oracles accepting the native
          CV+block minus one role byte (95 or 191 bytes), truncated to n bytes.
          Charge one extra native compression PER public-key compression for
          seed/address setup. This is a capacity budget, not an implemented
          adapter. Context masks/encoding and XOR/packing have no time cost here.
          Enumerate T gadgets and restricted MD tails, requiring >=1 T gadget.

The reported percentages are reductions in native-call budgets, NOT measured
wall-clock improvements. SHA-512/SHA-256 cost ratios of 1 and 2 are sensitivities,
not assertions about a CPU. A zero-cost compression replacement is also shown
as an Amdahl ceiling. All other hash functions and signature fields stay fixed.

Sources:
  https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf
  https://github.com/sphincs/sphincsplus/blob/master/ref/thash_sha2_simple.c
  https://github.com/sphincs/sphincsplus/blob/master/ref/wotsx1.c
  https://eprint.iacr.org/2021/373.pdf (widening, Section 6)
"""

import json
from fractions import Fraction
from functools import lru_cache


PARAMETERS = [
    ('128s', 16, 63, 7, 12, 14),
    ('128f', 16, 66, 22, 6, 33),
    ('192s', 24, 63, 7, 14, 17),
    ('192f', 24, 66, 22, 8, 33),
    ('256s', 32, 64, 8, 14, 22),
    ('256f', 32, 68, 17, 9, 35),
]


def ceildiv(x, y):
    return (x + y - 1) // y


def standard(family, n, blocks):
    if family == 'SHAKE':
        return (n + 32 + n * blocks) // 136 + 1
    if n == 16 or blocks == 1:
        return ceildiv(22 + n * blocks + 9, 64)
    return ceildiv(22 + n * blocks + 17, 128)


def direct(family, n, blocks):
    # First gadget handles 5 or 8 blocks; later gadgets 4 or 7 fresh blocks.
    return min(3 * standard(family, n, width) *
               max(1, ceildiv(blocks - 1, 3 * width - 2))
               for width in (2, 3))


def raw_wide(n, blocks):
    m = 95 if n == 16 else 191
    fresh = 3 * m - 2 * n
    tail = m - n
    size = n * blocks
    # Can zero-pad a final gadget; always include per-key setup cost.
    plans = [(1 + 3 * k + ceildiv(max(0, size - n - k * fresh), tail), k)
             for k in range(1, max(1, ceildiv(max(0, size - n), fresh)) + 1)]
    return min(plans)[0]


@lru_cache(maxsize=None)
def expected_verify_chain_steps(n):
    # Checksum = sum of complements of 2n uniform base-16 message digits.
    counts = [1]
    for _ in range(2 * n):
        nxt = [0] * (len(counts) + 15)
        for checksum, count in enumerate(counts):
            for digit in range(16):
                nxt[checksum + digit] += count
        counts = nxt
    checksum_digit_sum = sum(count *
                             ((value & 15) + ((value >> 4) & 15) +
                              ((value >> 8) & 15))
                             for value, count in enumerate(counts))
    expected_checksum = Fraction(checksum_digit_sum, 16 ** (2 * n))
    return float(15 * (2 * n + 3) - 15 * n - expected_checksum)


def estimate(family, params, ratio=1):
    name, n, h, d, a, k = params
    ell = 2 * n + 3
    leaves = d * 2 ** (h // d)
    fors_leaves = k * 2 ** a
    chain_steps = expected_verify_chain_steps(n)
    c_w, c_k = standard(family, n, ell), standard(family, n, k)
    c_f, c_h = standard(family, n, 1), standard(family, n, 2)
    weight = ratio if family == 'SHA2' and n > 16 else 1
    # PRF and F both cost one SHA256 compression or one Keccak permutation.
    signing_other = (leaves * ell * (1 + 15 * c_f) +
                     d * (2 ** (h // d) - 1) * c_h * weight +
                     fors_leaves * (1 + c_f) + k +
                     k * (2 ** a - 1) * c_h * weight)
    verification_other = ((d * chain_steps + k) * c_f +
                          (h + k * a) * c_h * weight)
    sign_long = (leaves * c_w + c_k) * weight
    verify_long = (d * c_w + c_k) * weight
    out = dict(family=family, parameter=name, sha512_relative_cost=ratio,
               signature_bytes=n * (1 + k * (a + 1) + d * ell + h),
               wots_blocks=ell, expected_verify_chain_steps=chain_steps,
               baseline_wots_calls=c_w, baseline_fors_calls=c_k,
               direct_wots_calls=direct(family, n, ell),
               direct_fors_calls=direct(family, n, k),
               signing_budget=signing_other + sign_long,
               verification_budget=verification_other + verify_long,
               zero_cost_signing_ceiling_pct=100 * sign_long / (signing_other + sign_long),
               zero_cost_verification_ceiling_pct=100 * verify_long / (verification_other + verify_long))
    if family == 'SHA2':
        r_w, r_k = raw_wide(n, ell), raw_wide(n, k)
        # Retain standard compression wherever the candidate loses.
        r_w, r_k = min(c_w, r_w), min(c_k, r_k)
        sign_save = (leaves * (c_w - r_w) + c_k - r_k) * weight
        verify_save = (d * (c_w - r_w) + c_k - r_k) * weight
        out.update(candidate_wots_calls=r_w, candidate_fors_calls=r_k,
                   saved_signing_budget=sign_save, saved_verification_budget=verify_save,
                   signing_reduction_pct=100 * sign_save / (signing_other + sign_long),
                   verification_reduction_pct=100 * verify_save / (verification_other + verify_long))
    return out


if __name__ == '__main__':
    rows = [estimate(family, p, ratio)
            for family in ('SHA2', 'SHAKE')
            for p in PARAMETERS
            for ratio in ((1, 2) if family == 'SHA2' and p[1] > 16 else (1,))]
    assert [estimate('SHA2', p)['signature_bytes'] for p in PARAMETERS] == [
        7856, 17088, 16224, 35664, 29792, 49856]
    assert all(r['direct_wots_calls'] >= r['baseline_wots_calls'] for r in rows)
    print(json.dumps(rows, indent=2))
