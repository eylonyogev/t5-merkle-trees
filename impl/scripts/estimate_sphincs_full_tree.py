#!/usr/bin/env python3
"""Full-tree T8 cost estimates, including exact fixed-size authentication paths.

Uses the baseline and public-key-compression model in estimate_sphincs_compression.
No cryptographic proof or wall-clock claim. Leaf generation and WOTS chains stay
unchanged. A radix-eight level is T8(a,b,c,d,e,f,g,h), with two three-input branch
hashes and one three-input root hash. Group eight bottom-up; retain 0/1/2 binary
levels at the top. Original binary leaf counts are preserved exactly.

An opening of positions 0..5 sends the other two inputs of its branch, the other
branch digest XOR g, g, and h: five digests, two oracle calls. Position 6 sends
the two branch digests and h: three digests, one call. Position 7 sends the two
branch digests XOR g and g: three digests, one call. The latter two cases get two
padding slots, making signatures fixed length. Mean is 1.75 calls per T8 level
for uniform leaf indices; worst case is two. XOR work is excluded.

Two native-cost models:
  optimistic: a three-input T8 oracle costs the same as a binary node oracle.
              Assumes a suitable raw adapter; extra per-node setup is NOT charged.
  addressed: three-input oracles cost standard addressed SHA2/SHAKE hashes.

Same-size retuning keeps n, w, total hypertree height h, k, a, and FORS leaf
counts. Search 1..d hypertree layers. Unequal layer heights differ by at most
one; choose the least signing-budget layout fitting the original byte budget.
Pad any spare bytes to preserve EXACT original signature length. This is a new
parameterization, not a standard equal-height SLH-DSA implementation. All results
assume no persistent tree caches and fused WOTS signature/leaf generation.
"""

import json
from estimate_sphincs_compression import PARAMETERS, estimate, standard


def tree(height):
    rounds, binary = divmod(height, 3)
    leaves = 2 ** height
    top_leaves = 2 ** binary
    return dict(leaves=leaves,
                t8_oracle_calls=3 * (leaves - top_leaves) // 7,
                binary_calls=top_leaves - 1,
                auth_digests=5 * rounds + binary,
                mean_t8_verify_calls=1.75 * rounds,
                worst_t8_verify_calls=2 * rounds,
                binary_verify_calls=binary)


def layout(family, params, ratio, heights, model):
    _, n, h, _, a, k = params
    d = len(heights)
    ell = 2 * n + 3
    baseline = estimate(family, params, ratio)
    weight = ratio if family == 'SHA2' and n > 16 else 1
    c_h = standard(family, n, 2) * weight
    c_t = c_h if model == 'optimistic' else standard(family, n, 3) * weight
    c_f = standard(family, n, 1)
    c_w = baseline.get('candidate_wots_calls', baseline['baseline_wots_calls']) * weight
    c_k = baseline.get('candidate_fors_calls', baseline['baseline_fors_calls']) * weight
    ht = [tree(height) for height in heights]
    ft = tree(a)
    leaf_count = sum(t['leaves'] for t in ht)
    signature_bytes = n * (1 + k * (1 + ft['auth_digests']) + d * ell +
                           sum(t['auth_digests'] for t in ht))
    signing = (leaf_count * (ell * (1 + 15 * c_f) + c_w) +
               sum(t['t8_oracle_calls'] * c_t + t['binary_calls'] * c_h for t in ht) +
               k * ft['leaves'] * (1 + c_f) + k + c_k +
               k * (ft['t8_oracle_calls'] * c_t + ft['binary_calls'] * c_h))
    verification = ((d * baseline['expected_verify_chain_steps'] + k) * c_f +
                    d * c_w + c_k +
                    sum(t['mean_t8_verify_calls'] * c_t +
                        t['binary_verify_calls'] * c_h for t in ht) +
                    k * (ft['mean_t8_verify_calls'] * c_t + ft['binary_verify_calls'] * c_h))
    worst_path_verification = ((d * baseline['expected_verify_chain_steps'] + k) * c_f +
                              d * c_w + c_k +
                              sum(t['worst_t8_verify_calls'] * c_t +
                                  t['binary_verify_calls'] * c_h for t in ht) +
                              k * (ft['worst_t8_verify_calls'] * c_t + ft['binary_verify_calls'] * c_h))
    return dict(family=family, parameter=params[0], model=model, ratio=ratio,
                layer_heights=heights, layers=d,
                original_signature_bytes=baseline['signature_bytes'],
                payload_signature_bytes=signature_bytes,
                signing_budget=signing, verification_budget=verification,
                signing_reduction_pct=100 * (1 - signing / baseline['signing_budget']),
                verification_reduction_pct=100 * (1 - verification / baseline['verification_budget']),
                worst_path_verification_reduction_pct=100 *
                (1 - worst_path_verification / baseline['verification_budget']),
                signing_cost_factor=signing / baseline['signing_budget'],
                signature_growth_pct=100 * (signature_bytes / baseline['signature_bytes'] - 1))


def retune(family, params, ratio, model):
    _, _, h, d, _, _ = params
    limit = estimate(family, params, ratio)['signature_bytes']
    feasible = []
    for layers in range(1, d + 1):
        short, count_tall = divmod(h, layers)
        heights = [short + 1] * count_tall + [short] * (layers - count_tall)
        row = layout(family, params, ratio, heights, model)
        if row['payload_signature_bytes'] <= limit:
            row['padding_bytes'] = limit - row['payload_signature_bytes']
            row['transmitted_signature_bytes'] = limit
            feasible.append(row)
    return min(feasible, key=lambda r: r['signing_budget']) if feasible else None


if __name__ == '__main__':
    rows = []
    for family in ('SHA2', 'SHAKE'):
        for params in PARAMETERS:
            for ratio in ((1, 2) if family == 'SHA2' and params[1] > 16 else (1,)):
                for model in ('optimistic', 'addressed'):
                    row = layout(family, params, ratio,
                                 [params[2] // params[3]] * params[3], model)
                    row['same_size_retuned'] = retune(family, params, ratio, model)
                    rows.append(row)
    # Exact node count identity for each complete power-of-two mixed-radix tree.
    for height in range(1, 20):
        t = tree(height)
        assert (t['t8_oracle_calls'] // 3) * 7 + t['binary_calls'] == t['leaves'] - 1
    print(json.dumps(rows, indent=2))
