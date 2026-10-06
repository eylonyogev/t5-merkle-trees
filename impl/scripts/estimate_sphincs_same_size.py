#!/usr/bin/env python3
"""Same-size SPHINCS estimates: constant-sum WOTS + selective T8; tree caches.

Construction model:
  Keep n, h, d, a, k, w=16 and all leaf populations fixed.
  WOTS+C-style z=0 constant-sum encoding removes three checksum chains.
  Sign G(PK.seed, address, lower-root, counter) with digit sum exactly 15*n.
  Charge a four-byte counter per WOTS signature and one addressed hash per trial.
  Exact expected trial count is computed by convolution of uniform hex digits.
  Verification checks the condition and hashes forward 15*n chain steps.
  Use the saved bytes for bottom T8 levels in selected FORS trees; each level
  replaces 3 binary levels, saving half the population's binary-node calls at
  the first level but adding 2*n authentication bytes. Additional rounds yield
  successively smaller construction savings. Allocate to largest savings first.
  Pad remaining bytes so the transmitted signature has EXACT original length.

One-call and standard-addressed T8 models match estimate_sphincs_full_tree.
SHA2 leaf compression uses the prior optimistic raw-wide model. SHAKE uses the
ordinary endpoint-vector hash. New G is one addressed n-byte hash with four
extra bytes. It is domain-separated in a specified new address type (encoding
is not implemented). This is a cost model, not a signature implementation.
No FORS/security-parameter reduction, proof, or runtime benchmark is claimed.

Implementation model:
  Exact standard signatures; retain binary tree nodes for every subtree in the
  chosen top layers. Regenerate only the selected WOTS signature on a cache hit.
  Cold setup is charged and
  shown separately. Top-tree work is already incurred at standard keygen;
  retaining its values adds memory, not extra keygen hash calls.
  A cache is optional acceleration, not one-time-key allocation state.
  Include 2*N-1 Merkle nodes per subtree; no chain tables are stored.
  Memory excludes indexing, alignment and allocator overhead.

All percentages count serial native hash budgets; data movement is excluded.
Sources: https://eprint.iacr.org/2022/778.pdf (WOTS+C, Sections 3 and 5).
"""

import json
from functools import lru_cache
from estimate_sphincs_compression import PARAMETERS, estimate, raw_wide, standard, ceildiv


@lru_cache(maxsize=None)
def trials(n):
    counts = [1]
    for _ in range(2 * n):
        nxt = [0] * (len(counts) + 15)
        for total, count in enumerate(counts):
            for digit in range(16):
                nxt[total + digit] += count
        counts = nxt
    return 16 ** (2 * n) / counts[15 * n]


def construction(family, params, ratio=1, model='optimistic'):
    name, n, h, d, a, k = params
    base = estimate(family, params, ratio)
    weight = ratio if family == 'SHA2' and n > 16 else 1
    ch = standard(family, n, 2) * weight
    ct = ch if model == 'optimistic' else standard(family, n, 3) * weight
    if family == 'SHAKE':
        cg = (n + 32 + n + 4) // 136 + 1
    else:
        cg = ceildiv(22 + n + 4 + (9 if n == 16 else 17),
                     64 if n == 16 else 128) * weight
    # Counter-search hash may use SHA512 although WOTS F remains SHA256.
    lw = standard(family, n, 2 * n)
    lk = standard(family, n, k)
    if family == 'SHA2':
        lw = min(lw, raw_wide(n, 2 * n))
        lk = base['candidate_fors_calls']
    lw, lk = lw * weight, lk * weight
    leaves = d * 2 ** (h // d)
    old_lw = base['baseline_wots_calls'] * weight
    old_lk = base['baseline_fors_calls'] * weight
    sign = (base['signing_budget'] - leaves * (3 * 16 + old_lw - lw) -
            (old_lk - lk) + d * trials(n) * cg)
    verify = (base['verification_budget'] -
              d * (base['expected_verify_chain_steps'] - 15 * n + old_lw - lw) -
              (old_lk - lk) + d * cg)
    freed_bytes = 3 * d * n - 4 * d
    budget = freed_bytes // (2 * n)
    rounds = [0] * k
    gain_tree, gain_verify = 0, 0
    # Bottom-up T8 replacement; 7 parents replaced by 3 oracle calls per group.
    for level in range(a // 3):
        groups = 2 ** (a - 3 * (level + 1))
        gain = groups * (7 * ch - 3 * ct)
        if gain <= 0:
            break
        for tree_index in range(k):
            if budget == 0:
                break
            rounds[tree_index] += 1
            gain_tree += gain
            gain_verify += 3 * ch - 1.75 * ct
            budget -= 1
        if budget == 0:
            break
    sign -= gain_tree
    verify -= gain_verify
    used = sum(rounds) * 2 * n
    padding = freed_bytes - used
    payload = base['signature_bytes'] - freed_bytes + used
    assert payload + padding == base['signature_bytes'] and padding >= 0
    return dict(family=family, parameter=name, ratio=ratio, model=model,
                signature_bytes=base['signature_bytes'], payload_bytes=payload,
                padding_bytes=padding, freed_wots_bytes=freed_bytes,
                expected_counter_trials_per_layer=trials(n),
                t8_rounds_per_fors_tree=rounds,
                signing_reduction_pct=100 * (1 - sign / base['signing_budget']),
                verification_reduction_pct=100 * (1 - verify / base['verification_budget']),
                t8_only_signing_reduction_pct=100 * gain_tree / base['signing_budget'],
                t8_only_verification_reduction_pct=100 * gain_verify / base['verification_budget'])


def cache(params, ratio=1, layers=1):
    name, n, h, d, a, k = params
    base = estimate('SHA2', params, ratio)
    N = 2 ** (h // d)
    ell = 2 * n + 3
    weight = ratio if n > 16 else 1
    subtree_cost = N * (16 * ell + base['baseline_wots_calls'] * weight) + (N - 1) * weight
    tree_count = sum(N ** level for level in range(layers))
    memory = tree_count * (2 * N - 1) * n
    selected_signature_cost = ell + 15 * ell - base['expected_verify_chain_steps']
    saved = layers * (subtree_cost - selected_signature_cost)
    extra_setup = (tree_count - 1) * subtree_cost
    return dict(parameter=name, ratio=ratio, cached_top_layers=layers,
                cached_subtrees=tree_count, cache_bytes=memory,
                signing_reduction_pct=100 * saved / base['signing_budget'],
                extra_setup_in_original_signatures=extra_setup / base['signing_budget'],
                break_even_signatures_after_extra_setup=extra_setup / saved,
                signature_bytes=base['signature_bytes'])


def combined(params, ratio=1, layers=1):
    """Cache binary hypertree nodes in the constant-sum/T8-FORS variant."""
    _, n, h, d, _, _ = params
    base = estimate('SHA2', params, ratio)
    changed = construction('SHA2', params, ratio)
    weight = ratio if n > 16 else 1
    N = 2 ** (h // d)
    cw = min(standard('SHA2', n, 2 * n), raw_wide(n, 2 * n)) * weight
    subtree_cost = N * (16 * 2 * n + cw) + (N - 1) * weight
    # Counter-search cost is already charged by construction and stays online.
    selected_signature_cost = 2 * n + 15 * n
    saving = layers * (subtree_cost - selected_signature_cost)
    tree_count = sum(N ** level for level in range(layers))
    return dict(parameter=params[0], ratio=ratio, cached_top_layers=layers,
                cache_bytes=tree_count * (2 * N - 1) * n,
                signing_reduction_pct=changed['signing_reduction_pct'] +
                100 * saving / base['signing_budget'],
                verification_reduction_pct=changed['verification_reduction_pct'],
                signature_bytes=base['signature_bytes'],
                break_even_signatures_after_extra_setup=
                (tree_count - 1) * subtree_cost / saving)


if __name__ == '__main__':
    result = dict(construction=[], caching=[], combined=[])
    for params in PARAMETERS:
        for ratio in ((1, 2) if params[1] > 16 else (1,)):
            for model in ('optimistic', 'addressed'):
                result['construction'].append(construction('SHA2', params, ratio, model))
            for layers in ((1, 2, 3) if params[0].endswith('f') else (1,)):
                result['caching'].append(cache(params, ratio, layers))
                result['combined'].append(combined(params, ratio, layers))
        result['construction'].append(construction('SHAKE', params, 1, 'addressed'))
    print(json.dumps(result, indent=2))
