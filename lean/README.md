# Lean proofs for the T5 / T8 collision bound

Machine-checked proofs for the security section of the note (`../t5-trees.tex`).

The headline result is the case `n = 256`, `Q <= 2^120`:

```text
  Pr[collision in T5 or T8]  <=  86.10 * Q^2 / 2^256
```

## Build

```sh
lake build
```

- Toolchain and Mathlib are pinned in `lean-toolchain` and `lakefile.toml`.
- Warnings are errors, so an unfinished proof cannot build.
- The proofs use no `sorry`, no `native_decide`, and no axioms beyond `propext`, `Classical.choice` and `Quot.sound`.

## Map from the note to the code

| Note | Lean | File |
|------|------|------|
| `c_k`, `K_*`, `gamma_n(Q)` | `coeff`, `cutoff`, `gamma` | `Coefficient.lean` |
| the stopping rule gives the global minimum | `gamma_le_coeff` | `Coefficient.lean` |
| the stopping rule ends by `k = n` | `cutoff_le` | `Coefficient.lean` |
| `gamma` is monotone in the budget | `gamma_mono` | `Coefficient.lean` |
| uniform bound (eq. t5-uniform-cutoff) | `gamma_le_uniform` | `Coefficient.lean` |
| `B_n(Q, K) = c_K * rho` | `coeff_mul_rho` | `Coefficient.lean` |
| the `1/k!` tail bound | `sum_powersetCard_prod_le` | `Sums.lean` |
| the double-sum identity | `sum_range_sum_range_sq` | `Sums.lean` |
| Theorem (refined collision bound) | `collision_le_gamma` | `Assembly.lean` |
| eq. refined-binding | `binding_le` | `Assembly.lean` |
| the `n = 256` table, both columns | `gamma_le_of_le_two_pow_*`, `cutoff_two_pow_*` | `Concrete.lean` |
| the coefficients are rounded up by less than `0.01` | `gamma_two_pow_*_gt` | `Concrete.lean` |
| consistent triples, `s = a + c` | `Oracles.outerQuery_eq_iff` | `Transcript.lean` |
| one query cannot create two colliding evaluations | `Transcript.eq_of_*_eq` | `Transcript.lean` |
| a query adds at most one pair to a bucket | `card_filter_add_eq_le_one` | `Transcript.lean` |
| Proposition (binding) | `binding` | `Binding.lean` |

## What is proved, and what is assumed

The probabilistic step is the trust boundary.

The proof in the note conditions on the history of an adaptive adversary.

That gives four per-round estimates:

| estimate | value |
|----------|-------|
| simple collision in round `i` | at most `2i / S` |
| `K + 1` gains of one bucket | at most `e_(K+1)(0/S, 1/S, ..., (Q-1)/S)` |
| a new collision in round `i` under a good prefix | at most `K / S * E[V_i]` |
| expected evaluation count `E[V_i]` | at most `K i + sum_(j<i) j^2 / (4S)` |

They are the fields of `RoundEstimates`, together with the set inclusions that relate the bad events.

Everything downstream of them is machine-checked:

- the union bounds;
- the factorial tail inequality;
- the closed-form sums;
- the comparison with `c_K * rho`;
- the optimal cutoff;
- every number in the table.

The deterministic case analysis behind the estimates is also checked, in `Transcript.lean`.

The adaptive-adversary probability model itself is not formalized.

## Observations from the formalization

- The intermediate bound `c_K * rho` holds for every `Q` and every `K >= 1`.
  The hypothesis `Q <= 2^(n/2)` matters only for the optimality of the stopping rule.
- Strict convexity of `k |-> c_k` holds from `k = 0` on, slightly more than the note's `k >= 1`.
- Every row of the table was checked against its exact value: each entry is that value rounded up at two decimals.
- Past the table, `K = 49` satisfies `3 * 2^256 <= 2^50 * 50!`.
  The uniform bound then gives `gamma_256(Q) <= 1203.53` for every `Q <= 2^128`.
