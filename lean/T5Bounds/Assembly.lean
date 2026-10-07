import T5Bounds.Coefficient
import T5Bounds.Sums

/-!
# Assembling the refined collision bound

The proof splits the collision event three ways.

```text
  collision  ⊆  Bad_0                  a simple collision in one table
             ∪  Bad_K \ Bad_0          some matching-pair bucket exceeds K
             ∪  collision ∩ G_Q        a collision while every prefix stayed good
```

The paper bounds each piece from per-round estimates.

It obtains them by conditioning on the history of an adaptive adversary.

Those estimates are the fields of the record below, and nothing else is assumed.

This file checks everything after them:

- the union bounds over buckets and over rounds;

- the factorial tail inequality;

- the round sums in closed form;

- the comparison with `c_K * rho`;

- the choice of the optimal cutoff and the cap at one.
-/

namespace T5Bounds

open Finset MeasureTheory

/-- The per-round estimates of the refined collision proof at cutoff `K`.

Rounds count from `0`: round `i` is the fresh query that has `i` queries before it.

Write `S = 2^n` for the size of the output space. -/
structure RoundEstimates {Ω : Type*} [MeasurableSpace Ω] (μ : Measure Ω)
    (n Q K : ℕ) (Bucket : Type*) [Fintype Bucket] (collision : Set Ω) where
  /-- `Bad_0`: two answers of one oracle coincide, or two shifted outer answers coincide. -/
  simpleCollision : Set Ω
  /-- `Bad_K`: some matching-pair bucket ends with more than `K` entries. -/
  overfull : Set Ω
  /-- A fixed bucket ends with at least `K + 1` entries, and no simple collision occurs. -/
  bucketOverfull : Bucket → Set Ω
  /-- `G_i`: neither bad event occurs during the first `i` rounds. -/
  good : ℕ → Set Ω
  /-- Round `i` creates a collision involving an evaluation it completes. -/
  newCollision : ℕ → Set Ω
  /-- `E[V_i]`: the expected evaluation count after `i` rounds, zero once a bad event occurs. -/
  expectedEvals : ℕ → ℝ
  /-- Three bucket families, with one bucket per output value in each. -/
  card_bucket : Fintype.card Bucket = 3 * 2 ^ n
  /-- Without simple collisions, an overfull table has an overfull bucket. -/
  overfull_sub : overfull \ simpleCollision ⊆ ⋃ b, bucketOverfull b
  /-- After the last round, good means that neither bad event occurred. -/
  good_final : good Q = (simpleCollision ∪ overfull)ᶜ
  /-- A collision at a good end was first created in a round with a good prefix. -/
  collision_sub : collision ∩ good Q ⊆ ⋃ i ∈ range Q, newCollision i ∩ good i
  /-- Round `i` causes a simple collision with probability at most `2i / S`. -/
  simpleCollision_le : μ.real simpleCollision ≤ ∑ i ∈ range Q, 2 * (i : ℝ) / 2 ^ n
  /-- `K + 1` gains of a bucket, each with probability at most `i / S` in round `i`.

  Successive conditioning bounds this by a sum over the rounds of the gains. -/
  bucketOverfull_le : ∀ b, μ.real (bucketOverfull b)
    ≤ ∑ rounds ∈ (range Q).powersetCard (K + 1), ∏ i ∈ rounds, (i : ℝ) / 2 ^ n
  /-- With a good prefix, each old evaluation is hit with probability at most `K / S`. -/
  newCollision_le : ∀ i ∈ range Q,
    μ.real (newCollision i ∩ good i) ≤ K / 2 ^ n * expectedEvals i
  /-- At most `K` evaluations per outer query, plus `j^2 / (4S)` expected per inner query. -/
  expectedEvals_le : ∀ i ∈ range Q,
    expectedEvals i ≤ K * i + (∑ j ∈ range i, (j : ℝ) ^ 2) / (4 * 2 ^ n)

namespace RoundEstimates

variable {Ω : Type*} [MeasurableSpace Ω] {μ : Measure Ω} [IsFiniteMeasure μ]
  {n Q K : ℕ} {Bucket : Type*} [Fintype Bucket] {collision : Set Ω}
  (E : RoundEstimates μ n Q K Bucket collision)
include E

omit [IsFiniteMeasure μ] in
/-- `Pr[Bad_0] <= Q (Q - 1) / S <= rho`. -/
theorem simpleCollision_le_rho : μ.real E.simpleCollision ≤ rho n Q := by
  refine E.simpleCollision_le.trans ?_
  -- The round sum is `2 * (Q (Q - 1) / 2) / S`.
  rw [← sum_div, ← mul_sum, sum_range_cast, rho]
  gcongr
  nlinarith [Q.cast_nonneg (α := ℝ)]

/-- `Pr[Bad_K \ Bad_0] <= 3S / (K+1)! * (rho / 2)^(K+1)`. -/
theorem overfull_le :
    μ.real (E.overfull \ E.simpleCollision)
      ≤ 3 * 2 ^ n / (K + 1).factorial * (rho n Q / 2) ^ (K + 1) := by
  -- The weights `i / S` add up to `Q (Q - 1) / (2S) <= rho / 2`.
  have hweights : ∑ i ∈ range Q, (i : ℝ) / 2 ^ n ≤ rho n Q / 2 := by
    rw [← sum_div, sum_range_cast, rho, div_div, div_div, mul_comm (2 : ℝ)]
    gcongr
    nlinarith
  -- The factorial tail inequality bounds each bucket by `(rho / 2)^(K+1) / (K+1)!`.
  have hbucket : ∀ b,
      μ.real (E.bucketOverfull b) ≤ (rho n Q / 2) ^ (K + 1) / (K + 1).factorial := fun b =>
    (E.bucketOverfull_le b).trans <|
      (sum_powersetCard_prod_le _ (fun i _ => by positivity) _).trans (by gcongr)
  -- A union bound over the `3S` buckets.
  calc μ.real (E.overfull \ E.simpleCollision)
      ≤ μ.real (⋃ b, E.bucketOverfull b) := measureReal_mono E.overfull_sub
    _ ≤ ∑ b, μ.real (E.bucketOverfull b) := measureReal_iUnion_fintype_le _
    _ ≤ ∑ _b : Bucket, (rho n Q / 2) ^ (K + 1) / (K + 1).factorial :=
      sum_le_sum fun b _ => hbucket b
    _ = _ := by
      rw [sum_const, card_univ, E.card_bucket, nsmul_eq_mul]
      push_cast
      ring

/-- `Pr[collision ∩ G_Q] <= K^2 rho / 2 + K rho^2 / 48`. -/
theorem collision_good_le :
    μ.real (collision ∩ E.good Q) ≤ (K : ℝ) ^ 2 / 2 * rho n Q + K / 48 * rho n Q ^ 2 := by
  -- Phase 1: a union bound over the round in which the collision first appears.
  have hunion : μ.real (collision ∩ E.good Q)
      ≤ ∑ i ∈ range Q,
          K / 2 ^ n * (K * i + (∑ j ∈ range i, (j : ℝ) ^ 2) / (4 * 2 ^ n)) :=
    calc μ.real (collision ∩ E.good Q)
        ≤ μ.real (⋃ i ∈ range Q, E.newCollision i ∩ E.good i) :=
          measureReal_mono E.collision_sub (measure_ne_top _ _)
      _ ≤ ∑ i ∈ range Q, μ.real (E.newCollision i ∩ E.good i) :=
          measureReal_biUnion_finset_le _ _
      _ ≤ _ := sum_le_sum fun i hi =>
        (E.newCollision_le i hi).trans (by gcongr; exact E.expectedEvals_le i hi)
  -- Phase 2: the round sums in closed form.
  --
  --     sum_i K^2 i / S                 = K^2 Q (Q - 1) / (2S)
  --     sum_i K sum_(j<i) j^2 / (4S^2)  = K Q (Q - 1)^2 (Q - 2) / (48 S^2)
  have hclosed :
      ∑ i ∈ range Q, K / 2 ^ n * (K * i + (∑ j ∈ range i, (j : ℝ) ^ 2) / (4 * 2 ^ n))
        = (K : ℝ) ^ 2 / 2 ^ n * (Q * (Q - 1) / 2)
          + K / (4 * (2 ^ n) ^ 2) * (Q * (Q - 1) ^ 2 * (Q - 2) / 12) := by
    rw [← sum_range_cast, ← sum_range_sum_range_sq, mul_sum, mul_sum, ← sum_add_distrib]
    exact sum_congr rfl fun i _ => by ring
  -- Phase 3: `Q (Q - 1) <= Q^2` and `Q (Q - 1)^2 (Q - 2) <= Q^4` give the powers of `rho`.
  have hQ : (Q : ℝ) * (Q - 1) ≤ (Q : ℝ) ^ 2 := by nlinarith [Q.cast_nonneg (α := ℝ)]
  calc μ.real (collision ∩ E.good Q)
      ≤ (K : ℝ) ^ 2 / 2 ^ n * (Q * (Q - 1) / 2)
        + K / (4 * (2 ^ n) ^ 2) * (Q * (Q - 1) ^ 2 * (Q - 2) / 12) := hclosed ▸ hunion
    _ ≤ (K : ℝ) ^ 2 / 2 ^ n * ((Q : ℝ) ^ 2 / 2)
        + K / (4 * (2 ^ n) ^ 2) * ((Q : ℝ) ^ 4 / 12) := by
      gcongr
      exact quartic_le Q
    _ = _ := by ring

/-- The intermediate bound `Pr[collision] <= c_K * rho`. -/
theorem collision_le_coeff : μ.real collision ≤ coeff n (rho n Q) K * rho n Q := by
  -- Split the collision event along the two bad events.
  have hsplit : collision
      ⊆ E.simpleCollision ∪ (E.overfull \ E.simpleCollision) ∪ (collision ∩ E.good Q) := by
    intro ω hω
    by_cases h₀ : ω ∈ E.simpleCollision
    · exact Or.inl (Or.inl h₀)
    by_cases hK : ω ∈ E.overfull
    · exact Or.inl (Or.inr ⟨hK, h₀⟩)
    · exact Or.inr ⟨hω, by simp [E.good_final, h₀, hK]⟩
  -- Add the three estimates, then recognize `c_K * rho` term by term.
  have h₁ := measureReal_mono (μ := μ) hsplit
  have h₂ := measureReal_union_le (μ := μ)
    (E.simpleCollision ∪ (E.overfull \ E.simpleCollision)) (collision ∩ E.good Q)
  have h₃ := measureReal_union_le (μ := μ) E.simpleCollision (E.overfull \ E.simpleCollision)
  rw [coeff_mul_rho]
  linarith [E.simpleCollision_le_rho, E.overfull_le, E.collision_good_le]

end RoundEstimates

/-! ### The refined collision bound -/

variable {Ω : Type*} [MeasurableSpace Ω] {μ : Measure Ω} [IsProbabilityMeasure μ]
  {n Q : ℕ} {Bucket : Type*} [Fintype Bucket] {collision : Set Ω}

/-- **Refined collision bound.**

```text
  Pr[collision] <= min(1, gamma_n(Q) * rho)
```

It needs the per-round estimates at every cutoff `K >= 1`. -/
theorem collision_le_gamma (E : ∀ K, 1 ≤ K → RoundEstimates μ n Q K Bucket collision) :
    μ.real collision ≤ min 1 (gamma n (rho n Q) * rho n Q) :=
  -- A probability is at most one, and the estimates at the optimal cutoff give the rest.
  le_min measureReal_le_one (E _ (one_le_cutoff _ _)).collision_le_coeff

/-- **Merkle binding.**

```text
  advantage <= leaf collision + node collision
            <= gamma_n(Q) * rho + Q (Q - 1) / 2^(n+1)
            <= (gamma_n(Q) + 1/2) * rho
```
-/
theorem binding_le {advantage leafCollision nodeCollision : ℝ}
    (hsplit : advantage ≤ leafCollision + nodeCollision)
    (hleaf : leafCollision ≤ gamma n (rho n Q) * rho n Q)
    (hnode : nodeCollision ≤ (Q : ℝ) * (Q - 1) / 2 ^ (n + 1)) :
    advantage ≤ (gamma n (rho n Q) + 1 / 2) * rho n Q := by
  -- The node birthday bound is at most `rho / 2`.
  have hnode' : (Q : ℝ) * (Q - 1) / 2 ^ (n + 1) ≤ rho n Q / 2 := by
    rw [rho, div_div, ← pow_succ]
    gcongr
    nlinarith [Q.cast_nonneg (α := ℝ)]
  linarith

end T5Bounds
