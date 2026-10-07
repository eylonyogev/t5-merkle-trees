import Mathlib

/-!
# Finite sums used by the collision bound

- Closed forms for the round sums met when per-round probabilities are added up.

- The factorial tail inequality for nonnegative weights.

```text
  e_k(x) = sum over k-subsets s of prod_(i in s) x_i  <=  (sum_i x_i)^k / k!
```

The refined bound keeps this `1/k!`, which the original analysis drops.
-/

namespace T5Bounds

open Finset

/-! ### Closed forms for the round sums -/

/-- `sum_(i < Q) i = Q (Q - 1) / 2`. -/
theorem sum_range_cast (Q : ℕ) : ∑ i ∈ range Q, (i : ℝ) = Q * (Q - 1) / 2 := by
  induction Q with
  | zero => simp
  | succ Q ih =>
    rw [sum_range_succ, ih]
    push_cast
    ring

/-- `sum_(i < Q) i^2 = Q (Q - 1) (2Q - 1) / 6`. -/
theorem sum_range_cast_sq (Q : ℕ) :
    ∑ i ∈ range Q, (i : ℝ) ^ 2 = Q * (Q - 1) * (2 * Q - 1) / 6 := by
  induction Q with
  | zero => simp
  | succ Q ih =>
    rw [sum_range_succ, ih]
    push_cast
    ring

/-- `sum_(i < Q) sum_(j < i) j^2 = Q (Q - 1)^2 (Q - 2) / 12`.

This is the double sum over pairs of rounds `j < i` behind the `rho^2 / 48` term. -/
theorem sum_range_sum_range_sq (Q : ℕ) :
    ∑ i ∈ range Q, ∑ j ∈ range i, (j : ℝ) ^ 2 = Q * (Q - 1) ^ 2 * (Q - 2) / 12 := by
  induction Q with
  | zero => simp
  | succ Q ih =>
    rw [sum_range_succ, ih, sum_range_cast_sq]
    push_cast
    ring

/-- The `rho^2` numerator is at most `Q^4`: `Q (Q - 1)^2 (Q - 2) <= Q^4`. -/
theorem quartic_le (Q : ℕ) : (Q : ℝ) * (Q - 1) ^ 2 * (Q - 2) ≤ (Q : ℝ) ^ 4 := by
  -- For `Q <= 1` the left side vanishes, and for `Q >= 2` every factor is in `[0, Q]`.
  rcases Nat.lt_or_ge Q 2 with hQ | hQ
  · interval_cases Q <;> norm_num
  · have h2 : (2 : ℝ) ≤ Q := by exact_mod_cast hQ
    have hsq : ((Q : ℝ) - 1) ^ 2 ≤ (Q : ℝ) ^ 2 := by nlinarith
    calc (Q : ℝ) * (Q - 1) ^ 2 * (Q - 2) ≤ (Q : ℝ) * (Q : ℝ) ^ 2 * Q := by
          gcongr <;> linarith
      _ = (Q : ℝ) ^ 4 := by ring

/-! ### The factorial tail inequality -/

/-- Bernoulli's inequality, homogeneous form: `p^(k+1) + (k+1) x p^k <= (p + x)^(k+1)`. -/
theorem pow_succ_add_mul_le {p x : ℝ} (hp : 0 ≤ p) (hx : 0 ≤ x) (k : ℕ) :
    p ^ (k + 1) + (k + 1) * x * p ^ k ≤ (p + x) ^ (k + 1) := by
  have := pow_add_mul_le_add_pow hp (by linarith : 0 ≤ 2 * p + x) (k + 1)
  push_cast at this
  simpa [mul_comm, mul_left_comm, mul_assoc] using this

variable {ι : Type*} [DecidableEq ι]

/-- Splitting the `(k+1)`-subsets of `insert a A` by whether they contain `a`:

```text
  e_(k+1)(A + {a}) = e_(k+1)(A) + x_a * e_k(A)
```
-/
theorem sum_powersetCard_succ_insert {A : Finset ι} {a : ι} (ha : a ∉ A) (x : ι → ℝ)
    (k : ℕ) :
    ∑ s ∈ (insert a A).powersetCard (k + 1), ∏ i ∈ s, x i
      = ∑ s ∈ A.powersetCard (k + 1), ∏ i ∈ s, x i
        + x a * ∑ s ∈ A.powersetCard k, ∏ i ∈ s, x i := by
  -- A subset of `A` never contains `a`.
  have hnot : ∀ t ∈ A.powersetCard k, a ∉ t := fun t ht h =>
    ha ((mem_powersetCard.1 ht).1 h)
  rw [powersetCard_succ_insert ha, sum_union, sum_image, mul_sum]
  · -- Adding `a` to such a subset multiplies its product by `x_a`.
    congr 1
    exact sum_congr rfl fun t ht => prod_insert (hnot t ht)
  · -- Adding `a` is injective on subsets that do not contain it.
    intro t ht u hu h
    rw [← erase_insert (hnot t ht), ← erase_insert (hnot u hu)]
    exact congrArg (·.erase a) h
  · -- The subsets without `a` and those with `a` are disjoint.
    rw [disjoint_left]
    intro s hs hs'
    obtain ⟨t, -, rfl⟩ := mem_image.1 hs'
    exact ha ((mem_powersetCard.1 hs).1 (mem_insert_self a t))

/-- The factorial tail inequality `k! * e_k(x) <= (sum_i x_i)^k` for nonnegative weights.

Expanding the power lists every ordered `k`-tuple of indices.

Each `k`-subset appears `k!` times, once per ordering.

The tuples with a repeated index only add nonnegative terms. -/
theorem factorial_mul_sum_powersetCard_prod_le (A : Finset ι) {x : ι → ℝ}
    (hx : ∀ i ∈ A, 0 ≤ x i) (k : ℕ) :
    k.factorial * ∑ s ∈ A.powersetCard k, ∏ i ∈ s, x i ≤ (∑ i ∈ A, x i) ^ k := by
  induction A using Finset.induction_on generalizing k with
  | empty =>
    -- No nonempty subsets: the left side is `1` for `k = 0` and `0` otherwise.
    cases k <;> simp [powersetCard_eq_empty.2]
  | insert a A ha ih =>
    have hxA : ∀ i ∈ A, 0 ≤ x i := fun i hi => hx i (mem_insert_of_mem hi)
    have hxa : 0 ≤ x a := hx a (mem_insert_self a A)
    cases k with
    | zero => simp
    | succ k =>
      -- Both induction hypotheses: degree `k + 1` and degree `k` over `A`.
      have ih₁ := ih hxA (k + 1)
      have ih₀ := ih hxA k
      set p := ∑ i ∈ A, x i
      set e₁ := ∑ s ∈ A.powersetCard (k + 1), ∏ i ∈ s, x i
      set e₀ := ∑ s ∈ A.powersetCard k, ∏ i ∈ s, x i
      rw [sum_powersetCard_succ_insert ha, sum_insert ha, add_comm (x a)]
      -- Phase 1: `(k+1)! * x_a * e_k = (k+1) * x_a * (k! * e_k) <= (k+1) * x_a * p^k`.
      have hstep : ((k + 1).factorial : ℝ) * (x a * e₀) ≤ (k + 1) * x a * p ^ k := by
        rw [Nat.factorial_succ]
        push_cast
        have := mul_le_mul_of_nonneg_left ih₀ (by positivity : (0 : ℝ) ≤ (k + 1) * x a)
        linarith
      -- Phase 2: Bernoulli closes `p^(k+1) + (k+1) x_a p^k <= (p + x_a)^(k+1)`.
      have hp : 0 ≤ p := sum_nonneg hxA
      have := pow_succ_add_mul_le hp hxa k
      rw [mul_add]
      linarith

/-- The factorial tail inequality in the form used by the bucket bound:
`e_k(x) <= (sum_i x_i)^k / k!`. -/
theorem sum_powersetCard_prod_le (A : Finset ι) {x : ι → ℝ} (hx : ∀ i ∈ A, 0 ≤ x i)
    (k : ℕ) :
    ∑ s ∈ A.powersetCard k, ∏ i ∈ s, x i ≤ (∑ i ∈ A, x i) ^ k / k.factorial := by
  rw [le_div_iff₀ (by positivity), mul_comm]
  exact factorial_mul_sum_powersetCard_prod_le A hx k

end T5Bounds
