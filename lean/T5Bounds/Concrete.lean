import T5Bounds.Assembly

/-!
# The concrete table for 256-bit digests

Every row of the note's table for `n = 256`, checked in exact rational arithmetic.

| query budget | `K_*` | coefficient |
|--------------|-------|-------------|
| `2^64`       | 2     | 3.07        |
| `2^80`       | 3     | 5.51        |
| `2^96`       | 4     | 9.01        |
| `2^112`      | 8     | 33.01       |
| `2^120`      | 13    | 86.10       |

Each coefficient covers every query count up to its budget.

Each coefficient is also the exact value rounded up at two decimals, never further.
-/

namespace T5Bounds

open MeasureTheory

/-- A coefficient computed at a budget `2^e <= 2^128` bounds every smaller query count. -/
theorem gamma_le_of_row {e K Q : ℕ} {c : ℝ} (he : e ≤ 128) (hK : 1 ≤ K)
    (hrow : coeff 256 (rho 256 (2 ^ e)) K ≤ c) (hQ : Q ≤ 2 ^ e) :
    gamma 256 (rho 256 Q) ≤ c := by
  -- `rho` at `Q` is below `rho` at the budget, which is at most one.
  have hρ : rho 256 Q ≤ rho 256 (2 ^ e) := by
    unfold rho
    gcongr
  have hbudget := rho_two_pow_le_one (n := 256) (by omega : 2 * e ≤ 256)
  -- Minimality of the optimal cutoff, then monotonicity of the fixed coefficient in `rho`.
  exact (gamma_le_coeff (by norm_num) (by positivity) (hρ.trans hbudget) hK).trans
    ((coeff_mono (by positivity) hρ K).trans hrow)

/-- At a budget `2^e <= 2^128`, the cutoff is `K` when the step into `K` decreases.

The step out of `K` must not decrease. -/
theorem cutoff_eq_of_row {e K : ℕ} (he : e ≤ 128) (hK : 2 ≤ K)
    (hprev : coeff 256 (rho 256 (2 ^ e)) K < coeff 256 (rho 256 (2 ^ e)) (K - 1))
    (hstop : coeff 256 (rho 256 (2 ^ e)) K ≤ coeff 256 (rho 256 (2 ^ e)) (K + 1)) :
    cutoff 256 (rho 256 (2 ^ e)) = K :=
  cutoff_eq_of (by norm_num) (by positivity) (rho_two_pow_le_one (by omega)) (by omega) hstop
    fun _ => hprev

/-! ### The coefficient column -/

theorem gamma_le_of_le_two_pow_64 {Q : ℕ} (hQ : Q ≤ 2 ^ 64) : gamma 256 (rho 256 Q) ≤ 3.07 :=
  gamma_le_of_row (K := 2) (by norm_num) (by norm_num) (by norm_num [coeff, tail]) hQ

theorem gamma_le_of_le_two_pow_80 {Q : ℕ} (hQ : Q ≤ 2 ^ 80) : gamma 256 (rho 256 Q) ≤ 5.51 :=
  gamma_le_of_row (K := 3) (by norm_num) (by norm_num) (by norm_num [coeff, tail]) hQ

theorem gamma_le_of_le_two_pow_96 {Q : ℕ} (hQ : Q ≤ 2 ^ 96) : gamma 256 (rho 256 Q) ≤ 9.01 :=
  gamma_le_of_row (K := 4) (by norm_num) (by norm_num) (by norm_num [coeff, tail]) hQ

theorem gamma_le_of_le_two_pow_112 {Q : ℕ} (hQ : Q ≤ 2 ^ 112) :
    gamma 256 (rho 256 Q) ≤ 33.01 :=
  gamma_le_of_row (K := 8) (by norm_num) (by norm_num)
    (by norm_num [coeff, tail, Nat.factorial]) hQ

theorem gamma_le_of_le_two_pow_120 {Q : ℕ} (hQ : Q ≤ 2 ^ 120) :
    gamma 256 (rho 256 Q) ≤ 86.10 :=
  gamma_le_of_row (K := 13) (by norm_num) (by norm_num)
    (by norm_num [coeff, tail, Nat.factorial]) hQ

/-- Past the table, up to the birthday bound `2^128`.

The uniform bound applies with `K = 49`, the least `K` with `3 * 2^256 <= 2^(K+1) * (K+1)!`. -/
theorem gamma_le_of_le_two_pow_128 {Q : ℕ} (hQ : Q ≤ 2 ^ 128) :
    gamma 256 (rho 256 Q) ≤ 1203.53 := by
  -- `rho` is at most one exactly up to `Q = 2^128`.
  have hρ1 : rho 256 Q ≤ 1 :=
    (show rho 256 Q ≤ rho 256 (2 ^ 128) by unfold rho; gcongr).trans
      (rho_two_pow_le_one le_rfl)
  refine (gamma_le_uniform (K := 49) (by norm_num) (by positivity) hρ1 (by norm_num)
    (by norm_num [Nat.factorial])).trans ?_
  norm_num

/-! ### The cutoff column -/

theorem cutoff_two_pow_64 : cutoff 256 (rho 256 (2 ^ 64)) = 2 :=
  cutoff_eq_of_row (by norm_num) le_rfl (by norm_num [coeff, tail]) (by norm_num [coeff, tail])

theorem cutoff_two_pow_80 : cutoff 256 (rho 256 (2 ^ 80)) = 3 :=
  cutoff_eq_of_row (by norm_num) (by norm_num) (by norm_num [coeff, tail])
    (by norm_num [coeff, tail])

theorem cutoff_two_pow_96 : cutoff 256 (rho 256 (2 ^ 96)) = 4 :=
  cutoff_eq_of_row (by norm_num) (by norm_num) (by norm_num [coeff, tail])
    (by norm_num [coeff, tail])

theorem cutoff_two_pow_112 : cutoff 256 (rho 256 (2 ^ 112)) = 8 :=
  cutoff_eq_of_row (by norm_num) (by norm_num) (by norm_num [coeff, tail, Nat.factorial])
    (by norm_num [coeff, tail, Nat.factorial])

theorem cutoff_two_pow_120 : cutoff 256 (rho 256 (2 ^ 120)) = 13 :=
  cutoff_eq_of_row (by norm_num) (by norm_num) (by norm_num [coeff, tail, Nat.factorial])
    (by norm_num [coeff, tail, Nat.factorial])

/-! ### The rounding is tight

At each budget the exact coefficient exceeds the tabulated value minus `0.01`. -/

theorem gamma_two_pow_64_gt : 3.06 < gamma 256 (rho 256 (2 ^ 64)) := by
  rw [gamma, cutoff_two_pow_64]
  norm_num [coeff, tail]

theorem gamma_two_pow_80_gt : 5.50 < gamma 256 (rho 256 (2 ^ 80)) := by
  rw [gamma, cutoff_two_pow_80]
  norm_num [coeff, tail]

theorem gamma_two_pow_96_gt : 9.00 < gamma 256 (rho 256 (2 ^ 96)) := by
  rw [gamma, cutoff_two_pow_96]
  norm_num [coeff, tail]

theorem gamma_two_pow_112_gt : 33.00 < gamma 256 (rho 256 (2 ^ 112)) := by
  rw [gamma, cutoff_two_pow_112]
  norm_num [coeff, tail, Nat.factorial]

theorem gamma_two_pow_120_gt : 86.09 < gamma 256 (rho 256 (2 ^ 120)) := by
  rw [gamma, cutoff_two_pow_120]
  norm_num [coeff, tail, Nat.factorial]

/-! ### The headline bound -/

/-- **T5 and T8 collisions at 256 bits.**

```text
  Q <= 2^120   ==>   Pr[collision] <= 86.10 * Q^2 / 2^256
```
-/
theorem collision_le_of_le_two_pow_120 {Ω : Type*} [MeasurableSpace Ω] {μ : Measure Ω}
    [IsProbabilityMeasure μ] {Bucket : Type*} [Fintype Bucket] {collision : Set Ω} {Q : ℕ}
    (hQ : Q ≤ 2 ^ 120) (E : ∀ K, 1 ≤ K → RoundEstimates μ 256 Q K Bucket collision) :
    μ.real collision ≤ 86.10 * rho 256 Q :=
  -- Drop the cap at one, then bound the optimized coefficient by its table entry.
  (collision_le_gamma E).trans <| (min_le_right _ _).trans <|
    mul_le_mul_of_nonneg_right (gamma_le_of_le_two_pow_120 hQ) (by positivity)

end T5Bounds
