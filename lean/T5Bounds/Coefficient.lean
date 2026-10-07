import Mathlib

/-!
# The collision coefficient and its minimizing cutoff

The refined bound reads `Pr[collision] <= c_K * rho` at every cutoff `K >= 1`.

```text
  rho = Q^2 / 2^n
  c_K = 1 + K^2 / 2 + K * rho / 48 + a_K
  a_K = 3 * 2^n * rho^K / (2^(K+1) * (K+1)!)
```

The polynomial part grows with `K`.

The tail `a_K` shrinks factorially with `K`.

For `0 <= rho <= 1` this file proves:

- `k |-> c_k` is strictly convex;

- the first `k >= 1` where it stops decreasing is a global minimizer;

- that cutoff is at most `n`;

- the minimum grows with `rho`, so a bound at a budget covers every smaller budget.
-/

namespace T5Bounds

/-- The normalized query count `rho = Q^2 / 2^n`. -/
noncomputable abbrev rho (n Q : ℕ) : ℝ := (Q : ℝ) ^ 2 / 2 ^ n

/-- The bucket-tail term `a_k = 3 * 2^n * rho^k / (2^(k+1) * (k+1)!)`. -/
noncomputable def tail (n : ℕ) (ρ : ℝ) (k : ℕ) : ℝ :=
  3 * 2 ^ n * ρ ^ k / (2 ^ (k + 1) * (k + 1).factorial)

/-- The collision coefficient `c_k = 1 + k^2 / 2 + k * rho / 48 + a_k`. -/
noncomputable def coeff (n : ℕ) (ρ : ℝ) (k : ℕ) : ℝ :=
  1 + (k : ℝ) ^ 2 / 2 + k * ρ / 48 + tail n ρ k

variable {n : ℕ} {ρ ρ' : ℝ}

/-! ### The tail term -/

/-- The tail is nonnegative. -/
theorem tail_nonneg (hρ : 0 ≤ ρ) (k : ℕ) : 0 ≤ tail n ρ k := by
  unfold tail
  positivity

/-- Each step multiplies the tail by `rho / (2 * (k + 2))`. -/
theorem tail_succ (k : ℕ) : tail n ρ (k + 1) = tail n ρ k * (ρ / (2 * (k + 2))) := by
  -- Unfold `(k+2)! = (k+2) * (k+1)!` and clear the denominators.
  unfold tail
  rw [Nat.factorial_succ (k + 1)]
  push_cast
  field_simp
  ring

/-- The tail is nondecreasing in `rho` on the nonnegative reals. -/
theorem tail_mono (hρ : 0 ≤ ρ) (hρρ' : ρ ≤ ρ') (k : ℕ) :
    tail n ρ k ≤ tail n ρ' k := by
  -- Only the factor `rho^k` depends on `rho`, and the rest is a positive constant.
  unfold tail
  gcongr

/-- At `k = n` the powers of two cancel, leaving `3 * rho^n / (2 * (n+1)!)`. -/
theorem tail_self (n : ℕ) (ρ : ℝ) : tail n ρ n = 3 * ρ ^ n / (2 * (n + 1).factorial) := by
  unfold tail
  rw [pow_succ]
  field_simp

/-! ### Successive differences and convexity -/

/-- The first difference `c_(k+1) - c_k`. -/
theorem coeff_succ_sub (k : ℕ) :
    coeff n ρ (k + 1) - coeff n ρ k
      = k + 1 / 2 + ρ / 48 - tail n ρ k * (1 - ρ / (2 * (k + 2))) := by
  -- Rewrite the next tail through the recurrence, then the identity is polynomial.
  unfold coeff
  rw [tail_succ]
  push_cast
  ring

/-- The second difference `c_(k+2) - 2 c_(k+1) + c_k`. -/
theorem coeff_second_diff (k : ℕ) :
    coeff n ρ (k + 2) - 2 * coeff n ρ (k + 1) + coeff n ρ k
      = 1 + tail n ρ k * (1 - ρ / (k + 2) + ρ ^ 2 / (4 * (k + 2) * (k + 3))) := by
  -- Two applications of the recurrence express both later tails through `a_k`.
  unfold coeff
  rw [tail_succ (k + 1), tail_succ k]
  push_cast
  field_simp
  ring

/-- For `0 <= rho <= 1` the coefficients are strictly convex in `k`. -/
theorem coeff_second_diff_pos (hρ0 : 0 ≤ ρ) (hρ1 : ρ ≤ 1) (k : ℕ) :
    0 < coeff n ρ (k + 2) - 2 * coeff n ρ (k + 1) + coeff n ρ k := by
  rw [coeff_second_diff]
  -- The bracket is positive.
  -- Why: `rho / (k+2) <= 1/2` and the square term is nonnegative.
  have hk : (2 : ℝ) ≤ k + 2 := by linarith [k.cast_nonneg (α := ℝ)]
  have hfrac : ρ / (k + 2) ≤ 1 / 2 := by
    rw [div_le_div_iff₀ (by positivity) (by norm_num)]
    linarith
  have hbracket : 0 ≤ 1 - ρ / (k + 2) + ρ ^ 2 / (4 * (k + 2) * (k + 3)) := by
    have : 0 ≤ ρ ^ 2 / (4 * (k + 2) * (k + 3)) := by positivity
    linarith
  -- So the second difference is `1 + (nonnegative) * (nonnegative) > 0`.
  have := mul_nonneg (tail_nonneg (n := n) hρ0 k) hbracket
  linarith

/-- For `0 <= rho <= 1` the first differences `c_(k+1) - c_k` strictly increase with `k`. -/
theorem strictMono_coeff_diff (hρ0 : 0 ≤ ρ) (hρ1 : ρ ≤ 1) :
    StrictMono fun k => coeff n ρ (k + 1) - coeff n ρ k := by
  -- A sequence is strictly increasing once each term beats its predecessor.
  refine strictMono_nat_of_lt_succ fun k => ?_
  have := coeff_second_diff_pos (n := n) hρ0 hρ1 k
  simp only [add_assoc, one_add_one_eq_two]
  linarith

/-- The step from `c_n` to `c_(n+1)` is an increase.

At `k = n` the tail is at most `3/4`, too small to offset the growth `n + 1/2`. -/
theorem coeff_lt_coeff_succ_self (hn : 1 ≤ n) (hρ0 : 0 ≤ ρ) (hρ1 : ρ ≤ 1) :
    coeff n ρ n < coeff n ρ (n + 1) := by
  -- Bound the tail by `3/4`.
  -- Why: `rho^n <= 1` and `(n+1)! >= 2! = 2` once `n >= 1`.
  have hfact : (2 : ℝ) ≤ (n + 1).factorial := by
    exact_mod_cast Nat.factorial_le (show 2 ≤ n + 1 by omega)
  have htail : tail n ρ n ≤ 3 / 4 := by
    rw [tail_self, div_le_div_iff₀ (by positivity) (by norm_num)]
    nlinarith [pow_le_one₀ hρ0 hρ1 (n := n)]
  -- The damping factor `1 - rho / (2 (n+2))` is at most one, so it can only shrink the tail.
  have hdamp : 1 - ρ / (2 * (n + 2)) ≤ 1 := by
    have : 0 ≤ ρ / (2 * (n + 2)) := by positivity
    linarith
  have hprod := mul_le_of_le_one_right (tail_nonneg (n := n) hρ0 n) hdamp
  -- Hence the step is at least `n + 1/2 - 3/4 > 0`.
  have hn' : (1 : ℝ) ≤ n := by exact_mod_cast hn
  have := coeff_succ_sub (n := n) (ρ := ρ) n
  linarith

/-! ### The stopping rule -/

/-- A convex sequence is minimized where it first stops decreasing.

```text
  f_1 > f_2 > ... > f_K <= f_(K+1) <= ...
```
-/
theorem le_of_first_stop {f : ℕ → ℝ} {K k : ℕ}
    (hconv : Monotone fun j => f (j + 1) - f j)
    (hstop : f K ≤ f (K + 1))
    (hdec : ∀ j, 1 ≤ j → j < K → f (j + 1) ≤ f j)
    (hk : 1 ≤ k) : f K ≤ f k := by
  rcases le_total K k with hKk | hkK
  · -- Right of `K`: each step is at least the step at `K`, which is nonnegative.
    clear hk
    induction k, hKk using Nat.le_induction with
    | base => exact le_rfl
    | succ j hKj ih =>
      have := hconv hKj
      simp only at this
      linarith
  · -- Left of `K`: walk up from `k` to `K`, never increasing.
    have walk : ∀ m, k + m ≤ K → f (k + m) ≤ f k := by
      intro m
      induction m with
      | zero => exact fun _ => le_rfl
      | succ m ih =>
        intro hm
        rw [← add_assoc]
        exact (hdec _ (by omega) (by omega)).trans (ih (by omega))
    simpa [Nat.add_sub_cancel' hkK] using walk (K - k) (by omega)

/-- Some `k >= 1` has `c_k <= c_(k+1)`, so the stopping rule terminates. -/
theorem exists_stop (hn : 1 ≤ n) (hρ0 : 0 ≤ ρ) (hρ1 : ρ ≤ 1) :
    ∃ j, coeff n ρ (j + 1) ≤ coeff n ρ (j + 2) := by
  -- Index `j = n - 1` is the cutoff `k = n`.
  refine ⟨n - 1, ?_⟩
  rw [Nat.sub_add_cancel hn, show n - 1 + 2 = n + 1 by omega]
  exact (coeff_lt_coeff_succ_self hn hρ0 hρ1).le

open Classical in
/-- The cutoff `K_*`: the first `k >= 1` with `c_k <= c_(k+1)`.

It falls back to `1` when no such `k` exists, which never happens for `n >= 1` and `rho <= 1`. -/
noncomputable def cutoff (n : ℕ) (ρ : ℝ) : ℕ :=
  if h : ∃ j, coeff n ρ (j + 1) ≤ coeff n ρ (j + 2) then Nat.find h + 1 else 1

/-- The optimized coefficient `gamma_n(Q) = c_(K_*)`, as a function of `rho`. -/
noncomputable def gamma (n : ℕ) (ρ : ℝ) : ℝ :=
  coeff n ρ (cutoff n ρ)

/-- The cutoff is at least one. -/
theorem one_le_cutoff (n : ℕ) (ρ : ℝ) : 1 ≤ cutoff n ρ := by
  unfold cutoff
  split_ifs <;> omega

section Minimizer

variable (hn : 1 ≤ n) (hρ0 : 0 ≤ ρ) (hρ1 : ρ ≤ 1)
include hn hρ0 hρ1

/-- The sequence stops decreasing at the cutoff. -/
theorem coeff_cutoff_le_succ : coeff n ρ (cutoff n ρ) ≤ coeff n ρ (cutoff n ρ + 1) := by
  have h := exists_stop hn hρ0 hρ1
  simp only [cutoff, h, dite_true]
  exact Nat.find_spec h

/-- The sequence strictly decreases before the cutoff. -/
theorem coeff_succ_lt_of_lt_cutoff {k : ℕ} (hk : 1 ≤ k) (hkK : k < cutoff n ρ) :
    coeff n ρ (k + 1) < coeff n ρ k := by
  have h := exists_stop hn hρ0 hρ1
  simp only [cutoff, h, dite_true] at hkK
  -- Index `k - 1` precedes the first stopping index, so it is not a stopping index.
  have := Nat.find_min h (m := k - 1) (by omega)
  rw [show k - 1 + 1 = k by omega, show k - 1 + 2 = k + 1 by omega] at this
  exact lt_of_not_ge this

/-- The cutoff is at most `n`. -/
theorem cutoff_le : cutoff n ρ ≤ n := by
  -- Otherwise `n` lies before the cutoff, which forces `c_(n+1) < c_n`.
  -- The step out of `n` is an increase, a contradiction.
  by_contra! h
  exact (coeff_succ_lt_of_lt_cutoff hn hρ0 hρ1 hn h).not_ge
    (coeff_lt_coeff_succ_self hn hρ0 hρ1).le

/-- The cutoff attains the global minimum of `c_k` over all `k >= 1`. -/
theorem gamma_le_coeff {k : ℕ} (hk : 1 ≤ k) : gamma n ρ ≤ coeff n ρ k :=
  le_of_first_stop (strictMono_coeff_diff hρ0 hρ1).monotone
    (coeff_cutoff_le_succ hn hρ0 hρ1)
    (fun _ hj hjK => (coeff_succ_lt_of_lt_cutoff hn hρ0 hρ1 hj hjK).le) hk

/-- The stopping rule returns `K` when the step into `K` decreases and the step out does not.

By convexity, no earlier step needs checking. -/
theorem cutoff_eq_of {K : ℕ} (hK : 1 ≤ K)
    (hstop : coeff n ρ K ≤ coeff n ρ (K + 1))
    (hprev : 2 ≤ K → coeff n ρ K < coeff n ρ (K - 1)) :
    cutoff n ρ = K := by
  have h := exists_stop hn hρ0 hρ1
  simp only [cutoff, h, dite_true]
  -- Search index `j` stands for cutoff `j + 1`, so the claim is that the first index is `K - 1`.
  suffices Nat.find h = K - 1 by omega
  rw [Nat.find_eq_iff]
  refine ⟨by rwa [show K - 1 + 1 = K by omega, show K - 1 + 2 = K + 1 by omega], ?_⟩
  intro m hm
  -- Every earlier step is a strict decrease: its difference is below the negative step into `K`.
  have hstep := hprev (by omega)
  have hmono := (strictMono_coeff_diff (n := n) hρ0 hρ1).monotone (show m + 1 ≤ K - 1 by omega)
  simp only [show K - 1 + 1 = K by omega] at hmono
  rw [not_le, show m + 2 = m + 1 + 1 by rfl]
  linarith

end Minimizer

/-! ### Dependence on the query budget -/

/-- A query budget `Q = 2^e` with `2e <= n` has `rho <= 1`. -/
theorem rho_two_pow_le_one {e : ℕ} (he : 2 * e ≤ n) : rho n (2 ^ e) ≤ 1 := by
  -- `(2^e)^2 = 2^(2e) <= 2^n`.
  rw [rho, div_le_one (by positivity)]
  push_cast
  rw [← pow_mul, mul_comm]
  exact pow_le_pow_right₀ (by norm_num) he

/-- Each coefficient is nondecreasing in `rho` on the nonnegative reals. -/
theorem coeff_mono (hρ : 0 ≤ ρ) (hρρ' : ρ ≤ ρ') (k : ℕ) :
    coeff n ρ k ≤ coeff n ρ' k := by
  unfold coeff
  gcongr
  exact tail_mono hρ hρρ' k

/-- The optimized coefficient is nondecreasing in `rho` on `[0, 1]`.

A coefficient computed at a query budget therefore bounds every smaller query count. -/
theorem gamma_mono (hn : 1 ≤ n) (hρ : 0 ≤ ρ) (hρρ' : ρ ≤ ρ') (hρ'1 : ρ' ≤ 1) :
    gamma n ρ ≤ gamma n ρ' :=
  -- Minimality at `rho`, then monotonicity of the fixed coefficient used at `rho'`.
  (gamma_le_coeff hn hρ (hρρ'.trans hρ'1) (one_le_cutoff n ρ')).trans (coeff_mono hρ hρρ' _)

/-- The uniform bound `gamma_n(Q) <= 2 + K^2/2 + K/48`.

It holds at every `K >= 1` with `3 * 2^n <= 2^(K+1) * (K+1)!`.

Stirling's formula, not formalized here, gives such a `K` of order `n / log n`. -/
theorem gamma_le_uniform (hn : 1 ≤ n) (hρ0 : 0 ≤ ρ) (hρ1 : ρ ≤ 1) {K : ℕ} (hK : 1 ≤ K)
    (hbig : (3 * 2 ^ n : ℝ) ≤ 2 ^ (K + 1) * (K + 1).factorial) :
    gamma n ρ ≤ 2 + (K : ℝ) ^ 2 / 2 + K / 48 := by
  refine (gamma_le_coeff hn hρ0 hρ1 hK).trans ?_
  -- The large factorial makes the tail at most `rho^K <= 1`.
  have htail : tail n ρ K ≤ 1 := by
    unfold tail
    rw [div_le_one (by positivity)]
    calc 3 * 2 ^ n * ρ ^ K ≤ 3 * 2 ^ n * 1 := by gcongr; exact pow_le_one₀ hρ0 hρ1
      _ ≤ _ := by simpa using hbig
  -- The middle term is at most `K / 48` because `rho <= 1`.
  have hmid : (K : ℝ) * ρ / 48 ≤ K / 48 := by
    gcongr
    exact mul_le_of_le_one_right K.cast_nonneg hρ1
  unfold coeff
  linarith

/-! ### The bound as a function of `rho` -/

/-- The intermediate bound `B_n(Q, K) = c_K * rho`, written term by term. -/
theorem coeff_mul_rho (n K : ℕ) (ρ : ℝ) :
    coeff n ρ K * ρ
      = (1 + (K : ℝ) ^ 2 / 2) * ρ + K * ρ ^ 2 / 48
        + 3 * 2 ^ n / (K + 1).factorial * (ρ / 2) ^ (K + 1) := by
  unfold coeff tail
  rw [div_pow, pow_succ ρ]
  field_simp
  ring

end T5Bounds
