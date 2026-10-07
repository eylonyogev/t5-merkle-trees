import Mathlib

/-!
# Transcripts of the generalized T5 compression function

The construction, over an output group `G` where every element is its own inverse:

```text
  H(u, v, s, w) = h_3(h_1(u) + s, h_2(v) + s, w) + s
```

- With `w` empty this is T5.

- With `u`, `v` three blocks each and `w` one block it is the eight-input leaf T8.

This file proves the deterministic facts behind the collision proof.

- Each evaluation is a consistent triple of queries, one per oracle.

- With no simple collision, two evaluations that share a query cannot collide.

- One query adds at most one pair to any matching-pair bucket.

Probability enters only through the per-round estimates in the assembly file.
-/

namespace T5Bounds

open Finset

variable {U V W G : Type*} [AddCommGroup G]

/-! ### Addition in a group of exponent two -/

section ExponentTwo

variable (hG : ∀ x : G, x + x = 0)
include hG

/-- Adding the same element twice cancels it. -/
theorem add_add_cancel_right (a b : G) : a + b + b = a := by
  rw [add_assoc, hG, add_zero]

end ExponentTwo

/-! ### The construction -/

/-- Three independent oracles: two inner compressions and one outer compression. -/
structure Oracles (U V W G : Type*) where
  /-- The first inner compression, applied to the first input block group. -/
  h₁ : U → G
  /-- The second inner compression, applied to the second input block group. -/
  h₂ : V → G
  /-- The outer compression, applied to the two shifted inner digests and the spare blocks. -/
  h₃ : G × G × W → G

namespace Oracles

variable (O : Oracles U V W G)

/-- The outer query made while evaluating at `(u, v, s, w)`. -/
def outerQuery (u : U) (v : V) (s : G) (w : W) : G × G × W :=
  (O.h₁ u + s, O.h₂ v + s, w)

/-- The generalized T5 function `H(u, v, s, w) = h_3(h_1(u) + s, h_2(v) + s, w) + s`. -/
def eval (u : U) (v : V) (s : G) (w : W) : G :=
  O.h₃ (O.outerQuery u v s w) + s

/-- The left shifted answer `r = h_3(q) + c` of an outer query `q = (c, d, w)`. -/
def shiftL (q : G × G × W) : G := O.h₃ q + q.1

/-- The right shifted answer `t = h_3(q) + d` of an outer query `q = (c, d, w)`. -/
def shiftR (q : G × G × W) : G := O.h₃ q + q.2.1

/-! ### Evaluations are consistent triples -/

section ExponentTwo

variable (hG : ∀ x : G, x + x = 0)
include hG

/-- An inner pair and an outer query form an evaluation exactly when `a + b = c + d`.

The shift is then forced to be `s = a + c`. -/
theorem outerQuery_eq_iff {u : U} {v : V} {s : G} {w : W} {q : G × G × W} :
    O.outerQuery u v s w = q ↔
      O.h₁ u + O.h₂ v = q.1 + q.2.1 ∧ s = O.h₁ u + q.1 ∧ w = q.2.2 := by
  obtain ⟨c, d, w'⟩ := q
  simp only [outerQuery, Prod.mk.injEq]
  constructor
  · -- From the query: `s = a + c` and `b + s = d`, hence `a + b = c + d`.
    rintro ⟨hc, hd, rfl⟩
    have hs : s = O.h₁ u + c := by rw [← hc, ← add_assoc, hG, zero_add]
    refine ⟨?_, hs, rfl⟩
    rw [← hc, ← hd]
    calc O.h₁ u + O.h₂ v = O.h₁ u + O.h₂ v + s + s := (add_add_cancel_right hG _ _).symm
      _ = O.h₁ u + s + (O.h₂ v + s) := by abel
  · -- From consistency and the forced shift: both shifted digests match the query.
    rintro ⟨hcons, rfl, rfl⟩
    refine ⟨by rw [← add_assoc, hG, zero_add], ?_, rfl⟩
    calc O.h₂ v + (O.h₁ u + c) = O.h₁ u + O.h₂ v + c := by abel
      _ = c + d + c := by rw [hcons]
      _ = d := by rw [add_comm c d, add_add_cancel_right hG]

/-- The output read through the left shift: `H = a + r`. -/
theorem eval_eq_h₁_add_shiftL (u : U) (v : V) (s : G) (w : W) :
    O.eval u v s w = O.h₁ u + O.shiftL (O.outerQuery u v s w) := by
  -- `h_3(q) + s = h_3(q) + c + a` because `c = a + s`.
  simp only [eval, shiftL, outerQuery]
  calc O.h₃ _ + s = O.h₃ _ + s + O.h₁ u + O.h₁ u := by rw [add_add_cancel_right hG]
    _ = O.h₁ u + (O.h₃ _ + (O.h₁ u + s)) := by abel

/-- The output read through the right shift: `H = b + t`. -/
theorem eval_eq_h₂_add_shiftR (u : U) (v : V) (s : G) (w : W) :
    O.eval u v s w = O.h₂ v + O.shiftR (O.outerQuery u v s w) := by
  -- `h_3(q) + s = h_3(q) + d + b` because `d = b + s`.
  simp only [eval, shiftR, outerQuery]
  calc O.h₃ _ + s = O.h₃ _ + s + O.h₂ v + O.h₂ v := by rw [add_add_cancel_right hG]
    _ = O.h₂ v + (O.h₃ _ + (O.h₂ v + s)) := by abel

end ExponentTwo

end Oracles

/-! ### T5 and T8 -/

/-- The eight-block leaf T8, written exactly as in the note.

```text
  a = h_1(z_1, z_2, z_3)      b = h_2(z_4, z_5, z_6)
  T8(z) = h_3(a + z_7, b + z_7, z_8) + z_7
```
-/
def leaf8 (O : Oracles (G × G × G) (G × G × G) G G) (z : Fin 8 → G) : G :=
  O.h₃ (O.h₁ (z 0, z 1, z 2) + z 6, O.h₂ (z 3, z 4, z 5) + z 6, z 7) + z 6

/-- T8 is the generalized construction with three-block inner inputs and one spare block. -/
theorem leaf8_eq_eval (O : Oracles (G × G × G) (G × G × G) G G) (z : Fin 8 → G) :
    leaf8 O z = O.eval (z 0, z 1, z 2) (z 3, z 4, z 5) (z 6) (z 7) :=
  rfl

/-- T5 is the generalized construction with no spare blocks. -/
def leaf5 (O : Oracles (G × G) (G × G) Unit G) (z : Fin 5 → G) : G :=
  O.eval (z 0, z 1) (z 2, z 3) (z 4) ()

/-! ### Transcripts and simple collisions -/

/-- The oracles together with the finite sets of inputs queried so far. -/
structure Transcript (U V W G : Type*) extends Oracles U V W G where
  /-- Inputs queried to the first inner compression. -/
  queries₁ : Finset U
  /-- Inputs queried to the second inner compression. -/
  queries₂ : Finset V
  /-- Inputs queried to the outer compression. -/
  queries₃ : Finset (G × G × W)

namespace Transcript

variable (T : Transcript U V W G)

/-- The transcript contains all three queries needed to evaluate at `(u, v, s, w)`. -/
def Contains (u : U) (v : V) (s : G) (w : W) : Prop :=
  u ∈ T.queries₁ ∧ v ∈ T.queries₂ ∧ T.outerQuery u v s w ∈ T.queries₃

/-- `Bad_0` fails: all answers within one oracle are distinct, and so are both shifted answers. -/
structure NoSimpleCollision : Prop where
  /-- Distinct first inner queries have distinct answers. -/
  inj₁ : Set.InjOn T.h₁ T.queries₁
  /-- Distinct second inner queries have distinct answers. -/
  inj₂ : Set.InjOn T.h₂ T.queries₂
  /-- Distinct outer queries have distinct left shifted answers. -/
  injL : Set.InjOn T.shiftL T.queries₃
  /-- Distinct outer queries have distinct right shifted answers. -/
  injR : Set.InjOn T.shiftR T.queries₃

variable {T} (hG : ∀ x : G, x + x = 0) (hT : T.NoSimpleCollision)
include hG hT

/-! ### Evaluations that share a query never collide -/

/-- Two evaluations through the same outer query with equal outputs are the same evaluation. -/
theorem eq_of_outerQuery_eq {u u' : U} {v v' : V} {s s' : G} {w w' : W}
    (hx : T.Contains u v s w) (hx' : T.Contains u' v' s' w')
    (hq : T.outerQuery u v s w = T.outerQuery u' v' s' w')
    (hf : T.eval u v s w = T.eval u' v' s' w') :
    u = u' ∧ v = v' ∧ s = s' ∧ w = w' := by
  -- Phase 1: equal outputs and a shared `r` force equal answers `a = a'`, hence `u = u'`.
  rw [T.eval_eq_h₁_add_shiftL hG, T.eval_eq_h₁_add_shiftL hG, hq] at hf
  obtain rfl : u = u' := hT.inj₁ hx.1 hx'.1 (add_right_cancel hf)
  -- Phase 2: the shared query then fixes the shift, the spare blocks and the answer `b`.
  simp only [Oracles.outerQuery, Prod.mk.injEq, add_right_inj] at hq
  obtain ⟨rfl, hb, rfl⟩ := hq
  exact ⟨rfl, hT.inj₂ hx.2.1 hx'.2.1 (add_right_cancel hb), rfl, rfl⟩

/-- Two evaluations through the same first inner query with equal outputs are the same. -/
theorem eq_of_h₁_query_eq {u : U} {v v' : V} {s s' : G} {w w' : W}
    (hx : T.Contains u v s w) (hx' : T.Contains u v' s' w')
    (hf : T.eval u v s w = T.eval u v' s' w') :
    v = v' ∧ s = s' ∧ w = w' := by
  -- A shared answer `a` and equal outputs force equal `r`, hence the same outer query.
  have hr := hf
  rw [T.eval_eq_h₁_add_shiftL hG, T.eval_eq_h₁_add_shiftL hG] at hr
  have hq := hT.injL hx.2.2 hx'.2.2 (add_left_cancel hr)
  exact (eq_of_outerQuery_eq hG hT hx hx' hq hf).2

/-- Two evaluations through the same second inner query with equal outputs are the same. -/
theorem eq_of_h₂_query_eq {u u' : U} {v : V} {s s' : G} {w w' : W}
    (hx : T.Contains u v s w) (hx' : T.Contains u' v s' w')
    (hf : T.eval u v s w = T.eval u' v s' w') :
    u = u' ∧ s = s' ∧ w = w' := by
  -- A shared answer `b` and equal outputs force equal `t`, hence the same outer query.
  have ht := hf
  rw [T.eval_eq_h₂_add_shiftR hG, T.eval_eq_h₂_add_shiftR hG] at ht
  have hq := hT.injR hx.2.2 hx'.2.2 (add_left_cancel ht)
  obtain ⟨hu, -, hs, hw⟩ := eq_of_outerQuery_eq hG hT hx hx' hq hf
  exact ⟨hu, hs, hw⟩

end Transcript

/-! ### Matching-pair buckets grow by at most one per query -/

/-- A fresh value `a` matches at most one stored value under an injective labelling.

```text
  #{ x in X : a + g(x) = z } <= 1      whenever g is injective on X
```

This covers every case of a query joining a bucket.

- First inner answer joining the first-pair bucket: `X` holds the second inner queries.

- First inner answer joining the first-outer bucket: `X` holds the outer queries, labelled by `r`.

- Outer query joining either outer bucket: `X` holds the inner queries.

- The second inner answer is symmetric. -/
theorem card_filter_add_eq_le_one [DecidableEq G] {X : Type*} {S : Finset X} {g : X → G}
    (hg : Set.InjOn g S) (a z : G) :
    (S.filter fun x => a + g x = z).card ≤ 1 := by
  -- Two members of the filter have the same label `z - a`, so they are equal.
  refine card_le_one.2 fun x hx y hy => ?_
  rw [mem_filter] at hx hy
  exact hg hx.1 hy.1 (add_left_cancel (hx.2.trans hy.2.symm))

end T5Bounds
