import Mathlib

/-!
# Position binding of the Merkle commitment

Any leaf function and any ordered node function give a position-binding tree.

Two accepted openings of different records at one position expose a collision.

- Either the leaf function maps both records to the same digest.

- Or the two verification paths merge at some level through two different node inputs.

No probability is involved, and the statement holds for every pair of functions.
-/

namespace T5Bounds

open Function

variable {Record Digest : Type*}

/-- Recompute the root from a leaf digest, its position and the sibling digests, bottom to top.

At each level, an even position puts the current digest on the left. -/
def reconstruct (node : Digest → Digest → Digest) : ℕ → Digest → List Digest → Digest
  | _, y, [] => y
  | i, y, s :: siblings =>
    reconstruct node (i / 2) (if i % 2 = 0 then node y s else node s y) siblings

/-- The verifier for a tree of depth `d`.

It checks the position range and the proof length, then recomputes the root from the full record. -/
def Accepts (leaf : Record → Digest) (node : Digest → Digest → Digest) (d : ℕ)
    (root : Digest) (i : ℕ) (record : Record) (proof : List Digest) : Prop :=
  i < 2 ^ d ∧ proof.length = d ∧ reconstruct node i (leaf record) proof = root

variable {node : Digest → Digest → Digest}

/-- Two paths at the same position that reach the same root either start equal or expose a
node collision. -/
theorem eq_or_node_collision {i : ℕ} {y y' : Digest} {π π' : List Digest}
    (hlen : π.length = π'.length) (hroot : reconstruct node i y π = reconstruct node i y' π') :
    y = y' ∨ ¬Injective (uncurry node) := by
  induction π generalizing i y y' π' with
  | nil =>
    -- Depth zero: the root is the leaf digest itself.
    obtain rfl : π' = [] := List.length_eq_zero_iff.1 hlen.symm
    exact Or.inl hroot
  | cons s π ih =>
    obtain _ | ⟨s', π'⟩ := π'
    · simp at hlen
    -- One level up, the parents agree or a collision appeared higher in the tree.
    rcases ih (by simpa using hlen) hroot with hparent | hcoll
    · -- Equal parents from the same input slot: equal children, or two node inputs collide.
      refine or_iff_not_imp_right.2 fun hcoll => ?_
      have hinj := not_not.1 hcoll
      split_ifs at hparent
      · exact congrArg Prod.fst (hinj (a₁ := (y, s)) (a₂ := (y', s')) hparent)
      · exact congrArg Prod.snd (hinj (a₁ := (s, y)) (a₂ := (s', y')) hparent)
    · exact Or.inr hcoll

/-- **Position binding.**

Two accepted openings of different records at the same position give a leaf or a node collision. -/
theorem binding {leaf : Record → Digest} {d : ℕ} {root : Digest} {i : ℕ}
    {record record' : Record} {proof proof' : List Digest}
    (h : Accepts leaf node d root i record proof)
    (h' : Accepts leaf node d root i record' proof')
    (hne : record ≠ record') :
    ¬Injective leaf ∨ ¬Injective (uncurry node) := by
  -- Both proofs have length `d` and recompute the same root.
  rcases eq_or_node_collision (h.2.1.trans h'.2.1.symm) (h.2.2.trans h'.2.2.symm) with hleaf | hnode
  · -- Equal leaf digests of different records form a leaf collision.
    exact Or.inl fun hinj => hne (hinj hleaf)
  · exact Or.inr hnode

end T5Bounds
