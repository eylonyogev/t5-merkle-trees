#!/usr/bin/env python3
"""Reproduce theoretical native-call counts for proposed leaf hash modes.

Run from any directory with Python 3.10 or later (standard library only):
    python3 impl/scripts/candidate_compression_counts.py

The default output is impl/results/candidate-compression-counts.csv. These are
arithmetic call minima under the schedules below, NOT timing measurements,
implemented cryptographic modes, or security certifications. The 32-byte output
and public, trusted leaf width are fixed. Common binary upper-tree calls are
excluded. A candidate never silently falls back to standard hashing; only the
existing SHA-256 T253 mode has its documented short-input standard fallback.

For a candidate with an m-bit oracle input and a 256-bit output, an MD-only plan
uses one direct m-bit message head, followed by calls absorbing the previous
256-bit output plus at most m-256 fresh bits. Head and tail share one public MD
role, separated from gadget roles; their positions are determined by fixed width.
For a gadget plan, k gadgets can hold 256+k*D message bits: the first has capacity
256+D, and later gadgets replace one 256-bit message word by the previous output.
We enumerate full gadgets followed by MD tails and gadgets with a zero-padded
final gadget. All partial heads/tails/gadgets use right zero padding. Fixed
trusted width makes that encoding unambiguous; variable-width use requires an
additional specified encoding. The plan is determined solely by public width.
Tie breaking is minimum calls, then minimum zero padding, then more gadgets.

Three-call T gadgets have D=3*m-512. Seven-call widened ABR3 gadgets have
D=7*m-1024. The MD role and distinct gadget roles need specified disjoint
domains in any realization. No role bytes/bits may be added beyond the capacities
already budgeted here. The SHA-256 2-bit-role row is an especially tight bit-level
capacity model: namespace/domain allocation still needs a full specification.

Candidate inputs budget the following payload after role/domain reservations:
  BLAKE3 T277/ABR625: 103 bytes (CV32 + block64 + counter payload7; role byte1).
  SHA-256 ABR569: 95 bytes (native CV32 + block64 minus one role byte).
  SHA-256 T255bits: 766 bits (native 768-bit input minus two role bits).
  Keccak T520: 184 bytes, as a proposed one-permutation compression adapter;
    its security is not implied by the T-gadget arithmetic.

SHAKE128 uses its standard 168-byte rate, no message prefix, 32-byte output, and
SHAKE domain suffix/padding. The two SPONGEDM capacity candidates use rates 166
and 160 bytes, respectively, a fixed 17-byte domain prefix, and sponge padding.
For these three rows there is no extra squeezing permutation for 32-byte output.
The SPONGEDM names describe capacity candidates, not implemented NIST SHA3 modes.

Two fixed-width MD comparisons use a fixed initial state, without a free direct
head: rawmd-fixedwidth absorbs 64 bytes per SHA-256 compression; pa199-fixedwidth
absorbs 167 bytes per Keccak permutation (32-byte state plus 167 fresh bytes,
with one of the 200 input bytes reserved for a role). These rows count online
leaf work only; any domain/width IV precomputation is a separate setup cost.

Every standard/current row is checked against results/compression-counts.csv.
Primitive specifications and research context:
  https://eprint.iacr.org/2021/373.pdf (T widening, Section 6)
  https://cs.nyu.edu/~dodis/ps/ABR.pdf (ordinary ABR3; not a widening theorem)
  https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.tex
  https://doi.org/10.6028/NIST.FIPS.202 (SHA3/SHAKE rates and padding)
"""

from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass
from pathlib import Path


IMPL = Path(__file__).resolve().parents[1]
DIGEST_BITS = 256
WIDTHS = tuple(1 << k for k in range(15))
PRIMITIVES = {
    "sha256": "SHA-256 compression",
    "sha3_256": "Keccak-f[1600] permutation",
    "blake3": "BLAKE3 compression",
}


def ceil_div(numerator: int, denominator: int) -> int:
    assert numerator >= 0 and denominator > 0
    return (numerator + denominator - 1) // denominator


def standard_calls(hash_name: str, byte_count: int) -> int:
    assert byte_count > 0
    if hash_name == "sha256":
        return byte_count // 64 + 1 + int(byte_count % 64 >= 56)
    if hash_name == "sha3_256":
        return byte_count // 136 + 1
    if hash_name == "blake3":
        return ceil_div(byte_count, 64) + ceil_div(byte_count, 1024) - 1
    raise ValueError(hash_name)


@dataclass(frozen=True)
class Plan:
    calls: int
    kind: str
    gadgets: int = 0
    md_head_calls: int = 0
    md_tail_calls: int = 0
    zero_padding_bits: int | None = None


def hybrid_plan(message_bits: int, oracle_bits: int, gadget_calls: int,
                fresh_bits: int) -> Plan:
    """Find the minimum among explicitly enumerated gadget/MD schedules."""
    assert message_bits > 0 and oracle_bits > DIGEST_BITS
    assert fresh_bits > 0 and gadget_calls > 0
    tail_bits = oracle_bits - DIGEST_BITS
    md_tails = ceil_div(max(0, message_bits - oracle_bits), tail_bits)
    plans = [Plan(1 + md_tails, "md-only", md_head_calls=1,
                  md_tail_calls=md_tails,
                  zero_padding_bits=oracle_bits + md_tails * tail_bits
                  - message_bits)]

    # One or more gadgets, with the last gadget possibly zero padded.
    padded_gadgets = max(1, ceil_div(max(0, message_bits - DIGEST_BITS),
                                   fresh_bits))
    plans.append(Plan(gadget_calls * padded_gadgets, "gadgets-padded",
                      gadgets=padded_gadgets,
                      zero_padding_bits=DIGEST_BITS
                      + padded_gadgets * fresh_bits - message_bits))

    # Every feasible count of complete gadgets followed by a short MD tail.
    max_full_gadgets = max(0, (message_bits - DIGEST_BITS) // fresh_bits)
    for count in range(1, max_full_gadgets + 1):
        remaining = message_bits - DIGEST_BITS - count * fresh_bits
        tails = ceil_div(remaining, tail_bits)
        plans.append(Plan(gadget_calls * count + tails, "gadgets-md-tail",
                          gadgets=count, md_tail_calls=tails,
                          zero_padding_bits=tails * tail_bits - remaining))

    result = min(plans, key=lambda p: (p.calls, p.zero_padding_bits,
                                      -p.gadgets, p.kind))
    assert result.calls > 0 and result.zero_padding_bits >= 0
    if result.kind == "md-only":
        capacity = oracle_bits + result.md_tail_calls * tail_bits
    else:
        capacity = (DIGEST_BITS + result.gadgets * fresh_bits
                    + result.md_tail_calls * tail_bits)
    assert capacity == message_bits + result.zero_padding_bits
    assert result.calls == (result.md_head_calls + result.md_tail_calls
                            + gadget_calls * result.gadgets)
    return result


def current_t253(byte_count: int) -> tuple[Plan, bool]:
    if byte_count < 253:
        return Plan(standard_calls("sha256", byte_count), "standard-fallback"), True
    gadgets, remaining = divmod(byte_count - 32, 221)
    tails = ceil_div(remaining, 64)
    return Plan(3 * gadgets + tails, "current-t253", gadgets=gadgets,
                md_tail_calls=tails,
                zero_padding_bits=(64 * tails - remaining) * 8), False


def current_t8(hash_name: str, byte_count: int) -> Plan:
    gadgets = max(1, ceil_div(max(0, byte_count - 32), 224))
    native_per_gadget = 6 if hash_name == "sha256" else 3
    return Plan(native_per_gadget * gadgets, "current-t8", gadgets=gadgets,
                zero_padding_bits=(32 + 224 * gadgets - byte_count) * 8)


# hash family is also the native standard denominator. All outputs are 32 bytes.
# The names encode first-gadget capacities, except T255bits (2042 input bits).
CANDIDATES = (
    ("blake3", "t8-hybrid", 96 * 8, 3, 224 * 8),
    ("blake3", "t277-hybrid", 103 * 8, 3, 245 * 8),
    ("sha256", "abr569-hybrid", 95 * 8, 7, 537 * 8),
    ("blake3", "abr625-hybrid", 103 * 8, 7, 593 * 8),
    ("sha256", "t255bits-hybrid", 766, 3, 1786),
    ("sha3_256", "t520-hybrid", 184 * 8, 3, 488 * 8),
)
SPONGES = (
    ("shake128", 168, 0),
    ("spongedm-c272-prefix17", 166, 17),
    ("spongedm-c320-prefix17", 160, 17),
)


def row(hash_name: str, scheme: str, status: str, width: int, plan: Plan,
        fallback: bool = False, oracle_bits: int | None = None,
        fresh_bits: int | None = None, prefix_bytes: int = 0) -> dict:
    byte_count = width * 4
    baseline = standard_calls(hash_name, byte_count)
    return {
        "hash": hash_name,
        "primitive": PRIMITIVES[hash_name],
        "scheme": scheme,
        "status": status,
        "elements_per_leaf": width,
        "leaf_bytes": byte_count,
        "native_leaf_calls": plan.calls,
        "standard_leaf_calls": baseline,
        "relative_calls": f"{plan.calls / baseline:.12f}",
        "calls_saved": baseline - plan.calls,
        "saving_percent": f"{100 * (baseline - plan.calls) / baseline:.12f}",
        "standard_fallback": str(fallback).lower(),
        "plan_kind": plan.kind,
        "gadgets": plan.gadgets,
        "md_head_calls": plan.md_head_calls,
        "md_tail_calls": plan.md_tail_calls,
        "zero_padding_bits": plan.zero_padding_bits,
        "oracle_payload_bits": oracle_bits,
        "fresh_bits_per_gadget": fresh_bits,
        "md_tail_payload_bits": (None if oracle_bits is None
                                 else oracle_bits - DIGEST_BITS),
        "input_prefix_bytes": prefix_bytes,
    }


def generate() -> list[dict]:
    rows = []
    for width in WIDTHS:
        byte_count = width * 4
        for hash_name in PRIMITIVES:
            rows.append(row(hash_name, "standard", "existing", width,
                            Plan(standard_calls(hash_name, byte_count), "standard")))
            rows.append(row(hash_name, "t8", "existing", width,
                            current_t8(hash_name, byte_count)))
        plan, fallback = current_t253(byte_count)
        rows.append(row("sha256", "t253", "existing", width, plan, fallback))
        for hash_name, scheme, oracle_bits, cost, fresh_bits in CANDIDATES:
            plan = hybrid_plan(byte_count * 8, oracle_bits, cost, fresh_bits)
            rows.append(row(hash_name, scheme, "theoretical-candidate", width,
                            plan, oracle_bits=oracle_bits, fresh_bits=fresh_bits))
        for scheme, rate, prefix in SPONGES:
            # Domain suffix and pad10*1 require a new rate block at exact multiples.
            calls = (byte_count + prefix) // rate + 1
            status = "specified-alternative" if scheme == "shake128" else "theoretical-candidate"
            rows.append(row("sha3_256", scheme, status, width,
                            Plan(calls, "sponge"), prefix_bytes=prefix))
        for hash_name, scheme, fresh_bytes in (
            ("sha256", "rawmd-fixedwidth", 64),
            ("sha3_256", "pa199-fixedwidth", 167),
        ):
            calls = ceil_div(byte_count, fresh_bytes)
            rows.append(row(hash_name, scheme, "theoretical-candidate", width,
                            Plan(calls, "fixed-width-md", md_tail_calls=calls,
                                 zero_padding_bits=(calls * fresh_bytes
                                                    - byte_count) * 8),
                            oracle_bits=(fresh_bytes + 32) * 8))
    return rows


def verify(rows: list[dict], existing_path: Path) -> int:
    assert standard_calls("sha256", 55) == 1
    assert standard_calls("sha256", 56) == 2
    assert standard_calls("sha256", 64) == 2
    assert standard_calls("sha3_256", 135) == 1
    assert standard_calls("sha3_256", 136) == 2
    assert standard_calls("blake3", 1024) == 16
    assert standard_calls("blake3", 1025) == 18
    assert current_t253(252)[1] and not current_t253(253)[1]
    assert current_t253(253)[0].calls == 3
    assert current_t8("blake3", 256).calls == 3
    assert current_t8("blake3", 257).calls == 6
    for _, _, oracle_bits, cost, fresh_bits in CANDIDATES:
        assert fresh_bits == (3 * oracle_bits - 512 if cost == 3
                              else 7 * oracle_bits - 1024)
        first = DIGEST_BITS + fresh_bits
        assert hybrid_plan(first, oracle_bits, cost, fresh_bits).calls <= cost
        # Check capacity accounting around all relevant head/gadget boundaries.
        for size in (1, oracle_bits - 1, oracle_bits, oracle_bits + 1,
                     first - 1, first, first + 1,
                     first + fresh_bits - 1, first + fresh_bits,
                     first + fresh_bits + 1):
            hybrid_plan(size, oracle_bits, cost, fresh_bits)

    indexed = {(r["hash"], r["scheme"], r["elements_per_leaf"]): r for r in rows}
    assert len(indexed) == len(rows) == 270
    for hash_name, scheme, expected in (
        ("blake3", "t277-hybrid", 803),
        ("sha256", "abr569-hybrid", 854),
        ("blake3", "abr625-hybrid", 774),
        ("sha3_256", "t520-hybrid", 403),
        ("sha256", "t255bits-hybrid", 881),
        ("sha256", "rawmd-fixedwidth", 1024),
        ("sha3_256", "pa199-fixedwidth", 393),
    ):
        assert indexed[hash_name, scheme, 16384]["native_leaf_calls"] == expected

    checked = 0
    with existing_path.open(newline="") as source:
        for existing in csv.DictReader(source):
            if existing["scheme"] not in ("standard", "t8", "t253"):
                continue
            key = (existing["hash"], existing["scheme"],
                   int(existing["elements_per_leaf"]))
            candidate = indexed[key]
            for field in ("leaf_bytes", "native_leaf_calls", "standard_leaf_calls",
                          "calls_saved"):
                assert candidate[field] == int(existing[field]), (key, field)
            assert candidate["standard_fallback"] == existing["standard_fallback"], key
            checked += 1
    assert checked == 105
    return checked


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--output", type=Path,
                        default=IMPL / "results" / "candidate-compression-counts.csv")
    parser.add_argument("--existing-counts", type=Path,
                        default=IMPL / "results" / "compression-counts.csv")
    args = parser.parse_args()
    rows = generate()
    checked = verify(rows, args.existing_counts)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    print(f"Wrote {len(rows)} theoretical count rows to {args.output}")
    print(f"Cross-checked {checked} existing rows; boundary and 64 KiB assertions passed.")


if __name__ == "__main__":
    main()
