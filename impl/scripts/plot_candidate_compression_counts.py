# /// script
# requires-python = ">=3.11"
# dependencies = ["matplotlib==3.10.9"]
# ///
"""Plot analytical compression counts for current and proposed leaf hashes.

Run from the repository root:
    python3 impl/scripts/candidate_compression_counts.py
    uv run impl/scripts/plot_candidate_compression_counts.py

These figures are count comparisons, not timings or security certifications.
"""

from __future__ import annotations

import csv
import math
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import FixedLocator, FuncFormatter, NullLocator


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "results" / "candidate-compression-counts.csv"
OUT = ROOT / "results" / "candidate-compression-count-plots"
WIDTHS = tuple(1 << exponent for exponent in range(15))
HASHES = ("sha256", "sha3_256", "blake3")
TITLES = {"sha256": "SHA-256 compression", "sha3_256": "Keccak-f[1600] permutation",
          "blake3": "BLAKE3 compression"}

# (scheme, concise label, color, marker). Solid filled curves are current modes;
# dashed hollow curves are alternatives/candidates, including standardized SHAKE.
SERIES = {
    "sha256": (
        ("standard", "Standard SHA-256", "#273444", "o"),
        ("t253", "Current T253", "#168364", "s"),
        ("t255bits-hybrid", "T255bits + MD tail", "#D87928", "^"),
        ("abr569-hybrid", "ABR569* + MD tail", "#9B4EAB", "D"),
        ("rawmd-fixedwidth", "Fixed-width raw MD", "#286FAC", "v"),
    ),
    "sha3_256": (
        ("standard", "Standard SHA3-256", "#273444", "o"),
        ("shake128", "SHAKE128 / 32-byte output", "#D87928", "^"),
        ("spongedm-c272-prefix17", "SPONGE-DM c = 272", "#168364", "s"),
        ("spongedm-c320-prefix17", "SPONGE-DM c = 320", "#9B4EAB", "D"),
        ("t520-hybrid", "T520* + MD tail", "#286FAC", "v"),
        ("pa199-fixedwidth", "PA199 fixed-width MD", "#C34B62", "P"),
    ),
    "blake3": (
        ("standard", "Standard BLAKE3", "#273444", "o"),
        ("t8", "Current T8", "#168364", "s"),
        ("t8-hybrid", "T8 + MD tail", "#D87928", "^"),
        ("t277-hybrid", "T277 + MD tail", "#286FAC", "v"),
        ("abr625-hybrid", "ABR625* + MD tail", "#9B4EAB", "D"),
    ),
}
GADGETS = {
    ("blake3", "t8-hybrid"): (768, 3, 1792),
    ("blake3", "t277-hybrid"): (824, 3, 1960),
    ("sha256", "abr569-hybrid"): (760, 7, 4296),
    ("blake3", "abr625-hybrid"): (824, 7, 4744),
    ("sha256", "t255bits-hybrid"): (766, 3, 1786),
    ("sha3_256", "t520-hybrid"): (1472, 3, 3904),
}
SPONGES = {"shake128": (168, 0), "spongedm-c272-prefix17": (166, 17),
           "spongedm-c320-prefix17": (160, 17)}


def ceil_div(numerator, denominator):
    return (numerator + denominator - 1) // denominator


def standard_count(hash_name, size):
    if hash_name == "sha256":
        return size // 64 + 1 + (size % 64 >= 56)
    if hash_name == "sha3_256":
        return size // 136 + 1
    return ceil_div(size, 64) + ceil_div(size, 1024) - 1


def expected_count(hash_name, scheme, size):
    """Independently evaluate counts, including all possible gadget counts."""
    if scheme == "standard":
        return standard_count(hash_name, size)
    if scheme == "t253":
        if size < 253:
            return standard_count(hash_name, size)
        full, remainder = divmod(size - 32, 221)
        return 3 * full + ceil_div(remainder, 64)
    if scheme == "t8":
        return (6 if hash_name == "sha256" else 3) * max(1, ceil_div(size - 32, 224))
    if scheme == "rawmd-fixedwidth":
        return ceil_div(size, 64)
    if scheme == "pa199-fixedwidth":
        return ceil_div(size, 167)
    if scheme in SPONGES:
        rate, prefix = SPONGES[scheme]
        return (size + prefix) // rate + 1
    oracle, cost, fresh = GADGETS[hash_name, scheme]
    bits = size * 8
    tail = oracle - 256
    # A direct head is the no-gadget route. All other routes have a first
    # gadget capacity 256 + fresh and can finish with MD calls or padding.
    best = 1 + ceil_div(max(0, bits - oracle), tail)
    for count in range(1, max(1, ceil_div(max(0, bits - 256), fresh)) + 1):
        remaining = max(0, bits - (256 + count * fresh))
        best = min(best, count * cost + ceil_div(remaining, tail))
    return best


def load():
    with SOURCE.open(newline="") as source:
        rows = list(csv.DictReader(source))
    indexed = {}
    for row in rows:
        for field in ("elements_per_leaf", "leaf_bytes", "native_leaf_calls",
                      "standard_leaf_calls", "calls_saved", "gadgets",
                      "md_head_calls", "md_tail_calls", "input_prefix_bytes"):
            row[field] = int(row[field])
        for field in ("zero_padding_bits", "oracle_payload_bits",
                      "fresh_bits_per_gadget", "md_tail_payload_bits"):
            row[field] = int(row[field]) if row[field] else None
        for field in ("relative_calls", "saving_percent"):
            row[field] = float(row[field])
        if row["standard_fallback"] not in ("true", "false"):
            raise ValueError("Invalid standard fallback flag")
        row["standard_fallback"] = row["standard_fallback"] == "true"
        hash_name, scheme, width = row["hash"], row["scheme"], row["elements_per_leaf"]
        key = hash_name, scheme, width
        calls, reference = row["native_leaf_calls"], row["standard_leaf_calls"]
        if key in indexed or calls <= 0 or reference <= 0:
            raise ValueError(f"Duplicate key or nonpositive count: {key}")
        if row["leaf_bytes"] != width * 4:
            raise ValueError(f"Incorrect byte width: {key}")
        if reference != standard_count(hash_name, width * 4):
            raise ValueError(f"Incorrect standard formula: {key}")
        if calls != expected_count(hash_name, scheme, width * 4):
            raise ValueError(f"Incorrect candidate formula: {key}")
        if row["calls_saved"] != reference - calls:
            raise ValueError(f"Incorrect difference: {key}")
        if not math.isclose(row["relative_calls"], calls / reference, abs_tol=1e-11):
            raise ValueError(f"Incorrect ratio: {key}")
        if not math.isclose(row["saving_percent"], 100 * (1 - calls / reference),
                            abs_tol=1e-10):
            raise ValueError(f"Incorrect percentage: {key}")
        expected_status = ("existing" if scheme in ("standard", "t8", "t253") else
                           "specified-alternative" if scheme == "shake128" else
                           "theoretical-candidate")
        if row["status"] != expected_status:
            raise ValueError(f"Incorrect status: {key}")
        expected_fallback = scheme == "t253" and width * 4 < 253
        if row["standard_fallback"] != expected_fallback:
            raise ValueError(f"Incorrect fallback flag: {key}")
        indexed[key] = row

    series = {(hash_name, entry[0]) for hash_name in HASHES for entry in SERIES[hash_name]}
    # The CSV also retains existing T8 for SHA-256 and SHA3, although the new
    # candidate figures focus on their better current/standard references.
    series |= {("sha256", "t8"), ("sha3_256", "t8")}
    expected = {(hash_name, scheme, width)
                for hash_name, scheme in series for width in WIDTHS}
    if set(indexed) != expected:
        raise ValueError(f"Incomplete/unexpected data grid; missing {expected - set(indexed)}, "
                         f"extra {set(indexed) - expected}")
    return indexed


def format_axes(ax):
    ax.set_xscale("log", base=2)
    ax.set_xlim(.78, 21_000)
    ax.set_xticks(WIDTHS, [f"{width:,}" for width in WIDTHS], rotation=55, ha="right")
    ax.xaxis.set_minor_locator(NullLocator())
    ax.yaxis.set_minor_locator(NullLocator())
    ax.tick_params(axis="x", labelsize=9)
    ax.tick_params(axis="y", labelsize=10)
    ax.grid(axis="y", color="#DDE2E8", linewidth=.7)
    ax.set_axisbelow(True)


def draw_series(ax, indexed, hash_name, relative, widths=WIDTHS, small=False):
    for scheme, label, color, marker in SERIES[hash_name]:
        rows = [indexed[hash_name, scheme, width] for width in widths]
        values = [row["native_leaf_calls"] / row["standard_leaf_calls"]
                  if relative else row["native_leaf_calls"] for row in rows]
        existing = rows[0]["status"] == "existing"
        ax.plot(widths, values, color=color, marker=marker,
                lw=1.3 if small else 2, ms=3 if small else 5.4,
                ls="-" if existing else "--", label=label,
                markerfacecolor=color if existing else "white",
                markeredgewidth=.8 if existing else 1.2, zorder=3,
                alpha=.93)


def plot(indexed, relative):
    plt.rcParams.update({
        "font.family": "DejaVu Sans", "font.size": 11,
        "axes.titleweight": "bold", "axes.titlesize": 16,
        "axes.spines.top": False, "axes.spines.right": False,
        "axes.edgecolor": "#A1A9B1", "xtick.color": "#374151",
        "ytick.color": "#374151", "text.color": "#17212B",
        "axes.labelcolor": "#17212B", "svg.fonttype": "none",
        "savefig.facecolor": "white",
    })
    fig, axes = plt.subplots(1, 3, figsize=(18.4, 9.2), sharex=True,
                             sharey=not relative)
    fig.subplots_adjust(left=.065, right=.983, top=.80, bottom=.35, wspace=.21)
    title = ("Proposed leaf hashes: calls relative to the optimized standard baseline"
             if relative else "Native calls per leaf: current modes and proposed candidates")
    fig.suptitle(title, y=.97, fontsize=22, fontweight="bold")
    fig.text(.5, .915, "Analytical counts · all 15 power-of-two leaf widths · 32-bit elements · 32-byte digests",
             ha="center", fontsize=12, color="#475569")
    fig.text(.5, .879, "Solid + filled: current implementation     Dashed + hollow: alternative or proposed mode",
             ha="center", fontsize=11, color="#475569")

    for column, hash_name in enumerate(HASHES):
        ax = axes[column]
        ax.set_title(TITLES[hash_name], pad=13)
        format_axes(ax)
        if relative:
            bounds = {"sha256": (.43, 1.10), "sha3_256": (.63, 1.09),
                      "blake3": (.43, 3.16)}[hash_name]
            ax.set_ylim(*bounds)
            ax.yaxis.set_major_formatter(FuncFormatter(lambda value, _: f"{value:g}×"))
            ax.axhspan(bounds[0], 1, color="#E7F5ED", zorder=0)
            ax.axhspan(1, bounds[1], color="#FCF4F2", zorder=0)
            ax.axhline(1, color="#667085", lw=1, zorder=2)
        else:
            ax.set_yscale("log", base=2)
            ax.set_ylim(.78, 1450)
            ax.yaxis.set_major_locator(FixedLocator([1, 2, 4, 8, 16, 32, 64, 128,
                                                    256, 512, 1024]))
            ax.yaxis.set_major_formatter(FuncFormatter(lambda value, _: f"{int(value):,}"))
        draw_series(ax, indexed, hash_name, relative)
        ax.legend(loc="upper center", bbox_to_anchor=(.5, -.28), ncol=2,
                  frameon=False, fontsize=9.6, columnspacing=1.2,
                  handlelength=2.2, labelspacing=.7)
        if column == 0:
            ax.set_ylabel("Candidate calls / standard calls (linear scale)" if relative
                          else "Native calls per leaf (log₂ scale)", labelpad=12)

        # Current BLAKE3 T8 requires three calls even for a tiny leaf. Preserve
        # those points on the main linear axis and magnify the wide-leaf region.
        if relative and hash_name == "blake3":
            inset = ax.inset_axes([.46, .47, .50, .42])
            inset.set_xscale("log", base=2)
            inset.set_xlim(220, 19_000)
            inset.set_ylim(.69, 1.035)
            inset.axhspan(.69, 1, color="#E7F5ED", zorder=0)
            inset.axhline(1, color="#667085", lw=.7)
            inset.grid(axis="y", color="#DDE2E8", lw=.6)
            inset.set_xticks([256, 1024, 4096, 16384], ["256", "1K", "4K", "16K"])
            inset.set_yticks([.7, .8, .9, 1], ["0.7×", "0.8×", "0.9×", "1×"])
            inset.xaxis.set_minor_locator(NullLocator())
            inset.tick_params(labelsize=8, length=2)
            inset.set_title("Wide-leaf detail", fontsize=10, pad=6)
            draw_series(inset, indexed, hash_name, True, WIDTHS[8:], small=True)

    fig.supxlabel("u32 elements per leaf (log₂ spacing; bytes = 4 × width)", y=.259, fontsize=12)
    first_note = (
        "Below 1× = fewer native calls. Panel y-ranges differ; BLAKE3 inset magnifies wide leaves. These are not measured speedups."
        if relative else
        "Leaf hashing only; the common binary upper tree is excluded. Compression counts and permutation counts are different units."
    )
    fig.text(.065, .106, first_note, fontsize=10.2)
    fig.text(.065, .077,
             "* Widened ABR3 and T520 have unfinished security arguments for these modes. All candidate assumptions are in NEXT_CONSTRUCTIONS.md.",
             fontsize=9.6, color="#596574")
    fig.text(.065, .048,
             "Hybrid candidates may use MD-only plans at small widths; only current T253 has a standard-hash fallback. SPONGE-DM includes a 17-byte prefix.",
             fontsize=9.6, color="#596574")
    fig.text(.065, .019,
             "Fixed-width raw MD excludes amortized public-IV setup. Arithmetic counts do not establish security; SHAKE128 has 128-bit preimage security.",
             fontsize=9.6, color="#596574")
    stem = "relative-calls" if relative else "native-calls"
    for extension in ("png", "svg"):
        output = OUT / f"{stem}.{extension}"
        fig.savefig(output, dpi=180)
        print(output)
    plt.close(fig)


def write_readme(indexed):
    lines = [
        "# Native calls for proposed leaf-hash candidates", "",
        "Exact analytical counts at all 15 power-of-two widths from 1 to 16,384",
        "u32 elements (4 bytes to 64 KiB per leaf), with 32-byte digests.",
        "These are not timings, implemented new modes, or security certifications.", "",
        "![Native calls per leaf](native-calls.png)", "",
        "![Calls relative to standard hashing](relative-calls.png)", "",
        "Solid lines and filled markers are current modes. Dashed lines and hollow",
        "markers are alternatives or proposals; SHAKE128 is standardized, while",
        "the other candidate parameterizations are research modes. In particular,",
        "widened ABR3 and T520, marked `*`, have unfinished security arguments",
        "for the proposed modes; widened ABR3 has a provisional new reduction.", "",
        "The ratio is candidate calls / standard calls. Below 1 means fewer calls.",
        "The relative plot uses linear y axes with different panel ranges; its",
        "BLAKE3 inset magnifies large widths while preserving the three-call",
        "small-leaf cost of current T8 on the main axis. Cross-backend count ratios",
        "do not compare execution time. SIMD and parallelism do not change counts.", "",
        "## Scope and counting conventions", "",
        "- SHA-256 and BLAKE3 count native compression invocations; Keccak counts",
        "  full Keccak-f[1600] permutations, including the sponge padding block.",
        "- T/ABR hybrids minimize calls among a direct MD head followed by MD",
        "  tails, full gadgets followed by MD tails, and a padded final gadget.",
        "  The public leaf width chooses the plan. Small widths may use an MD-only",
        "  plan; no candidate silently falls back to standard hashing.",
        "- Current SHA-256 T253 does retain its existing standard fallback below",
        "  253 bytes. Current BLAKE3 T8 always uses full, possibly padded gadgets.",
        "- SPONGE-DM includes a 17-byte prefix. SHAKE128 uses its standard suffix",
        "  and no message prefix; all outputs are 32 bytes.",
        "- Fixed-width raw SHA-256 MD counts online message-block calls and",
        "  excludes the amortized precomputation of a public IV for the trusted",
        "  domain and width. PA199 uses a fixed initial state and 167 fresh bytes",
        "  per call, with one input byte reserved for domain separation.",
        "- All proposals require fixed trusted geometry and a complete domain",
        "  specification. Their security assumptions differ: see the research note.",
        "- Zero-call injective short-leaf encodings and higher-arity parent trees",
        "  are excluded because they change the interface or upper-tree structure.", "",
        "For L leaves and an unchanged one-call binary parent, total commitment",
        "calls are `L * leaf_calls + L - 1`; one whole-leaf verification uses",
        "`leaf_calls + log2(L)`. Only leaf calls are plotted.", "",
        "- [Complete source CSV](../candidate-compression-counts.csv)",
        "- [Research note and security assumptions](../../NEXT_CONSTRUCTIONS.md)",
        "- [Absolute counts, SVG](native-calls.svg)",
        "- [Relative counts, SVG](relative-calls.svg)", "",
        "## Exact counts at every plotted width", "",
    ]
    for hash_name in HASHES:
        series = SERIES[hash_name]
        lines += [f"### {TITLES[hash_name]}", "",
                  "| u32 / leaf | Bytes / leaf | " + " | ".join(s[1] for s in series) + " |",
                  "| ---: | ---: | " + " | ".join("---:" for _ in series) + " |"]
        for width in WIDTHS:
            values = [indexed[hash_name, entry[0], width]["native_leaf_calls"] for entry in series]
            lines.append(f"| {width:,} | {4 * width:,} | " +
                         " | ".join(f"{value:,}" for value in values) + " |")
        lines.append("")
    lines += ["## Reproduction", "", "From the repository root:", "",
              "    python3 impl/scripts/candidate_compression_counts.py",
              "    uv run impl/scripts/plot_candidate_compression_counts.py", "",
              "The plot script checks the complete series/width grid, all count",
              "formulas independently, standard references, differences, ratios,",
              "statuses and fallback flags before rendering. It retains the extra",
              "current SHA-256/SHA3 T8 rows in the CSV but omits them from these",
              "candidate-focused figures. Matplotlib 3.10.9 is the only dependency.", ""]
    (OUT / "README.md").write_text("\n".join(lines))


def main():
    indexed = load()
    OUT.mkdir(parents=True, exist_ok=True)
    plot(indexed, relative=False)
    plot(indexed, relative=True)
    write_readme(indexed)
    print(f"Validated {len(indexed)} rows and all formulas; matplotlib {matplotlib.__version__}")


if __name__ == "__main__":
    main()
