# /// script
# requires-python = ">=3.11"
# dependencies = ["matplotlib==3.10.9"]
# ///
"""Plot analytical native calls from the Rust compression_counts example.

Run from the repository root: uv run impl/scripts/plot_compression_counts.py
This reads saved counts; it does not run a timing benchmark.
"""

import csv
import math
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.ticker import FixedLocator, FuncFormatter, NullLocator


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "results" / "compression-counts.csv"
OUT = ROOT / "results" / "compression-count-plots"
HASHES = ("sha256", "sha3_256", "blake3")
TITLES = {"sha256": "SHA-256", "sha3_256": "SHA3-256", "blake3": "BLAKE3"}
STYLES = {
    "standard": ("#364152", "o", "Standard"),
    "t5": ("#D87928", "o", "T5"),
    "t8": ("#286FAC", "^", "T8"),
    "abr3": ("#9B4EAB", "D", "ABR3"),
    "t253": ("#168364", "s", "T253 · SHA-256 only"),
}
WIDTHS = [1 << k for k in range(15)]


def load():
    with SOURCE.open(newline="") as source:
        rows = list(csv.DictReader(source))
    indexed = {}
    for row in rows:
        for field in ("elements_per_leaf", "leaf_bytes", "native_leaf_calls",
                      "standard_leaf_calls", "calls_saved"):
            row[field] = int(row[field])
        for field in ("relative_calls", "saving_percent"):
            row[field] = float(row[field])
        if row["standard_fallback"] not in ("true", "false"):
            raise ValueError("Invalid fallback marker")
        row["standard_fallback"] = row["standard_fallback"] == "true"
        width = row["elements_per_leaf"]
        calls = row["native_leaf_calls"]
        standard = row["standard_leaf_calls"]
        key = (row["hash"], width, row["scheme"])
        if key in indexed or calls <= 0 or standard <= 0:
            raise ValueError(f"Duplicate key or invalid count: {key}")
        if row["leaf_bytes"] != width * 4:
            raise ValueError(f"Incorrect byte width: {key}")
        if row["calls_saved"] != standard - calls:
            raise ValueError(f"Incorrect difference: {key}")
        if not math.isclose(row["relative_calls"], calls / standard, abs_tol=1e-11):
            raise ValueError(f"Incorrect ratio: {key}")
        if not math.isclose(row["saving_percent"], 100 * (1 - calls / standard),
                            abs_tol=1e-10):
            raise ValueError(f"Incorrect percentage: {key}")
        indexed[key] = row
    expected = {
        (hash_name, width, scheme)
        for hash_name in HASHES
        for width in WIDTHS
        for scheme in STYLES
        if scheme != "t253" or hash_name == "sha256"
    }
    if set(indexed) != expected or len(rows) != 195:
        raise ValueError("Expected all 195 supported hash/width/mode combinations")
    for row in rows:
        reference = indexed[(row["hash"], row["elements_per_leaf"], "standard")]
        if row["standard_leaf_calls"] != reference["native_leaf_calls"]:
            raise ValueError("Mismatched standard reference")
    return indexed


def plot(indexed, relative):
    plt.rcParams.update({
        "font.family": "DejaVu Sans",
        "font.size": 11,
        "axes.titleweight": "bold",
        "axes.titlesize": 16,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "axes.edgecolor": "#A1A9B1",
        "xtick.color": "#374151",
        "ytick.color": "#374151",
        "text.color": "#17212B",
        "axes.labelcolor": "#17212B",
        "svg.fonttype": "none",
        "savefig.facecolor": "white",
    })
    fig, axes = plt.subplots(1, 3, figsize=(16.2, 7.1), sharex=True, sharey=True)
    fig.subplots_adjust(left=.077, right=.979, top=.740, bottom=.250, wspace=.13)
    title = ("Native calls relative to standard hashing" if relative
             else "Native compression / permutation calls per leaf")
    fig.suptitle(title, y=.969, fontsize=23, fontweight="bold")
    fig.text(.5, .899,
             "Exact analytical counts · all 15 power-of-two widths · 32-bit elements · 32-byte digests",
             ha="center", fontsize=12, color="#475569")
    handles = [
        Line2D([], [], color=color, marker=marker, lw=2.2, ms=6, label=label)
        for scheme, (color, marker, label) in STYLES.items()
        if not relative or scheme != "standard"
    ]
    fig.legend(handles=handles, loc="upper center", bbox_to_anchor=(.5, .882),
               ncol=len(handles), frameon=False, fontsize=11, columnspacing=1.9)

    for column, hash_name in enumerate(HASHES):
        ax = axes[column]
        ax.set_title(TITLES[hash_name], pad=13)
        ax.set_xscale("log", base=2)
        ax.set_yscale("log", base=2)
        ax.set_xlim(.78, 21_000)
        ax.set_xticks(WIDTHS, [f"{width:,}" for width in WIDTHS],
                      rotation=55, ha="right")
        ax.xaxis.set_minor_locator(NullLocator())
        ax.yaxis.set_minor_locator(NullLocator())
        ax.tick_params(axis="x", labelsize=9)
        ax.tick_params(axis="y", labelsize=10)
        ax.grid(axis="y", color="#DDE2E8", linewidth=.7)
        ax.set_axisbelow(True)
        if relative:
            ax.set_ylim(.70, 8.2)
            ax.yaxis.set_major_locator(FixedLocator([.75, 1, 1.5, 2, 3, 4, 6, 8]))
            ax.yaxis.set_major_formatter(FuncFormatter(lambda value, _: f"{value:g}×"))
            ax.axhspan(.70, 1, color="#E7F5ED", zorder=0)
            ax.axhspan(1, 8.2, color="#FCF4F2", zorder=0)
            ax.axhline(1, color="#4B5563", lw=1.5, ls="--", zorder=2)
        else:
            ax.set_ylim(.78, 2300)
            ax.yaxis.set_major_locator(FixedLocator([1, 2, 4, 8, 16, 32, 64,
                                                    128, 256, 512, 1024, 2048]))
            ax.yaxis.set_major_formatter(FuncFormatter(lambda value, _: f"{int(value):,}"))
        for scheme, (color, marker, _) in STYLES.items():
            if relative and scheme == "standard":
                continue
            if scheme == "t253" and hash_name != "sha256":
                continue
            rows = [indexed[(hash_name, width, scheme)] for width in WIDTHS]
            values = [
                row["native_leaf_calls"] / row["standard_leaf_calls"]
                if relative else row["native_leaf_calls"]
                for row in rows
            ]
            ax.plot(WIDTHS, values, color=color, lw=2.1,
                    alpha=.85 if scheme == "standard" else 1, zorder=3)
            for fallback in (False, True):
                points = [(width, value) for width, value, row in zip(WIDTHS, values, rows)
                          if row["standard_fallback"] == fallback]
                if points:
                    ax.scatter(*zip(*points), marker=marker, s=31,
                               facecolors="white" if fallback else color,
                               edgecolors=color if fallback else "white",
                               linewidths=1.25 if fallback else .55, zorder=4)
        if column == 0:
            ax.set_ylabel("Variant calls / standard calls (log scale)" if relative
                          else "Native calls per leaf (log₂ scale)", labelpad=13)

    fig.supxlabel("u32 elements per leaf (log₂ spacing; leaf bytes = 4 × width)",
                  y=.117, fontsize=12)
    explanation = (
        "Below 1× = fewer calls; above 1× = more calls.  Example: 0.8× means 20% fewer calls, not a measured speedup."
        if relative else
        "SHA-256 and BLAKE3: compression calls.  SHA3-256: Keccak-f[1600] permutations.  Units are specific to each backend."
    )
    fig.text(.077, .072, explanation, fontsize=10.5)
    fig.text(.077, .044,
             "Leaf hashing only; upper-tree calls are common to all modes.  Hollow green squares: T253 uses standard SHA-256.",
             fontsize=9.5, color="#596574")
    fig.text(.077, .018,
             "Counts include each implementation’s padding and domain separation.  SIMD does not change counts.  Lines connect sampled widths.",
             fontsize=9.5, color="#596574")
    stem = "relative-calls" if relative else "native-calls"
    for extension in ("png", "svg"):
        path = OUT / f"{stem}.{extension}"
        fig.savefig(path, dpi=180)
        print(path)
    plt.close(fig)


def write_readme(indexed):
    lines = [
        "# Exact native compression counts",
        "",
        "These are deterministic analytical counts from the Rust LeafPlan API,",
        "not elapsed timings. All 15 power-of-two leaf widths from 1 to 16,384",
        "u32 elements are included; one element occupies four bytes.",
        "",
        "![Native calls per leaf](native-calls.png)",
        "",
        "![Calls relative to standard hashing](relative-calls.png)",
        "",
        "The ratio is variant calls / standard calls: below 1 means fewer calls.",
        "SHA-256 and BLAKE3 count native compressions; SHA3-256 counts Keccak-f[1600]",
        "permutations. Comparing these units across different hash functions does",
        "not compare execution time. SIMD and parallel scheduling do not change",
        "the counts. Padding and the current domain-separated adapters are included.",
        "",
        "T253 exists only for SHA-256. Hollow green markers denote its standard",
        "SHA-256 fallback below 253 bytes. ABR3 is the implemented height-three",
        "gadget, chained inside whole-record leaves.",
        "",
        "For L leaves, total commitment calls are L × leaf_calls + L − 1.",
        "Verification of one complete leaf uses leaf_calls + log₂(L).",
        "The upper binary tree is identical in all modes and is excluded from",
        "the plotted per-leaf counts.",
        "",
        "- [Full 195-row data, including differences and percentages](../compression-counts.csv)",
        "- [Native counts, SVG](native-calls.svg)",
        "- [Relative counts, SVG](relative-calls.svg)",
        "- [Construction and adapter definitions](../../EXPERIMENTS.md)",
        "",
        "## Exact counts at every plotted width",
        "",
    ]
    for hash_name in HASHES:
        modes = [mode for mode in STYLES if mode != "t253" or hash_name == "sha256"]
        lines += [
            f"### {TITLES[hash_name]}",
            "",
            "| u32 / leaf | Bytes / leaf | " +
            " | ".join("Standard" if mode == "standard" else mode.upper() for mode in modes) + " |",
            "| ---: | ---: | " + " | ".join("---:" for _ in modes) + " |",
        ]
        for width in WIDTHS:
            counts = [indexed[(hash_name, width, mode)]["native_leaf_calls"] for mode in modes]
            lines.append(f"| {width:,} | {width * 4:,} | " +
                         " | ".join(f"{value:,}" for value in counts) + " |")
        lines.append("")
    lines += [
        "## Reproduction",
        "",
        "From the repository root:",
        "",
        "    cargo run --locked --offline --manifest-path impl/Cargo.toml --example compression_counts > impl/results/compression-counts.csv",
        "    uv run impl/scripts/plot_compression_counts.py",
        "",
        "The plot script validates the complete hash/width/mode grid, standard",
        "references, differences and ratios before rendering. It requires",
        "Matplotlib 3.10.9. No timing benchmark is run.",
        "",
    ]
    (OUT / "README.md").write_text("\n".join(lines))


def main():
    indexed = load()
    OUT.mkdir(parents=True, exist_ok=True)
    plot(indexed, relative=False)
    plot(indexed, relative=True)
    write_readme(indexed)
    print(f"Validated {len(indexed)} rows; matplotlib {matplotlib.__version__}")


if __name__ == "__main__":
    main()
