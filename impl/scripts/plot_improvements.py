# /// script
# requires-python = ">=3.11"
# dependencies = ["matplotlib==3.10.9"]
# ///
"""Plot median speedups against the optimized, same-root standard tree.

Run from any directory: uv run impl/scripts/plot_improvements.py
Inputs are the checked-in final sweeps; no benchmarks are rerun. The PNG and
vector SVG exports, plus the exact plotted ratios, go to impl/results/plots/.
"""

import csv
import math
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.ticker import FuncFormatter, MultipleLocator


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "results" / "plots"
HASHES = ("sha256", "sha3_256", "blake3")
TITLES = {"sha256": "SHA-256", "sha3_256": "SHA3-256", "blake3": "BLAKE3"}
STYLES = {
    "t5": ("#D87928", "o", "T5"),
    "t8": ("#286FAC", "^", "T8"),
    "t253": ("#168364", "s", "T253 (SHA-256 only)"),
}


def ratios(path):
    with path.open(newline="") as source:
        rows = list(csv.DictReader(source))
    keys = ("hash", "operation", "total_log", "width_log")
    standards = {}
    for row in rows:
        if row["scheme"] != "standard":
            continue
        key = tuple(row[k] for k in keys)
        if key in standards:
            raise ValueError(f"Duplicate standard reference: {key}")
        standards[key] = row
    plotted = []
    for row in rows:
        if row["scheme"] not in STYLES:
            continue
        key = tuple(row[k] for k in keys)
        reference = standards[key]
        if reference["matrix_bytes"] != row["matrix_bytes"]:
            raise ValueError("Reference and variant matrix sizes disagree")
        standard_ns, variant_ns = float(reference["median_ns"]), float(row["median_ns"])
        if not (math.isfinite(standard_ns) and math.isfinite(variant_ns)
                and standard_ns > 0 and variant_ns > 0):
            raise ValueError("Timings must be finite and positive")
        width = int(row["elements_per_leaf"])
        speedup = standard_ns / variant_ns
        plotted.append({
            "source": path.name,
            "hash": row["hash"],
            "scheme": row["scheme"],
            "operation": row["operation"],
            "total_log": int(row["total_log"]),
            "elements_per_leaf": width,
            "samples": int(row["samples"]),
            "standard_median_ns": standard_ns,
            "variant_median_ns": variant_ns,
            "speedup": speedup,
            "latency_reduction_percent": 100 * (1 - variant_ns / standard_ns),
            "standard_fallback": row["scheme"] == "t253" and width * 4 < 253,
        })
    return plotted


def plot(rows, total_log, stem):
    selected = [row for row in rows if row["total_log"] == total_log]
    widths = sorted({row["elements_per_leaf"] for row in selected})
    schemes = [s for s in STYLES if any(r["scheme"] == s for r in selected)]
    samples = {row["samples"] for row in selected}
    if samples != {7}:
        raise ValueError("Update the figure caption for changed sampling")

    plt.rcParams.update({
        "font.family": "DejaVu Sans", "font.size": 11,
        "axes.titleweight": "bold", "axes.titlesize": 14,
        "axes.labelsize": 11, "axes.spines.top": False,
        "axes.spines.right": False, "axes.edgecolor": "#A1A9B1",
        "xtick.color": "#374151", "ytick.color": "#374151",
        "text.color": "#17212B", "axes.labelcolor": "#17212B",
        "svg.fonttype": "none", "savefig.facecolor": "white",
    })
    fig, axes = plt.subplots(2, 3, figsize=(14.5, 8.5), sharex=True, sharey=True)
    fig.subplots_adjust(left=0.080, right=0.972, top=0.785, bottom=0.190,
                        wspace=0.11, hspace=0.20)
    displayed_modes = "T5 / T8 / T253" if "t5" in schemes else "T8 / T253"
    fig.suptitle(f"{displayed_modes} vs optimized standard hashing", x=0.5, y=0.970,
                 fontsize=21, fontweight="bold")
    size = "4 MiB" if total_log == 20 else "256 MiB"
    fig.text(0.5, 0.921,
             f"2$^{{{total_log}}}$ u32 elements ({size})  ·  four Rayon threads  ·  arm64 macOS",
             ha="center", fontsize=12, color="#475569")
    handles = [Line2D([], [], color=STYLES[s][0], marker=STYLES[s][1],
                      lw=2.2, markersize=7, label=STYLES[s][2]) for s in schemes]
    handles.append(Line2D([], [], color="#4B5563", ls="--", lw=1.3,
                          label="Optimized standard = 1×"))
    fig.legend(handles=handles, loc="upper center", bbox_to_anchor=(0.5, 0.898),
               ncol=len(handles), frameon=False, fontsize=11, handlelength=2.5,
               columnspacing=2.0)

    y_limit = max(1.5, math.ceil(max(r["speedup"] for r in selected) * 4) / 4)
    for row_index, operation in enumerate(("commit", "verify")):
        for col_index, hash_name in enumerate(HASHES):
            ax = axes[row_index, col_index]
            ax.set_xscale("log", base=2)
            ax.set_xlim(widths[0] / 1.4, widths[-1] * 2.7)
            ax.set_ylim(0, y_limit)
            ax.axhspan(1, y_limit, color="#EAF6F0", alpha=0.85, zorder=0)
            ax.axhline(1, color="#4B5563", linestyle="--", lw=1.25, zorder=2)
            ax.grid(axis="y", color="#DADEE4", linewidth=0.7, zorder=0)
            ax.set_axisbelow(True)
            ax.yaxis.set_major_locator(MultipleLocator(0.25))
            ax.yaxis.set_major_formatter(FuncFormatter(lambda value, _: f"{value:g}×"))
            ax.set_xticks(widths, [f"{w:,}" for w in widths])
            ax.tick_params(axis="both", labelsize=10)
            if row_index == 0:
                ax.set_title(TITLES[hash_name], pad=13)
            if col_index == 0:
                ax.set_ylabel(("Commitment" if operation == "commit" else "Verification")
                              + "\nSpeedup", labelpad=12)
            for scheme in schemes:
                data = sorted((r for r in selected if r["hash"] == hash_name
                               and r["scheme"] == scheme and r["operation"] == operation),
                              key=lambda r: r["elements_per_leaf"])
                if not data:
                    continue
                color, marker, _ = STYLES[scheme]
                actual = [r for r in data if not r["standard_fallback"]]
                fallback = [r for r in data if r["standard_fallback"]]
                ax.plot([r["elements_per_leaf"] for r in actual],
                        [r["speedup"] for r in actual], color=color, marker=marker,
                        lw=2.2, ms=6.5, markeredgecolor="white", markeredgewidth=0.7,
                        zorder=4)
                if fallback:
                    ax.scatter([r["elements_per_leaf"] for r in fallback],
                               [r["speedup"] for r in fallback], marker=marker,
                               facecolors="white", edgecolors=color, linewidths=1.5,
                               s=46, zorder=5)
                if scheme == "t253" and actual:
                    last = actual[-1]
                    ax.annotate(f"{last['speedup']:.2f}×",
                                (last["elements_per_leaf"], last["speedup"]),
                                xytext=(9, 2), textcoords="offset points", va="center",
                                color=color, fontsize=11, fontweight="bold")
    fig.supxlabel("u32 elements per leaf (log₂ spacing)", y=0.128, fontsize=12)
    fig.text(0.080, 0.076,
             "Speedup = optimized-standard median time / variant median time.  Above 1× is faster; below 1× is slower.",
             fontsize=10.5)
    note = ("Hollow T253 markers: standard-hash fallback below 253 bytes."
            if any(r["standard_fallback"] for r in selected)
            else "T5 was not measured in this scaling sweep; T253 is available only for SHA-256.")
    fig.text(0.080, 0.048, note + "  Seven batch samples per case; no ratio confidence intervals.",
             fontsize=9.5, color="#596574")
    fig.text(0.080, 0.022,
             f"Source: {selected[0]['source']}  ·  Fixed benchmark order; small changes near 1× can reflect measurement noise.",
             fontsize=9, color="#596574")
    for extension in ("png", "svg"):
        path = OUTPUT / f"{stem}.{extension}"
        fig.savefig(path, dpi=180)
        print(path)
    plt.close(fig)


def main():
    OUTPUT.mkdir(parents=True, exist_ok=True)
    representative = ratios(ROOT / "results" / "representative-final.csv")
    scaling = ratios(ROOT / "results" / "scaling-final.csv")
    plot(representative, 20, "improvement-vs-optimized-n20")
    plot(scaling, 26, "improvement-vs-optimized-n26")
    with (OUTPUT / "improvement-ratios.csv").open("w", newline="") as target:
        writer = csv.DictWriter(target, fieldnames=list(representative[0]))
        writer.writeheader()
        writer.writerows(representative + scaling)
    print(f"matplotlib {matplotlib.__version__}; {len(representative + scaling)} plotted ratios")


if __name__ == "__main__":
    main()
