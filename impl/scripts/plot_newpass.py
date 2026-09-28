# /// script
# requires-python = ">=3.11"
# dependencies = ["matplotlib==3.10.9"]
# ///
"""Plot the second optimization pass without changing historical figures.

Run: uv run impl/scripts/plot_newpass.py
Reads checked-in newpass CSV files; does not run benchmarks.
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
OUT = ROOT / "results" / "newpass-plots"
HASHES = ("sha256", "sha3_256", "blake3")
TITLES = {"sha256": "SHA-256", "sha3_256": "SHA3-256", "blake3": "BLAKE3"}
STYLES = {"t5": ("#D87928", "o", "T5"), "t8": ("#286FAC", "^", "T8"),
          "t253": ("#168364", "s", "T253 (SHA-256 only)")}
KEYS = ("hash", "scheme", "operation", "total_log", "width_log")


def load(name):
    with (ROOT / "results" / name).open(newline="") as source:
        rows = list(csv.DictReader(source))
    result = {}
    for row in rows:
        key = tuple(row[k] for k in KEYS)
        if key in result:
            raise ValueError(f"Duplicate result in {name}: {key}")
        row["source"] = name
        for field in ("median_ns", "p10_ns", "p90_ns"):
            row[field] = float(row[field])
            if not math.isfinite(row[field]) or row[field] <= 0:
                raise ValueError(f"Invalid timing in {name}: {key}")
        result[key] = row
    return result


def standard(row, rows):
    key = list(row[k] for k in KEYS)
    key[1] = "standard"
    return rows[tuple(key)]


def export_ratios(before, after, scaling):
    fields = ["source", "hash", "scheme", "operation", "total_log", "elements_per_leaf",
              "samples", "standard_ns", "variant_ns", "speedup_vs_standard",
              "before_variant_ns", "implementation_speedup", "standard_fallback"]
    output = []
    for rows in (after, scaling):
        for key, row in rows.items():
            if row["scheme"] not in STYLES:
                continue
            previous = before.get(key)
            output.append(dict(zip(fields, [row["source"], row["hash"], row["scheme"],
                row["operation"], row["total_log"], row["elements_per_leaf"], row["samples"],
                standard(row, rows)["median_ns"], row["median_ns"],
                standard(row, rows)["median_ns"] / row["median_ns"],
                previous["median_ns"] if previous else "",
                previous["median_ns"] / row["median_ns"] if previous else "",
                row["scheme"] == "t253" and int(row["elements_per_leaf"]) * 4 < 253])))
    with (OUT / "newpass-ratios.csv").open("w", newline="") as target:
        writer = csv.DictWriter(target, fieldnames=fields)
        writer.writeheader()
        writer.writerows(output)


def chart(rows, total_log, stem, before=None, implementation=False):
    selected = [r for r in rows.values() if int(r["total_log"]) == total_log
                and r["scheme"] in STYLES]
    widths = sorted({int(r["elements_per_leaf"]) for r in selected})
    samples = {int(r["samples"]) for r in selected}
    if samples != {7}:
        raise ValueError("Update figure caption for changed sampling")

    def value(row, source):
        if implementation:
            return before[tuple(row[k] for k in KEYS)]["median_ns"] / row["median_ns"]
        return standard(row, source)["median_ns"] / row["median_ns"]

    comparisons = selected
    if implementation:
        comparisons = [r for r in selected if tuple(r[k] for k in KEYS) in before]
    peak = max(value(r, rows) for r in comparisons)
    ymax = max(1.5, math.ceil(peak * 4) / 4)
    if peak > ymax - .1:
        ymax += .25
    if before and not implementation:
        old = [r for r in before.values() if int(r["total_log"]) == total_log
               and r["scheme"] in STYLES]
        ymax = max(ymax, math.ceil(max(value(r, before) for r in old) * 4) / 4)
    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 11,
        "axes.titleweight": "bold", "axes.titlesize": 14, "axes.labelsize": 11,
        "axes.spines.top": False, "axes.spines.right": False, "axes.edgecolor": "#A1A9B1",
        "xtick.color": "#374151", "ytick.color": "#374151", "text.color": "#17212B",
        "axes.labelcolor": "#17212B", "svg.fonttype": "none", "savefig.facecolor": "white"})
    fig, axes = plt.subplots(2, 3, figsize=(14.5, 8.5), sharex=True, sharey=True)
    fig.subplots_adjust(left=.080, right=.972, top=.785, bottom=.190, wspace=.11, hspace=.20)
    title = ("T5 / T8 / T253: implementation speedup" if implementation
             else "T5 / T8 / T253 vs optimized standard hashing")
    fig.suptitle(title, x=.5, y=.970, fontsize=21, fontweight="bold")
    size = "4 MiB" if total_log == 20 else "256 MiB"
    fig.text(.5, .921, f"2$^{{{total_log}}}$ u32 elements ({size})  ·  four Rayon threads  ·  arm64 macOS",
             ha="center", fontsize=12, color="#475569")
    handles = [Line2D([], [], color=c, marker=m, lw=2.2, markersize=7, label=label)
               for c, m, label in STYLES.values()]
    fig.legend(handles=handles, loc="upper center", bbox_to_anchor=(.5, .898),
               ncol=3, frameon=False, fontsize=11, handlelength=2.5, columnspacing=2)
    for ri, op in enumerate(("commit", "verify")):
        for ci, hash_name in enumerate(HASHES):
            ax = axes[ri, ci]
            ax.set_xscale("log", base=2)
            ax.set_xlim(widths[0] / 1.4, widths[-1] * 2.2)
            ax.set_ylim(0, ymax)
            ax.axhspan(1, ymax, color="#EAF6F0", alpha=.85, zorder=0)
            ax.axhline(1, color="#4B5563", ls="--", lw=1.25, zorder=2)
            ax.grid(axis="y", color="#DADEE4", linewidth=.7)
            ax.set_axisbelow(True)
            ax.yaxis.set_major_locator(MultipleLocator(.25 if ymax <= 2 else .5))
            ax.yaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v:g}×"))
            ax.set_xticks(widths, [f"{w:,}" for w in widths])
            ax.tick_params(axis="both", labelsize=10)
            if ri == 0:
                ax.set_title(TITLES[hash_name], pad=13)
            if ci == 0:
                ax.set_ylabel(("Commitment" if op == "commit" else "Verification") + "\nSpeedup", labelpad=12)
            for scheme, (color, marker, _) in STYLES.items():
                data = sorted((r for r in comparisons if r["hash"] == hash_name
                    and r["scheme"] == scheme and r["operation"] == op),
                    key=lambda r: int(r["elements_per_leaf"]))
                if not data:
                    continue
                actual = [r for r in data if scheme != "t253" or int(r["elements_per_leaf"]) * 4 >= 253]
                fallback = [r for r in data if r not in actual]
                ax.plot([int(r["elements_per_leaf"]) for r in actual], [value(r, rows) for r in actual],
                        color=color, marker=marker, lw=2.2, ms=6.5, markeredgecolor="white",
                        markeredgewidth=.7, zorder=4)
                if fallback:
                    ax.scatter([int(r["elements_per_leaf"]) for r in fallback],
                               [value(r, rows) for r in fallback], marker=marker,
                               facecolors="white", edgecolors=color, linewidths=1.5, s=46, zorder=5)
                if before and not implementation:
                    old = sorted((r for r in before.values() if r["hash"] == hash_name
                        and r["scheme"] == scheme and r["operation"] == op
                        and int(r["total_log"]) == total_log
                        and (scheme != "t253" or int(r["elements_per_leaf"]) * 4 >= 253)),
                        key=lambda r: int(r["elements_per_leaf"]))
                    ax.plot([int(r["elements_per_leaf"]) for r in old], [value(r, before) for r in old],
                            color=color, ls="--", lw=1.5, alpha=.45, zorder=3)
    fig.supxlabel("u32 elements per leaf (log₂ spacing)", y=.128, fontsize=12)
    explanation = ("Speedup = before-pass variant median / after-pass variant median.  Above 1× means this implementation got faster."
        if implementation else "Speedup = optimized-standard median / variant median.  Above 1× is faster; below 1× is slower.")
    fig.text(.080, .076, explanation, fontsize=10.5)
    note = ("Solid: after optimization.  Dashed: before optimization, each relative to its own standard comparator."
        if before and not implementation else "T253 is available only for SHA-256.  Roots and construction definitions are unchanged by this pass.")
    if any(r["scheme"] == "t253" and int(r["elements_per_leaf"]) * 4 < 253 for r in selected):
        note += "  Hollow T253: standard fallback."
    fig.text(.080, .048, note, fontsize=9, color="#596574")
    fig.text(.080, .022, "Seven batch samples per case; no ratio confidence intervals.  Fixed-order sweeps; small changes may be noise.",
             fontsize=9, color="#596574")
    for ext in ("png", "svg"):
        path = OUT / f"{stem}.{ext}"
        fig.savefig(path, dpi=180)
        print(path)
    plt.close(fig)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    before = load("newpass-before.csv")
    after = load("newpass-after.csv")
    scaling = load("newpass-scaling.csv")
    export_ratios(before, after, scaling)
    chart(after, 20, "vs-optimized-n20", before=before)
    chart(scaling, 26, "vs-optimized-n26")
    chart(after, 20, "implementation-speedup-n20", before=before, implementation=True)
    print(f"matplotlib {matplotlib.__version__}")


if __name__ == "__main__":
    main()
