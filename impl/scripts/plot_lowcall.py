# /// script
# requires-python = ">=3.11"
# dependencies = ["matplotlib==3.10.9"]
# ///
"""Plot the implemented low-call constructions against optimized standard trees.

Run from any directory: uv run impl/scripts/plot_lowcall.py

Reads lowcall-n20.csv and lowcall-scaling.csv emitted by perf_sweep. Does not run
benchmarks. Validates the complete intended grids, then exports PNG/SVG figures,
exact timing/count ratios, and a Markdown report without suppressing slowdowns.
"""

import argparse
import csv
import math
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter, MultipleLocator


ROOT = Path(__file__).resolve().parents[1]
HASHES = ("sha256", "blake3", "sha3_256")
TITLES = {"sha256": "SHA-256", "blake3": "BLAKE3", "sha3_256": "Keccak / SHA3-256"}
MODES = {
    "sha256": ("standard", "t253", "abr-wide"),
    "blake3": ("standard", "t8", "t277", "abr-wide"),
    "sha3_256": ("standard", "shake128", "sponge-dm272"),
}
# Each panel has its own legend; the two ABR adapters have different capacities.
STYLES = {
    ("sha256", "t253"): ("#777F8A", "s", "T253 (previous)", "--"),
    ("sha256", "abr-wide"): ("#CA5424", "o", "ABR-wide", "-"),
    ("blake3", "t8"): ("#777F8A", "^", "T8 (previous)", "--"),
    ("blake3", "t277"): ("#18877F", "s", "T277", "-"),
    ("blake3", "abr-wide"): ("#7853BB", "o", "ABR-wide", "-"),
    ("sha3_256", "shake128"): ("#177CB6", "^", "SHAKE128", "-"),
    ("sha3_256", "sponge-dm272"): ("#BF3F82", "o", "SPONGE-DM272", "-"),
}
OPERATIONS = ("commit", "verify")
KEY_FIELDS = ("hash", "scheme", "operation", "total_log", "width_log")
INTEGER_FIELDS = (
    "total_log", "width_log", "total_elements", "elements_per_leaf", "leaves",
    "matrix_bytes", "operation_input_bytes", "digest_bytes", "path_bytes",
    "native_calls", "abstract_leaf_calls", "samples", "iterations_per_sample",
)
TIMING_FIELDS = ("median_ns", "p10_ns", "p90_ns")
GEOMETRY_FIELDS = (
    "total_elements", "elements_per_leaf", "leaves", "matrix_bytes",
    "operation_input_bytes", "digest_bytes", "path_bytes", "primitive",
)


def key_of(row):
    return tuple(row[field] for field in KEY_FIELDS)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def baseline_leaf_calls(hash_name, byte_width):
    if hash_name == "sha256":
        return (byte_width + 9 + 63) // 64
    if hash_name == "blake3":
        return (byte_width + 63) // 64 + (byte_width + 1023) // 1024 - 1
    if hash_name == "sha3_256":
        return byte_width // 136 + 1
    raise ValueError(f"Unknown backend {hash_name!r}")


def read_rows(path):
    with path.open(newline="") as source:
        reader = csv.DictReader(source)
        required = set(INTEGER_FIELDS + TIMING_FIELDS + KEY_FIELDS + ("primitive",))
        require(required <= set(reader.fieldnames or ()), f"Missing CSV columns in {path}")
        raw_rows = list(reader)
    require(raw_rows, f"Empty sweep: {path}")
    rows = {}
    for raw in raw_rows:
        row = dict(raw)
        for field in INTEGER_FIELDS:
            row[field] = int(row[field])
        for field in TIMING_FIELDS:
            row[field] = float(row[field])
            require(math.isfinite(row[field]) and row[field] > 0,
                    f"Nonpositive/nonfinite {field} in {path}: {raw}")
        key = key_of(row)
        require(key not in rows, f"Duplicate timing in {path}: {key}")
        require(row["hash"] in HASHES and row["operation"] in OPERATIONS,
                f"Unexpected backend/operation in {path}: {key}")
        require(row["samples"] == 7, f"Expected seven samples; update report metadata: {key}")
        require(row["iterations_per_sample"] > 0, f"No timing iterations: {key}")
        require(row["p10_ns"] <= row["median_ns"] <= row["p90_ns"],
                f"Timing percentile order is invalid: {key}")
        total, width = 1 << row["total_log"], 1 << row["width_log"]
        require(total >= width, f"Leaf is larger than matrix: {key}")
        leaves, height = total // width, row["total_log"] - row["width_log"]
        expected = {
            "total_elements": total,
            "elements_per_leaf": width,
            "leaves": leaves,
            "matrix_bytes": total * 4,
            "operation_input_bytes": (total if row["operation"] == "commit" else width) * 4,
            "digest_bytes": (2 * leaves - 1) * 32,
            "path_bytes": height * 32,
        }
        for field, value in expected.items():
            require(row[field] == value, f"Incorrect {field} for {key}: {row[field]} != {value}")
        if row["operation"] == "commit":
            leaf_work = row["native_calls"] - (leaves - 1)
            require(leaf_work >= 0 and leaf_work % leaves == 0, f"Invalid commit call count: {key}")
            leaf_calls = leaf_work // leaves
        else:
            leaf_calls = row["native_calls"] - height
        require(leaf_calls >= 1, f"Expected a hashed, nonempty leaf: {key}")
        if row["scheme"] == "standard":
            require(leaf_calls == baseline_leaf_calls(row["hash"], width * 4),
                    f"Incorrect standard native count: {key}")
        row["native_leaf_calls"] = leaf_calls
        row["source"] = path.name
        rows[key] = row
    return rows


def validate_grid(rows, total_logs, width_logs, source):
    expected = {
        (hash_name, scheme, operation, total_log, width_log)
        for hash_name in HASHES
        for scheme in MODES[hash_name]
        for operation in OPERATIONS
        for total_log in total_logs
        for width_log in width_logs
    }
    missing, unexpected = expected - rows.keys(), rows.keys() - expected
    require(not missing and not unexpected,
            f"Incomplete/unexpected grid in {source}: missing={sorted(missing)}, "
            f"unexpected={sorted(unexpected)}")
    # Native counts describe the construction, independent of matrix height,
    # commit/verify operation, timing noise, or benchmark batching.
    seen_leaf_counts = {}
    for row in rows.values():
        key = (row["hash"], row["scheme"], row["width_log"])
        previous = seen_leaf_counts.setdefault(key, row["native_leaf_calls"])
        require(previous == row["native_leaf_calls"], f"Inconsistent leaf call count: {key}")


def standard_for(row, rows):
    key = list(key_of(row))
    key[1] = "standard"
    reference = rows[tuple(key)]
    for field in GEOMETRY_FIELDS:
        require(row[field] == reference[field],
                f"Variant/reference {field} mismatch: {key_of(row)}")
    return reference


def ratio_rows(rows):
    ratios = []
    for row in rows.values():
        if row["scheme"] == "standard":
            continue
        reference = standard_for(row, rows)
        ratios.append({
            "source": row["source"],
            "hash": row["hash"],
            "scheme": row["scheme"],
            "operation": row["operation"],
            "total_log": row["total_log"],
            "width_log": row["width_log"],
            "elements_per_leaf": row["elements_per_leaf"],
            "leaf_bytes": row["elements_per_leaf"] * 4,
            "samples": row["samples"],
            "standard_median_ns": reference["median_ns"],
            "variant_median_ns": row["median_ns"],
            "speedup_vs_standard": reference["median_ns"] / row["median_ns"],
            "latency_reduction_percent": 100 * (1 - row["median_ns"] / reference["median_ns"]),
            "standard_native_calls": reference["native_calls"],
            "variant_native_calls": row["native_calls"],
            "native_calls_reduction_percent": 100 * (1 - row["native_calls"] / reference["native_calls"]),
            "standard_native_leaf_calls": reference["native_leaf_calls"],
            "variant_native_leaf_calls": row["native_leaf_calls"],
            "standard_fallback": row["scheme"] == "t253" and row["elements_per_leaf"] * 4 < 253,
        })
    return sorted(ratios, key=key_of)


def plot(rows, total_log, output):
    selected = [row for row in rows if row["total_log"] == total_log]
    widths = sorted({row["elements_per_leaf"] for row in selected})
    ymax = max(1.25, math.ceil(max(row["speedup_vs_standard"] for row in selected) * 4) / 4 + .125)
    ystep = .25 if ymax <= 2 else .5 if ymax <= 4 else 1
    plt.rcParams.update({
        "font.family": "DejaVu Sans", "font.size": 11,
        "axes.titleweight": "bold", "axes.titlesize": 15,
        "axes.labelsize": 11, "axes.spines.top": False,
        "axes.spines.right": False, "axes.edgecolor": "#A1A9B1",
        "xtick.color": "#374151", "ytick.color": "#374151",
        "text.color": "#17212B", "axes.labelcolor": "#17212B",
        "svg.fonttype": "none", "savefig.facecolor": "white",
    })
    fig, axes = plt.subplots(2, 3, figsize=(15.5, 8.7), sharex=True, sharey=True)
    fig.subplots_adjust(left=.075, right=.980, top=.77, bottom=.19, wspace=.12, hspace=.19)
    fig.suptitle("Lower-call leaf hashes vs optimized standard hashing", y=.970,
                 fontsize=21, fontweight="bold")
    fig.text(.5, .921,
             f"2$^{{{total_log}}}$ u32 elements ({2 ** (total_log - 18):,} MiB)"
             "  ·  Apple M4 Max / macOS  ·  four Rayon threads",
             ha="center", fontsize=12, color="#475569")
    fig.text(.5, .883, "Higher is faster. Every measured point is shown, including slowdowns.",
             ha="center", fontsize=11, color="#475569")
    for ri, operation in enumerate(OPERATIONS):
        for ci, hash_name in enumerate(HASHES):
            ax = axes[ri, ci]
            ax.set_xscale("log", base=2)
            ax.set_xlim(widths[0] / 1.30, widths[-1] * 1.35)
            ax.set_ylim(0, ymax)
            ax.axhspan(1, ymax, color="#EAF6F0", alpha=.7, zorder=0)
            ax.axhline(1, color="#4B5563", ls="--", lw=1.2, zorder=2)
            ax.grid(axis="y", color="#DDE2E8", lw=.7)
            ax.set_axisbelow(True)
            ax.yaxis.set_major_locator(MultipleLocator(ystep))
            ax.yaxis.set_major_formatter(FuncFormatter(lambda value, _: f"{value:g}×"))
            tick_widths = widths[::2] if len(widths) > 8 else widths
            ax.set_xticks(tick_widths, [f"{width:,}" for width in tick_widths])
            ax.tick_params(axis="both", labelsize=10)
            if ri == 0:
                ax.set_title(TITLES[hash_name], pad=47)
            if ci == 0:
                ax.set_ylabel(("Commitment" if operation == "commit" else "Verification")
                              + "\nSpeedup", labelpad=12)
            for scheme in MODES[hash_name][1:]:
                data = sorted((row for row in selected if row["hash"] == hash_name
                               and row["scheme"] == scheme and row["operation"] == operation),
                              key=lambda row: row["elements_per_leaf"])
                color, marker, label, style = STYLES[(hash_name, scheme)]
                ax.plot([row["elements_per_leaf"] for row in data],
                        [row["speedup_vs_standard"] for row in data], color=color,
                        marker=marker, label=label, ls=style, lw=2.1, ms=5.2,
                        markeredgecolor="white", markeredgewidth=.7, zorder=4)
                fallback = [row for row in data if row["standard_fallback"]]
                if fallback:
                    ax.scatter([row["elements_per_leaf"] for row in fallback],
                               [row["speedup_vs_standard"] for row in fallback],
                               marker=marker, facecolors="white", edgecolors=color,
                               linewidths=1.2, s=29, zorder=5)
            if ri == 0:
                ax.legend(loc="lower center", bbox_to_anchor=(.5, 1.015),
                          ncol=len(MODES[hash_name]) - 1, frameon=False, fontsize=9,
                          handlelength=1.6, columnspacing=.9, handletextpad=.45)
    fig.supxlabel("u32 elements per leaf (log₂ spacing)", y=.125, fontsize=12)
    fig.text(.075, .077,
             "Speedup = optimized-standard median / variant median. Dashed horizontal line: standard = 1×.",
             fontsize=10.5)
    fig.text(.075, .048,
             "Seven batch samples per case; target 150 ms total sampling. No ratio confidence intervals; small differences may be noise.",
             fontsize=9.5, color="#596574")
    note = "Hollow T253 markers: standard-hash fallback. " if total_log == 20 else ""
    fig.text(.075, .022,
             note + "Variants change the leaf commitment; ordinary binary parents are unchanged. Source: "
             + selected[0]["source"], fontsize=9, color="#596574")
    for extension in ("png", "svg"):
        path = output / f"vs-optimized-n{total_log}.{extension}"
        fig.savefig(path, dpi=190)
        print(path)
    plt.close(fig)


def label_for(hash_name, scheme):
    return "Optimized standard" if scheme == "standard" else STYLES[(hash_name, scheme)][2]


def report(all_rows, ratios, output):
    lines = [
        "# Implemented low-call constructions: measured results", "",
        "These figures compare each implemented leaf mode with the **optimized standard tree "
        "of the same backend**. Both use the same binary-parent implementation. Roots change "
        "when a nonstandard leaf mode is selected. SHAKE128 is the standard XOF with a 32-byte output.", "",
        "Speedup is `standard median_ns / variant median_ns`; values below 1× are slower. "
        "Timing ratios are measured performance, not ratios of compression counts. "
        "No measured cases, including regressions, are omitted.", "",
        "Environment: Apple M4 Max, arm64 macOS, four Rayon threads for commitment. "
        "Verification measures one complete leaf opening. Each case has seven calibrated "
        "batch samples targeting 150 ms total sampling; calibration and integer batch sizes "
        "can change the actual duration. Sweeps use fixed case order. No confidence intervals "
        "are inferred from percentile bands; small ratios near 1× can reflect measurement noise.", "",
        "## Figures and source data", "",
        "- [N = 2²⁰, 4 MiB: all 15 widths](vs-optimized-n20.png) "
        "([SVG](vs-optimized-n20.svg)); [300 timing rows](../lowcall-n20.csv).",
        "- [N = 2²⁴, 64 MiB](vs-optimized-n24.png) ([SVG](vs-optimized-n24.svg)).",
        "- [N = 2²⁶, 256 MiB](vs-optimized-n26.png) ([SVG](vs-optimized-n26.svg)); "
        "[160 timing rows across both larger sizes](../lowcall-scaling.csv).",
        "- [Exact timing and native-call ratios](lowcall-ratios.csv).", "",
        "Dashed colored series are the prior T253/T8 comparisons. Hollow T253 markers "
        "use its standard-hash fallback below 253 bytes. The horizontal dashed line is 1×.", "",
        "## Representative 256 MiB matrices", "",
        "Times below are medians; displayed speedups are rounded, while the CSV retains "
        "the full computed ratio. Counts are logical native calls, regardless of SIMD batching. "
        "SHA-256/BLAKE3 count compression calls; the Keccak backend counts full 24-round "
        "permutations. These primitive counts are not interchangeable measures of CPU cost.", "",
    ]
    for width_log in (8, 14):
        width = 1 << width_log
        lines.extend([
            f"### {width:,} u32 elements per leaf ({width * 4:,} bytes)", "",
            "| Backend | Leaf mode | Calls / leaf | Commit (ms) | Commit speedup | Verify (µs) | Verify speedup |",
            "|---|---|---:|---:|---:|---:|---:|",
        ])
        for hash_name in HASHES:
            for scheme in MODES[hash_name]:
                commit = all_rows[(hash_name, scheme, "commit", 26, width_log)]
                verify = all_rows[(hash_name, scheme, "verify", 26, width_log)]
                standard_commit = standard_for(commit, all_rows)
                standard_verify = standard_for(verify, all_rows)
                lines.append(
                    f"| {TITLES[hash_name]} | {label_for(hash_name, scheme)} "
                    f"| {commit['native_leaf_calls']:,} | {commit['median_ns'] / 1e6:.4f} "
                    f"| {standard_commit['median_ns'] / commit['median_ns']:.3f}× "
                    f"| {verify['median_ns'] / 1e3:.4f} "
                    f"| {standard_verify['median_ns'] / verify['median_ns']:.3f}× |"
                )
        lines.append("")
    lines.extend([
        "For L leaves and c native calls per leaf, full commitment uses `L*c + L - 1` "
        "calls and one verification uses `c + log2(L)`. The exact operation counts, "
        "including all binary parents, are in the ratio CSV.", "",
        "## Validation and reproduction", "",
        "```sh", "uv run impl/scripts/plot_lowcall.py", "```", "",
        "The generator checks unique complete grids (10 backend/mode combinations, two "
        "operations, 15 widths at N20; four widths at each of N24/N26), finite positive "
        "timings, percentile ordering, seven samples, matrix geometry, matching comparators, "
        "standard-hash native counts, and identical per-leaf counts across commit/verify "
        "and matrix sizes. It does not rerun benchmarks.", "",
        f"Validated {len(all_rows)} raw timings and exported {len(ratios)} variant/comparator ratios. "
        f"Rendered using Matplotlib {matplotlib.__version__}.", "",
        "[Construction definitions and security distinctions](../../NEXT_CONSTRUCTIONS.md) "
        "remain separate from these performance measurements. Lower counts and successful "
        "correctness tests are not cryptographic security proofs.", "",
    ])
    (output / "README.md").write_text("\n".join(lines))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", type=Path, default=ROOT / "results")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "results" / "lowcall-plots")
    args = parser.parse_args()
    small_path = args.input_dir / "lowcall-n20.csv"
    scaling_path = args.input_dir / "lowcall-scaling.csv"
    small, scaling = read_rows(small_path), read_rows(scaling_path)
    validate_grid(small, (20,), tuple(range(15)), small_path.name)
    validate_grid(scaling, (24, 26), (6, 8, 10, 14), scaling_path.name)
    require(not small.keys() & scaling.keys(), "Sweep grids overlap")
    all_rows = small | scaling
    # Also compare overlapping widths between the separate input files.
    seen_counts = {}
    for row in all_rows.values():
        key = (row["hash"], row["scheme"], row["width_log"])
        previous = seen_counts.setdefault(key, row["native_leaf_calls"])
        require(previous == row["native_leaf_calls"], f"Native counts differ across input files: {key}")
    ratios = ratio_rows(all_rows)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    with (args.output_dir / "lowcall-ratios.csv").open("w", newline="") as target:
        writer = csv.DictWriter(target, fieldnames=list(ratios[0]))
        writer.writeheader()
        writer.writerows(ratios)
    for total_log in (20, 24, 26):
        plot(ratios, total_log, args.output_dir)
    report(all_rows, ratios, args.output_dir)
    print(f"Validated {len(all_rows)} timings; exported {len(ratios)} ratios. "
          f"Matplotlib {matplotlib.__version__}.")


if __name__ == "__main__":
    main()
