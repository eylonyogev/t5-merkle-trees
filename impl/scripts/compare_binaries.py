#!/usr/bin/env python3
"""Compare two frozen perf_sweep executables in alternating process order.

Uses Python's standard library. Build and copy each executable before running;
see CODE_SPEED_RESULTS.md for the build provenance and benchmark protocol.
"""
import argparse
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import time


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def case(row):
    return tuple(row[key] for key in
                 ("hash", "scheme", "operation", "total_log", "width_log"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--before", type=Path, required=True)
    parser.add_argument("--after", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="CSV/JSON stem")
    parser.add_argument("--runs", type=int, default=4)
    parser.add_argument("--threads", type=int, default=4)
    parser.add_argument("--totals", default="20,24")
    parser.add_argument("--widths", default="0,4,6,8,14")
    parser.add_argument("--hashes", default="sha256")
    parser.add_argument("--schemes", default="standard")
    parser.add_argument("--operations", default="commit,verify")
    parser.add_argument("--ms", type=int, default=300)
    parser.add_argument("--cpu-model", default=platform.processor() or "unknown")
    args = parser.parse_args()
    if min(args.runs, args.threads, args.ms) < 1:
        parser.error("runs, threads and ms must be positive")
    variants = [(label, getattr(args, label).resolve()) for label in ("before", "after")]
    environment = {
        "RAYON_NUM_THREADS": str(args.threads), "MERKLE_HASHES": args.hashes,
        "MERKLE_SCHEMES": args.schemes, "MERKLE_TOTAL_LOGS": args.totals,
        "MERKLE_WIDTH_LOGS": args.widths, "MERKLE_OPERATIONS": args.operations,
        "MERKLE_SWEEP_MS": str(args.ms), "MERKLE_SWEEP_SAMPLES": "7",
        "MERKLE_MAX_DIGEST_MIB": "256", "MERKLE_ALLOW_LARGE": "false",
        "MERKLE_FULL": "false",
    }
    metadata = {
        "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "platform": platform.platform(), "cpu_model": args.cpu_model,
        "environment": environment,
        "binaries": {label: {"path": str(path), "sha256": digest(path)}
                     for label, path in variants},
        "commands": [],
        "protocol": (
            "Sequential processes; alternating before/after order between passes. "
            "Each point is the median of seven calibrated batch averages. Fresh "
            "commit includes allocation/drop; verify includes the complete leaf "
            "and path. Input/proof preparation is outside timing. Case order is "
            "fixed within each process. Run spread is not a confidence interval."
        ),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    expected_cases = None
    for run in range(1, args.runs + 1):
        order = variants if run % 2 else variants[::-1]
        for label, binary in order:
            print(f"Pass {run}: {label}, threads={args.threads}", flush=True)
            started = time.monotonic()
            result = subprocess.run([str(binary)], env={**os.environ, **environment},
                                    check=True, text=True, capture_output=True)
            batch = list(csv.DictReader(io.StringIO(result.stdout)))
            cases = {case(row) for row in batch}
            if not batch or len(cases) != len(batch):
                raise RuntimeError("Empty or duplicate benchmark cases")
            if expected_cases is None:
                expected_cases = cases
            elif cases != expected_cases:
                raise RuntimeError("Before/after benchmark cases differ")
            for row in batch:
                row.update(variant=label, run=str(run), threads=str(args.threads))
            rows.extend(batch)
            elapsed = time.monotonic() - started
            metadata["commands"].append({
                "label": label, "run": run, "seconds": elapsed,
                "stderr": result.stderr,
            })
            print(f"  {len(batch)} measurements in {elapsed:.1f}s", flush=True)
            with args.output.with_suffix(".csv").open("w", newline="") as target:
                writer = csv.DictWriter(target, fieldnames=list(rows[0]))
                writer.writeheader()
                writer.writerows(rows)
            metadata["finished_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            args.output.with_suffix(".json").write_text(json.dumps(metadata, indent=2) + "\n")
    for label, path in variants:
        if digest(path) != metadata["binaries"][label]["sha256"]:
            raise RuntimeError("Benchmark executable changed during comparison")
    for key in sorted(expected_cases):
        medians = {
            label: statistics.median(float(row["median_ns"]) for row in rows
                                     if case(row) == key and row["variant"] == label)
            for label, _ in variants
        }
        print("/".join(key), f"{medians['before'] / 1e3:.3f} -> "
              f"{medians['after'] / 1e3:.3f} us; "
              f"{medians['before'] / medians['after']:.3f}x")
    print(f"Saved {args.output}.csv and .json", flush=True)


if __name__ == "__main__":
    main()
