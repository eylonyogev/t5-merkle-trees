#!/usr/bin/env python3
"""Run backend-specific, serial benchmark processes and record source provenance.

First build: cargo build --release --locked --manifest-path impl/Cargo.toml --example perf_sweep
Then run from any directory with Python 3.10+; no Python dependencies.
"""
import argparse
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import subprocess
import time

IMPL = Path(__file__).resolve().parents[1]
SCHEMES = {
    "sha256": "standard,t253,abr-wide",
    "sha3_256": "standard,shake128,sponge-dm272",
    "blake3": "standard,t8,abr-wide,t277",
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="lowcall-n20")
    parser.add_argument("--total-logs", default="20")
    parser.add_argument("--width-logs", default=",".join(map(str, range(15))))
    parser.add_argument("--hashes", default=",".join(SCHEMES))
    parser.add_argument("--ms", type=int, default=150)
    parser.add_argument("--samples", type=int, default=7)
    parser.add_argument("--threads", type=int, default=4)
    parser.add_argument("--cpu-model", default=platform.processor() or "not recorded")
    args = parser.parse_args()
    hashes = args.hashes.split(",")
    assert all(name in SCHEMES for name in hashes)
    assert Path(args.output).name == args.output
    binary = IMPL / "target/release/examples/perf_sweep"
    source_paths = sorted((IMPL / "src").rglob("*.rs")) + [
        IMPL / "examples/perf_sweep.rs", IMPL / "Cargo.toml", IMPL / "Cargo.lock"]
    fingerprint = {str(path.relative_to(IMPL)): digest(path) for path in source_paths}
    metadata = {
        "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "configuration": vars(args), "platform": platform.platform(),
        "machine": platform.machine(),
        "cpu_model": args.cpu_model,
        "rustc": subprocess.check_output(["rustc", "-Vv"], text=True),
        "git_revision": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=IMPL, text=True).strip(),
        "binary_sha256": digest(binary), "source_sha256": fingerprint,
        "rustflags_environment": os.environ.get("RUSTFLAGS", ""),
        "protocol": "Sequential backend processes; each contains fixed-order cases. Fresh commit includes allocation/drop. Verify includes complete leaf and path. Input/proof preparation outside timing. Batch medians and p10/p90 are not confidence intervals.",
        "commands": [],
    }
    rows = []
    log = []
    for name in hashes:
        changes = {
            "RAYON_NUM_THREADS": str(args.threads), "MERKLE_HASHES": name,
            "MERKLE_SCHEMES": SCHEMES[name], "MERKLE_TOTAL_LOGS": args.total_logs,
            "MERKLE_WIDTH_LOGS": args.width_logs, "MERKLE_OPERATIONS": "commit,verify",
            "MERKLE_SWEEP_MS": str(args.ms), "MERKLE_SWEEP_SAMPLES": str(args.samples),
        }
        metadata["commands"].append({"executable": str(binary), "environment": changes})
        print(f"Running {name}: N logs={args.total_logs}, width logs={args.width_logs}", flush=True)
        run = subprocess.run([str(binary)], env={**os.environ, **changes},
                             capture_output=True, text=True, check=True)
        batch = list(csv.DictReader(io.StringIO(run.stdout)))
        assert batch and all(row["hash"] == name for row in batch)
        rows.extend(batch)
        log.append(run.stderr)
        print(f"Finished {name}: {len(batch)} rows", flush=True)
    assert digest(binary) == metadata["binary_sha256"], "Benchmark executable changed during run"
    assert fingerprint == {str(path.relative_to(IMPL)): digest(path) for path in source_paths}, "Source changed during run"
    metadata["finished_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    destination = IMPL / "results" / args.output
    with destination.with_suffix(".csv").open("w", newline="") as target:
        writer = csv.DictWriter(target, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    destination.with_suffix(".json").write_text(json.dumps(metadata, indent=2) + "\n")
    destination.with_suffix(".log").write_text("\n".join(log))
    print(f"Saved {len(rows)} rows to {destination.with_suffix('.csv')}", flush=True)


if __name__ == "__main__":
    main()
