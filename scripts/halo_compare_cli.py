#!/usr/bin/env python3
"""Compare Halo-only and a directed-havoc control on one built fixed CLI row."""

import argparse
import csv
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

import halo_magma as campaign


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def corpus_sha256(path):
    digest = hashlib.sha256()
    for file in sorted(p for p in path.rglob("*") if p.is_file()):
        digest.update(str(file.relative_to(path)).encode())
        digest.update(b"\0")
        digest.update(bytes.fromhex(sha256(file)))
    return digest.hexdigest()


def count_files(path):
    return sum(p.is_file() for p in path.rglob("*")) if path.is_dir() else 0


def run_one(row, seconds, seed, mode):
    base = campaign.WORK_ROOT / row["bug"]
    out, shared = base / "out", base / "shared"
    entry = row["entry"]
    target, corpus, monitor = out / entry, base / "target/corpus" / entry, out / "monitor"
    runner = campaign.ROOT / "target/release" / ("halo_cli" if mode == "halo_only" else "halo_control_cli")
    if not all(path.is_file() for path in (target, monitor, runner)) or not corpus.is_dir():
        raise RuntimeError("build the fixed Halo CLI target and both runners first")
    findings = shared / f"comparison_{mode}"
    logfile = out / f"comparison_{mode}.log"
    canaries = out / f"comparison_{mode}_canaries.csv"
    command = ["/usr/bin/timeout", "--signal=INT", "--kill-after=5", str(seconds),
               runner, "--target", target, "--input", corpus, "--output", findings,
               "--logfile", logfile]
    if mode == "halo_only":
        command += ["--halo-only", "--halo-seed", str(seed)]
    else:
        command += ["--seed", str(seed)]
    command += ["--", *campaign.cli_args(entry, "@@", out)]
    env = os.environ.copy()
    with canaries.open("w") as stream:
        with (out / f"comparison_{mode}_stderr.log").open("w") as errors:
            result = subprocess.run([monitor, "--dump", "row", "--fetch", "watch", *map(str, command)],
                                    cwd=shared, env=env, stdout=stream, stderr=errors)
    if result.returncode not in (0, 124, 130):
        raise RuntimeError(f"{mode} exited {result.returncode}; see {out}")
    with canaries.open(newline="") as stream:
        record = next(csv.DictReader(stream), {})
    lines = logfile.read_text(errors="replace").splitlines() if logfile.is_file() else []
    executions = [int(m.group(1)) for line in lines
                  if (m := re.search(r"executions: (\d+)", line))]
    if not executions:
        raise RuntimeError(f"{mode} reported no executions")
    seeds = count_files(corpus)
    if max(executions) <= seeds:
        raise RuntimeError(f"{mode} did not finish seed import: {max(executions)}/{seeds}")
    return {"mode": mode, "runner_sha256": sha256(runner), "target_sha256": sha256(target),
            "seed_corpus_sha256": corpus_sha256(corpus), "budget_seconds": seconds,
            "seed": seed, "fixed_entry": entry, "seed_files": seeds,
            "executions": max(executions), "queue_files": count_files(findings / "queue"),
            "crash_files": count_files(findings / "crashes"),
            "magma_reach_count": int(record.get(f"{row['bug']}_R", "0")),
            "magma_trigger_count": int(record.get(f"{row['bug']}_T", "0")),
            "canary_csv": str(canaries), "fuzzer_log": str(logfile),
            "invocation": list(map(str, command))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bug")
    parser.add_argument("--seconds", type=int, default=60)
    parser.add_argument("--seed", type=int, default=17)
    args = parser.parse_args()
    row = next((row for row in campaign.rows() if row["bug"] == args.bug), None)
    if row is None or row["entry"] not in campaign.CLI:
        parser.error("bug must be a fixed command-line row")
    results = [run_one(row, args.seconds, args.seed, mode)
               for mode in ("halo_only", "directed_havoc")]
    path = campaign.ROOT / "results/halo" / f"comparison-{args.bug}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"bug": args.bug, "results": results}, indent=2) + "\n")
    print(path)


if __name__ == "__main__":
    main()
