#!/usr/bin/env python3
"""Replay saved comparison inputs against the fixed Magma bug oracle."""

import argparse
import json
import subprocess
from pathlib import Path

import halo_magma as campaign


def replay(bug, mode, max_inputs):
    row = next(row for row in campaign.rows() if row["bug"] == bug)
    base = campaign.WORK_ROOT / bug
    out, shared = base / "out", base / "shared"
    findings = shared / f"comparison_{mode}"
    inputs = [p for folder in (findings / "queue", findings / "crashes")
              if folder.is_dir() for p in folder.rglob("*") if p.is_file()]
    inputs.sort(key=lambda p: (p.stat().st_mtime_ns, str(p)))
    for index, path in enumerate(inputs):
        if max_inputs and index >= max_inputs:
            break
        try:
            command = [out / "monitor", "--dump", "row", "--fetch", "watch",
                       out / row["entry"], *campaign.cli_args(row["entry"], path, out)]
            result = subprocess.run(list(map(str, command)), cwd=shared,
                                    capture_output=True, text=True, timeout=5)
        except subprocess.TimeoutExpired:
            continue
        lines = result.stdout.splitlines()
        if len(lines) < 2:
            continue
        record = dict(zip(lines[0].split(","), lines[1].split(",")))
        if int(record.get(f"{bug}_T", "0")) > 0:
            return str(path), index + 1
    return "", min(len(inputs), max_inputs) if max_inputs else len(inputs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bug")
    parser.add_argument("--max-inputs", type=int, default=0)
    args = parser.parse_args()
    result_path = campaign.ROOT / "results/halo" / f"comparison-{args.bug}.json"
    result = json.loads(result_path.read_text())
    for arm in result["results"]:
        if arm["magma_trigger_count"] > 0:
            witness, checked = replay(args.bug, arm["mode"], args.max_inputs)
            arm["replayed_trigger_witness"] = witness
            arm["replay_inputs_checked"] = checked
            print(arm["mode"], checked, witness or "no retained witness", flush=True)
    result_path.write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
