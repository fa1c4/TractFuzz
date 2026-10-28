#!/usr/bin/env python3
"""Independently scan PBFuzz-generated inputs when an engine run did not finish."""
import argparse
import json
import re
import time
from pathlib import Path

from pbfuzz_replay import invoke, replay, sha256


ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bug_id")
    parser.add_argument("--max-candidates", type=int, default=500)
    parser.add_argument("--wall-sec", type=int, default=120)
    args = parser.parse_args()
    work = ROOT / "results/pbfuzz/fixed" / args.bug_id
    manifest = json.loads((work / "manifest.json").read_text())
    if manifest["bug_id"] != args.bug_id:
        parser.error("manifest bug ID mismatch")
    binary = Path(manifest["binary"])
    monitor = binary.parent / "monitor"
    output = Path(manifest["output_dir"])
    candidates = sorted(p for folder in ("crashes", "testcases")
                        for p in (output / folder).rglob("*") if p.is_file())
    started = time.monotonic()
    scanned = 0
    reached = 0
    trigger = None
    for candidate in candidates:
        if scanned >= args.max_candidates or time.monotonic() - started >= args.wall_sec:
            break
        if candidate.stat().st_size > 16 * 1024 * 1024:
            continue
        command = ["python3", str(ROOT / "scripts/pbfuzz_monitor_oracle.py"),
                   "--monitor", str(monitor), "--binary", str(binary),
                   "--bug-id", args.bug_id, "--entry", manifest["fixed_entry"],
                   "--input", str(candidate)]
        _, _, stderr = invoke(command, ROOT)
        scanned += 1
        stderr_text = stderr.decode("utf-8", errors="replace")
        reached += bool(re.search(rf"MAGMA: Bug {re.escape(args.bug_id)} reached", stderr_text))
        if re.search(rf"MAGMA: Bug {re.escape(args.bug_id)} triggered", stderr_text):
            evidence = replay(binary, candidate, args.bug_id, manifest["fixed_entry"], monitor)
            trials = evidence["trials"]
            trigger = {
                "input": str(candidate), "input_sha256": sha256(candidate),
                "input_bytes": candidate.stat().st_size,
                "trigger_trials": sum(t.get("monitor_triggered", 0) > 0 for t in trials),
                "reach_trials": sum(t.get("monitor_reached", 0) > 0 for t in trials),
                "timeouts": sum(bool(t.get("timeout")) for t in trials),
                "replay": evidence,
            }
            break
    record = {"schema": 1, "bug_id": args.bug_id, "generated_candidates": len(candidates),
              "scanned": scanned, "reached": reached, "elapsed_seconds": round(time.monotonic() - started, 3),
              "trigger": trigger}
    (work / "generated-scan.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps({key: value for key, value in record.items() if key != "trigger"}
                     | {"trigger_trials": trigger["trigger_trials"] if trigger else 0}, sort_keys=True))


if __name__ == "__main__":
    main()
