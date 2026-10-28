#!/usr/bin/env python3
"""Independently replay one fixed-Magma PBFuzz PoV through the pinned monitor."""
import argparse
import hashlib
import json
from pathlib import Path

from pbfuzz_replay import replay


ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bug_id")
    args = parser.parse_args()
    work = ROOT / "results/pbfuzz/fixed" / args.bug_id
    manifest = json.loads((work / "manifest.json").read_text())
    if manifest["bug_id"] != args.bug_id:
        parser.error("manifest bug ID mismatch")
    state_path = Path(manifest["output_dir"]) / "state/state.json"
    state = json.loads(state_path.read_text())
    if state.get("phase") != "SUCCESS" or not state.get("poc", {}).get("input_path"):
        parser.error("campaign has no successful engine-confirmed PoV")
    witness = Path(state["poc"]["input_path"])
    if not witness.is_file():
        parser.error("recorded PoV file is absent")
    binary = Path(manifest["binary"])
    monitor = binary.parent / "monitor"
    result = {
        "schema": 1,
        "track": manifest["track"],
        "bug_id": args.bug_id,
        "fixed_entry": manifest["fixed_entry"],
        "magma_commit": manifest["magma_commit"],
        "witness": str(witness),
        "witness_sha256": hashlib.sha256(witness.read_bytes()).hexdigest(),
        "witness_bytes": witness.stat().st_size,
        "fixed_benchmark_binary": replay(binary, witness, args.bug_id,
                                         manifest["fixed_entry"], monitor),
    }
    (work / "replay.json").write_text(json.dumps(result, indent=2) + "\n")
    trials = result["fixed_benchmark_binary"]["trials"]
    print(json.dumps({
        "bug_id": args.bug_id,
        "trigger_trials": sum(trial.get("monitor_triggered", 0) > 0 for trial in trials),
        "reach_trials": sum(trial.get("monitor_reached", 0) > 0 for trial in trials),
        "timeouts": sum(bool(trial.get("timeout")) for trial in trials),
        "record": str(work / "replay.json"),
    }, sort_keys=True))


if __name__ == "__main__":
    main()
