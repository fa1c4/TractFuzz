#!/usr/bin/env python3
"""Summarize every frozen Magma row in the DeepSeek-backed PBFuzz track."""
import csv
import json
import re
from collections import Counter
from datetime import datetime
from pathlib import Path

from run_pbfuzz_60 import ROOT, RESULTS, rows


def read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return {}


def main() -> None:
    attempted_ledger = set()
    ledger = RESULTS / "batch-status-fixed.jsonl"
    if ledger.is_file():
        for line in ledger.read_text().splitlines():
            try:
                attempted_ledger.add(json.loads(line)["bug_id"])
            except (ValueError, KeyError):
                continue
    usage_path = RESULTS / "usage.json"
    usage = read_json(usage_path)
    if not isinstance(usage, list):
        usage = []
    usage_by_bug = {}
    for item in usage:
        if item.get("track") == "fixed" and item.get("isolated_source"):
            usage_by_bug.setdefault(item["bug_id"], []).append(item)
    fields = ["bug_id", "project", "fixed_entry", "attempted", "model", "hard_wall_seconds",
              "max_pier_rounds", "pier_wall_minutes", "max_fuzz_iterations", "isolated_source",
              "original_work_hidden", "landlock_read_boundary", "prior_witness_reference",
              "phase", "exit_code",
              "agent_wall_seconds", "pov_bytes", "replay_trigger_trials", "replay_reach_trials",
              "replay_timeouts", "replay_binary_hash_match", "generated_candidates_scanned", "generated_reached",
              "generated_trigger_trials", "model_calls", "input_tokens", "cache_read_tokens",
              "output_tokens", "evidence_dir"]
    records = []
    for bug, project, entry in rows():
        evidence = RESULTS / "fixed" / bug
        run = read_json(evidence / "run.json")
        manifest = read_json(evidence / "manifest.json")
        model_config = read_json(evidence / "model-config.json")
        state = read_json(Path(manifest["output_dir"]) / "state/state.json") if manifest else {}
        replay = read_json(evidence / "replay.json")
        generated_scan = read_json(evidence / "generated-scan.json")
        run_log = (evidence / "run.log").read_text(errors="replace") if (evidence / "run.log").is_file() else ""
        trials = replay.get("fixed_benchmark_binary", {}).get("trials", [])
        pov = state.get("poc", {}).get("input_path", "")
        pov_path = Path(pov) if pov else None
        tokens = {"model_calls": 0, "input_tokens": 0,
                  "cache_read_tokens": 0, "output_tokens": 0}
        run_started = datetime.fromisoformat(run["started_at"].replace("Z", "+00:00")) \
            if run.get("started_at") else None
        used_sessions = [item for item in usage_by_bug.get(bug, [])
                         if run_started and item.get("session_started_at") and
                         datetime.fromisoformat(item["session_started_at"].replace("Z", "+00:00"))
                         >= run_started]
        for item in used_sessions:
            for key in tokens:
                tokens[key] += item.get(key, 0)
        records.append({
            "bug_id": bug, "project": project, "fixed_entry": entry,
            "attempted": int(bool(run) or bug in attempted_ledger),
            "model": model_config.get("model", ""),
            "hard_wall_seconds": run.get("hard_wall_seconds", ""),
            "max_pier_rounds": model_config.get("budget", {}).get("maxPierRounds", ""),
            "pier_wall_minutes": model_config.get("budget", {}).get("campaignWallTimeMin", ""),
            "max_fuzz_iterations": model_config.get("fuzzing", {}).get("maxIters", ""),
            "isolated_source": int(str(manifest.get("source_repo", "")).startswith(
                str(RESULTS / "isolated"))) if manifest else "",
            "original_work_hidden": run.get("original_work_hidden", ""),
            "landlock_read_boundary": run.get("landlock_read_boundary", ""),
            "prior_witness_reference": int(bool(re.search(
                r"trigger_witness_|shared/findings_|known trigger witness|prior baseline witness",
                run_log, re.I)))
                if run_log else "",
            "phase": state.get("phase", "not_attempted"),
            "exit_code": run.get("exit_code", ""),
            "agent_wall_seconds": run.get("elapsed_seconds", ""),
            "pov_bytes": pov_path.stat().st_size if pov_path and pov_path.is_file() else "",
            "replay_trigger_trials": sum(t.get("monitor_triggered", 0) > 0 for t in trials) if replay else "",
            "replay_reach_trials": sum(t.get("monitor_reached", 0) > 0 for t in trials) if replay else "",
            "replay_timeouts": sum(bool(t.get("timeout")) for t in trials) if replay else "",
            "replay_binary_hash_match": int(replay.get("fixed_benchmark_binary", {}).get(
                "binary_sha256") == manifest.get("binary_sha256")) if replay else "",
            "generated_candidates_scanned": generated_scan.get("scanned", ""),
            "generated_reached": generated_scan.get("reached", ""),
            "generated_trigger_trials": (generated_scan.get("trigger") or {}).get("trigger_trials", 0)
                if generated_scan else "",
            "model_calls": tokens["model_calls"] if used_sessions else "",
            "input_tokens": tokens["input_tokens"] if used_sessions else "",
            "cache_read_tokens": tokens["cache_read_tokens"] if used_sessions else "",
            "output_tokens": tokens["output_tokens"] if used_sessions else "",
            "evidence_dir": str(evidence.relative_to(ROOT)) if evidence.exists() else "",
        })
    output = ROOT / "fuzzers/pbfuzz/fixed-60.csv"
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(records)
    summary = {
        "rows": len(records), "attempted": sum(r["attempted"] for r in records),
        "phases": dict(Counter(r["phase"] for r in records)),
        "replay_3_of_3": sum(r["replay_trigger_trials"] == 3 for r in records),
        "generated_replay_3_of_3": sum(r["generated_trigger_trials"] == 3 for r in records),
        "generated_reached_without_trigger": sum(
            isinstance(r["generated_reached"], int) and r["generated_reached"] > 0
            and r["replay_trigger_trials"] == "" and r["generated_trigger_trials"] == 0
            for r in records),
        "binary_hash_mismatches": sum(r["replay_binary_hash_match"] == 0 for r in records),
        "prior_witness_references": sum(r["prior_witness_reference"] == 1 for r in records),
        "landlock_runs": sum(r["landlock_read_boundary"] is True for r in records),
        "replay_partial": sum(isinstance(r["replay_trigger_trials"], int)
                              and 0 < r["replay_trigger_trials"] < 3 for r in records),
        "replay_zero": sum(r["replay_trigger_trials"] == 0 for r in records),
        "missing_replay": sum(r["phase"] == "SUCCESS" and r["replay_trigger_trials"] == ""
                              for r in records),
        "matrix": str(output.relative_to(ROOT)),
    }
    (RESULTS / "fixed-summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    main()
