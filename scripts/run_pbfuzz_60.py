#!/usr/bin/env python3
"""Run all frozen Magma rows sequentially with the current author PBFuzz.

Without --execute, print the exact pending list and make no model calls.
"""
import argparse
import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results/pbfuzz"


def rows() -> list[tuple[str, str, str]]:
    text = (ROOT / "docs/tractfuzz_magma_benchmarks.md").read_text()
    found = re.findall(
        r"^\|\s*\d+\s*\|\s*(\w+)\s*\|\s*`([A-Z]{3}\d{3})`\s*\|\s*`([^`]+)`\s*\|",
        text, re.M,
    )
    if len(found) != 60 or len({bug for _, bug, _ in found}) != 60:
        raise SystemExit("expected 60 distinct fixed benchmark rows")
    return [(bug, project, entry) for project, bug, entry in found]


def phase(project: str, bug: str, track: str) -> str:
    if track == "fixed":
        state = ROOT / "magma/work/idfuzz" / bug / "target/repo/.pbfuzz" / f"fixed-{bug.lower()}" / "state/state.json"
    else:
        state = RESULTS / "work" / project / "repo/.pbfuzz" / f"{project}-{bug}".lower() / "state/state.json"
    if not state.is_file():
        return "not_attempted"
    try:
        return str(json.loads(state.read_text()).get("phase", "unknown"))
    except (OSError, ValueError):
        return "invalid_state"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true", help="make model calls and build targets")
    parser.add_argument("--track", choices=("fixed", "author"), default="fixed")
    parser.add_argument("--bug-id", action="append", help="restrict to these fixed IDs")
    parser.add_argument("--max-rows", type=int, default=0, help="stop after this many rows; 0 means all")
    parser.add_argument("--rounds", type=int, default=1)
    parser.add_argument("--wall-min", type=int, default=3)
    parser.add_argument("--max-iters", type=int, default=100)
    parser.add_argument("--hard-wall-sec", type=int, default=360)
    parser.add_argument("--include-completed", action="store_true")
    args = parser.parse_args()
    if min(args.rounds, args.wall_min, args.max_iters, args.hard_wall_sec) < 1 or args.max_rows < 0:
        parser.error("budgets must be positive and --max-rows nonnegative")
    selected = [row for row in rows() if not args.bug_id or row[0] in args.bug_id]
    if args.bug_id and set(args.bug_id) - {row[0] for row in selected}:
        parser.error("one or more bug IDs are outside the frozen 60")
    if not args.include_completed:
        selected = [row for row in selected if phase(row[1], row[0], args.track) not in ("SUCCESS", "STOPPED")]
    if args.max_rows:
        selected = selected[:args.max_rows]
    print(json.dumps({"execute": args.execute, "track": args.track,
                      "rows": len(selected), "bug_ids": [r[0] for r in selected]}))
    if not args.execute:
        return
    RESULTS.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env.update(PBFUZZ_MAX_ROUNDS=str(args.rounds), PBFUZZ_WALL_MIN=str(args.wall_min),
               PBFUZZ_MAX_ITERS=str(args.max_iters), PBFUZZ_HARD_WALL_SEC=str(args.hard_wall_sec))
    runner = ROOT / "scripts" / ("run_pbfuzz_fixed.sh" if args.track == "fixed" else "run_pbfuzz_magma.sh")
    ledger = RESULTS / f"batch-status-{args.track}.jsonl"
    for bug, project, entry in selected:
        started = datetime.now(timezone.utc)
        command = [str(runner), bug] if args.track == "fixed" else [str(runner), bug, project, entry]
        run = subprocess.run(command,
                             cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        final_phase = phase(project, bug, args.track)
        replay = None
        if args.track == "fixed" and final_phase == "SUCCESS":
            checked = subprocess.run(
                ["python3", str(ROOT / "scripts/pbfuzz_fixed_replay.py"), bug],
                cwd=ROOT, capture_output=True, text=True,
            )
            try:
                replay = json.loads(checked.stdout) if checked.returncode == 0 else {
                    "error": checked.stderr.strip()[-1000:], "exit_code": checked.returncode,
                }
            except ValueError:
                replay = {"error": "invalid replay output", "exit_code": checked.returncode}
        record = {
            "schema": 1, "track": args.track, "bug_id": bug, "project": project, "fixed_entry": entry,
            "started_at": started.isoformat(), "finished_at": datetime.now(timezone.utc).isoformat(),
            "exit_code": run.returncode, "phase": final_phase, "replay": replay,
            "round_limit": args.rounds, "wall_minutes": args.wall_min,
            "max_iterations": args.max_iters, "hard_wall_seconds": args.hard_wall_sec,
        }
        with ledger.open("a") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
        print(json.dumps(record, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
