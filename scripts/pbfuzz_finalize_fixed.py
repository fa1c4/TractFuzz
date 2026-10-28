#!/usr/bin/env python3
"""Scan unfinished generated inputs, collect model usage, and refresh the 60-row audit."""
import json
import subprocess
from pathlib import Path

from run_pbfuzz_60 import ROOT, RESULTS, rows


def call(*args: str, quiet: bool = False) -> None:
    subprocess.run(["python3", str(ROOT / "scripts" / args[0]), *args[1:]],
                   cwd=ROOT, check=True, stdout=subprocess.DEVNULL if quiet else None)


def main() -> None:
    for bug, _, _ in rows():
        work = RESULTS / "fixed" / bug
        run_path = work / "run.json"
        manifest_path = work / "manifest.json"
        if not run_path.is_file() or not manifest_path.is_file():
            continue
        manifest = json.loads(manifest_path.read_text())
        state_path = Path(manifest["output_dir"]) / "state/state.json"
        phase = json.loads(state_path.read_text()).get("phase") if state_path.is_file() else "no_state"
        scan_path = work / "generated-scan.json"
        # A later campaign can replace run.json and generate new inputs after an
        # earlier scan. Refresh the scan whenever it predates that campaign.
        if phase != "SUCCESS" and (
            not scan_path.is_file() or scan_path.stat().st_mtime_ns < run_path.stat().st_mtime_ns
        ):
            call("pbfuzz_scan_generated.py", bug, "--max-candidates", "500", "--wall-sec", "120")
    call("pbfuzz_usage.py", quiet=True)
    call("pbfuzz_audit_fixed.py")


if __name__ == "__main__":
    main()
