#!/usr/bin/env python3
"""Replay an author PBFuzz PoV on its binary and the frozen Magma entry."""
import argparse
import hashlib
import json
import os
import re
import signal
import subprocess
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def invoke(argv: list[str], cwd: Path) -> tuple[int | None, bytes, bytes]:
    process = subprocess.Popen(argv, cwd=cwd, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, start_new_session=True)
    try:
        stdout, stderr = process.communicate(timeout=5)
        return process.returncode, stdout, stderr
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.communicate()
        return None, b"", b""


def replay(binary: Path, witness: Path, bug: str, entry: str, monitor: Path | None = None) -> dict:
    if entry == "tiffcp":
        args = ["-M", str(witness), str(binary.parent / "pbfuzz-replay-copy.tif")]
    elif entry == "xmllint":
        args = ["--valid", "--oldxml10", "--push", "--memory", str(witness)]
    elif entry == "pdftoppm":
        args = ["-mono", "-cropbox", str(witness)]
    elif entry == "pdfimages":
        args = [str(witness), str(binary.parent / "pbfuzz-replay-pdfimages")]
    else:
        args = [str(witness)]
    argv = [str(binary), *args]
    if monitor is not None:
        argv = [str(monitor), "--dump", "row", "--fetch", "watch", *argv]
    result = {"binary": str(binary), "binary_sha256": sha256(binary), "argv": argv}
    trials = []
    for _ in range(3):
        started = time.monotonic()
        try:
            return_code, stdout, stderr_bytes = invoke(argv, binary.parent)
            if return_code is None:
                trials.append({"timeout": True, "elapsed_seconds": round(time.monotonic() - started, 3)})
                continue
            stderr = stderr_bytes.decode("utf-8", errors="replace")
            counts = {}
            if monitor is not None:
                lines = stdout.decode("utf-8", errors="replace").splitlines()
                if len(lines) >= 2:
                    counts = dict(zip(lines[0].split(","), lines[1].split(",")))
            trial = {
                "exit_code": return_code,
                "reached_lines": len(re.findall(rf"MAGMA: Bug {bug} reached", stderr)),
                "triggered_lines": len(re.findall(rf"MAGMA: Bug {bug} triggered", stderr)),
                "monitor_reached": int(counts.get(f"{bug}_R", "0")),
                "monitor_triggered": int(counts.get(f"{bug}_T", "0")),
                "detected_fault": return_code < 0 or "AddressSanitizer" in stderr or "runtime error:" in stderr,
                "elapsed_seconds": round(time.monotonic() - started, 3),
            }
            if monitor is not None:
                direct_code, _, direct_stderr_bytes = invoke([str(binary), *args], binary.parent)
                direct_stderr = direct_stderr_bytes.decode("utf-8", errors="replace")
                trial["target_exit_code_without_monitor"] = direct_code
                trial["target_timeout_without_monitor"] = direct_code is None
                trial["target_detected_fault_without_monitor"] = (
                    direct_code is not None and (direct_code < 0 or "AddressSanitizer" in direct_stderr
                    or "runtime error:" in direct_stderr)
                )
            trials.append(trial)
        except subprocess.TimeoutExpired:
            trials.append({"timeout": True, "elapsed_seconds": round(time.monotonic() - started, 3)})
    result["trials"] = trials
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bug_id")
    args = parser.parse_args()
    rows = re.findall(
        r"^\|\s*\d+\s*\|\s*(\w+)\s*\|\s*`([A-Z]{3}\d{3})`\s*\|\s*`([^`]+)`\s*\|",
        (ROOT / "docs/tractfuzz_magma_benchmarks.md").read_text(), re.M,
    )
    target = next(((project, entry) for project, bug, entry in rows if bug == args.bug_id), None)
    if target is None:
        parser.error("bug ID is not in the frozen 60-row benchmark")
    project, entry = target
    state_file = ROOT / "results/pbfuzz/work" / project / "repo/.pbfuzz" / f"{project}-{args.bug_id}".lower() / "state/state.json"
    if not state_file.is_file():
        parser.error("author campaign state not found")
    state = json.loads(state_file.read_text())
    if state.get("phase") != "SUCCESS" or not state.get("poc", {}).get("input_path"):
        parser.error("author campaign has no confirmed PoV")
    witness = Path(state["poc"]["input_path"])
    author_binary = ROOT / "results/pbfuzz/work" / project / "out" / entry
    primary_binary = ROOT / "magma/work/idfuzz" / args.bug_id / "out" / entry
    primary_monitor = primary_binary.parent / "monitor"
    for binary in (author_binary, primary_binary):
        if not binary.is_file():
            parser.error(f"replay binary missing: {binary}")
    if not primary_monitor.is_file():
        parser.error("fixed benchmark monitor is missing")
    record = {
        "schema": 1,
        "bug_id": args.bug_id,
        "fixed_entry": entry,
        "witness": str(witness),
        "witness_sha256": sha256(witness),
        "witness_bytes": witness.stat().st_size,
        "author_binary": replay(author_binary, witness, args.bug_id, entry),
        "fixed_benchmark_binary": replay(primary_binary, witness, args.bug_id, entry, primary_monitor),
    }
    output = ROOT / "results/pbfuzz" / f"{args.bug_id}-replay.json"
    output.write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps({
        "bug_id": args.bug_id,
        "author_triggers": sum(t.get("triggered_lines", 0) > 0 for t in record["author_binary"]["trials"]),
        "fixed_triggers": sum(t.get("monitor_triggered", 0) > 0 for t in record["fixed_benchmark_binary"]["trials"]),
        "trials": 3,
        "record": str(output),
    }, sort_keys=True))


if __name__ == "__main__":
    main()
