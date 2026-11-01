#!/usr/bin/env python3
"""Measure one reproducible IDFuzz CLI window alongside the host RAID."""
import argparse
import json
import os
import shutil
import signal
import subprocess
import tempfile
import time
from pathlib import Path


def process_io(pid):
    return {key: int(value) for key, value in
            (line.split(": ", 1) for line in Path(f"/proc/{pid}/io").read_text().splitlines())}


def disk_io(device):
    fields = Path(f"/sys/block/{device}/stat").read_text().split()
    return [int(value) for value in fields]


def file_count(path):
    return sum(item.is_file() for item in path.iterdir()) if path.is_dir() else 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--seed", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--device", default="sda")
    parser.add_argument("--seconds", type=int, default=10)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    seeds = args.output / "seeds"
    seeds.mkdir()
    shutil.copyfile(args.seed, seeds / args.seed.name)
    findings = args.output / "findings"
    command = [str(args.binary.resolve()), "--target", str(args.target.resolve()),
               "--input", str(seeds), "--output", str(findings), "--control",
               "--logfile", str(args.output / "fuzzer.log"),
               "--idfuzz-seed", "1337", "--", "@@"]
    with (args.output / "stdout.log").open("w") as stdout:
        process = subprocess.Popen(command, stdout=stdout, stderr=subprocess.STDOUT,
                                   start_new_session=True)
        try:
            time.sleep(2)
            if process.poll() is not None:
                raise RuntimeError(f"fuzzer exited with {process.returncode}")
            before_process = process_io(process.pid)
            before_disk = disk_io(args.device)
            start = time.monotonic()
            time.sleep(args.seconds)
            elapsed = time.monotonic() - start
            after_process = process_io(process.pid)
            after_disk = disk_io(args.device)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGINT)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
    # SIGINT bypasses Rust Drop; a container normally discards its tmpfs on exit.
    for scratch in Path(tempfile.gettempdir()).glob(f"idfuzz-cli-{process.pid}-*"):
        shutil.rmtree(scratch)
    writes = after_disk[4] - before_disk[4]
    report = {
        "binary": str(args.binary.resolve()), "target": str(args.target.resolve()),
        "seed": str(args.seed.resolve()), "seed_bytes": args.seed.stat().st_size,
        "seconds": elapsed, "process_write_bytes": after_process["write_bytes"] - before_process["write_bytes"],
        "process_write_calls": after_process["syscw"] - before_process["syscw"],
        "raid_write_bytes": (after_disk[6] - before_disk[6]) * 512,
        "raid_write_iops": writes / elapsed,
        "raid_write_await_ms": (after_disk[7] - before_disk[7]) / writes if writes else 0,
        "raid_average_queue": (after_disk[10] - before_disk[10]) / (elapsed * 1000),
        "queue_files": file_count(findings / "queue"),
        "queue_inputs": sum(not path.name.startswith(".") for path in (findings / "queue").iterdir()),
        "queue_metadata_bytes": sum(path.stat().st_size for path in (findings / "queue").glob("*.metadata")),
        "crash_files": file_count(findings / "crashes"),
        "result_file_bytes": sum(path.stat().st_size for path in findings.rglob("*") if path.is_file()),
        "result_allocated_bytes": sum(path.stat().st_blocks * 512 for path in findings.rglob("*") if path.is_file()),
    }
    (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
