#!/usr/bin/env python3
"""Expose a fixed Magma monitor's row counts as PBFuzz's text oracle.

This is a fixed-benchmark adaptation, separate from the standalone author run.
"""
import argparse
import csv
import os
import signal
import subprocess
import sys
import tempfile
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--monitor", required=True)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--bug-id", required=True)
    parser.add_argument("--entry", help="fixed benchmark entry name for CLI argument mapping")
    parser.add_argument("--input", required=True)
    args = parser.parse_args()
    entry = args.entry or Path(args.binary).name
    with tempfile.TemporaryDirectory(prefix="pbfuzz-oracle-") as temporary:
        if entry == "tiffcp":
            target_args = ["-M", args.input, str(Path(temporary) / "copy.tif")]
        elif entry == "xmllint":
            target_args = ["--valid", "--oldxml10", "--push", "--memory", args.input]
        elif entry == "pdfimages":
            target_args = [args.input, str(Path(temporary) / "image")]
        elif entry == "pdftoppm":
            target_args = ["-mono", "-cropbox", args.input]
        else:
            target_args = [args.input]
        command = [args.monitor, "--dump", "row", "--fetch", "watch", args.binary, *target_args]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   start_new_session=True)
        try:
            stdout, stderr = process.communicate(timeout=float(os.environ.get("PBFUZZ_ORACLE_TIMEOUT_SEC", "6")))
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.communicate()
            raise SystemExit(124)
    if stderr:
        sys.stderr.buffer.write(stderr[-8192:])
    lines = stdout.decode("utf-8", errors="replace").splitlines()
    if len(lines) >= 2:
        fields = next(csv.reader([lines[0]]))
        values = next(csv.reader([lines[1]]))
        counts = dict(zip(fields, values))
        if int(counts.get(args.bug_id + "_R", "0")) > 0:
            print(f"MAGMA: Bug {args.bug_id} reached", file=sys.stderr)
        if int(counts.get(args.bug_id + "_T", "0")) > 0:
            print(f"MAGMA: Bug {args.bug_id} triggered", file=sys.stderr)
    raise SystemExit(process.returncode)


if __name__ == "__main__":
    main()
