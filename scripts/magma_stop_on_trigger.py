#!/usr/bin/env python3
"""Watch one Magma bug while running a campaign under `monitor --fetch watch`.

The monitor sets MAGMA_STORAGE to its private, freshly initialized mapping.
Reading the producer counters does not consume or change the monitor protocol.
"""

import argparse
import json
import mmap
import os
import signal
import struct
import subprocess
import sys
import time
from pathlib import Path


CANARY = struct.Struct("<16sQQ")
PRODUCER_OFFSET = 8  # offsetof(stored_data_t, producer_buffer) on this x86-64 build
CANARY_COUNT = 31   # BUFFERLEN in magma/magma/src/storage.h
POLL_SECONDS = 0.25


def wrap_command(command: list[str], bug: str, stamp: Path) -> list[str]:
    if os.environ.get("TRACTFUZZ_STOP_ON_TRIGGER") != "1":
        return command
    stamp.unlink(missing_ok=True)
    return [sys.executable, str(Path(__file__).resolve()), "--bug", bug,
            "--stamp", str(stamp), "--", *command]


def read_timing(stamp: Path, bug: str) -> dict:
    try:
        data = json.loads(stamp.read_text())
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) and data.get("schema") == 1 and data.get("bug") == bug else {}


def timing_metrics(stamp: Path, bug: str) -> dict[str, str]:
    data = read_timing(stamp, bug)
    result = {field: "" if data.get(field) is None else str(data[field])
              for field in ("first_reach_seconds", "first_trigger_seconds", "stop_reason")}
    result["fuzz_elapsed_seconds"] = ("" if data.get("elapsed_seconds") is None
                                      else str(data["elapsed_seconds"]))
    return result


def counts(mapping: mmap.mmap, bug: str) -> tuple[int, int]:
    expected = bug.encode()
    for index in range(CANARY_COUNT):
        name, reached, triggered = CANARY.unpack_from(
            mapping, PRODUCER_OFFSET + index * CANARY.size)
        if name.split(b"\0", 1)[0] == expected:
            return reached, triggered
        if not name[0]:
            break
    return 0, 0


def save_stamp(path: Path, record: dict) -> None:
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(record, sort_keys=True) + "\n")
    temporary.replace(path)


def run(bug: str, stamp: Path, command: list[str]) -> int:
    storage = os.environ.get("MAGMA_STORAGE")
    if not storage:
        raise RuntimeError("MAGMA_STORAGE is required; run under monitor --fetch watch")
    with open(storage, "rb") as stream:
        with mmap.mmap(stream.fileno(), 2048, access=mmap.ACCESS_READ) as mapping:
            started = time.monotonic()
            child = subprocess.Popen(command, start_new_session=True)
            record = {"schema": 1, "bug": bug, "first_reach_seconds": None,
                      "first_trigger_seconds": None, "stop_reason": None}
            stopped_for_trigger = False
            try:
                while True:
                    reached, triggered = counts(mapping, bug)
                    elapsed = time.monotonic() - started
                    changed = False
                    if reached and record["first_reach_seconds"] is None:
                        record["first_reach_seconds"] = elapsed
                        changed = True
                    if triggered and record["first_trigger_seconds"] is None:
                        record["first_trigger_seconds"] = elapsed
                        changed = True
                    if changed:
                        save_stamp(stamp, record)
                    if child.poll() is not None:
                        break
                    if triggered:
                        # Let the current target execution finish and give the
                        # fuzzer a short chance to admit its triggering input.
                        time.sleep(1)
                        if child.poll() is None:
                            child.send_signal(signal.SIGINT)
                            stopped_for_trigger = True
                        break
                    time.sleep(POLL_SECONDS)
                if stopped_for_trigger:
                    try:
                        child.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        os.killpg(child.pid, signal.SIGKILL)
                        child.wait()
                    record["stop_reason"] = "trigger"
                    record["elapsed_seconds"] = time.monotonic() - started
                    save_stamp(stamp, record)
                    return 0
                code = child.wait()
                record["stop_reason"] = "timeout" if code == 124 else "exit"
                record["elapsed_seconds"] = time.monotonic() - started
                save_stamp(stamp, record)
                return code
            finally:
                if child.poll() is None:
                    os.killpg(child.pid, signal.SIGTERM)
                    try:
                        child.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        os.killpg(child.pid, signal.SIGKILL)
                        child.wait()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bug", required=True)
    parser.add_argument("--stamp", required=True, type=Path)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("a campaign command is required after --")
    return run(args.bug, args.stamp, command)


if __name__ == "__main__":
    raise SystemExit(main())
