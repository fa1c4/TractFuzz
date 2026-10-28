#!/usr/bin/env python3
"""Summarize DSH model usage per PBFuzz Magma campaign without storing prompts."""
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results/pbfuzz"


def main() -> None:
    summaries = []
    homes = [RESULTS / "dsh-home", *(RESULTS / "dsh-homes").glob("*")]
    for path in (session for home in homes for session in
                 (home / "sessions").rglob("session.v4.jsonl.zstd")):
        raw = subprocess.check_output(["zstd", "-dc", str(path)])
        events = [json.loads(line) for line in raw.splitlines() if line.strip()]
        commands = [str(event.get("data", {})) for event in events
                    if event.get("type") == "user/message"]
        bugs = sorted(set(re.findall(r"([A-Z]{3}\d{3})(?:\.fixed)?\.campaign\.yaml", " ".join(commands))))
        if len(bugs) != 1:
            continue
        usage = [event.get("data", {}).get("usage", {}) for event in events
                 if event.get("type") == "assistant/message"]
        summaries.append({
            "bug_id": bugs[0],
            "session_id": path.parent.name,
            "session_started_at": datetime.fromtimestamp(
                int(events[0].get("createdAt", 0)) / 1000, timezone.utc
            ).isoformat().replace("+00:00", "Z"),
            "track": "fixed" if any(".fixed.campaign.yaml" in command for command in commands) else "author",
            "isolated_source": any("/results/pbfuzz/isolated/" in command for command in commands),
            "model_calls": sum(bool(item) for item in usage),
            "input_tokens": sum(int(item.get("inputTokens", 0)) for item in usage),
            "cache_read_tokens": sum(int(item.get("cacheReadTokens", 0)) for item in usage),
            "cache_write_tokens": sum(int(item.get("cacheWriteTokens", 0)) for item in usage),
            "output_tokens": sum(int(item.get("outputTokens", 0)) for item in usage),
            "total_tokens": sum(int(item.get("totalTokens", 0)) for item in usage),
            "unmetered_title_requests": sum(event.get("type") == "session/title-llm-request" for event in events),
            "tool_calls": sum(event.get("type") == "tool/call" for event in events),
            "session_archive": str(path),
        })
    summaries.sort(key=lambda item: (item["bug_id"], item["session_id"]))
    (RESULTS / "usage.json").write_text(json.dumps(summaries, indent=2) + "\n")
    print(json.dumps(summaries, indent=2))


if __name__ == "__main__":
    main()
