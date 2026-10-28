#!/usr/bin/env python3
"""Import a PBFuzz-generated file as a provenance-tagged LibAFLGo seed."""
import argparse
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bug-id", required=True)
    parser.add_argument("--entry", required=True)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--generator-id", required=True)
    parser.add_argument("--corpus", type=Path, required=True,
                        help="LibAFLGo initial corpus directory for the same fixed row")
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Z]{3}\d{3}", args.bug_id):
        parser.error("invalid bug ID")
    rows = re.findall(
        r"^\|\s*\d+\s*\|\s*\w+\s*\|\s*`([A-Z]{3}\d{3})`\s*\|\s*`([^`]+)`\s*\|",
        (ROOT / "docs/tractfuzz_magma_benchmarks.md").read_text(), re.M,
    )
    fixed = dict(rows)
    if fixed.get(args.bug_id) != args.entry:
        parser.error("entry does not match the frozen benchmark row")
    data = args.input.read_bytes()
    if not data:
        parser.error("empty PBFuzz seed")
    config_path = ROOT / "results/pbfuzz" / f"{args.bug_id}-model-config.json"
    if not config_path.is_file():
        parser.error("model configuration provenance is missing")
    config_bytes = config_path.read_bytes()
    seed_hash = digest(data)
    args.corpus.mkdir(parents=True, exist_ok=True)
    destination = args.corpus / f"pbfuzz-{args.bug_id}-{seed_hash[:16]}"
    if destination.exists() and destination.read_bytes() != data:
        parser.error("seed destination hash collision")
    destination.write_bytes(data)
    record = {
        "schema": 1,
        "track": "PBFuzz + LibAFLGo seed import",
        "bug_id": args.bug_id,
        "fixed_entry": args.entry,
        "generator_id": args.generator_id,
        "source_path": str(args.input.resolve()),
        "seed_sha256": seed_hash,
        "bytes": len(data),
        "model_config_sha256": digest(config_bytes),
        "imported_at": datetime.now(timezone.utc).isoformat(),
        "corpus_path": str(destination.resolve()),
    }
    ledger_dir = ROOT / "results/pbfuzz/adapter" / args.bug_id
    ledger_dir.mkdir(parents=True, exist_ok=True)
    ledger = ledger_dir / "provenance.jsonl"
    with ledger.open("a") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")
    print(json.dumps(record, sort_keys=True))


if __name__ == "__main__":
    main()
