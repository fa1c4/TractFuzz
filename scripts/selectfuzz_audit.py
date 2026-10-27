#!/usr/bin/env python3
"""Materialize fixed-row build, target, and corpus evidence for SelectFuzz."""

import csv
import hashlib
import json
import re
from pathlib import Path

import selectfuzz_magma as campaign


def digest_file(path):
    if not path.is_file():
        return ""
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def digest_corpus(path):
    if not path.is_dir():
        return ""
    h = hashlib.sha256()
    for file in sorted(p for p in path.rglob("*") if p.is_file()):
        h.update(str(file.relative_to(path)).encode())
        h.update(b"\0")
        h.update(bytes.fromhex(digest_file(file)))
    return h.hexdigest()


def manifest_counts(path):
    if not path.is_file():
        return ("", "", "")
    with path.open() as stream:
        rows = csv.DictReader((line for line in stream if not line.startswith("#")),
                              delimiter="\t")
        all_blocks = selected = targets = 0
        for block in rows:
            all_blocks += 1
            selected += int(block["id"] != "0")
            targets += int(bool(int(block["kind"]) & 4))
    return str(all_blocks), str(selected), str(targets)


def observed_campaign_seconds(path):
    if not path.is_file():
        return ""
    for line in reversed(path.read_text(errors="replace").splitlines()):
        match = re.search(r"run time: (\d+)h-(\d+)m-(\d+)s", line)
        if match:
            hours, minutes, seconds = map(int, match.groups())
            return str(hours * 3600 + minutes * 60 + seconds)
    return ""


def monitor_stats(path):
    if not path.is_file():
        return ("", "", "")
    for line in reversed(path.read_text(errors="replace").splitlines()):
        match = re.search(r"edges: (\d+)/", line)
        if match:
            minimum = re.search(r"distance_min: ([0-9.]+)", line)
            maximum = re.search(r"distance_max: ([0-9.]+)", line)
            return (match.group(1), minimum.group(1) if minimum else "",
                    maximum.group(1) if maximum else "")
    return ("", "", "")


def runtime_peaks(path):
    if not path.is_file():
        return ("", "")
    executions = probes = None
    with path.open(errors="replace") as stream:
        for line in stream:
            match = re.search(r"selectfuzz_executions=(\d+) selectfuzz_probes=(\d+)", line)
            if match:
                executions = max(executions or 0, int(match.group(1)))
                probes = max(probes or 0, int(match.group(2)))
    return (str(executions) if executions is not None else "",
            str(probes) if probes is not None else "")


def main():
    status = campaign.load_status()
    output = campaign.ROOT / "results/selectfuzz/applicability.csv"
    output.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = (
        "number", "project", "bug", "entry", "status", "detail", "trial",
        "budget_seconds", "observed_campaign_seconds", "end_to_end_seconds", "non_campaign_seconds",
        "executions", "runtime_executions_peak", "probes_peak", "reach_count",
        "trigger_count", "detected_crashes", "relevant_edge_entries",
        "minimum_distance", "maximum_distance", "probes", "improvements", "witness",
        "binary_sha256", "manifest_sha256", "target_lines_sha256",
        "seed_corpus_sha256", "seed_files", "queue_files", "seed_phase_passed",
        "method_config_sha256", "extended_cg", "blocks_total",
        "blocks_selected", "target_blocks", "target_lines", "target_invocation",
        "fuzzer_invocation",
    )
    with output.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames)
        writer.writeheader()
        for row in campaign.rows():
            bug, entry = row["bug"], row["entry"]
            base = campaign.WORK_ROOT / bug
            out = base / "out"
            binary = out / entry
            linked_entry = f"php-fuzz-{entry}" if row["project"] == "php" else entry
            manifest = out / f"selectfuzz-blocks-{linked_entry}.tsv"
            targets = out / "aflgo_targets.txt"
            corpus = base / "target/corpus" / entry
            actual = status.get(bug, {})
            is_cli = entry in campaign.CLI
            extended_cg = actual.get("extended_cg", "1" if is_cli else "0")
            stamp = out / ".selectfuzz_runtime_hash"
            config = {
                "schema": "selectfuzz-method-v1",
                "magma_revision": "cec1fec38fdc510c2cb8e6ae690e738b1042cb8d",
                "entry": entry, "bug": bug, "target_lines_sha256": digest_file(targets),
                "linked_entry": linked_entry,
                "extended_call_graph": extended_cg == "1", "clang": "/usr/bin/clang-15",
                "canaries": "MAGMA_ENABLE_CANARIES", "asan": True,
                "map_size": campaign.CLI_MAP_SIZE,
                "build_stamp": stamp.read_text().strip() if stamp.is_file() else "",
            }
            config_hash = hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()
            total, selected, target_blocks = manifest_counts(manifest)
            trial = actual.get("trial", "")
            suffix = "selectfuzz" if not trial else f"selectfuzz_{trial}"
            crashes = base / "shared" / f"findings_{suffix}" / "crashes"
            queue = base / "shared" / f"findings_{suffix}" / "queue"
            seed_files = sum(path.is_file() for path in corpus.rglob("*")) if corpus.is_dir() else 0
            queue_files = (sum(path.is_file() and not path.name.startswith(".")
                               for path in queue.rglob("*")) if queue.is_dir() else 0)
            reported_executions = actual.get("executions", "")
            seed_phase_passed = (str(int(int(reported_executions) > seed_files))
                                 if reported_executions else "")
            crash_count = (sum(p.is_file() and not p.name.startswith(".")
                               for p in crashes.iterdir()) if crashes.is_dir() else "")
            edge_entries, min_distance, max_distance = monitor_stats(
                out / f"fuzzer_{suffix}.log")
            runtime_exec_peak, probes_peak = runtime_peaks(out / f"fuzzer_{suffix}.log")
            observed = observed_campaign_seconds(out / f"fuzzer_{suffix}.log")
            end_to_end = actual.get("seconds", "")
            non_campaign = (str(round(max(0, float(end_to_end) - float(observed)), 2))
                            if observed and end_to_end else "")
            budget = int(observed) + 1 if observed and actual.get("status") == "campaign_complete" else None
            target_invocation = ([str(binary), *campaign.cli_args(entry, "@@", out)]
                                 if is_cli else [str(binary), "<input-file>"])
            fuzzer_invocation = ([str(campaign.ROOT / "target/release/selectfuzz_cli"),
                                  "--target", str(binary), "--input", str(corpus),
                                  "--output", str(base / "shared" / f"findings_{suffix}"),
                                  "--logfile", str(out / f"fuzzer_{suffix}.log"), "--",
                                  *campaign.cli_args(entry, "@@", out)] if is_cli else
                                 [str(binary), "--input", str(corpus),
                                  "--output", str(base / "shared" / f"findings_{suffix}"),
                                  "--logfile", str(out / f"fuzzer_{suffix}.log")])
            writer.writerow({
                **row,
                "status": actual.get("status") or "not_attempted",
                "detail": actual.get("detail", ""),
                "trial": trial,
                "budget_seconds": budget or "",
                "observed_campaign_seconds": observed,
                "end_to_end_seconds": end_to_end,
                "non_campaign_seconds": non_campaign,
                "executions": actual.get("executions", ""),
                "runtime_executions_peak": runtime_exec_peak,
                "probes_peak": probes_peak,
                "reach_count": actual.get("reach_count", ""),
                "trigger_count": actual.get("trigger_count", ""),
                "detected_crashes": crash_count,
                "relevant_edge_entries": edge_entries,
                "minimum_distance": min_distance,
                "maximum_distance": max_distance,
                "probes": actual.get("probes", ""),
                "improvements": actual.get("improvements", ""),
                "witness": actual.get("witness", ""),
                "binary_sha256": digest_file(binary),
                "manifest_sha256": digest_file(manifest),
                "target_lines_sha256": digest_file(targets),
                "seed_corpus_sha256": digest_corpus(corpus),
                "seed_files": seed_files,
                "queue_files": queue_files,
                "seed_phase_passed": seed_phase_passed,
                "method_config_sha256": config_hash,
                "extended_cg": extended_cg,
                "blocks_total": total,
                "blocks_selected": selected,
                "target_blocks": target_blocks,
                "target_lines": ";".join(targets.read_text().splitlines()) if targets.is_file() else "",
                "target_invocation": json.dumps(target_invocation),
                "fuzzer_invocation": json.dumps(fuzzer_invocation),
            })
    print(output)


if __name__ == "__main__":
    main()
