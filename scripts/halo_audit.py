#!/usr/bin/env python3
"""Write a fixed-row Halo applicability and provenance audit."""

import csv
import hashlib
import json
import re
import subprocess

import halo_magma as campaign


def digest_file(path):
    if not path.is_file():
        return ""
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def digest_corpus(path):
    if not path.is_dir():
        return ""
    result = hashlib.sha256()
    for file in sorted(path for path in path.rglob("*") if path.is_file()):
        result.update(str(file.relative_to(path.parent)).encode())
        result.update(b"\0")
        result.update(bytes.fromhex(digest_file(file)))
    return result.hexdigest()


def count_files(path):
    return sum(file.is_file() and not file.name.startswith(".")
               for file in path.rglob("*")) if path.is_dir() else 0


def campaign_seconds(path):
    if not path.is_file():
        return ""
    durations = []
    for line in path.read_text(errors="replace").splitlines():
        match = re.search(r"run time: (\d+)h-(\d+)m-(\d+)s", line)
        if match:
            hours, minutes, seconds = map(int, match.groups())
            durations.append(hours * 3600 + minutes * 60 + seconds)
    return str(max(durations)) if durations else ""


def halo_checkpoint(path):
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text())
        totals = data["totals"]
        return {"inference_ns": totals["inference_ns"],
                "generation_ns": totals["generation_ns"],
                "reaching_pool_size": len(data["reaching"]),
                "missing_pool_size": len(data["missing"]),
                "candidate_count": len(data["candidates"])}
    except (OSError, ValueError, KeyError):
        return {}


def project_revision(repo):
    if not (repo / ".git").is_dir():
        return ""
    try:
        return subprocess.check_output(["git", "-C", str(repo), "rev-parse", "magma-init"],
                                       stderr=subprocess.DEVNULL, text=True).strip()
    except (OSError, subprocess.CalledProcessError):
        return ""


def main():
    status = campaign.load_status()
    destination = campaign.ROOT / "results/halo/applicability.csv"
    destination.parent.mkdir(parents=True, exist_ok=True)
    budgets_path = campaign.ROOT / "results/halo/campaign-budgets.json"
    budgets = json.loads(budgets_path.read_text()) if budgets_path.is_file() else {
        "default_seconds": 60, "overrides": {}}
    benchmark_manifest_sha256 = digest_file(campaign.MANIFEST)
    budget_manifest_sha256 = digest_file(budgets_path)
    fields = ("number", "project", "bug", "entry", "status", "detail", "trial",
              "budget_seconds", "seconds", "observed_campaign_seconds", "non_campaign_seconds",
              "executions", "reach_count", "trigger_count", "halo_observed",
              "halo_reached", "halo_generated", "halo_inferences", "witness",
              "inference_ns", "generation_ns", "reaching_pool_size",
              "missing_pool_size", "candidate_count",
              "binary_sha256", "target_lines_sha256", "seed_corpus_sha256",
              "runner_sha256",
              "seed_files", "queue_files", "crash_files", "input_trace_sha256",
              "invariant_trace_sha256", "checkpoint_sha256", "method_config_sha256",
              "benchmark_manifest_sha256", "budget_manifest_sha256",
              "project_revision", "magma_patch_sha256", "input_adapter",
              "canary_mode", "sanitizer", "timeout_ms", "memory_limit_mb",
              "extended_cg", "target_lines", "target_invocation", "fuzzer_invocation")
    with destination.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for row in campaign.rows():
            bug, entry = row["bug"], row["entry"]
            actual = status.get(bug, {})
            base = campaign.WORK_ROOT / bug
            out = base / "out"
            binary = out / entry
            revision = project_revision(base / "target/repo")
            patch_sha256 = digest_file(out / f"bug_{bug}.diff")
            targets = out / "aflgo_targets.txt"
            corpus = base / "target/corpus" / entry
            trial = actual.get("trial", "")
            suffix = "halo" if not trial else f"halo_{trial}"
            findings = base / "shared" / f"findings_{suffix}"
            checkpoint = halo_checkpoint(findings / "halo-checkpoint-v1.json")
            observed = campaign_seconds(out / f"fuzzer_{suffix}.log")
            end_to_end = actual.get("seconds", "")
            budget = budgets["overrides"].get(bug, budgets["default_seconds"])
            non_campaign = (str(round(max(0.0, float(end_to_end) - float(observed)), 2))
                            if observed and end_to_end else "")
            cli = entry in campaign.CLI
            adapter = "command-file" if cli else "libfuzzer-bytes"
            archived = (campaign.ROOT / "results/halo/method-build" /
                        ("halo_cli-campaign" if cli else "libhalo-campaign.a"))
            runner = archived if archived.is_file() else (
                campaign.ROOT / "target/release/halo_cli" if cli else
                campaign.ROOT / "build/install/lib/libhalo.a")
            target_args = campaign.cli_args(entry, "@@", out) if cli else ["<input-file>"]
            target_invocation = [str(binary), *map(str, target_args)]
            if cli:
                fuzzer_invocation = [str(campaign.ROOT / "target/release/halo_cli"),
                    "--target", str(binary), "--input", str(corpus),
                    "--output", str(findings), "--logfile", str(out / f"fuzzer_{suffix}.log"),
                    "--", *map(str, target_args)]
            else:
                fuzzer_invocation = [str(binary), "--input", str(corpus),
                    "--output", str(findings), "--logfile", str(out / f"fuzzer_{suffix}.log")]
            config = {"schema": "halo-method-v1", "magma_revision": "cec1fec38fdc510c2cb8e6ae690e738b1042cb8d",
                      "bug": bug, "entry": entry, "target_lines_sha256": digest_file(targets),
                      "binary_sha256": digest_file(binary), "seed_corpus_sha256": digest_corpus(corpus),
                      "runner_sha256": digest_file(runner),
                      "project_revision": revision, "magma_patch_sha256": patch_sha256,
                      "input_adapter": adapter,
                      "extended_call_graph": actual.get("extended_cg", "1" if cli else "0") == "1",
                      "compiler": "/usr/bin/clang-15", "canaries": "MAGMA_ENABLE_CANARIES",
                      "asan": True, "timeout_ms": 1200, "memory_limit_mb": "unlimited",
                      "map_size": campaign.CLI_MAP_SIZE,
                      "build_stamp": (out / ".halo_runtime_hash").read_text().strip()
                       if (out / ".halo_runtime_hash").is_file() else ""}
            config["budget_seconds"] = budget
            config["benchmark_manifest_sha256"] = benchmark_manifest_sha256
            writer.writerow({**row, "status": actual.get("status") or "not_attempted",
                "detail": actual.get("detail", ""), "trial": trial,
                "budget_seconds": budget, "seconds": end_to_end,
                "observed_campaign_seconds": observed,
                "non_campaign_seconds": non_campaign,
                **{key: actual.get(key, "") for key in ("executions", "reach_count", "trigger_count",
                   "halo_observed", "halo_reached", "halo_generated", "halo_inferences", "witness")},
                **checkpoint,
                "binary_sha256": digest_file(binary), "target_lines_sha256": digest_file(targets),
                "runner_sha256": digest_file(runner),
                "seed_corpus_sha256": digest_corpus(corpus), "seed_files": count_files(corpus),
                "queue_files": count_files(findings / "queue"), "crash_files": count_files(findings / "crashes"),
                "input_trace_sha256": digest_file(findings / "halo-inputs-v1.tsv"),
                "invariant_trace_sha256": digest_file(findings / "halo-invariants-v1.tsv"),
                "checkpoint_sha256": digest_file(findings / "halo-checkpoint-v1.json"),
                "method_config_sha256": hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest(),
                "benchmark_manifest_sha256": benchmark_manifest_sha256,
                "budget_manifest_sha256": budget_manifest_sha256,
                "project_revision": revision, "magma_patch_sha256": patch_sha256,
                "input_adapter": adapter, "canary_mode": "MAGMA_ENABLE_CANARIES",
                "sanitizer": "address", "timeout_ms": 1200,
                "memory_limit_mb": "unlimited",
                "extended_cg": actual.get("extended_cg", "1" if cli else "0"),
                "target_lines": ";".join(targets.read_text().splitlines()) if targets.is_file() else "",
                "target_invocation": json.dumps(target_invocation),
                "fuzzer_invocation": json.dumps(fuzzer_invocation)})
    print(destination)


if __name__ == "__main__":
    main()
