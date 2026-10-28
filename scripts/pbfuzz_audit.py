#!/usr/bin/env python3
"""Audit PBFuzz applicability against the frozen 60 Magma entry/bug rows."""
import csv
import hashlib
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results/pbfuzz"
ARCHIVED = {
    "LUA001": ("lua", "lua", "@@"),
    "PDF002": ("poppler", "pdftoppm", "-mono -cropbox @@"),
    "PHP014": ("php", "unserialize", "@@"),
    "PNG006": ("libpng", "libpng_read_fuzzer", "@@"),
    "SND001": ("libsndfile", "sndfile_fuzzer", "@@"),
    "SQL012": ("sqlite3", "sqlite3_fuzz", "@@"),
    "SSL002": ("openssl", "server", "@@"),
    "TIF006": ("libtiff", "tiffcp", "-M @@ tmp.out"),
    "XML002": ("libxml2", "xmllint", "--valid --oldxml10 --push --memory @@"),
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else ""


def main() -> None:
    benchmark = (ROOT / "docs/tractfuzz_magma_benchmarks.md").read_text()
    rows = re.findall(
        r"^\|\s*(\d+)\s*\|\s*(\w+)\s*\|\s*`([A-Z]{3}\d{3})`\s*\|\s*`([^`]+)`\s*\|",
        benchmark,
        re.M,
    )
    if len(rows) != 60 or len({row[2] for row in rows}) != 60:
        raise SystemExit("fixed benchmark parsing did not yield 60 distinct rows")
    model_probe = RESULTS / "api-probe.json"
    model_ok = model_probe.is_file() and json.loads(model_probe.read_text()).get("status") == "ok"
    out = []
    for number, project, bug, entry in rows:
        artifact = ARCHIVED.get(bug)
        source = RESULTS / "source/magma-author/targets" / project
        configrc = source / "configrc"
        binary = RESULTS / "work" / project / "out" / entry
        campaign = RESULTS / "work" / project / "campaigns" / f"{bug}.campaign.yaml"
        if bug == "PDF020" and (RESULTS / "work/pdf020-fixed/PDF020.campaign.yaml").is_file():
            campaign = RESULTS / "work/pdf020-fixed/PDF020.campaign.yaml"
        model_config = RESULTS / f"{bug}-model-config.json"
        state_path = RESULTS / "work" / project / "repo/.pbfuzz" / f"{project}-{bug}".lower() / "state/state.json"
        log_path = RESULTS / f"{bug}-run.log"
        state = "not_attempted"
        track = "current_author_dsh"
        if log_path.is_file():
            state = "attempted_no_state"
        if bug == "PDF020" and log_path.is_file():
            track = "fixed_binary_monitor_oracle_adaptation"
            state_path = ROOT / "magma/work/idfuzz/PDF020/target/repo/.pbfuzz/pdf020-fixed/state/state.json"
        if state_path.is_file():
            try:
                state_obj = json.loads(state_path.read_text())
                state = str(state_obj.get("phase") or state_obj.get("status") or "state_written")
            except (OSError, ValueError):
                state = "invalid_state"
        if bug == "PDF020" and (RESULTS / "PDF020-interruption.json").is_file():
            state = "interrupted_in_PLAN"
        replay_path = RESULTS / f"{bug}-replay.json"
        replay = json.loads(replay_path.read_text()) if replay_path.is_file() else None
        author_trials = replay["author_binary"]["trials"] if replay else []
        fixed_trials = replay["fixed_benchmark_binary"]["trials"] if replay else []
        out.append({
            "number": number,
            "project": project,
            "bug_id": bug,
            "fixed_entry": entry,
            "archived_prepared": str(artifact is not None).lower(),
            "archived_entry": artifact[1] if artifact else "",
            "archived_args": artifact[2] if artifact else "",
            "archived_exact_entry": str(artifact is not None and artifact[1] == entry).lower(),
            "current_source_available": str((source / "configrc").is_file()).lower(),
            "current_entry_declared": str(configrc.is_file() and bool(re.search(r"\b" + re.escape(entry) + r"\b", configrc.read_text()))).lower(),
            "current_binary_ready": str(binary.is_file() and bool(binary.stat().st_mode & 0o111)).lower(),
            "current_binary_sha256": sha256(binary),
            "campaign_ready": str(campaign.is_file()).lower(),
            "campaign_sha256": sha256(campaign),
            "model_config_sha256": sha256(model_config),
            "author_magma_commit": "a6ec7b915a478306d0727f07848172500c3c4e11",
            "model_api_verified": str(model_ok).lower(),
            "current_run_state": state,
            "run_track": track,
            "witness_sha256": replay["witness_sha256"] if replay else "",
            "author_trigger_replays": sum(int(trial.get("triggered_lines", 0) > 0) for trial in author_trials) if replay else "",
            "fixed_trigger_replays": sum(int(trial.get("monitor_triggered", 0) > 0) for trial in fixed_trials) if replay else "",
            "fixed_replay_timeouts": sum(int(trial.get("timeout", False)) for trial in fixed_trials) if replay else "",
        })
    RESULTS.mkdir(parents=True, exist_ok=True)
    path = RESULTS / "applicability-60.csv"
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(out[0]))
        writer.writeheader()
        writer.writerows(out)
    summary = {
        "fixed_rows": len(out),
        "archived_prepared_overlap": sum(row["archived_prepared"] == "true" for row in out),
        "archived_exact_entry_overlap": sum(row["archived_exact_entry"] == "true" for row in out),
        "current_source_available": sum(row["current_source_available"] == "true" for row in out),
        "current_entry_declared": sum(row["current_entry_declared"] == "true" for row in out),
        "current_binary_ready": sum(row["current_binary_ready"] == "true" for row in out),
        "attempted": sum(row["current_run_state"] != "not_attempted" for row in out),
        "model_api_verified": model_ok,
    }
    (RESULTS / "applicability-summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    main()
