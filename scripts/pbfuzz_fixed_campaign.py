#!/usr/bin/env python3
"""Prepare one exact-entry fixed-Magma campaign for the author DSH PBFuzz engine."""
import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results/pbfuzz"
AUTHOR = RESULTS / "source/github"
FIXED = ROOT / "magma/work/idfuzz"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def make_isolated_git_objects_self_contained(repo: Path) -> None:
    """Copy alternate Git objects into the isolated workspace copy only."""
    source_root = Path(os.environ["TRACTFUZZ_SOURCE_ROOT"]).resolve()
    workspace = source_root / "workspace"
    if not repo.resolve().is_relative_to(workspace):
        raise RuntimeError("refusing to update Git objects outside workspace")
    objects = repo / ".git/objects"
    alternates = objects / "info/alternates"
    if not alternates.is_file():
        return
    visited = {objects.resolve()}
    sources = []
    def collect(source: Path) -> None:
        source = source.resolve()
        if source in visited:
            return
        if not source.is_dir():
            raise RuntimeError(f"missing Git alternate for {repo}: {source}")
        visited.add(source)
        nested = source / "info/alternates"
        if nested.is_file():
            for line in nested.read_text().splitlines():
                if line.strip():
                    collect(Path(line.strip()))
        sources.append(source)
    for line in alternates.read_text().splitlines():
        if line.strip():
            collect(Path(line.strip()))
    for source in sources:
        subprocess.run(["cp", "-a", "--reflink=auto", str(source) + "/.",
                        str(objects)], check=True)
    alternates.unlink(missing_ok=True)


def fixed_rows() -> dict[str, tuple[str, str]]:
    content = (ROOT / "docs/tractfuzz_magma_benchmarks.md").read_text()
    rows = re.findall(
        r"^\|\s*\d+\s*\|\s*(\w+)\s*\|\s*`([A-Z]{3}\d{3})`\s*\|\s*`([^`]+)`\s*\|",
        content, re.M,
    )
    if len(rows) != 60:
        raise RuntimeError("expected 60 frozen Magma rows")
    return {bug: (project, entry) for project, bug, entry in rows}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bug_id")
    args = parser.parse_args()
    row = fixed_rows().get(args.bug_id)
    if row is None:
        parser.error("bug ID is outside the frozen benchmark")
    project, entry = row
    target = FIXED / args.bug_id / "target"
    repo = target / "repo"
    out = FIXED / args.bug_id / "out"
    binary = out / entry
    if not binary.is_file() and project == "php":
        binary = out / f"php-fuzz-{entry}"
    monitor = out / "monitor"
    seeds = target / "corpus" / entry
    targets = out / "aflgo_targets.txt"
    for path in (binary, monitor, targets):
        if not path.is_file():
            parser.error(f"missing fixed benchmark asset: {path}")
    if not repo.is_dir() or not seeds.is_dir():
        parser.error("fixed source or corpus is missing")
    locations = []
    for item in targets.read_text().splitlines():
        if not item.strip():
            continue
        name, number = item.rsplit(":", 1)
        source = Path(name).resolve()
        if not source.is_relative_to(repo.resolve()):
            parser.error(f"target location escapes this row's source: {item}")
        line = source.read_text(errors="replace").splitlines()[int(number) - 1]
        if f'MAGMA_LOG("{args.bug_id}"' not in line:
            parser.error(f"target line does not name {args.bug_id}: {item}")
        locations.append(f"{source.name}:{number}")
    if not locations:
        parser.error("no verified MAGMA_LOG target lines")

    work = RESULTS / "fixed" / args.bug_id
    work.mkdir(parents=True, exist_ok=True)
    isolated = RESULTS / "isolated" / args.bug_id
    isolated_repo = isolated / "repo"
    isolated_bin = isolated / "bin"
    isolated_corpus = isolated / "corpus"
    if not isolated_repo.is_dir():
        isolated.mkdir(parents=True, exist_ok=True)
        subprocess.run(["cp", "-a", "--reflink=auto", str(repo), str(isolated_repo)], check=True)
        shutil.rmtree(isolated_repo / ".pbfuzz", ignore_errors=True)
    if os.environ.get("TRACTFUZZ_EVAL_STAGED") == "1":
        make_isolated_git_objects_self_contained(isolated_repo)
    isolated_bin.mkdir(exist_ok=True)
    isolated_binary = isolated_bin / binary.name
    isolated_monitor = isolated_bin / "monitor"
    if not isolated_binary.is_file() or sha256(isolated_binary) != sha256(binary):
        shutil.copy2(binary, isolated_binary)
    if not isolated_monitor.is_file() or sha256(isolated_monitor) != sha256(monitor):
        shutil.copy2(monitor, isolated_monitor)
    if sha256(isolated_binary) != sha256(binary) or sha256(isolated_monitor) != sha256(monitor):
        parser.error("isolated binary or monitor differs from the frozen benchmark")
    if not isolated_corpus.is_dir():
        subprocess.run(["cp", "-a", "--reflink=auto", str(seeds), str(isolated_corpus)], check=True)
    bbtargets = work / "BBtargets.txt"
    bbtargets.write_text("\n".join(locations) + "\n")
    campaign = isolated_repo / ".pbfuzz/campaigns" / f"{args.bug_id}.fixed.campaign.yaml"
    campaign.parent.mkdir(parents=True, exist_ok=True)
    output = isolated_repo / ".pbfuzz" / f"fixed-{args.bug_id.lower()}"
    status_link = repo / ".pbfuzz" / output.name
    if not status_link.exists() and not status_link.is_symlink():
        status_link.parent.mkdir(exist_ok=True)
        status_link.symlink_to(output, target_is_directory=True)
    engine = AUTHOR / "engine/.venv/bin/python"
    command = [str(engine), "-m", "pbfuzz_engine.adapters.magma",
               "--target-name", project, "--target-repo", str(isolated_repo),
               "--bug-id", args.bug_id, "--binary", str(isolated_binary),
               "--campaign-id", f"{project}-{args.bug_id.lower()}-fixed",
               "--run-cmd", f"{isolated_binary} @@", "--bbtargets", str(bbtargets),
               "--no-static-analysis", "--seeds-dir", str(isolated_corpus),
               "--output-dir", str(output), "--write", str(campaign)]
    subprocess.run(command, cwd=AUTHOR, check=True, stdout=subprocess.DEVNULL)
    data = yaml.safe_load(campaign.read_text())
    shim = ROOT / "scripts/pbfuzz_monitor_oracle.py"
    argv = ["python3", str(shim), "--monitor", str(isolated_monitor), "--binary", str(isolated_binary),
            "--bug-id", args.bug_id, "--entry", entry, "--input", "@@"]
    data["entry"]["run_cmd"] = " ".join(shlex.quote(arg) for arg in argv)
    data["tracer"] = "off"
    data["analysis"]["deviation"] = {
        "enabled": False,
        "disabled_reason": "fixed benchmark monitor oracle has no debugger trace",
    }
    campaign.write_text(
        "# Fixed Magma binary and monitor adapter; current author DSH PBFuzz engine.\n"
        + yaml.safe_dump(data, sort_keys=False)
    )
    manifest = {
        "schema": 1,
        "track": "current-author-dsh-fixed-magma-monitor",
        "bug_id": args.bug_id,
        "project": project,
        "fixed_entry": entry,
        "magma_commit": "cec1fec38fdc510c2cb8e6ae690e738b1042cb8d",
        "author_commit": "70d0b96dce14961ca184e10d96838902bee9bae1",
        "binary": str(binary),
        "binary_sha256": sha256(binary),
        "monitor_sha256": sha256(monitor),
        "source_repo": str(isolated_repo),
        "isolated_binary": str(isolated_binary),
        "isolated_binary_sha256": sha256(isolated_binary),
        "isolated_monitor_sha256": sha256(isolated_monitor),
        "target_locations": locations,
        "corpus_dir": str(isolated_corpus),
        "corpus_files": sum(path.is_file() for path in isolated_corpus.rglob("*")),
        "campaign": str(campaign),
        "campaign_sha256": sha256(campaign),
        "output_dir": str(output),
    }
    (work / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"bug_id": args.bug_id, "campaign": str(campaign),
                      "binary_sha256": manifest["binary_sha256"],
                      "campaign_sha256": manifest["campaign_sha256"]}))


if __name__ == "__main__":
    main()
