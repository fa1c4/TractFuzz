#!/usr/bin/env python3
"""Run six fixed-entry Magma baselines over repeated 60-target trials.

The default is one 24-hour campaign per target and arm. Use --dry-run to inspect
the schedule without building, fuzzing, making model calls, or changing results.
"""

import argparse
import csv
import fcntl
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import uuid
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results/baselines"
BENCHMARK = ROOT / "docs/tractfuzz_magma_benchmarks.md"
PINNED_MAGMA_COMMIT = "cec1fec38fdc510c2cb8e6ae690e738b1042cb8d"
PINNED_PBFUZZ_COMMIT = "70d0b96dce14961ca184e10d96838902bee9bae1"
BASELINES = ("aflgo", "beacon", "selectfuzz", "halo", "idfuzz", "pbfuzz")
PBFUZZ_AGENT_OVERHEAD_SEC = 3600
CONTAINER = {
    "beacon": "run_beacon_magma_container.sh",
    "selectfuzz": "run_selectfuzz_magma_container.sh",
    "halo": "run_halo_magma_container.sh",
    "idfuzz": "run_idfuzz_magma_container.sh",
    "aflgo": "run_idfuzz_magma_container.sh",
}
STATUS = {
    "beacon": ROOT / "results/beacon/status.csv",
    "selectfuzz": ROOT / "results/selectfuzz/status.csv",
    "halo": ROOT / "results/halo/status.csv",
    "idfuzz": ROOT / "results/idfuzz/status-idfuzz.csv",
    "aflgo": ROOT / "results/idfuzz/status-control.csv",
}


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def atomic_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def read_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text())
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def benchmark_rows() -> list[tuple[str, str, str]]:
    found = re.findall(
        r"^\|\s*\d+\s*\|\s*(\w+)\s*\|\s*`([A-Z]{3}\d{3})`\s*\|\s*`([^`]+)`\s*\|",
        BENCHMARK.read_text(), re.M,
    )
    if len(found) != 60 or len({bug for _, bug, _ in found}) != 60:
        raise RuntimeError("expected 60 distinct fixed Magma rows")
    return [(bug, project, entry) for project, bug, entry in found]


def parse_duration(value: str) -> int:
    match = re.fullmatch(r"([1-9]\d*)([smhd]?)", value.lower())
    if not match:
        raise argparse.ArgumentTypeError("use a positive duration such as 90s, 30m, 24h, or 1d")
    seconds = int(match[1]) * {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[match[2]]
    if seconds > 2_147_483_647:
        raise argparse.ArgumentTypeError("duration is too large")
    return seconds


def trial_name(run_id: str, index: int) -> str:
    return f"{run_id}_t{index:02d}"


def pbfuzz_overhead(seconds: int) -> int:
    return min(PBFUZZ_AGENT_OVERHEAD_SEC, max(300, seconds // 4))


def command_for(arm: str, trial: str, seconds: int, seed: int, bug: str,
                build_only: bool = False) -> list[str]:
    command = [str(ROOT / "scripts" / CONTAINER[arm]), "run", bug, "--seconds", str(seconds),
               "--trial", trial]
    if arm == "beacon":
        command += ["--mode", "hard"]
    elif arm in ("selectfuzz", "halo"):
        command += ["--extended-cg"]
        if arm == "halo":
            command += ["--rng-seed", str(seed)]
    elif arm in ("idfuzz", "aflgo"):
        command += ["--mode", "control" if arm == "aflgo" else "idfuzz",
                    "--rng-seed", str(seed)]
    if build_only:
        command.append("--build-only")
    return command


def run_logged(command: list[str], log: Path, env: dict | None = None,
               core: int | None = None) -> int:
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("a") as stream:
        stream.write(f"\n[{now()}] $ {shlex.join(command)}\n")
        stream.flush()
        environment = dict(os.environ if env is None else env)
        if core is not None:
            environment["TRACTFUZZ_CPUSET"] = str(core)
        actual = ["taskset", "-c", str(core), *command] if core is not None else command
        return subprocess.run(actual, cwd=ROOT, env=environment,
                              stdout=stream,
                              stderr=subprocess.STDOUT, check=False).returncode


def copy_asset(source: Path, destination: Path) -> None:
    if destination.exists() or destination.is_symlink():
        return
    if not source.exists():
        raise RuntimeError(f"required staging asset is missing: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + f".staging-{uuid.uuid4().hex[:8]}")
    try:
        subprocess.run(["cp", "-a", "--reflink=auto", str(source), str(temporary)], check=True)
        temporary.rename(destination)
    finally:
        if temporary.is_dir() and not temporary.is_symlink():
            shutil.rmtree(temporary)
        elif temporary.exists() or temporary.is_symlink():
            temporary.unlink()


def stage_frozen_pbfuzz_inputs(source_root: Path, destination: Path,
                               rows: list[tuple[str, str, str]]) -> None:
    for bug, project, entry in rows:
        source = source_root / "magma/work/idfuzz" / bug
        target = destination / "magma/work/idfuzz" / bug
        copy_asset(source / "target/repo", target / "target/repo")
        copy_asset((source / "target/corpus" / entry).resolve(),
                   target / "target/corpus" / entry)
        output = target / "out"
        output.mkdir(parents=True, exist_ok=True)
        binary = source / "out" / entry
        if project == "php" and not binary.is_file():
            binary = source / "out" / f"php-fuzz-{entry}"
        for asset in (binary, source / "out/monitor", source / "out/aflgo_targets.txt"):
            copy_asset(asset, output / asset.name)
        targets = output / "aflgo_targets.txt"
        targets.write_text(targets.read_text().replace(
            str(source_root / "magma/work/idfuzz"),
            str(destination / "magma/work/idfuzz")))
        shutil.rmtree(target / "target/repo/.pbfuzz", ignore_errors=True)


def stage_evaluation(source_root: Path, destination: Path, arms: list[str],
                     rows: list[tuple[str, str, str]]) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    active_lock = destination / "results/baselines/.evaluation.lock"
    if active_lock.is_file():
        with active_lock.open("r") as stream:
            try:
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise RuntimeError(f"evaluation is already running: {destination}") from error
    (destination / "tmp").mkdir(exist_ok=True)
    (destination / "home").mkdir(exist_ok=True)
    for relative in ("scripts", "fuzzers", "docs/tractfuzz_magma_benchmarks.md",
                     "build/install", "magma/.git", "magma/targets", "magma/magma",
                     "magma/fuzzers"):
        copy_asset(source_root / relative, destination / relative)
    # Resume with the repaired runners while retaining all staged builds and logs.
    shutil.copytree(source_root / "scripts", destination / "scripts",
                    dirs_exist_ok=True, symlinks=True)
    if any(arm != "pbfuzz" for arm in arms):
        svf_json = Path("build/_deps/svf-src/svf/include/Util/ExtAPI.json")
        copy_asset(source_root / svf_json, destination / svf_json)
        source_cache = destination / "magma/source-cache"
        for project in dict.fromkeys(project for _, project, _ in rows):
            target = source_cache / project / "target"
            if (target / "repo/.git").is_dir():
                continue
            for bug, row_project, _ in rows:
                if row_project != project:
                    continue
                candidate = source_root / "magma/work/beacon" / bug / "target/repo"
                if not (candidate / ".git").is_dir() or (
                    candidate / ".git/objects/info/alternates").exists():
                    continue
                if project == "php" and not (candidate / "oniguruma/.git").is_dir():
                    continue
                if project == "poppler" and not (
                    candidate.parent / "freetype2/subprojects/dlg/include/dlg/dlg.h").is_file():
                    continue
                tagged = subprocess.run(["git", "-C", str(candidate), "rev-parse",
                                         "--verify", "magma-init"],
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if tagged.returncode:
                    continue
                copy_asset(candidate / ".git", target / "repo/.git")
                if project == "php":
                    copy_asset(candidate / "oniguruma/.git",
                               target / "repo/oniguruma/.git")
                if project == "poppler":
                    freetype = candidate.parent / "freetype2"
                    if (freetype / "subprojects/dlg/include/dlg/dlg.h").is_file():
                        copy_asset(freetype, target / "freetype2")
                break
    for name in ("beacon_cli", "selectfuzz_cli", "halo_cli", "idfuzz_cli"):
        asset = source_root / "target/release" / name
        if asset.is_file():
            copy_asset(asset, destination / "target/release" / name)
    archives = source_root / "magma/work/beacon/source-archives"
    if archives.is_dir():
        for arm in ("beacon", "selectfuzz", "halo", "idfuzz"):
            copy_asset(archives, destination / "magma/work" / arm / "source-archives")
    for wrapper in (destination / "build/install/bin").glob("libaflgo_*"):
        if wrapper.is_file() and wrapper.read_bytes().startswith(b"#!/usr/bin/env python"):
            content = wrapper.read_text()
            rebased = content.replace(str(source_root / "build/install"),
                                      str(destination / "build/install"))
            if rebased != content:
                wrapper.write_text(rebased)
    if "pbfuzz" in arms:
        for relative in ("results/pbfuzz/source/github",
                         "results/pbfuzz/dsh-home/profiles/headless",
                         "results/pbfuzz/bin/pbfuzz-landlock"):
            copy_asset(source_root / relative, destination / relative)
        profile = destination / "results/pbfuzz/dsh-home/profiles/headless"
        for name in ("package.json", "pnpm-lock.yaml", "cordis.patch.yml", "cordis.yml"):
            path = profile / name
            if path.is_file():
                content = path.read_text()
                rebased = content.replace(str(source_root / "results/pbfuzz"),
                                          str(destination / "results/pbfuzz"))
                if rebased != content:
                    path.write_text(rebased)
        if "idfuzz" not in arms:
            stage_frozen_pbfuzz_inputs(source_root, destination, rows)
    binary = destination / "bin/eval-workspace-landlock"
    binary.parent.mkdir(exist_ok=True)
    build_env = dict(os.environ, TMPDIR=str(destination / "tmp"),
                     HOME=str(destination / "home"))
    subprocess.run(["cc", "-O2", "-Wall", "-Wextra", "-Werror",
                    str(destination / "scripts/eval_workspace_landlock.c"), "-o", str(binary)],
                   env=build_env, check=True)


def enter_evaluation(source_root: Path, destination: Path) -> None:
    environment = dict(os.environ)
    key_script = Path(os.environ.get("PBFUZZ_KEY_SCRIPT",
                             str(Path.home() / "api_keys/set_api_key.sh"))).expanduser().resolve()
    environment.update(TRACTFUZZ_EVAL_STAGED="1", TRACTFUZZ_SOURCE_ROOT=str(source_root),
                       TRACTFUZZ_PAR_JOBS="1", PYTHONDONTWRITEBYTECODE="1",
                       PBFUZZ_SKIP_PATCH_HIDE="1",
                       PBFUZZ_KEY_SCRIPT=str(key_script))
    for name, relative in (("HOME", "home"), ("TMPDIR", "tmp"),
                           ("XDG_CACHE_HOME", "home/.cache"),
                           ("XDG_CONFIG_HOME", "home/.config"),
                           ("XDG_DATA_HOME", "home/.local/share"),
                           ("NPM_CONFIG_CACHE", "home/.npm"),
                           ("PNPM_HOME", "home/.local/share/pnpm")):
        path = destination / relative
        path.mkdir(parents=True, exist_ok=True)
        environment[name] = str(path)
    sandbox = destination / "bin/eval-workspace-landlock"
    script = destination / "scripts/evaluate_magma_baselines.py"
    os.execve(sandbox, [str(sandbox), str(destination), "--", sys.executable,
                        str(script), *sys.argv[1:]], environment)


def preflight(arms: list[str], rows: list[tuple[str, str, str]]) -> None:
    if not (ROOT / "magma/.git").is_dir():
        raise RuntimeError("Magma is absent; run scripts/setup_magma.sh first")
    revision = subprocess.check_output(
        ["git", "-C", str(ROOT / "magma"), "rev-parse", "HEAD"], text=True).strip()
    if revision != PINNED_MAGMA_COMMIT:
        raise RuntimeError(f"Magma checkout is {revision}; expected {PINNED_MAGMA_COMMIT}")
    if any(arm != "pbfuzz" for arm in arms) and not shutil.which("docker"):
        raise RuntimeError("Docker is required by the BEACON/SelectFuzz/Halo/IDFuzz wrappers")
    if not shutil.which("taskset"):
        raise RuntimeError("taskset is required to pin each campaign to one logical CPU")
    images = set()
    if any(arm in arms for arm in ("aflgo", "idfuzz")):
        images.add("tractfuzz-idfuzz-magma:ubuntu24.04")
    if any(arm in arms for arm in ("beacon", "selectfuzz", "halo")):
        images.add("tractfuzz-beacon-magma:ubuntu24.04")
    for image in sorted(images):
        if subprocess.run(["docker", "image", "inspect", image], stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL, check=False).returncode:
            raise RuntimeError(f"prebuild Docker image {image} before evaluation; evaluation never builds images")
    for arm in arms:
        if arm == "pbfuzz":
            continue
        base = "idfuzz" if arm == "aflgo" else arm
        wrapper = ROOT / "build/install/bin" / f"libaflgo_{base}_cc"
        if not wrapper.is_file():
            raise RuntimeError(f"{wrapper} is missing; run scripts/build_{base}.sh")
    if "pbfuzz" not in arms:
        return
    key_script = Path(os.environ.get("PBFUZZ_KEY_SCRIPT",
                       str(Path.home() / "api_keys/set_api_key.sh"))).expanduser()
    if not key_script.is_file():
        raise RuntimeError(f"PBFuzz key script is missing: {key_script}")
    dsh_home = ROOT / "results/pbfuzz/dsh-home"
    for asset in (ROOT / "results/pbfuzz/source/github/engine/.venv/bin/python",
                  dsh_home / "profiles/headless/cordis.patch.yml"):
        if not asset.is_file():
            raise RuntimeError(f"PBFuzz is not installed: {asset}; see fuzzers/pbfuzz/BUILD.md")
    author = ROOT / "results/pbfuzz/source/github"
    author_revision = subprocess.check_output(
        ["git", "-C", str(author), "rev-parse", "HEAD"], text=True).strip()
    if author_revision != PINNED_PBFUZZ_COMMIT:
        raise RuntimeError(f"PBFuzz checkout is {author_revision}; expected {PINNED_PBFUZZ_COMMIT}")
    if "idfuzz" not in arms:
        for bug, project, entry in rows:
            out = ROOT / "magma/work/idfuzz" / bug / "out"
            binary = out / entry
            if project == "php" and not binary.is_file():
                binary = out / f"php-fuzz-{entry}"
            if not binary.is_file() or not (out / "monitor").is_file():
                raise RuntimeError(f"PBFuzz needs the frozen IDFuzz build for {bug}; see fuzzers/pbfuzz/BUILD.md")
    hidden = ROOT / "results/pbfuzz/.hidden"
    if os.environ.get("TRACTFUZZ_EVAL_STAGED") == "1" and hidden.is_dir() and any(hidden.iterdir()):
        raise RuntimeError("PBFuzz has hidden Magma directories from an active or interrupted run")


def snapshot_status(arm: str, trial: str, rows: list[tuple[str, str, str]],
                    destination: Path) -> dict:
    source = STATUS[arm]
    if not source.is_file():
        raise RuntimeError(f"status file missing after {arm}: {source}")
    with source.open(newline="") as stream:
        actual = list(csv.DictReader(stream))
    expected = {bug for bug, _, _ in rows}
    matching = {row.get("bug", ""): row for row in actual if row.get("trial", "") == trial}
    if set(matching) != expected:
        missing = sorted(expected - set(matching))
        raise RuntimeError(f"{arm} {trial} recorded {len(matching)}/60 rows; missing {missing[:8]}")
    shutil.copy2(source, destination)
    counts = Counter(row.get("status", "") for row in matching.values())
    def positive(row: dict, field: str) -> bool:
        try:
            return int(row.get(field, "") or 0) > 0
        except ValueError:
            return False
    try:
        snapshot = str(destination.relative_to(ROOT))
    except ValueError:
        snapshot = str(destination)
    return {"rows": len(matching), "statuses": dict(sorted(counts.items())),
            "reached_rows": sum(positive(row, "reach_count") for row in matching.values()),
            "triggered_rows": sum(positive(row, "trigger_count") for row in matching.values()),
            "witness_rows": sum(bool(row.get("witness")) for row in matching.values()),
            "snapshot": snapshot}


def warm_project_sources(arm: str, trial: str, seconds: int, seed: int,
                         rows: list[tuple[str, str, str]], directory: Path,
                         cores: list[int]) -> None:
    first_by_project = {}
    for bug, project, _ in rows:
        first_by_project.setdefault(project, bug)
    warmup = directory / "warmup"
    warmup.mkdir(exist_ok=True)
    slots = Queue()
    for core in cores:
        slots.put(core)
    def prepare(bug: str) -> tuple[str, str]:
        record_path = warmup / f"{bug}.json"
        if read_json(record_path).get("state") == "complete":
            return bug, "complete"
        core = slots.get()
        try:
            command = command_for(arm, trial, seconds, seed, bug, build_only=True)
            code = run_logged(command, warmup / f"{bug}.log", core=core)
            status = "missing_status"
            if STATUS[arm].is_file():
                with STATUS[arm].open(newline="") as stream:
                    status = next((row.get("status", "") for row in csv.DictReader(stream)
                                   if row.get("bug") == bug and row.get("trial") == trial),
                                  "missing_status")
            state = "complete" if code == 0 and status == "build_complete" else "failed"
            atomic_json(record_path, {"state": state, "bug": bug, "cpu_core": core,
                                      "command": command, "exit_code": code,
                                      "runner_status": status, "finished_at": now()})
            return bug, state
        finally:
            slots.put(core)
    failures = []
    with ThreadPoolExecutor(max_workers=min(len(cores), len(first_by_project))) as pool:
        futures = [pool.submit(prepare, bug) for bug in first_by_project.values()]
        for future in as_completed(futures):
            bug, state = future.result()
            if state != "complete":
                failures.append(bug)
    if failures:
        raise RuntimeError(f"{arm} project warmup failed for {sorted(failures)}; see {warmup}")


def run_container_arm(arm: str, trial: str, seconds: int, seed: int,
                      rows: list[tuple[str, str, str]], directory: Path,
                      cores: list[int]) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    record_path = directory / "step.json"
    previous = read_json(record_path)
    if previous.get("state") == "complete":
        print(f"{trial} {arm}: already recorded", flush=True)
        return
    slots = Queue()
    for core in cores:
        slots.put(core)
    record = {"schema": 1, "arm": arm, "trial": trial, "seconds_per_target": seconds,
              "parallel_workers": len(cores), "started_at": now(), "state": "running"}
    atomic_json(record_path, record)
    warm_project_sources(arm, trial, seconds, seed, rows, directory, cores)
    print(f"{trial} {arm}: starting 60 targets on {len(cores)} cores", flush=True)
    bugs_dir = directory / "bugs"
    bugs_dir.mkdir(exist_ok=True)
    def run_bug(bug: str) -> tuple[str, int]:
        path = bugs_dir / f"{bug}.json"
        if read_json(path).get("state") == "complete":
            return bug, 0
        core = slots.get()
        try:
            command = command_for(arm, trial, seconds, seed, bug)
            atomic_json(path, {"state": "running", "command": command,
                               "cpu_core": core, "started_at": now()})
            code = run_logged(command, bugs_dir / f"{bug}.log", core=core)
            atomic_json(path, {"state": "complete" if code == 0 else "failed",
                               "command": command, "cpu_core": core, "exit_code": code,
                               "finished_at": now()})
            return bug, code
        finally:
            slots.put(core)
    failures = []
    with ThreadPoolExecutor(max_workers=len(cores)) as pool:
        futures = [pool.submit(run_bug, bug) for bug, _, _ in rows]
        for future in as_completed(futures):
            bug, code = future.result()
            if code:
                failures.append(f"{bug}: exit {code}")
    record.update(finished_at=now(), failed_bugs=failures)
    if not failures:
        try:
            record.update(snapshot_status(arm, trial, rows, directory / "status.csv"))
            record["state"] = "complete"
        except RuntimeError as error:
            record.update(state="incomplete", error=str(error))
    else:
        record["state"] = "failed"
    atomic_json(record_path, record)
    if record["state"] != "complete":
        raise RuntimeError(f"{trial} {arm}: {record['state']}; see {directory / 'run.log'}")
    print(f"{trial} {arm}: {record['statuses']}", flush=True)


def archive_current_pbfuzz(bug: str, registry_path: Path) -> None:
    work = ROOT / "results/pbfuzz/fixed" / bug
    if not work.is_dir():
        return
    log = RESULTS / "pbfuzz-archive.log"
    command = [sys.executable, str(ROOT / "scripts/pbfuzz_reset_fixed.py"),
               bug, "--allow-incomplete"]
    with (work / "run.lock").open("a") as run_lock:
        try:
            fcntl.flock(run_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError(f"PBFuzz {bug} is already running") from error
        with log.open("a") as stream:
            process = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE,
                                     stderr=stream, text=True, check=False)
    if process.returncode != 0:
        raise RuntimeError(f"PBFuzz could not archive {bug}; see {log}")
    try:
        archive = Path(json.loads(process.stdout.splitlines()[-1])["archived_to"])
    except (IndexError, ValueError, KeyError) as error:
        raise RuntimeError(f"PBFuzz archive for {bug} returned no path") from error
    old_isolated = ROOT / "results/pbfuzz/isolated" / bug
    atomic_json(archive / "path-map.json", {
        "old_evidence_dir": str(work), "new_evidence_dir": str(archive / "evidence"),
        "old_isolated_dir": str(old_isolated), "new_isolated_dir": str(archive / "isolated"),
    })
    registry = read_json(registry_path)
    owner = registry.get(bug, {})
    previous_record_path = Path(owner.get("record_path", "")) if owner else None
    if previous_record_path and previous_record_path.is_file():
        previous_record = read_json(previous_record_path)
        previous_record["raw_evidence_dir"] = str(archive / "evidence")
        previous_record["isolated_dir"] = str(archive / "isolated")
        witness = previous_record.get("witness_path", "")
        if witness.startswith(str(old_isolated) + os.sep):
            previous_record["witness_path"] = str(archive / "isolated") + witness[len(str(old_isolated)):]
        atomic_json(previous_record_path, previous_record)
    registry.pop(bug, None)
    atomic_json(registry_path, registry)


def run_pbfuzz_arm(trial: str, seconds: int, rows: list[tuple[str, str, str]],
                   directory: Path, registry_path: Path, cores: list[int]) -> None:
    preflight(["pbfuzz"], rows)
    directory.mkdir(parents=True, exist_ok=True)
    bugs_dir = directory / "bugs"
    bugs_dir.mkdir(exist_ok=True)
    hard_wall = seconds + pbfuzz_overhead(seconds)
    wall_minutes = (hard_wall + 59) // 60
    environment = dict(os.environ, PBFUZZ_MAX_ROUNDS="100",
                       PBFUZZ_WALL_MIN=str(wall_minutes),
                       PBFUZZ_MAX_ITERS="1000000000",
                       PBFUZZ_FUZZ_TIMEOUT_SEC=str(seconds),
                       PBFUZZ_HARD_WALL_SEC=str(hard_wall))
    slots = Queue()
    for core in cores:
        slots.put(core)
    for bug, _, _ in rows:
        record_path = bugs_dir / f"{bug}.json"
        if read_json(record_path).get("state") != "recorded":
            archive_current_pbfuzz(bug, registry_path)
    def run_bug(bug: str) -> tuple[str, dict | None]:
        record_path = bugs_dir / f"{bug}.json"
        if read_json(record_path).get("state") == "recorded":
            return bug, None
        core = slots.get()
        try:
            return bug, run_one_bug(bug, core)
        finally:
            slots.put(core)
    def run_one_bug(bug: str, core: int) -> dict:
        home = ROOT / "home/pbfuzz" / bug
        home.mkdir(parents=True, exist_ok=True)
        dsh_home = ROOT / "results/pbfuzz/dsh-homes" / bug
        copy_asset(ROOT / "results/pbfuzz/dsh-home/profiles/headless",
                   dsh_home / "profiles/headless")
        bug_env = dict(environment, HOME=str(home), TMPDIR=str(ROOT / "tmp"),
                       XDG_CACHE_HOME=str(home / ".cache"),
                       XDG_CONFIG_HOME=str(home / ".config"),
                       XDG_DATA_HOME=str(home / ".local/share"),
                       NPM_CONFIG_CACHE=str(home / ".npm"),
                       PNPM_HOME=str(home / ".local/share/pnpm"),
                       PBFUZZ_DSH_HOME=str(dsh_home))
        command = [str(ROOT / "scripts/run_pbfuzz_fixed.sh"), bug]
        print(f"{trial} pbfuzz: {bug} on CPU {core}", flush=True)
        started = now()
        code = run_logged(command, bugs_dir / f"{bug}.log", bug_env, core)
        work = ROOT / "results/pbfuzz/fixed" / bug
        run = read_json(work / "run.json")
        manifest = read_json(work / "manifest.json")
        phase = run.get("phase", "setup_failure")
        replay = {}
        scan = {}
        if phase == "SUCCESS":
            replay_command = [sys.executable, str(ROOT / "scripts/pbfuzz_fixed_replay.py"), bug]
            replay_code = run_logged(replay_command, bugs_dir / f"{bug}.replay.log", bug_env, core)
            replay = read_json(work / "replay.json")
            if replay_code != 0:
                replay = {"error": f"replay exit {replay_code}"}
        elif run:
            scan_command = [sys.executable, str(ROOT / "scripts/pbfuzz_scan_generated.py"),
                            bug, "--max-candidates", "500", "--wall-sec", "120"]
            scan_code = run_logged(scan_command, bugs_dir / f"{bug}.scan.log", bug_env, core)
            scan = read_json(work / "generated-scan.json")
            if scan_code != 0:
                scan = {"error": f"generated-input scan exit {scan_code}"}
        trials = replay.get("fixed_benchmark_binary", {}).get("trials", [])
        binary_hash_match = bool(replay and
            replay.get("fixed_benchmark_binary", {}).get("binary_sha256") ==
            manifest.get("binary_sha256"))
        generated_hash_match = bool(scan.get("trigger") and
            scan["trigger"].get("replay", {}).get("binary_sha256") ==
            manifest.get("binary_sha256"))
        record = {
            "schema": 1, "state": "recorded", "trial": trial, "bug_id": bug,
            "cpu_core": core,
            "started_at": started, "finished_at": now(), "run_exit_code": code,
            "phase": phase, "seconds_per_target": seconds,
            "pbfuzz_campaign_wall_minutes": wall_minutes,
            "hard_wall_seconds": hard_wall,
            "replay_trigger_trials": sum(item.get("monitor_triggered", 0) > 0 for item in trials),
            "replay_timeouts": sum(bool(item.get("timeout")) for item in trials),
            "replay_binary_hash_match": binary_hash_match,
            "witness_path": replay.get("witness", ""),
            "generated_candidates_scanned": scan.get("scanned", 0),
            "generated_reached": scan.get("reached", 0),
            "generated_trigger_trials": (scan.get("trigger") or {}).get("trigger_trials", 0),
            "generated_binary_hash_match": generated_hash_match,
            "raw_evidence_dir": str(work),
            "isolated_dir": str(ROOT / "results/pbfuzz/isolated" / bug),
            "run_log": str(bugs_dir / f"{bug}.log"),
        }
        atomic_json(bugs_dir / f"{bug}.json", record)
        return record
    with ThreadPoolExecutor(max_workers=len(cores)) as pool:
        futures = [pool.submit(run_bug, bug) for bug, _, _ in rows]
        for future in as_completed(futures):
            bug, record = future.result()
            if record is not None:
                registry = read_json(registry_path)
                registry[bug] = {"trial": trial, "record_path": str(bugs_dir / f"{bug}.json")}
                atomic_json(registry_path, registry)
    matrix = directory / "trial-60.csv"
    fields = ("trial", "bug_id", "project", "fixed_entry", "phase", "run_exit_code",
              "seconds_per_target", "replay_trigger_trials", "replay_timeouts",
              "replay_binary_hash_match", "generated_candidates_scanned",
              "generated_reached", "generated_trigger_trials", "generated_binary_hash_match",
              "record_path")
    records = []
    with matrix.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for bug, project, entry in rows:
            record_path = bugs_dir / f"{bug}.json"
            record = read_json(record_path)
            if record.get("trial") != trial:
                raise RuntimeError(f"{trial} PBFuzz record missing for {bug}")
            records.append(record)
            row = {key: record.get(key, "") for key in fields}
            row.update(trial=trial, bug_id=bug, project=project, fixed_entry=entry,
                       record_path=str(record_path.relative_to(ROOT)))
            writer.writerow(row)
    final_log = directory / "finalize.log"
    global_audit_complete = False
    registry = read_json(registry_path)
    current_owned = all(registry.get(bug, {}).get("trial") == trial for bug, _, _ in rows)
    global_audit_reason = ("one or more target setup failures" if any(
        record.get("phase") == "setup_failure" for record in records)
        else "current raw evidence belongs to another trial")
    if current_owned and all(record.get("phase") != "setup_failure" for record in records):
        code = run_logged([sys.executable, str(ROOT / "scripts/pbfuzz_finalize_fixed.py")], final_log)
        if code == 0:
            shutil.copy2(ROOT / "fuzzers/pbfuzz/fixed-60.csv", directory / "global-fixed-audit.csv")
            atomic_json(directory / "global-fixed-audit-summary.json",
                        read_json(ROOT / "results/pbfuzz/fixed-summary.json"))
            global_audit_complete = True
        else:
            global_audit_reason = f"finalizer exited {code}; see {final_log}"
    atomic_json(directory / "step.json", {
        "schema": 1, "arm": "pbfuzz", "trial": trial, "state": "complete",
        "rows": len(records), "seconds_per_target": seconds,
        "engine_success_rows": sum(record.get("phase") == "SUCCESS" for record in records),
        "verified_3_of_3": sum((record.get("replay_trigger_trials") == 3
                                and record.get("replay_binary_hash_match")) or
                               (record.get("generated_trigger_trials") == 3
                                and record.get("generated_binary_hash_match"))
                               for record in records),
        "generated_verified_3_of_3": sum(record.get("generated_trigger_trials") == 3
                                         and record.get("generated_binary_hash_match")
                                         for record in records),
        "global_audit_complete": global_audit_complete,
        "global_audit_reason": "" if global_audit_complete else global_audit_reason,
        "matrix": str(matrix.relative_to(ROOT)),
        "finished_at": now(),
    })
    if not global_audit_complete:
        print(f"{trial} pbfuzz: per-trial matrix complete; global audit unavailable: {global_audit_reason}",
              flush=True)
    print(f"{trial} pbfuzz: 60 rows recorded", flush=True)


def write_summary(directory: Path, run_id: str, trials: int, arms: list[str]) -> None:
    output = directory / "summary.csv"
    fields = ("trial", "arm", "rows", "campaign_complete", "reached_rows",
              "triggered_rows", "witness_rows", "engine_success_rows", "verified_3_of_3",
              "generated_verified_3_of_3")
    with output.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for index in range(1, trials + 1):
            trial = trial_name(run_id, index)
            for arm in arms:
                step = read_json(directory / trial / arm / "step.json")
                writer.writerow({
                    "trial": trial, "arm": arm, "rows": step.get("rows", ""),
                    "campaign_complete": step.get("statuses", {}).get("campaign_complete", ""),
                    "reached_rows": step.get("reached_rows", ""),
                    "triggered_rows": step.get("triggered_rows", ""),
                    "witness_rows": step.get("witness_rows", ""),
                    "engine_success_rows": step.get("engine_success_rows", ""),
                    "verified_3_of_3": step.get("verified_3_of_3", ""),
                    "generated_verified_3_of_3": step.get("generated_verified_3_of_3", ""),
                })


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trials", type=int, default=1,
                        help="repeat each selected arm on the frozen 60 targets (default: 1)")
    parser.add_argument("--fuzz-time", type=parse_duration, default=parse_duration("24h"),
                        metavar="DURATION", help="per-target budget, e.g. 90s, 30m, 24h (default: 24h)")
    parser.add_argument("--baselines", nargs="+", choices=("all", *BASELINES), default=["all"],
                        help="selected methods (default: all six)")
    parser.add_argument("--parallel-worker", type=int, default=64,
                        help="maximum concurrent campaigns, one logical CPU each (default: 64)")
    parser.add_argument("--eval-name", "--run-id", dest="eval_name",
                        help="directory name under workspace/; reuse to resume")
    parser.add_argument("--dry-run", action="store_true", help="print commands without changing results")
    args = parser.parse_args()
    if args.trials < 1:
        parser.error("--trials must be positive")
    if args.parallel_worker < 1:
        parser.error("--parallel-worker must be positive")
    if "all" in args.baselines and len(args.baselines) > 1:
        parser.error("--baselines all cannot be combined with method names")
    run_id = args.eval_name or (datetime.now(timezone.utc).strftime("eval_%Y%m%dT%H%M%SZ_")
                             + uuid.uuid4().hex[:6])
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,39}", run_id):
        parser.error("--eval-name must start with a letter and contain at most 40 letters, digits, _ or -")
    selected = set(BASELINES if "all" in args.baselines else args.baselines)
    arms = [name for name in BASELINES if name in selected]
    rows = benchmark_rows()
    seconds = args.fuzz_time
    cores = sorted(os.sched_getaffinity(0))[:args.parallel_worker]
    if not cores:
        raise RuntimeError("no logical CPU is available in the current affinity mask")
    source_root = (Path(os.environ["TRACTFUZZ_SOURCE_ROOT"])
                   if os.environ.get("TRACTFUZZ_EVAL_STAGED") == "1"
                   else ROOT)
    workspace = source_root / "workspace"
    if workspace.is_symlink() or (workspace / run_id).is_symlink():
        raise RuntimeError("workspace and evaluation directory must be real directories")
    eval_root = workspace / run_id
    if args.dry_run:
        print(f"eval_root={eval_root} targets=60 trials={args.trials} fuzz_seconds={seconds} arms={','.join(arms)}")
        print(f"parallel_workers={len(cores)} requested={args.parallel_worker} cores={cores}")
        print(f"campaign budget={seconds * 60 * len(arms) * args.trials} CPU seconds plus setup and analysis")
        for index in range(1, args.trials + 1):
            trial = trial_name(run_id, index)
            for arm in arms:
                if arm == "pbfuzz":
                    print(f"{trial} pbfuzz: 60 x scripts/run_pbfuzz_fixed.sh BUG; "
                          f"fuzz stage cap={seconds}s; agent/hard wall={seconds + pbfuzz_overhead(seconds)}s")
                else:
                    print(shlex.join(command_for(arm, trial, seconds, 1336 + index, rows[0][0]))
                          + "  # repeated for all 60 bugs")
        return
    if os.environ.get("TRACTFUZZ_EVAL_STAGED") != "1":
        preflight(arms, rows)
        stage_evaluation(source_root, eval_root, arms, rows)
        if args.eval_name is None:
            sys.argv.extend(["--eval-name", run_id])
        enter_evaluation(source_root, eval_root)
        raise AssertionError("execve returned")
    if ROOT != eval_root:
        raise RuntimeError("staged evaluation root does not match workspace/<eval-name>")
    preflight(arms, rows)
    RESULTS.mkdir(parents=True, exist_ok=True)
    with (RESULTS / ".evaluation.lock").open("w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError("another baseline evaluation is running") from error
        directory = RESULTS / "evaluations" / run_id
        directory.mkdir(parents=True, exist_ok=True)
        manifest_path = directory / "manifest.json"
        configuration = {
            "schema": 1, "run_id": run_id, "trials": args.trials,
            "seconds_per_target": seconds, "arms": arms,
            "parallel_workers": len(cores), "cpu_set": cores,
            "benchmark_sha256": hashlib.sha256(BENCHMARK.read_bytes()).hexdigest(),
            "magma_commit": subprocess.check_output(
                ["git", "-C", str(ROOT / "magma"), "rev-parse", "HEAD"], text=True).strip(),
        }
        previous = read_json(manifest_path)
        if previous:
            if any(previous.get(key) != value for key, value in configuration.items()):
                raise RuntimeError(f"{run_id} exists with a different budget, arm set, or benchmark")
        else:
            atomic_json(manifest_path, dict(configuration, created_at=now(), state="running"))
        registry_path = RESULTS / "pbfuzz-current-owner.json"
        for index in range(1, args.trials + 1):
            trial = trial_name(run_id, index)
            for arm in arms:
                arm_dir = directory / trial / arm
                if arm == "pbfuzz":
                    if read_json(arm_dir / "step.json").get("state") == "complete":
                        print(f"{trial} pbfuzz: already recorded", flush=True)
                        continue
                    run_pbfuzz_arm(trial, seconds, rows, arm_dir, registry_path, cores)
                else:
                    run_container_arm(arm, trial, seconds, 1336 + index, rows, arm_dir, cores)
        write_summary(directory, run_id, args.trials, arms)
        atomic_json(manifest_path, dict(configuration, created_at=previous.get("created_at", now()),
                                        finished_at=now(), state="complete"))
        print(f"evaluation complete: {directory}", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, subprocess.CalledProcessError) as error:
        print(f"evaluation error: {error}", file=sys.stderr)
        raise SystemExit(1)
