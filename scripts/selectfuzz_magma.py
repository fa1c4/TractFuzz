#!/usr/bin/env python3
"""Build and run the fixed Magma rows with the workspace SelectFuzz adaptation.

Examples:
  python3 scripts/selectfuzz_magma.py matrix
  python3 scripts/selectfuzz_magma.py run PNG006 --seconds 60
  python3 scripts/selectfuzz_magma.py all --seconds 60

The all command records every row. LibFuzzer entries use the in-process runner;
command-line entries use the shared-memory LibAFL command executor. Builds and
campaigns are resumed from per-bug workdirs.
"""

import argparse
import csv
import fcntl
import hashlib
import os
import re
import shlex
import shutil
import struct
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAGMA_ROOT = ROOT / "magma"
WORK_ROOT = MAGMA_ROOT / "work" / "selectfuzz"
MANIFEST = ROOT / "docs" / "tractfuzz_magma_benchmarks.md"
STATUS = ROOT / "results" / "selectfuzz" / "status.csv"
ROW = re.compile(r"^\|\s*(\d+)\s*\|\s*([^|]+)\|\s*`([^`]+)`\s*\|\s*`([^`]+)`")
CLI = {"tiffcp", "xmllint", "lua", "pdfimages", "pdftoppm"}
CLI_MAP_SIZE = 2_621_440
PINNED_GIT = {
    "libpng": ("https://github.com/glennrp/libpng.git", "a37d4836519517bdce6cb9d956092321eca3e73b"),
    "libsndfile": ("https://github.com/libsndfile/libsndfile.git", "86c9f9eb7022d186ad4d0689487e7d4f04ce2b29"),
    "libtiff": ("https://gitlab.com/libtiff/libtiff.git", "c145a6c14978f73bb484c955eb9f84203efcb12e"),
    "libxml2": ("https://gitlab.gnome.org/GNOME/libxml2.git", "ec6e3efb06d7b15cf5a2328fabd3845acea4c815"),
    "lua": ("https://github.com/lua/lua.git", "dbdc74dc5502c2e05e1c1e2ac894943f418c8431"),
    "openssl": ("https://github.com/openssl/openssl.git", "3bd5319b5d0df9ecf05c8baba2c401ad8e3ba130"),
    "php": ("https://github.com/php/php-src.git", "bc39abe8c3c492e29bc5d60ca58442040bbf063b"),
    "poppler": ("https://gitlab.freedesktop.org/poppler/poppler.git", "1d23101ccebe14261c6afc024ea14f29d209e760"),
}
ARCHIVE_SHA256 = {
    "php-php-src-bc39abe8c3c492e29bc5d60ca58442040bbf063b.tar.gz":
        "61c8d8df1c313dc3f2d4f798344c4809d1de172c287c9ee5a2735175e0011b0f",
    "kkos-oniguruma-227ec0bd690207812793c09ad70024707c405376.tar.gz":
        "9f3cd4d0aeb30ba980173b47b48ea34a2ffd33d8678bc2eea647d1070b87f233",
}
METRIC_FIELDS = ("executions", "reach_count", "trigger_count", "probes", "improvements", "witness")
FIELDS = ("number", "project", "bug", "entry", "status", "detail", "seconds", "mode", "extended_cg",
          *METRIC_FIELDS, "trial")


def rows():
    found = []
    for line in MANIFEST.read_text().splitlines():
        match = ROW.match(line)
        if match:
            n, project, bug, entry = match.groups()
            found.append(dict(number=n, project=project.strip(), bug=bug, entry=entry))
    if len(found) != 60 or len({row["bug"] for row in found}) != 60:
        raise RuntimeError("Expected 60 unique fixed benchmark rows")
    return found


def load_status():
    if STATUS.exists():
        with STATUS.open(newline="") as stream:
            return {row["bug"]: row for row in csv.DictReader(stream)}
    return {}


def save_status(data):
    STATUS.parent.mkdir(parents=True, exist_ok=True)
    temporary = STATUS.with_suffix(".tmp")
    with temporary.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS)
        writer.writeheader()
        for row in rows():
            result = data.get(row["bug"], {})
            writer.writerow({key: result.get(key, row.get(key, "")) for key in FIELDS})
    temporary.replace(STATUS)


def update_status(row):
    STATUS.parent.mkdir(parents=True, exist_ok=True)
    with STATUS.with_suffix(".lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        latest = load_status()
        latest[row["bug"]] = row
        save_status(latest)
        fcntl.flock(lock, fcntl.LOCK_UN)


def call(command, env, log, cwd=ROOT, allowed=(0,)):
    started = time.monotonic()
    with log.open("a") as stream:
        stream.write("\n$ " + " ".join(map(str, command)) + "\n")
        stream.flush()
        result = subprocess.run(command, cwd=cwd, env=env, stdout=stream, stderr=stream)
    elapsed = time.monotonic() - started
    if result.returncode not in allowed:
        raise RuntimeError(f"exit {result.returncode}: {' '.join(map(str, command))}; see {log}")
    return elapsed


def local_checkout(cache, destination, revision, env, log):
    destination.mkdir(parents=True, exist_ok=True)
    call(["git", "-C", destination, "init"], env, log)
    alternates = destination / ".git/objects/info/alternates"
    alternates.write_text(str(cache / ".git/objects") + "\n")
    shallow = cache / ".git/shallow"
    if shallow.is_file():
        shutil.copy2(shallow, destination / ".git/shallow")
    call(["git", "-C", destination, "checkout", revision], env, log)


def shallow_checkout(remote, revision, destination, env, log):
    destination.mkdir(parents=True, exist_ok=True)
    call(["git", "-C", destination, "init"], env, log)
    call(["git", "-C", destination, "remote", "add", "origin", remote], env, log)
    try:
        call(["git", "-C", destination, "-c", "http.version=HTTP/1.1",
              "fetch", "--depth=1", "--filter=blob:none", "origin", revision], env, log)
    except RuntimeError:
        call(["git", "-C", destination, "-c", "http.version=HTTP/1.1",
              "fetch", "--depth=1", "origin", revision], env, log)
    for attempt in range(3):
        try:
            call(["git", "-C", destination, "checkout", "--detach", "FETCH_HEAD"], env, log)
            return
        except RuntimeError:
            time.sleep(attempt + 1)
    call(["git", "-C", destination, "-c", "http.version=HTTP/1.1",
          "fetch", "--depth=1", "origin", revision], env, log)
    call(["git", "-C", destination, "checkout", "--detach", "FETCH_HEAD"], env, log)


def github_archive_checkout(remote, revision, destination, env, log):
    match = re.fullmatch(r"https://github\.com/([^/]+)/([^/]+)\.git", remote)
    if not match:
        raise ValueError(f"archive fallback requires a GitHub repository: {remote}")
    archive_dir = WORK_ROOT / "source-archives"
    archive_dir.mkdir(parents=True, exist_ok=True)
    archive = archive_dir / f"{match[1]}-{match[2]}-{revision}.tar.gz"
    if not archive.is_file():
        temporary = archive.with_suffix(".partial")
        call(["curl", "-fL", "--retry", "3", "--retry-all-errors", "-o", temporary,
              f"https://codeload.github.com/{match[1]}/{match[2]}/tar.gz/{revision}"], env, log)
        temporary.replace(archive)
    with archive.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    expected = ARCHIVE_SHA256.get(archive.name)
    if expected is None or digest != expected:
        raise RuntimeError(f"pinned source archive checksum mismatch: {archive}")
    destination.mkdir(parents=True, exist_ok=True)
    call(["tar", "-xzf", archive, "--strip-components=1", "-C", destination], env, log)
    call(["git", "-C", destination, "init"], env, log)
    call(["git", "-C", destination, "add", "-A"], env, log)
    call(["git", "-C", destination, "commit", "-m", f"archive of {remote} at {revision}"], env, log)


def has_directed_target_call(binary):
    process = subprocess.Popen(["objdump", "-d", binary], stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, text=True)
    found = False
    try:
        for line in process.stdout:
            if re.search(r"\bcallq?\s+.*<__aflgo_trace_bb_target>", line):
                found = True
                break
    finally:
        if found:
            process.terminate()
        process.stdout.close()
        process.wait()
    return found


def cli_args(entry, input_file, out):
    input_file = str(input_file)
    if entry == "tiffcp":
        return ["-M", input_file, str(out / "cli-copy.tif")]
    if entry == "xmllint":
        return ["--valid", "--oldxml10", "--push", "--memory", input_file]
    if entry == "lua":
        return [input_file]
    if entry == "pdfimages":
        return [input_file, str(out / "cli-pdfimages")]
    if entry == "pdftoppm":
        return ["-mono", "-cropbox", input_file]
    raise ValueError(f"unsupported command-line entry: {entry}")


def cli_executions(findings):
    shared = findings / ".selectfuzz_cli_state"
    offset = CLI_MAP_SIZE + 16 + 256
    if not shared.is_file() or shared.stat().st_size < offset + 8:
        return None
    with shared.open("rb") as stream:
        stream.seek(offset)
        return struct.unpack("<Q", stream.read(8))[0]


def run(row, seconds, mode, trial, extended_cg=False):
    bug, project, entry = row["bug"], row["project"], row["entry"]
    is_cli = entry in CLI
    extended_cg = is_cli or extended_cg
    linked_entry = f"php-fuzz-{entry}" if project == "php" else entry
    if not (MAGMA_ROOT / ".git").is_dir():
        call([ROOT / "scripts/setup_magma.sh"], os.environ.copy(), ROOT / "setup_magma.log")
    wrapper = ROOT / "build/install/bin" / (
        "libaflgo_selectfuzz_cli_cc" if is_cli else "libaflgo_selectfuzz_cc")
    if not wrapper.is_file():
        return "missing_build", "build and install the CMake project first", 0
    map_stamp = ROOT / "build/install/lib/.selectfuzz_edges_map_size"
    if not map_stamp.is_file() or map_stamp.read_text().strip() != "2621440":
        return "missing_build", "rebuild SelectFuzz with scripts/build_selectfuzz.sh", 0
    runtime_library = ROOT / "build/install/lib" / (
        "libSelectFuzzCliRuntime.a" if is_cli else "libselectfuzz.a")
    if not runtime_library.is_file():
        return "missing_build", str(runtime_library), 0
    with runtime_library.open("rb") as stream:
        runtime_hash = hashlib.file_digest(stream, "sha256").hexdigest()
    linker_pass = ROOT / "build/install/lib/AFLGoLTOPlugin.so"
    runtime_hash = hashlib.sha256((
        runtime_hash + hashlib.sha256(wrapper.read_bytes()).hexdigest() +
        hashlib.sha256(linker_pass.read_bytes()).hexdigest() + linked_entry +
        str(int(extended_cg))
    ).encode()).hexdigest()

    base = WORK_ROOT / bug
    target, out, shared, fuzzer = (base / name for name in ("target", "out", "shared", "fuzzer"))
    for directory in (target, out, shared, fuzzer):
        directory.mkdir(parents=True, exist_ok=True)
    log = out / "workflow.log"
    target_source = MAGMA_ROOT / "targets" / project
    for name in ("patches", "build.sh", "corpus", "src", "configrc"):
        source = target_source / name
        link = target / name
        if source.exists() and not link.exists():
            link.symlink_to(source)
    if project == "php":
        # The pinned PHP version's intl extension does not compile against
        # Ubuntu 24.04's ICU. None of the fixed PHP rows targets intl.
        build_script = target / "build.sh"
        original = (target_source / "build.sh").read_text()
        compatible = original.replace("--enable-intl \\\n", "--disable-intl \\\n")
        if compatible == original:
            raise RuntimeError("PHP build script no longer has the expected intl switch")
        if build_script.is_symlink():
            build_script.unlink()
        build_script.write_text(compatible)
    (fuzzer / "configrc").write_text(
        f'{project}_BUILD_PROGRAMS=({entry})\n' if project in ("openssl", "php", "poppler") else ""
    )
    env = os.environ.copy()
    env.update({
        "MAGMA": str(MAGMA_ROOT / "magma"), "TARGET": str(target),
        "OUT": str(out), "SHARED": str(shared), "FUZZER": str(fuzzer),
        "MAGMA_BUG": bug, "MAGMA_BUG_FILE": str(out / f"bug_{bug}.diff"),
        "APPLY_ALL": "", "GIT_CONFIG_GLOBAL": str(base / "gitconfig"),
        "AFLGO_TARGETS": str(out / "aflgo_targets.txt"),
        "AFLGO_CLANG": "/usr/bin/clang-15", "AFLGO_SKIP_TARGETS_CHECK": "1",
        "AFLGO_SELECTFUZZ_MANIFEST": str(out / "selectfuzz-blocks.tsv"),
        "AFLGO_SELECTFUZZ_EXTEND_CG": "1" if extended_cg else "0",
        "AFLGO_SELECTFUZZ_ENTRY": linked_entry,
        "PAR_JOBS": "4", "AR": "/usr/bin/llvm-ar-15",
        "RANLIB": "/usr/bin/llvm-ranlib-15", "LD": "/usr/bin/ld",
        "LDFLAGS": f"-L{out} -g -Wl,--export-dynamic",
        "LIBS": ("-l:magma.o -lrt -lbrotlidec -lbz2" if project == "poppler" else
                 "-l:magma.o -lrt -ljbig -lLerc -ldeflate -lzstd -lwebp" if project == "libtiff" else
                 "-l:magma.o -lrt"),
        "REQUIRE_GET_BITCODE": "", "REQUIRE_COPY_BITCODE": "",
    })
    (base / "gitconfig").write_text("[user]\n\tname = magma\n\temail = magma@example.invalid\n")
    raw_flags = f"-include {env['MAGMA']}/src/canary.h -DMAGMA_ENABLE_CANARIES -g -O0"
    started = time.monotonic()

    repo = target / "repo"
    if repo.is_dir() and not (out / f"bug_{bug}.diff").is_file():
        head = subprocess.run(["git", "-C", repo, "rev-parse", "--verify", "HEAD"],
                              capture_output=True)
        if head.returncode != 0:
            if (repo / ".git/FETCH_HEAD").is_file():
                for attempt in range(3):
                    try:
                        call(["git", "-C", repo, "checkout", "--detach", "FETCH_HEAD"], env, log)
                        break
                    except RuntimeError:
                        time.sleep(attempt + 1)
            head = subprocess.run(["git", "-C", repo, "rev-parse", "--verify", "HEAD"],
                                  capture_output=True)
            if head.returncode != 0:
                shutil.rmtree(repo)
    if not repo.is_dir():
        cache = None
        for other in rows():
            if other["project"] != project or other["bug"] == bug:
                continue
            candidate = WORK_ROOT / other["bug"] / "target/repo"
            if not (candidate / ".git").is_dir():
                candidate = MAGMA_ROOT / "work/beacon" / other["bug"] / "target/repo"
            if (candidate / ".git").is_dir():
                tagged = subprocess.run(["git", "-C", candidate, "rev-parse", "magma-init"],
                                        capture_output=True, text=True)
                if tagged.returncode == 0:
                    cache = candidate
                    break
        if cache is not None:
            revision = subprocess.check_output(
                ["git", "-C", cache, "rev-parse", "magma-init"], text=True
            ).strip()
            local_checkout(cache, target / "repo", revision, env, log)
            if project == "libtiff":
                shutil.copy2(target / "src/tiff_read_rgba_fuzzer.cc",
                             target / "repo/contrib/oss-fuzz/tiff_read_rgba_fuzzer.cc")
            elif project == "openssl":
                shutil.copy2(target / "src/abilist.txt", target / "repo/abilist.txt")
            elif project == "php":
                nested = cache / "oniguruma"
                nested_rev = subprocess.check_output(
                    ["git", "-C", nested, "rev-parse", "HEAD"], text=True
                ).strip()
                local_checkout(nested, target / "repo/oniguruma", nested_rev, env, log)
            elif project == "poppler":
                nested = cache.parent / "freetype2"
                if (nested / "subprojects/dlg/include/dlg/dlg.h").is_file():
                    # FreeType's pinned checkout includes a nested dlg
                    # submodule. A local parent-only Git checkout leaves its
                    # gitlink without files and later omits libfreetype.a.
                    shutil.copytree(nested, target / "freetype2", symlinks=True)
                else:
                    nested_rev = subprocess.check_output(
                        ["git", "-C", nested, "rev-parse", "HEAD"], text=True
                    ).strip()
                    local_checkout(nested, target / "freetype2", nested_rev, env, log)
        elif project in PINNED_GIT:
            remote, revision = PINNED_GIT[project]
            if project == "php":
                github_archive_checkout(remote, revision, target / "repo", env, log)
            else:
                shallow_checkout(remote, revision, target / "repo", env, log)
            if project == "libtiff":
                shutil.copy2(target / "src/tiff_read_rgba_fuzzer.cc",
                             target / "repo/contrib/oss-fuzz/tiff_read_rgba_fuzzer.cc")
            elif project == "openssl":
                shutil.copy2(target / "src/abilist.txt", target / "repo/abilist.txt")
            elif project == "php":
                github_archive_checkout("https://github.com/kkos/oniguruma.git",
                                        "227ec0bd690207812793c09ad70024707c405376",
                                        target / "repo/oniguruma", env, log)
            elif project == "poppler":
                shallow_checkout("https://gitlab.freedesktop.org/freetype/freetype.git",
                                 "50d0033f7ee600c5f5831b28877353769d1f7d48",
                                 target / "freetype2", env, log)
        else:
            call(["bash", target_source / "fetch.sh"], env, log)
    if project == "php":
        oniguruma = repo / "oniguruma"
        if not (oniguruma / ".git").is_dir():
            if oniguruma.exists():
                shutil.rmtree(oniguruma)
            github_archive_checkout("https://github.com/kkos/oniguruma.git",
                                    "227ec0bd690207812793c09ad70024707c405376",
                                    oniguruma, env, log)
    if project == "poppler":
        freetype = target / "freetype2"
        if not (freetype / ".git").is_dir():
            if freetype.exists():
                shutil.rmtree(freetype)
            shallow_checkout("https://gitlab.freedesktop.org/freetype/freetype.git",
                             "50d0033f7ee600c5f5831b28877353769d1f7d48",
                             freetype, env, log)
        if not (freetype / "subprojects/dlg/include/dlg/dlg.h").is_file():
            for other in rows():
                candidate = WORK_ROOT / other["bug"] / "target/freetype2"
                if (other["bug"] != bug and other["project"] == "poppler" and
                        (candidate / "subprojects/dlg/include/dlg/dlg.h").is_file()
                ):
                    shutil.rmtree(freetype)
                    shutil.copytree(candidate, freetype, symlinks=True)
                    break
    # A source checkout may exist after a failed fetch. Check for its revision.
    if (target / "repo/.git").is_dir():
        call(["git", "-C", target / "repo", "rev-parse", "HEAD"], env, log)
    if not (out / f"bug_{bug}.diff").is_file():
        tagged = subprocess.run(["git", "-C", repo, "rev-parse", "--verify",
                                 f"refs/tags/magma-bug-{bug}"], capture_output=True)
        if tagged.returncode == 0:
            with (out / f"bug_{bug}.diff").open("w") as stream:
                subprocess.run(["git", "-C", repo, "diff",
                                f"magma-bug-{bug}^..magma-bug-{bug}"],
                               stdout=stream, check=True)
        else:
            call(["bash", env["MAGMA"] + "/apply_patches.sh"], env, log)
    if not (out / "aflgo_targets.txt").is_file():
        directed = (
            'source "$MAGMA/directed.sh"; '
            'store_magma_log_lines "$AFLGO_TARGETS"; '
            'test -s "$AFLGO_TARGETS"'
        )
        call(["bash", "-c", directed], env, log)
    if not (out / "aflgo_targets.txt").read_text().strip():
        return "target_resolution_failure", "no Magma canary source lines", 0

    env.update({"CC": "/usr/bin/clang-15", "CXX": "/usr/bin/clang++-15",
                "CFLAGS": raw_flags, "CXXFLAGS": raw_flags})
    if not (out / "monitor").is_file():
        call(["bash", env["MAGMA"] + "/prebuild.sh"], dict(env, LIBS=""), log)
    reset_marker = out / ".beacon_magma_reset_v1"
    if not reset_marker.is_file():
        canary_source = out / "beacon_canary.c"
        canary_source.write_text(
            f'#include "{env["MAGMA"]}/src/canary.c"\n'
            'void __beacon_magma_reset(void) { magma_faulty = 0; }\n'
        )
        define = f'-DMAGMA_STORAGE="{shared / "canaries.raw"}"'
        for source, output in ((canary_source, out / "canary.o"),
                               (Path(env["MAGMA"]) / "src/storage.c", out / "storage.o")):
            call(["/usr/bin/clang-15", *shlex.split(raw_flags), define,
                  "-fPIC", "-I", Path(env["MAGMA"]) / "src", "-c", source,
                  "-o", output], env, log)
        call(["/usr/bin/ld", "-r", out / "canary.o", out / "storage.o",
              "-o", out / "magma.o"], env, log)
        if (out / entry).is_file():
            (out / entry).unlink()
        reset_marker.write_text("Magma canary state resets before every input\n")
    if not (out / "stub_rt.a").is_file():
        stub = MAGMA_ROOT / "fuzzers/libaflgo_aflgo/stub_rt.c"
        call(["/usr/bin/clang-15", "-c", stub, "-o", out / "stub_rt.o"], env, log)
        call(["/usr/bin/llvm-ar-15", "rcs", out / "stub_rt.a", out / "stub_rt.o"], env, log)

    binary = out / entry
    runtime_stamp = out / ".selectfuzz_runtime_hash"
    if binary.is_file() and (not runtime_stamp.is_file() or
                            runtime_stamp.read_text().strip() != runtime_hash):
        binary.unlink()
    if not binary.is_file():
        if project == "libtiff":
            env["PATH"] = str(ROOT / "scripts/beacon-tools") + os.pathsep + env["PATH"]
        env.update({"CC": str(wrapper),
                    "CXX": str(ROOT / "build/install/bin" / (
                        "libaflgo_selectfuzz_cli_cxx" if is_cli else "libaflgo_selectfuzz_cxx")),
                    "CFLAGS": raw_flags + " -fsanitize=address -mllvm -asan-stack=0",
                    "CXXFLAGS": raw_flags + " -fsanitize=address -mllvm -asan-stack=0" +
                                (" -include limits" if project == "libxml2" else ""),
                    "LIB_FUZZING_ENGINE": str(out / "stub_rt.a")})
        try:
            call(["bash", target / "build.sh"], env, out / "build.log")
        except RuntimeError:
            # Some Magma build scripts also link an unrelated LibFuzzer
            # harness after copying the requested CLI program. That harness
            # requires the in-process main, so validate the CLI binary below.
            if not is_cli or not binary.is_file():
                raise
    if not binary.is_file():
        return "instrumentation_failure", "target build did not create fixed entry", time.monotonic() - started
    manifest = out / f"selectfuzz-blocks-{linked_entry}.tsv"
    if not manifest.is_file():
        return "instrumentation_failure", f"no selected-block manifest for linked {linked_entry}", time.monotonic() - started
    directed_target_call = has_directed_target_call(binary)
    with manifest.open() as stream:
        selected_blocks = any(line and line[0].isdigit() and line.split("\t", 1)[0] != "0"
                              for line in stream)
        if not selected_blocks and not (bug == "PDF020" and not directed_target_call):
            return "instrumentation_failure", "linked manifest has no selected blocks", time.monotonic() - started
    exported = subprocess.run(["nm", "-D", binary], capture_output=True, text=True, check=True)
    if not is_cli and "__beacon_magma_reset" not in exported.stdout:
        return "instrumentation_failure", "Magma per-input reset hook was not exported", time.monotonic() - started
    if not directed_target_call and bug != "PDF020":
        return "instrumentation_failure", "no directed target call survived linking", time.monotonic() - started
    runtime_stamp.write_text(runtime_hash + "\n")

    corpus = target / "corpus" / entry
    seeds = sorted(path for path in corpus.rglob("*") if path.is_file()) if corpus.is_dir() else []
    if not seeds:
        return "missing_corpus", f"no seeds at {corpus}", time.monotonic() - started

    monitor = out / "monitor"
    suffix = mode if not trial else f"{mode}_{trial}"
    for replay_mode in ("selectfuzz",):
        replay_env = dict(env)
        replay_suffix = replay_mode if not trial else f"{replay_mode}_{trial}"
        replay_args = cli_args(entry, seeds[0], out) if is_cli else [str(seeds[0])]
        with (out / f"replay_{replay_suffix}.csv").open("w") as stream:
            with log.open("a") as errors:
                subprocess.run([monitor, "--dump", "row", "--fetch", "watch", binary, *replay_args],
                               env=replay_env, cwd=shared, stdout=stream, stderr=errors, check=False)

    findings = shared / f"findings_{suffix}"
    if is_cli:
        cli_runner = ROOT / "target/release/selectfuzz_cli"
        if not cli_runner.is_file():
            return "missing_build", "build CLI runner with cargo +1.71.1 build -p selectfuzz_cli --release", 0
        command = ["/usr/bin/timeout", "--signal=INT", "--kill-after=5", str(seconds),
                   cli_runner, "--target", binary, "--input", corpus,
                   "--output", findings, "--logfile", out / f"fuzzer_{suffix}.log",
                   "--", *cli_args(entry, "@@", out)]
    else:
        command = ["/usr/bin/timeout", "--signal=INT", "--kill-after=5", str(seconds),
                   binary, "--input", corpus, "--output", findings,
                   "--logfile", out / f"fuzzer_{suffix}.log"]
    with (out / f"campaign_{suffix}_canaries.csv").open("w") as stream:
        with log.open("a") as errors:
            result = subprocess.run([monitor, "--dump", "row", "--fetch", "watch", *command],
                                    env=env, cwd=shared, stdout=stream, stderr=errors)
    if result.returncode not in (0, 124, 130):
        return "campaign_failure", f"exit {result.returncode}; see {log}", time.monotonic() - started
    fuzzer_log = out / f"fuzzer_{suffix}.log"
    if not fuzzer_log.is_file() or "executions:" not in fuzzer_log.read_text(errors="replace"):
        return "runtime_failure", "fuzzer exited before reporting executions", time.monotonic() - started
    if is_cli and not cli_executions(findings):
        return "runtime_failure", "CLI target produced no instrumented child executions", time.monotonic() - started
    if is_cli:
        imported = sum(1 for path in (findings / "queue").iterdir()
                       if path.is_file() and not path.name.startswith("."))
        if imported < len(seeds):
            return "seed_import_incomplete", f"only {imported}/{len(seeds)} initial seeds loaded", time.monotonic() - started
    observed_executions = [int(match.group(1)) for line in fuzzer_log.read_text(errors="replace").splitlines()
                           if (match := re.search(r"executions: (\d+)", line))]
    if observed_executions and max(observed_executions) <= len(seeds):
        return "seed_phase_incomplete", (
            f"peak executions {max(observed_executions)} did not exceed {len(seeds)} initial seeds"
        ), time.monotonic() - started
    canaries = out / f"campaign_{suffix}_canaries.csv"
    with canaries.open(newline="") as stream:
        record = next(csv.DictReader(stream), {})
    if int(record.get(f"{bug}_T", "0")) > 0:
        replay_inputs(row, mode, trial, 0, include_corpus=False)
    detail = str(canaries)
    if not directed_target_call:
        detail += "; no directed target call survived linking"
    return "campaign_complete", detail, time.monotonic() - started


def campaign_metrics(bug, mode, trial=""):
    out = WORK_ROOT / bug / "out"
    metrics = dict.fromkeys(METRIC_FIELDS, "")
    suffix = mode if not trial else f"{mode}_{trial}"
    canaries = out / f"campaign_{suffix}_canaries.csv"
    if canaries.is_file():
        with canaries.open(newline="") as stream:
            record = next(csv.DictReader(stream), {})
        metrics["reach_count"] = record.get(f"{bug}_R", "0")
        metrics["trigger_count"] = record.get(f"{bug}_T", "0")
    log = out / f"fuzzer_{suffix}.log"
    if log.is_file():
        lines = log.read_text(errors="replace").splitlines()
        for line in reversed(lines):
            match = re.search(r"executions: (\d+).*selectfuzz_executions=(\d+) selectfuzz_probes=(\d+)(?: selectfuzz_improvements=(\d+))?", line)
            if match:
                metrics["executions"] = match.group(1)
                metrics["probes"] = match.group(3)
                metrics["improvements"] = match.group(4) or ""
                break
        # A restarted LibAFL client can report zero in its final stats even
        # after earlier fuzzing. Retain the highest value observed in that log.
        if metrics["executions"] == "0":
            observations = [re.search(r"executions: (\d+).*selectfuzz_executions=(\d+) selectfuzz_probes=(\d+)", line)
                            for line in lines]
            observations = [match for match in observations if match]
            if observations:
                metrics["executions"] = str(max(int(match.group(1)) for match in observations))
                metrics["probes"] = str(max(int(match.group(3)) for match in observations))
    row = next(row for row in rows() if row["bug"] == bug)
    if row["entry"] in CLI:
        executions = cli_executions(WORK_ROOT / bug / "shared" / f"findings_{suffix}")
        if executions is not None:
            metrics["executions"] = str(executions)
        metrics["probes"] = ""
    witness = out / f"trigger_witness_{suffix}.txt"
    if witness.is_file():
        metrics["witness"] = witness.read_text().strip()
    return metrics


def replay_inputs(row, mode, trial, max_inputs, include_corpus=True):
    bug, entry = row["bug"], row["entry"]
    base = WORK_ROOT / bug
    out, shared = base / "out", base / "shared"
    binary, monitor = out / entry, out / "monitor"
    if not binary.is_file() or not monitor.is_file():
        raise RuntimeError(f"{bug} has no built target or Magma monitor")
    suffix = mode if not trial else f"{mode}_{trial}"
    findings = shared / f"findings_{suffix}"
    corpus = base / "target/corpus" / entry
    inputs = []
    saved_witness = out / f"trigger_witness_{suffix}.txt"
    if saved_witness.is_file():
        saved_path = Path(saved_witness.read_text().strip())
        if saved_path.is_file():
            inputs.append(saved_path)
    locations = [findings / "queue", findings / "crashes"]
    if include_corpus:
        locations.append(corpus)
    for location in locations:
        if location.is_dir():
            inputs.extend(sorted(path for path in location.rglob("*") if path.is_file()))
    env = dict(os.environ)
    for index, path in enumerate(inputs):
        if max_inputs and index >= max_inputs:
            break
        try:
            target_args = cli_args(entry, path, out) if entry in CLI else [str(path)]
            replay = subprocess.run([monitor, "--dump", "row", "--fetch", "watch", binary,
                                     *target_args],
                                    env=env, cwd=shared, capture_output=True, text=True,
                                    timeout=5)
        except subprocess.TimeoutExpired:
            continue
        lines = replay.stdout.splitlines()
        if len(lines) < 2:
            continue
        counts = dict(zip(lines[0].split(","), lines[1].split(",")))
        if int(counts.get(f"{bug}_T", "0")) > 0:
            witness = out / f"trigger_witness_{suffix}.txt"
            witness.write_text(str(path) + "\n")
            return str(path)
    return ""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("matrix", "run", "all", "replay"))
    parser.add_argument("bug", nargs="?")
    parser.add_argument("--seconds", type=int, default=60)
    parser.add_argument("--mode", choices=("selectfuzz",), default="selectfuzz")
    parser.add_argument("--trial", default="", help="separate artifacts for a repeated run")
    parser.add_argument("--pending-only", action="store_true",
                        help="with all, skip completed rows from this trial")
    parser.add_argument("--force", action="store_true",
                        help="rerun a completed fixed row after a method build change")
    parser.add_argument("--extended-cg", action="store_true",
                        help="resolve indirect call paths using the SVF call graph")
    parser.add_argument("--project", choices=sorted({row["project"] for row in rows()}),
                        help="with all, restrict attempts to one fixed project")
    parser.add_argument("--cli-only", action="store_true",
                        help="with all, attempt only fixed command-line entries")
    parser.add_argument("--max-inputs", type=int, default=0,
                        help="with replay, limit inputs checked (0 means all)")
    args = parser.parse_args()
    if args.seconds < 1:
        parser.error("--seconds must be positive")
    if args.trial and not re.fullmatch(r"[A-Za-z0-9_-]+", args.trial):
        parser.error("--trial must contain only letters, digits, underscore, or hyphen")
    inventory = rows()
    if args.action in ("run", "replay"):
        inventory = [row for row in inventory if row["bug"] == args.bug]
        if not inventory:
            parser.error("run and replay need one bug ID from the fixed 60 rows")
    elif args.action == "all" and args.project:
        inventory = [row for row in inventory if row["project"] == args.project]
    if args.action == "all" and args.cli_only:
        inventory = [row for row in inventory if row["entry"] in CLI]
    if args.action == "matrix":
        for row in inventory:
            current = load_status().get(row["bug"], {})
            current["status"] = current.get("status") or "not_attempted"
            current.setdefault("detail", "")
            update_status(dict(row, **current))
        print(STATUS)
        return
    if args.action == "replay":
        if args.max_inputs < 0:
            parser.error("--max-inputs cannot be negative")
        row = inventory[0]
        found = replay_inputs(row, args.mode, args.trial, args.max_inputs)
        if found:
            current = load_status().get(row["bug"], {})
            if current.get("mode") == args.mode and current.get("trial", "") == args.trial:
                updated = dict(row, **current)
                updated["witness"] = found
                update_status(updated)
            print(found)
        else:
            print(f"{row['bug']}: no triggering input replayed")
        return
    for row in inventory:
        previous = load_status().get(row["bug"], {})
        if args.action == "all" and args.pending_only and (
            (previous.get("status") == "campaign_complete" and
             previous.get("trial", "") == args.trial)
        ):
            continue
        lock_path = WORK_ROOT / row["bug"] / "out/.run.lock"
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        with lock_path.open("w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            previous = load_status().get(row["bug"], {})
            if (not args.force and previous.get("status") == "campaign_complete" and
                    previous.get("trial", "") == args.trial and
                    previous.get("mode") == args.mode):
                continue
            try:
                status, detail, duration = run(row, args.seconds, args.mode, args.trial,
                                               args.extended_cg)
            except Exception as error:
                status, detail, duration = "setup_or_build_failure", str(error), 0
            update_status(dict(row, status=status, detail=detail,
                               seconds=round(duration, 2), mode=args.mode, trial=args.trial,
                               extended_cg=int(row["entry"] in CLI or args.extended_cg),
                               **campaign_metrics(row["bug"], args.mode, args.trial)))
            print(f"{row['bug']}: {status}: {detail}", flush=True)


if __name__ == "__main__":
    main()
