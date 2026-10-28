# PBFuzz build and run

Raw source, builds, campaigns, keys and logs live under ignored `results/pbfuzz/`. `scripts/fetch_pbfuzz_author.sh` fetches and verifies the archived artifact, current author checkout and Magma fork pinned in [SOURCE.md](SOURCE.md). The archived Cursor launcher is retained for provenance; the runnable path below uses the current author's DSH plugin and the user's DeepSeek API key. The author `./build.sh` completed, producing the Python engine venv and DSH plugin; `./install.sh --profile headless` installed the plugin into isolated `results/pbfuzz/dsh-home`. The first install attempt failed because DSH's child `pnpm` could not see the locally installed executable. Adding `results/pbfuzz/source/github/.local/bin` to `PATH` fixed it. `scripts/run_pbfuzz_magma.sh` sets this path on every run.

The isolated DSH profile configures `pbfuzz-gateway` through `llm-pi-ai`, with `apiKeyEnv: API_KEY`, protocol `openai-completions`, and the model from the user key script. The secret itself is only sourced into the process environment. The script writes per-campaign model configuration and endpoint hash to `results/pbfuzz/<BUG>-model-config.json`; the profile and session archives are ignored. A default campaign is capped at two PIER rounds, ten minutes and 1,000 fuzz iterations. Override with `PBFUZZ_MAX_ROUNDS`, `PBFUZZ_WALL_MIN`, and `PBFUZZ_MAX_ITERS`. `PBFUZZ_HARD_WALL_SEC` supplies a process-level outer limit; the default is the PIER wall budget plus five minutes because the author PIER wall cap is checked only at phase transitions.

From the repository root:

```sh
scripts/fetch_pbfuzz_author.sh
cd results/pbfuzz/source/github
./build.sh
PATH="$PWD/.local/bin:$PATH" DSH_HOME=/data/zym/TractFuzz/results/pbfuzz/dsh-home ./install.sh --profile headless
cd /data/zym/TractFuzz
scripts/run_pbfuzz_api_probe.sh
scripts/run_pbfuzz_magma.sh PNG006 libpng libpng_read_fuzzer
python3 scripts/pbfuzz_replay.py PNG006
python3 scripts/pbfuzz_audit.py
python3 scripts/pbfuzz_usage.py
scripts/run_pbfuzz_fixed.sh PNG006
python3 scripts/pbfuzz_fixed_replay.py PNG006
python3 scripts/run_pbfuzz_60.py --track fixed --execute --max-iters 1000
python3 scripts/pbfuzz_finalize_fixed.py
```

`scripts/run_pbfuzz_magma.sh` sources `~/api_keys/set_api_key.sh` by default; `PBFUZZ_KEY_SCRIPT` can point to another export script. It suppresses that script's output. The runnable Magma target is built with the author's `examples/magma/build-target.sh`, `clang-15` and `clang++-15` in this environment. The exact campaign YAML and final state are retained with the raw run.

`scripts/run_pbfuzz_fixed.sh` uses the same DeepSeek API route and author engine with the frozen benchmark's already-built binary, exact entry, corpus and Magma monitor. It does not build the author's separate Magma fork. The campaign generator checks the target canary source line before each run. `PBFUZZ_HARD_WALL_SEC` defaults to 360 seconds per target in this track; the batch runner also exposes `--rounds`, `--wall-min`, `--max-iters` and `--hard-wall-sec`. `fuzzers/pbfuzz/fixed-60.csv` is refreshed by the audit script and reports every attempted row separately from PoV replay status.

The fixed runner stages the source, binary, monitor and corpus under `results/pbfuzz/isolated/<BUG>/` before calling the model. It temporarily hides the bug's original Magma work directory during the model session, then restores it for independent replay. `scripts/build_pbfuzz_landlock.sh` compiles a rootless Linux Landlock read boundary from `scripts/pbfuzz_landlock.c`; the fixed runner builds it on demand and allows the staged target, pinned author engine, DSH profile, Conda and Node runtimes, and required system paths. `scripts/pbfuzz_reset_fixed.py BUG_ID` archives a completed attempt and prepares a clean rerun. Earlier unisolated runs remain under `results/pbfuzz/prior-unisolated/`.

The libsndfile target needs GNU AutoGen. `scripts/install_pbfuzz_magma_deps.sh` downloads AutoGen, Guile and libopts into `results/pbfuzz/deps/root` without sudo; `scripts/pbfuzz_local_autogen_env.sh` exports their runtime paths during the build. `--system` installs the full Magma libsndfile dependency list through apt if sudo is available. The author's SQLite target links a C++ file-input proxy through a C compiler; `scripts/pbfuzz_sqlite_cc.sh` adds `-lstdc++` at link time without changing the pinned author source.
