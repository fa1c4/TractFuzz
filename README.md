# LibAFLGo

<img src="logo.png" width="340" align="right" />

_LibAFLGo: Evaluating and Advancing Directed Greybox Fuzzing_
(<a href="https://download.vusec.net/papers/libaflgo_eurosp25.pdf" target="_blank">paper</a>).

LibAFLGo extends [LibAFL](https://github.com/AFLplusplus/LibAFL) for directed fuzzing. It
re-implements three directed fuzzing policies in a modular fashion: AFLGo, Hawkeye, and DAFL. The
LLVM-based compiler passes integrate with [SVF](https://github.com/SVF-tools/SVF), which provides a
plethora of analyses out-of-the-box.

The research artifacts are split across three repositories:

- this repository contains directed fuzzing extensions for LibAFL, re-implemented fuzzers
- [MAGMA-directed](https://github.com/vusec/magma-directed) extends MAGMA for directed fuzzing
- [LibAFL-directed](https://github.com/vusec/LibAFL-directed) contains minor patches to LibAFL

We aim to upstream LibAFLGo to LibAFL.

## Project Structure

```
.
├── fuzzers                                             <- contains re-implemented fuzzers
│   ├── aflgo
│   ├── dafl
│   └── hawkeye
├── include                                             <- header files for LLVM passes
│   ├── AFLGoCompiler                                   <-   compile-time plugin
│   │   └── TargetInjection.hpp                         <-     instruments target locations
│   ├── AFLGoLinker                                     <-   link-time plugin
│   │   ├── DAFL.hpp                                    <-     DAFL instrumentation
│   │   ├── DistanceInstrumentation.hpp                 <-     AFLGo distance instrumentation
│   │   ├── DuplicateTargetRemoval.hpp                  <-     supporting target instrumentation
│   │   ├── FunctionDistanceInstrumentation.hpp         <-     Hawkeye distance instrumentation
│   │   └── TargetInjectionFixup.hpp                    <-     supporting target instrumentation
│   └── Analysis                                        <-   analyses used by plugins
│       ├── BasicBlockDistance.hpp                      <-     AFLGo basic block distance analysis
│       ├── DAFL.hpp                                    <-     DAFL data-flow distance
│       ├── ExtendedCallGraph.hpp                       <-     enhance CFG with PTA
│       ├── FunctionDistance.hpp                        <-     Hawkeye function distance analysis
│       └── TargetDetection.hpp                         <-     supporting target instrumentation
├── libaflgo                                            <- LibAFL fuzzer components
├── libaflgo_targets                                    <- LibAFL target instrumentation components
├── passes                                              <- implementation of LLVM passes
├── test                                                <- tests for LLVM passes
├── wrapper                                             <- compiler wrapper libaflgo_cc
├── Cargo.lock
├── Cargo.toml
├── CMakeLists.txt                                      <- cmake build entrypoint
├── README.md
├── rust-toolchain.toml
├── SVF-1282.patch                                      <- patch SVF for ASan compatibility
```

## Building

You can use `cmake` to build LLVM passes and LibAFL components. After opening the project in our devcontainer with your editor (we recommend VSCode), you can build the project with the following commands:

```
cmake -S /workspaces/libaflgo \
      -B /workspaces/libaflgo/build \
      -G Ninja \
      -DCMAKE_BUILD_TYPE=RelWithDebInfo \
      -DCMAKE_EXPORT_COMPILE_COMMANDS=TRUE \
      -DCMAKE_C_COMPILER=/usr/bin/clang-15 \
      -DCMAKE_CXX_COMPILER=/usr/bin/clang++-15 \
      -DBUILD_TESTING=ON \
      --no-warn-unused-cli

cmake --build /workspaces/libaflgo/build \
      --config RelWithDebInfo \
      --target all \
      --
```

You can then run the tests with the check target

## MAGMA Integration (mileage may vary, as this was not tested recently)

We extended [MAGMA](https://github.com/vusec/magma-directed) for directed fuzzing. The original
documentation applies also to our fork. The easiest way to get up and running to fuzz targets is to
look at the LibAFLGo integrations in the `fuzzers` folder in that repository.

## Baselines on the fixed 60 Magma bugs

The benchmark is the exact 60 bug/entry pairs in [docs/tractfuzz_magma_benchmarks.md](docs/tractfuzz_magma_benchmarks.md), including `PDF020`. The runners retain Magma canary reach, trigger, and replay evidence separately. A completed campaign with no trigger is a bounded observation, not proof that a bug is unreachable.

| Arm | Implementation in this repository | Evaluation setting |
| --- | --- | --- |
| AFLGo | IDFuzz's same-binary LibAFLGo control, with learned guidance disabled | `control` mode; paired RNG seed with IDFuzz |
| [BEACON](fuzzers/beacon/METHOD.md) | Conservative entry-precondition pruning on LibAFLGo; CLI entries use distance guidance without pruning guards | `hard` mode |
| [SelectFuzz](fuzzers/selectfuzz/METHOD.md) | LLVM 15 selected-block analysis and feedback with LibAFLGo scheduling | Extended call graph |
| [Halo](fuzzers/halo/METHOD.md) | Input-invariant inference and sampling plus LibAFLGo mutation | Extended call graph |
| [IDFuzz](fuzzers/idfuzz/METHOD.md) | Dominator feedback, asynchronous learned byte guidance, and LibAFLGo mutation | Same seed as the AFLGo control in each trial |
| [PBFuzz](fuzzers/pbfuzz/METHOD.md) | Current author DeepSeek Harness agent on frozen Magma binaries through a monitor oracle | Standalone fixed-binary adaptation; no LibAFLGo seed-import campaign is implied |

Build Magma and the four LibAFLGo method variants first. Prebuild both Docker images before evaluation. PBFuzz also requires the pinned author plugin and the DeepSeek-compatible `~/api_keys/set_api_key.sh`; follow [its build instructions](fuzzers/pbfuzz/BUILD.md). Its fixed-binary runs require the 60 IDFuzz Magma target builds; the combined command runs IDFuzz before PBFuzz. For PBFuzz alone, build those targets first. AFLGo is the same-binary IDFuzz control used for the paired comparison; it is not a separately built upstream AFLGo binary.

```sh
scripts/setup_magma.sh
scripts/install_magma_dependencies.sh --check
# If the check lists missing packages: scripts/install_magma_dependencies.sh
scripts/build_beacon.sh
scripts/build_selectfuzz.sh
scripts/build_halo.sh
scripts/build_idfuzz.sh
docker build -f scripts/beacon-magma.Dockerfile -t tractfuzz-beacon-magma:ubuntu24.04 scripts
docker build -f scripts/idfuzz-magma.Dockerfile -t tractfuzz-idfuzz-magma:ubuntu24.04 scripts
# For PBFuzz alone, if frozen IDFuzz binaries are absent:
# scripts/run_idfuzz_magma_container.sh all --seconds 60 --trial pbfuzz_prebuild

# Inspect the exact schedule without starting a campaign or making model calls.
python3 scripts/evaluate_magma_baselines.py --dry-run

# One trial of all six arms, 24 hours per target, up to 64 campaigns at once.
python3 scripts/evaluate_magma_baselines.py --trials 1 --fuzz-time 24h --parallel-worker 64 --eval-name magma24h_v1

# Repeat three trials. Use the same evaluation name to resume.
python3 scripts/evaluate_magma_baselines.py --trials 3 --fuzz-time 24h --parallel-worker 64 --eval-name magma24h_v3
```

`--trials` defaults to `1`; `--fuzz-time` defaults to `24h` and accepts `s`, `m`, `h`, or `d` (a bare number means seconds). The time is **per bug and per arm**. `--parallel-worker` defaults to `64` and uses at most that many logical CPUs from the caller's affinity mask. Each active campaign gets one distinct CPU: Docker uses `--cpuset-cpus`, and PBFuzz host processes inherit CPU affinity. The six arms schedule 360 target-days of campaigns per trial, excluding build and analysis time. PBFuzz gets the requested fuzz-stage cap plus up to one hour for agent planning and teardown; it can stop earlier, and its wall time is not a pure fuzzer-execution budget.

Before each LibAFLGo arm, the evaluator builds one target per Magma project to establish a local source cache; these nine warmups do not fuzz. It then runs the 60 bug campaigns in parallel. The arms run in the table order so IDFuzz's frozen binaries are ready for PBFuzz.

Run one or more arms by selecting them:

```sh
python3 scripts/evaluate_magma_baselines.py --baselines aflgo --trials 3 --fuzz-time 24h --eval-name aflgo24h
python3 scripts/evaluate_magma_baselines.py --baselines beacon --trials 3 --fuzz-time 24h --eval-name beacon24h
python3 scripts/evaluate_magma_baselines.py --baselines selectfuzz --trials 3 --fuzz-time 24h --eval-name selectfuzz24h
python3 scripts/evaluate_magma_baselines.py --baselines halo --trials 3 --fuzz-time 24h --eval-name halo24h
python3 scripts/evaluate_magma_baselines.py --baselines idfuzz --trials 3 --fuzz-time 24h --eval-name idfuzz24h
python3 scripts/evaluate_magma_baselines.py --baselines pbfuzz --trials 3 --fuzz-time 24h --eval-name pbfuzz24h
```

All evaluation files live under the ignored `workspace/<eval-name>/`. The evaluator stages scripts, Magma inputs, installed compiler/runtime files, and optional PBFuzz assets there. Its summary is `workspace/<eval-name>/results/baselines/evaluations/<eval-name>/summary.csv`; raw LibAFLGo outputs are under that evaluation's `magma/work/<method>/<BUG>/`, and PBFuzz evidence is under its `results/pbfuzz/`. The evaluation does not build Docker images. Each container bind-mounts only the staged evaluation root and uses a read-only root filesystem with container-only `/tmp`; a host Landlock write rule confines the evaluator and PBFuzz children to the evaluation root. Docker's temporary internal container state is removed with `docker run --rm`. PBFuzz archives each prior attempt before a new trial and records per-bug evidence in `trial-60.csv`. Its generated-input scan checks at most 500 inputs or 120 seconds after a non-successful campaign. Halo uses a recorded per-trial RNG seed; IDFuzz and its AFLGo control share one within each trial (`1337`, `1338`, …). BEACON and SelectFuzz seed their fuzzer RNG from process time. Compare canary outcomes, replayed inputs, budgets, and method limits before making an efficacy claim.
