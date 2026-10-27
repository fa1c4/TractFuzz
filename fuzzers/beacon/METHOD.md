# BEACON adaptation in this fork

This implementation is an **entry-precondition subset**, not a faithful port of
the original BEACON analysis. The original [artifact](https://github.com/5hadowblad3/Beacon_artifact)
is pinned at `cb4f042c96f35b65cac767ed0daf4615d72b5910`; its LLVM 4
`precondInfer` performs backward interval analysis with relational preservation
and bounded disjunction, then records `bbreaches.txt`, `range_res.txt`, and
`transed.bc`. Those analyses and the original process-exit instrumentation are
not present here. The fork retains LibAFLGo's distance scheduler and mutation.

## Implemented pruning rule

The LLVM 15 link pass considers `LLVMFuzzerTestOneInput` only. It accepts an
integer comparison of a function argument with a constant in the entry block
only when:

1. The entry prefix before the branch reads no memory and has no side effects.
2. The entry branch dominates every known target block and every call that may
   reach a target. Indirect and external calls are conservatively treated as
   possible target origins.
3. Exactly one branch successor can reach such an origin.
4. The other successor's entire reachable path reads no memory, has no side
   effects, and returns zero if it terminates.

The pass copies that comparison to a new entry check. A failed check calls
`__beacon_should_prune(guard_id)`. In `hard` mode the call returns true and the
function returns zero; `shadow` records the would-prune decision and continues;
`off` continues without counting. The in-process observer resets per-input
counters. Set `BEACON_TRACE=/path/to/trace.csv` for per-input guard decisions.
At the guard, target and canary code for this input has not executed. The build
log records the LLVM comparison for every emitted guard.

Magma's `magma_faulty` canary state also persists across in-process inputs.
The Magma runner compiles a generated canary object with
`__beacon_magma_reset`, exports that symbol from the target, and resolves it
once via `dlsym`. `begin_input` calls it before every input. The pinned Magma
sources are not edited. The runner checks the exported symbol and an actual
directed target call before accepting a built binary.

The 15 fixed command-line rows use `fuzzers/beacon_cli`, a separate LibAFL
`CommandExecutor` runner. Its target process writes edge hits, AFLGo distance,
target hits, and an execution counter to a shared map through
`libBeaconCliRuntime.a`. The runner resets feedback before each child, and a
fresh process resets Magma's canary state. The pinned LibAFL executor clears
the child environment when cloning a command, so the runner explicitly
passes its environment, including Magma's `MAGMA_STORAGE`, to each child.
`scripts/test_beacon_cli_magma.sh` checks coverage executions and canary
counts together. The CLI adapter follows each target's Magma `configrc`
flags; output file prefixes are moved into its row workdir. Since the current
LLVM pruning pass handles `LLVMFuzzerTestOneInput` only, these CLI rows have
distance guidance but no BEACON early-prune guards.

This proof applies only to the selected link-time IR and to concrete initialized
argument values. It does not infer byte-level, numeric relational, or nested
path conditions as BEACON does. Optimizations, external calls, and memory
predicates normally cause the pass to emit no guard. A zero-prune campaign is
therefore an AFLGo-like run and must not be presented as evidence of BEACON's
pruning benefit.

## Build and reproduce

Use LLVM 15, CMake 3.24+, Z3, and Rust 1.71.1. The root `CMakeLists.txt` has a
`LIBAFLGO_USE_SYSTEM_Z3` option for a locally installed `libz3-dev`. The build
script sets `LIBAFL_EDGES_MAP_SIZE=2621440`; the default 65,536-edge LibAFL
runtime exits before fuzzing larger targets such as SQLite.

```sh
scripts/setup_magma.sh
scripts/install_magma_dependencies.sh --check
scripts/build_beacon.sh
python3 scripts/beacon_magma.py matrix
python3 scripts/beacon_magma.py run PNG006 --seconds 30 --mode shadow
python3 scripts/beacon_magma.py run PNG006 --seconds 30 --mode hard
scripts/run_beacon_magma_container.sh all --cli-only --seconds 30 --mode shadow --trial cli3
scripts/test_beacon_cli_magma.sh
```

`scripts/beacon_magma.py all --seconds N` iterates the 60 fixed rows and
records every result in `results/beacon/status.csv`. Its target sources, build
logs, monitor outputs, and findings are under `magma/work/beacon/`. Fifteen
fixed rows use command-line programs through the external executor and retain
their fixed program and input placement.
Use `--trial NAME` for separate campaign artifacts and `--pending-only` to
resume an interrupted `all` pass.
If Magma reports a trigger without a saved queue witness, use
`scripts/run_beacon_magma_container.sh replay BUG --mode shadow --trial NAME`
to test the saved queue, crashes, and original seed corpus independently.
The container helper `scripts/run_beacon_magma_container.sh` installs target
build dependencies in an isolated Ubuntu image when host sudo is unavailable.
The runner supplies TIFF's codec libraries at final link and includes
`<limits>` for the pinned libxml2 C++ fuzzers. For PHP it checks the pinned
GitHub source archives against SHA-256 hashes and builds with `--disable-intl`:
the pinned PHP source's `intl` extension is incompatible with Ubuntu 24.04's
ICU, and none of the seven fixed PHP entries targets `intl`. These are build
compatibility changes, not bug patches; each row's Magma patch remains in its
source checkout. The per-row `build.log` records the actual compiler commands.
Poppler's static FreeType link adds Brotli and bzip2. The libtiff build uses
the packaged Autotools `config.guess` and `config.sub` files if its old
Savannah URL fails.

Magma-directed is pinned at `cec1fec38fdc510c2cb8e6ae690e738b1042cb8d`,
which is based on Magma v1.2 according to its README. The benchmark document's
inventory is labeled v1.2.1. Results from this checkout require row-by-row
replay before comparison with the v1.2.1 inventory.
