# Build and run

```bash
scripts/build_halo.sh
cargo +1.71.1 test -p libaflgo --lib --offline
scripts/test_halo_fixture.sh
python3 scripts/halo_magma.py matrix
python3 scripts/halo_magma.py run PNG006 --seconds 60
scripts/run_halo_magma_container.sh run TIF006 --seconds 60
scripts/run_halo_magma_container.sh all --seconds 60 --pending-only
python3 scripts/halo_audit.py
scripts/run_halo_compare_container.sh TIF006 --seconds 60 --seed 17
```

The build script pins LLVM 15, Rust 1.71.1, and a 2,621,440-entry LibAFL edge map. It installs in-process and CLI wrappers/runtimes and builds `target/release/halo_cli` and the separate `target/release/halo_control_cli` ablation runner. The Magma driver writes per-row builds and campaigns under `magma/work/halo/`, with summary `results/halo/status.csv`. The container launcher uses the shared Magma dependency image built by `scripts/beacon-magma.Dockerfile`.

For a manual target, set `AFLGO_TARGETS` to absolute source-line annotations. Set `AFLGO_HALO_ENTRY` to the fixed executable stem when a build links several programs; optional `AFLGO_HALO_EXTEND_CG=1` enables indirect call-graph resolution. The driver uses the fixed corpus and entry from `docs/tractfuzz_magma_benchmarks.md`. It attempts PDF020 even if its directed call is missing, and records that condition in the result detail.

`--trial NAME` keeps campaign files distinct. `--halo-seed N` fixes RNG initialization in either runner; record it along with the trial ID for repeat comparisons. `--halo-only` omits the standard havoc stage.
