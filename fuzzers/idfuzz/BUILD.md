# Build and run

Build LLVM 15 probes, Rust 1.71.1 in-process fuzzer, CLI runtime and CLI runner:

```sh
scripts/build_idfuzz.sh
```

The script writes `build/install/lib/.idfuzz_edges_map_size` and checks that the 2,621,440-byte LibAFL map size matches the linked target. The CLI runner uses a file-backed shared map. The Magma image extends `tractfuzz-beacon-magma:ubuntu24.04` with `python3-numpy`; `scripts/run_idfuzz_magma_container.sh` builds it if absent and runs the fixed-row driver. `scripts/setup_magma.sh` supplies Magma under `TractFuzz/magma` if needed.

```sh
scripts/run_idfuzz_magma_container.sh matrix
scripts/run_idfuzz_magma_container.sh run PNG006 --seconds 60
scripts/run_idfuzz_magma_container.sh run PNG006 --mode control --seconds 60
scripts/run_idfuzz_magma_container.sh all --seconds 60 --pending-only
IDFUZZ_WORKERS=6 scripts/run_idfuzz_all.sh
scripts/run_idfuzz_extended.py
python3 scripts/idfuzz_reconcile.py
python3 scripts/verify_idfuzz_campaign.py
```

The driver fixes RNG seed 1337, enforces the benchmark's entry per bug, records one manifest/config per campaign and replays trigger witnesses through Magma's monitor. After the initial matrix, `run_idfuzz_extended.py` reruns both arms of any row still importing seeds at 60 seconds with the same longer per-row budget, capped at 600 seconds. Use `--trial NAME` for separate repetitions. Exact Magma and author image IDs are in `results/idfuzz/image-ids.json`.

Author source download: `scripts/fetch_idfuzz_author.sh`. The author's Dockerfile is pinned in the downloaded source. `scripts/idfuzz-author.Dockerfile` changes only Ubuntu mirror URLs and otherwise retains the artifact's dependency/toolchain pinning; build it from the downloaded source directory for a separate author-method run.
