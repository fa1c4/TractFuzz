# Build and run

```bash
scripts/build_selectfuzz.sh
scripts/test_selectfuzz_fixture.sh
scripts/test_selectfuzz_hard_fixture.sh
python3 scripts/selectfuzz_magma.py matrix
python3 scripts/selectfuzz_magma.py run PNG006 --seconds 60
scripts/run_selectfuzz_magma_container.sh run TIF006 --seconds 60
scripts/run_selectfuzz_magma_container.sh run TIF002 --seconds 30 --extended-cg --trial extendedcg --force
scripts/run_selectfuzz_magma_container.sh all --seconds 60 --pending-only
python3 scripts/selectfuzz_audit.py
```

The build script pins Rust 1.71.1, Clang/LLVM 15, and the 2,621,440-entry LibAFL edge map. It installs `libaflgo_selectfuzz_cc`, `libaflgo_selectfuzz_cli_cc`, their C++ counterparts, the in-process and CLI runtimes, and the CLI runner. Set `AFLGO_TARGETS` to an absolute source-line file and `AFLGO_SELECTFUZZ_MANIFEST` to a TSV path before linking a target. The wrapper adds the executable stem to the manifest filename.

`scripts/selectfuzz_magma.py` uses the fixed rows from `docs/tractfuzz_magma_benchmarks.md`, stores status in `results/selectfuzz/status.csv`, and writes target artifacts under `magma/work/selectfuzz/`. It reuses pinned local source checkouts from the BEACON run when available. PDF020 is built and fuzzed on its specified `pdf_fuzzer` entry; a linked manifest with zero selected blocks is accepted for this row when the directed target call is absent.

The container launcher uses the existing `tractfuzz-beacon-magma:ubuntu24.04` dependency image. Its name reflects when it was first built; the image contains Magma build dependencies shared by both methods. The host lacks several `-dev` libraries required by CLI target builds.

`--extended-cg` enables SVF indirect-call resolution for an in-process target. The workflow includes this choice in its build stamp, so changing it rebuilds the target. Use `--trial` to keep a repeat campaign's log and findings separate.
