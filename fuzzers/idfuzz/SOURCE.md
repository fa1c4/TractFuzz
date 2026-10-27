# IDFuzz source and pin

- Paper: Chen et al., *IDFuzz: Intelligent Directed Grey-box Fuzzing*, USENIX Security 2025, <https://www.usenix.org/system/files/usenixsecurity25-chen-yiyang.pdf>.
- Author artifact: <https://github.com/vul337/IDFuzz>, pinned at `86d11b35c2d8885bd35ab7b9b8d627a91954d80d`. The source tarball SHA-256 is `bee9502244e5fdf696ee47f253e92ef3b81a2f2c3404a7d62965ec1a6f4726fe`. Fetch with `scripts/fetch_idfuzz_author.sh`. License: Apache-2.0 (`LICENSE` in the author artifact).
- Framework base: this checkout's LibAFLGo fork (`git rev-parse HEAD` at run time), LibAFL-directed `55145cae616e8e1d3d1cbc5774294756ed9bbe4b`, LLVM 15, Rust 1.71.1. Each Magma campaign saves binary, runtime, model-script, dominator-manifest and seed digests in `idfuzz-config-v1.json`.
- Magma source: `magma/` at the revision recorded by its Git checkout. The fixed 60 pairs are in `docs/tractfuzz_magma_benchmarks.md`.

The LibAFLGo code is an independent adaptation of the published design. It does not vendor or invoke the author's AFL2 fuzzer or PyTorch model. The original source is archived separately under `results/idfuzz/source/` and is never mixed into the LibAFLGo campaign data.
