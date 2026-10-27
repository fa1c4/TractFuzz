# SelectFuzz sources and reproduction boundary

- Paper: [SelectFuzz, IEEE S&P 2023](https://peng-hui.github.io/data/paper/sp23:selectfuzz.pdf).
- Author repository: [cuhk-seclab/SelectFuzz](https://github.com/cuhk-seclab/SelectFuzz), pinned at `1f1b5c53de6e85400c5317ac2c1984aea7d20f65` for this port. The local shallow checkout is `/tmp/tractfuzz-selectfuzz-author`.
- Framework: this repository's pinned LibAFLGo/LibAFL-directed revisions (see root `Cargo.toml` and `Cargo.lock`); Clang/LLVM 15.0.7 and Rust 1.71.1.
- Magma: checkout `cec1fec38fdc510c2cb8e6ae690e738b1042cb8d` under `magma/`; per-project revisions are fixed in `scripts/selectfuzz_magma.py`.
- Magma dependency container: local image `tractfuzz-beacon-magma:ubuntu24.04`, image ID `sha256:e69f7087fbf130ce01f977f623db46a94343edd224018063d08b2c94a28eee6f`, built from `scripts/beacon-magma.Dockerfile`. The image name predates this port; dependencies are shared.

The author repository contains AFL code and compiled `libDFUZZPASS.so` and `libINS.so`, but not the source of those two analysis and instrumentation libraries. The precise original selected-block set and instrumentation cannot be rebuilt from that snapshot. The author repository is Apache-2.0 licensed. This implementation follows the paper and records its approximations in `METHOD.md`. It is an independent LLVM 15 port, not a binary-identical reconstruction of the author's pass.

An attempt to load either bundled pass into the pinned LLVM 15 `opt-15` failed with `undefined symbol: _ZN4llvm2cl15GeneralCategoryE`; `opt-15` ignored both load requests. The raw diagnostics are in `results/selectfuzz/author-opt-help.txt` and `results/selectfuzz/author-ins-opt-help.txt`. Without pass source or a compatible author toolchain, the original selected-block trace is unavailable in this environment.
