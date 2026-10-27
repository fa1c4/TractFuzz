# Halo source and reproduction boundary

- Paper: [Halo: Targeted Greybox Fuzzing With Input Invariants](https://hexhive.epfl.ch/publications/files/24Oakland2.pdf), IEEE S&P 2024.
- No public author implementation was confirmed from the paper, author page, or public repository search on 2026-10-27. This repository implements an independent, paper-based approximation on the pinned LibAFLGo/LibAFL-directed stack, not a bit-for-bit port of the authors' AFL++ prototype.
- Author artifact revision and license: unavailable because no author code artifact was confirmed. The new implementation is part of this repository under its Apache-2.0 license.
- Framework base commit: `43c059b9f9816e4b8baccda20068e0b4adf5a103` plus this worktree's Halo changes. `Cargo.lock` pins LibAFL-directed to `55145cae616e8e1d3d1cbc5774294756ed9bbe4b`; Rust 1.71.1 and Ubuntu Clang/LLVM 15.0.7.
- Magma checkout: `cec1fec38fdc510c2cb8e6ae690e738b1042cb8d` under `magma/`, with project commits in `scripts/halo_magma.py`; the fixed 60 entry/bug rows come from `docs/tractfuzz_magma_benchmarks.md`.
- Dependency image: `tractfuzz-beacon-magma:ubuntu24.04`, image ID `sha256:e69f7087fbf130ce01f977f623db46a94343edd224018063d08b2c94a28eee6f`, built from `scripts/beacon-magma.Dockerfile` and shared with the earlier baselines.

The paper describes two input pools (target-reaching and non-reaching), likely invariant inference, utility-based invariant selection, and constrained sampling. It uses DIG for inference and Vaidya walk for linear-constraint sampling. These exact implementations and the paper's per-branch operand probes are absent here. The choices in `METHOD.md` are frozen for the current pilot and must be identified as deviations in comparisons.
