#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
export RUSTUP_TOOLCHAIN=1.71.1
export LIBAFL_EDGES_MAP_SIZE=2621440
export CARGO_NET_GIT_FETCH_WITH_CLI=true
export CARGO_HTTP_MULTIPLEXING=false

cmake -S . -B build -G Ninja \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_C_COMPILER=clang-15 -DCMAKE_CXX_COMPILER=clang++-15 \
    -DLIBAFLGO_USE_SYSTEM_Z3=ON \
    -DRust_TOOLCHAIN=1.71.1-x86_64-unknown-linux-gnu \
    -DCMAKE_INSTALL_PREFIX="$repo_root/build/install" "$@"
if [[ -e build/install/lib/AFLGoLTOPlugin.so ]]; then
    cmake --build build --target fuzzers/halo/libhalo.a HaloCliRuntime -j"${HALO_BUILD_JOBS:-8}"
else
    cmake --build build -j"${HALO_BUILD_JOBS:-8}"
fi
cmake --install build
RUSTUP_TOOLCHAIN=1.71.1 cargo build --locked --release \
    --package halo_cli --package halo_control_cli
printf '%s\n' "$LIBAFL_EDGES_MAP_SIZE" > \
    "$repo_root/build/install/lib/.halo_edges_map_size"
