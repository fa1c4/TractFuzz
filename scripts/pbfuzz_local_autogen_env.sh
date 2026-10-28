#!/usr/bin/env bash
# Source this file before a libsndfile author build when system autogen is absent.
local_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/results/pbfuzz/deps/root"
if [[ ! -x "$local_root/usr/bin/autogen" ]]; then
    echo "Run scripts/install_pbfuzz_magma_deps.sh first" >&2
    return 1
fi
export PATH="$local_root/usr/bin:$PATH"
export LD_LIBRARY_PATH="$local_root/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export GUILE_LOAD_PATH="$local_root/usr/share/guile/3.0${GUILE_LOAD_PATH:+:$GUILE_LOAD_PATH}"
export GUILE_LOAD_COMPILED_PATH="$local_root/usr/lib/x86_64-linux-gnu/guile/3.0/ccache${GUILE_LOAD_COMPILED_PATH:+:$GUILE_LOAD_COMPILED_PATH}"
export AUTOGEN_TEMPLATES="$local_root/usr/share/autogen"
