#!/usr/bin/env bash
# Install Magma libsndfile build tools, rootless by default.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
deps="$root/results/pbfuzz/deps"
if [[ "${1:-}" == --system ]]; then
    packages=(git make autoconf autogen automake build-essential libasound2-dev
        libflac-dev libogg-dev libtool libvorbis-dev libopus-dev libmp3lame-dev
        libmpg123-dev pkg-config python3)
    missing=()
    for package in "${packages[@]}"; do
        if ! dpkg-query -W -f='${Status}' "$package" 2>/dev/null | grep -q '^install ok installed$'; then
            missing+=("$package")
        fi
    done
    if ((${#missing[@]} == 0)); then
        echo 'Magma libsndfile dependencies are already installed.'
        exit 0
    fi
    if ((EUID == 0)); then
        apt-get update
        DEBIAN_FRONTEND=noninteractive apt-get install -y "${missing[@]}"
    else
        sudo apt-get update
        sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y "${missing[@]}"
    fi
    exit 0
fi
if [[ $# -ne 0 ]]; then
    echo 'usage: install_pbfuzz_magma_deps.sh [--system]' >&2
    exit 2
fi
mkdir -p "$deps/apt-cache" "$deps/root"
(cd "$deps/apt-cache" && apt-get download autogen guile-3.0-libs libopts25 libopts25-dev)
for package in "$deps"/apt-cache/*.deb; do
    dpkg-deb -x "$package" "$deps/root"
done
env \
    LD_LIBRARY_PATH="$deps/root/usr/lib/x86_64-linux-gnu" \
    GUILE_LOAD_PATH="$deps/root/usr/share/guile/3.0" \
    GUILE_LOAD_COMPILED_PATH="$deps/root/usr/lib/x86_64-linux-gnu/guile/3.0/ccache" \
    AUTOGEN_TEMPLATES="$deps/root/usr/share/autogen" \
    "$deps/root/usr/bin/autogen" --version
echo "Rootless AutoGen is ready under $deps/root."
