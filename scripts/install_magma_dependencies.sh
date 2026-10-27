#!/usr/bin/env bash
set -euo pipefail

# Host packages declared by Magma's preinstall scripts, with current Ubuntu
# names for Python and JPEG development headers. Run with --check to inspect.
if [[ ${1:-} != "" && ${1:-} != "--check" ]]; then
    echo "usage: $0 [--check]" >&2
    exit 2
fi
if ! command -v apt-get >/dev/null || ! command -v dpkg-query >/dev/null; then
    echo "This installer requires an apt-based host." >&2
    exit 1
fi

packages=(
    build-essential make git curl wget gawk time
    autoconf automake autogen libtool pkg-config cmake ninja-build
    clang-15 lld-15 llvm-15-dev libclang-rt-15-dev libz3-dev
    zlib1g-dev liblzma-dev libjpeg-dev nasm
    libasound2-dev libflac-dev libogg-dev libvorbis-dev libopus-dev
    libmp3lame-dev libmpg123-dev python-is-python3
    libreadline-dev bison re2c libicu-dev
    libopenjp2-7-dev libpng-dev libcairo2-dev libtiff-dev liblcms2-dev
    libjbig-dev liblerc-dev libdeflate-dev libzstd-dev libwebp-dev
    libbrotli-dev libbz2-dev
    libboost-dev tcl
)
missing=()
for package in "${packages[@]}"; do
    if [[ $(dpkg-query -W -f='${Status}' "$package" 2>/dev/null || true) != "install ok installed" ]]; then
        missing+=("$package")
    fi
done
if (( ${#missing[@]} == 0 )); then
    echo "All Magma host packages are installed."
elif [[ ${1:-} == "--check" ]]; then
    printf 'Missing Magma host packages: %s\n' "${missing[*]}"
else
    if (( EUID == 0 )); then
        apt=(apt-get)
    else
        apt=(sudo apt-get)
    fi
    export DEBIAN_FRONTEND=noninteractive
    "${apt[@]}" update
    "${apt[@]}" install -y --no-install-recommends "${missing[@]}"
fi

if [[ ${1:-} != "--check" ]] && command -v rustup >/dev/null &&
   ! rustup toolchain list | grep -q '^1\.71\.1-'; then
    rustup toolchain install 1.71.1 --profile minimal
fi
