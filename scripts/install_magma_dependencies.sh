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
export PATH="$HOME/.cargo/bin:$PATH"

llvm_packages=(clang-15 lld-15 llvm-15-dev libclang-rt-15-dev)
packages=(
    build-essential make git curl wget gawk time
    autoconf automake autogen libtool pkg-config ninja-build
    ca-certificates gnupg xz-utils
    "${llvm_packages[@]}" libz3-dev
    zlib1g-dev liblzma-dev libjpeg-dev nasm
    libasound2-dev libflac-dev libogg-dev libvorbis-dev libopus-dev
    libmp3lame-dev libmpg123-dev python-is-python3
    libreadline-dev bison re2c libicu-dev
    libopenjp2-7-dev libpng-dev libcairo2-dev libtiff-dev liblcms2-dev
    libjbig-dev liblerc-dev libdeflate-dev libzstd-dev libwebp-dev
    libbrotli-dev libbz2-dev
    libboost-dev tcl
)

if (( EUID == 0 )); then
    apt=(apt-get)
    as_root=()
else
    apt=(sudo apt-get)
    as_root=(sudo)
fi

declare -A llvm_package=()
for package in "${llvm_packages[@]}"; do
    llvm_package["$package"]=1
done

package_installed() {
    [[ $(dpkg-query -W -f='${Status}' "$1" 2>/dev/null || true) == "install ok installed" ]]
}

package_available() {
    apt-cache show "$1" >/dev/null 2>&1
}

add_llvm_repository() {
    local base codename keyring source suite
    codename="$(. /etc/os-release && printf '%s' "${VERSION_CODENAME:-}")"
    if [[ -z "$codename" ]]; then
        echo "Cannot determine the Ubuntu release codename for the LLVM 15 repository." >&2
        exit 1
    fi
    if ! command -v gpg >/dev/null || ! command -v curl >/dev/null; then
        DEBIAN_FRONTEND=noninteractive "${apt[@]}" install -y --no-install-recommends \
            ca-certificates curl gnupg
    fi
    keyring=/usr/share/keyrings/llvm-snapshot.gpg
    source=/etc/apt/sources.list.d/llvm-15.list
    suite="llvm-toolchain-${codename}-15"
    if ! curl -fsSL --retry 3 https://apt.llvm.org/llvm-snapshot.gpg.key |
        gpg --dearmor | "${as_root[@]}" tee "$keyring" >/dev/null; then
        if ! curl -fsSL --retry 3 \
            'https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x6084F3CF814B57C1CF12EFD515CF4D18AF4F7421' |
            gpg --dearmor | "${as_root[@]}" tee "$keyring" >/dev/null; then
            echo "Could not download the LLVM apt signing key." >&2
            exit 1
        fi
    fi
    "${as_root[@]}" chmod 0644 "$keyring"
    for base in \
        http://mirrors.tuna.tsinghua.edu.cn/llvm-apt \
        https://mirrors.tuna.tsinghua.edu.cn/llvm-apt \
        https://apt.llvm.org; do
        printf 'deb [signed-by=%s] %s/%s/ %s main\n' \
            "$keyring" "$base" "$codename" "$suite" |
            "${as_root[@]}" tee "$source" >/dev/null
        if "${apt[@]}" update; then
            return 0
        fi
        echo "LLVM repository $base is unavailable; trying another mirror." >&2
    done
    echo "Could not update an LLVM 15 apt repository." >&2
    exit 1
}

version_at_least() {
    printf '%s\n%s\n' "$2" "$1" | sort -V -C
}

install_cmake() {
    local arch attempt suffix temporary url
    arch="$(uname -m)"
    case "$arch" in
        x86_64) suffix=linux-x86_64 ;;
        aarch64|arm64) suffix=linux-aarch64 ;;
        *)
            echo "Install CMake 3.24 or newer manually for $arch." >&2
            exit 1
            ;;
    esac
    temporary="$(mktemp -d)"
    for url in \
        "https://cmake.org/files/v3.26/cmake-3.26.4-${suffix}.tar.gz" \
        "https://github.com/Kitware/CMake/releases/download/v3.26.4/cmake-3.26.4-${suffix}.tar.gz"; do
        for attempt in 1 2 3 4 5; do
            if curl -fL --retry 5 --retry-delay 2 -C - \
                -o "$temporary/cmake.tar.gz" "$url" &&
               tar -tzf "$temporary/cmake.tar.gz" >/dev/null 2>&1; then
                "${as_root[@]}" tar -xzf "$temporary/cmake.tar.gz" \
                    -C /usr/local --strip-components=1
                rm -rf "$temporary"
                hash -r
                return 0
            fi
            rm -f "$temporary/cmake.tar.gz"
            sleep "$((attempt * 2))"
        done
    done
    rm -rf "$temporary"
    echo "Could not download CMake 3.26.4." >&2
    exit 1
}

missing=()
unavailable=()
for package in "${packages[@]}"; do
    if package_installed "$package"; then
        continue
    fi
    if package_available "$package" || [[ -n "${llvm_package[$package]:-}" ]]; then
        missing+=("$package")
    else
        unavailable+=("$package")
    fi
done

if [[ ${1:-} == "--check" ]]; then
    if (( ${#missing[@]} == 0 )); then
        echo "All Magma host packages available on this host are installed."
    else
        printf 'Missing Magma host packages: %s\n' "${missing[*]}"
    fi
    if (( ${#unavailable[@]} > 0 )); then
        printf 'Unavailable on this host: %s\n' "${unavailable[*]}"
    fi
    if ! command -v cmake >/dev/null ||
       ! version_at_least "$(cmake --version | awk 'NR == 1 {print $3}')" 3.24.0; then
        echo "Missing CMake 3.24 or newer."
    fi
    if ! command -v rustup >/dev/null || ! command -v cargo >/dev/null; then
        echo "Missing rustup/cargo (Rust 1.71.1)."
    elif ! rustup toolchain list | grep -q '^1\.71\.1-'; then
        echo "Missing Rust 1.71.1 toolchain."
    fi
    exit 0
fi

export DEBIAN_FRONTEND=noninteractive
llvm_complete=1
for package in "${llvm_packages[@]}"; do
    if ! package_installed "$package"; then
        llvm_complete=0
        break
    fi
done
if (( ! llvm_complete )) && [[ -f /etc/apt/sources.list.d/llvm-15.list ]]; then
    "${as_root[@]}" rm -f /etc/apt/sources.list.d/llvm-15.list
fi
if ! "${apt[@]}" update; then
    echo "apt-get update reported errors; continuing with available package lists." >&2
fi

needs_llvm_repository=0
for package in "${llvm_packages[@]}"; do
    if ! package_installed "$package" && ! package_available "$package"; then
        needs_llvm_repository=1
        break
    fi
done
if (( needs_llvm_repository )); then
    add_llvm_repository
fi

installable=()
unavailable=()
for package in "${packages[@]}"; do
    if package_installed "$package"; then
        continue
    fi
    if package_available "$package"; then
        installable+=("$package")
    else
        unavailable+=("$package")
    fi
done
if (( ${#unavailable[@]} > 0 )); then
    printf 'Skipping packages unavailable on this host: %s\n' "${unavailable[*]}" >&2
fi
if (( ${#installable[@]} > 0 )); then
    "${apt[@]}" install -y --no-install-recommends "${installable[@]}"
fi

if ! command -v cmake >/dev/null ||
   ! version_at_least "$(cmake --version | awk 'NR == 1 {print $3}')" 3.24.0; then
    install_cmake
fi

rust_installed=0
if ! command -v rustup >/dev/null; then
    case "$(uname -m)" in
        x86_64) rust_host=x86_64-unknown-linux-gnu ;;
        aarch64|arm64) rust_host=aarch64-unknown-linux-gnu ;;
        *)
            echo "Install Rust 1.71.1 manually for $(uname -m)." >&2
            exit 1
            ;;
    esac
    temporary="$(mktemp -d)"
    for url in \
        "https://mirrors.ustc.edu.cn/rust-static/rustup/dist/${rust_host}/rustup-init" \
        "https://static.rust-lang.org/rustup/dist/${rust_host}/rustup-init"; do
        for attempt in 1 2 3 4 5; do
            if curl -fL --retry 5 --retry-delay 2 -C - \
                -o "$temporary/rustup-init" "$url"; then
                chmod +x "$temporary/rustup-init"
                if "$temporary/rustup-init" -y --profile minimal \
                    --default-toolchain none; then
                    rust_installed=1
                    break 2
                fi
            fi
            rm -f "$temporary/rustup-init"
            sleep "$((attempt * 2))"
        done
    done
    rm -rf "$temporary"
    if (( ! rust_installed )); then
        echo "Could not install rustup." >&2
        exit 1
    fi
fi
if ! rustup toolchain list | grep -q '^1\.71\.1-'; then
    if [[ -n "${RUSTUP_DIST_SERVER:-}" ]] ||
       ! RUSTUP_DIST_SERVER=https://mirrors.ustc.edu.cn/rust-static \
           rustup toolchain install 1.71.1 --profile minimal; then
        rustup toolchain install 1.71.1 --profile minimal
    fi
fi
rustup default 1.71.1 >/dev/null
if (( rust_installed )); then
    echo "Rust was installed in $HOME/.cargo; run 'source \"$HOME/.cargo/env\"' or open a new shell before building." >&2
fi
