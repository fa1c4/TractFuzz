#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source_root="$repo_root/results/pbfuzz/source/github"
dsh_home="$repo_root/results/pbfuzz/dsh-home"
profile=headless
key_script="${PBFUZZ_KEY_SCRIPT:-$HOME/api_keys/set_api_key.sh}"

check_landlock() {
    local abi
    abi="$(python3 - <<'PY'
import ctypes
libc = ctypes.CDLL(None, use_errno=True)
result = libc.syscall(444, None, 0, 1)
print(result if result >= 0 else 0)
PY
)"
    if (( abi < 3 )); then
        echo "PBFuzz evaluation requires Landlock ABI 3 or newer (Linux >= 6.2); current kernel provides ABI $abi." >&2
        exit 1
    fi
    if [[ ! -r /usr/include/linux/landlock.h ]] ||
       ! grep -q LANDLOCK_ACCESS_FS_TRUNCATE /usr/include/linux/landlock.h; then
        echo "Landlock ABI 3 headers are missing; install Linux 6.2 or newer UAPI headers." >&2
        exit 1
    fi
}

node_ok() {
    "$1" -e 'const [a,b]=process.versions.node.split(".").map(Number); process.exit(a>22||(a===22&&b>=19)?0:1)' \
        >/dev/null 2>&1
}

node_tree_ok() {
    local dir="$1"
    node_ok "$dir/bin/node" &&
        PATH="$dir/bin:$PATH" "$dir/bin/npm" --version >/dev/null 2>&1 &&
        PATH="$dir/bin:$PATH" "$dir/bin/corepack" --version >/dev/null 2>&1
}

ensure_node() {
    local attempt base downloaded filename expected node_dir sums temporary
    if command -v node >/dev/null && node_ok "$(command -v node)"; then
        return 0
    fi
    node_dir="$source_root/.local/node"
    if [[ -d "$node_dir" ]] && node_tree_ok "$node_dir"; then
        export PATH="$node_dir/bin:$PATH"
        return 0
    fi
    temporary="$(mktemp -d)"
    downloaded=0
    for base in \
        https://mirrors.tuna.tsinghua.edu.cn/nodejs-release \
        https://nodejs.org/dist; do
        if ! sums="$(curl -fsSL --http1.1 --retry 5 --retry-delay 3 \
            "$base/latest-v22.x/SHASUMS256.txt")"; then
            continue
        fi
        filename="$(printf '%s\n' "$sums" |
            awk '$2 ~ /^node-v[0-9.]+-linux-x64\.tar\.xz$/ {print $2; exit}')"
        expected="$(printf '%s\n' "$sums" |
            awk -v f="$filename" '$2 == f {print $1; exit}')"
        [[ -n "$filename" && -n "$expected" ]] || continue
        for attempt in 1 2 3 4 5; do
            if curl -fL --http1.1 --retry 5 --retry-delay 3 -C - \
                -o "$temporary/node.tar.xz" \
                "$base/latest-v22.x/$filename"; then
                if printf '%s  %s\n' "$expected" "$temporary/node.tar.xz" |
                    sha256sum -c - >/dev/null 2>&1; then
                    downloaded=1
                    break 2
                fi
                rm -f "$temporary/node.tar.xz"
            fi
            sleep "$((attempt * 3))"
        done
        rm -f "$temporary/node.tar.xz"
    done
    if (( ! downloaded )); then
        echo "Could not download Node.js 22." >&2
        rm -rf "$temporary"
        exit 1
    fi
    rm -rf "$node_dir"
    mkdir -p "$node_dir"
    tar -xJf "$temporary/node.tar.xz" -C "$node_dir" --strip-components=1
    rm -rf "$temporary"
    if ! node_tree_ok "$node_dir"; then
        echo "Local Node.js 22 installation failed." >&2
        exit 1
    fi
    export PATH="$node_dir/bin:$PATH"
}

check_landlock
"$repo_root/scripts/fetch_pbfuzz_author.sh"
ensure_node

(
    cd "$source_root"
    ./build.sh
    PATH="$source_root/.local/bin:$PATH" DSH_HOME="$dsh_home" \
        ./install.sh --profile "$profile"
)

bash "$repo_root/scripts/build_pbfuzz_landlock.sh" >/dev/null

test -x "$source_root/engine/.venv/bin/python"
test -f "$dsh_home/profiles/$profile/cordis.patch.yml"
test -x "$repo_root/results/pbfuzz/bin/pbfuzz-landlock"
if [[ ! -f "$key_script" ]]; then
    echo "PBFuzz is built, but the API key script is missing: $key_script" >&2
fi
echo "PBFuzz engine installed at $source_root/engine/.venv/bin/python"
