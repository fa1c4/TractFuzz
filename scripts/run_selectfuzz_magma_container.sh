#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
image="tractfuzz-beacon-magma:ubuntu24.04"
if ! docker image inspect "$image" >/dev/null 2>&1; then
    docker build -f "$repo_root/scripts/beacon-magma.Dockerfile" \
        -t "$image" "$repo_root/scripts"
fi
exec docker run --rm --init --network host \
    --user "$(id -u):$(id -g)" \
    -v "$repo_root:$repo_root" -w "$repo_root" \
    -e HOME=/tmp -e USER="$(id -un)" \
    "$image" python3 scripts/selectfuzz_magma.py "$@"
