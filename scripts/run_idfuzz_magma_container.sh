#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
image="tractfuzz-idfuzz-magma:ubuntu24.04"
cpuset=()
if [[ -n "${TRACTFUZZ_CPUSET:-}" ]]; then cpuset=(--cpuset-cpus "$TRACTFUZZ_CPUSET"); fi
eval_fs=()
if [[ "${TRACTFUZZ_EVAL_STAGED:-0}" == 1 ]]; then eval_fs=(--read-only --tmpfs /tmp:rw,exec,nosuid,nodev); fi
if ! docker image inspect "$image" >/dev/null 2>&1; then
    if [[ "${TRACTFUZZ_EVAL_STAGED:-0}" == 1 ]]; then echo "Missing prebuilt image: $image" >&2; exit 1; fi
    docker build -f "$repo_root/scripts/idfuzz-magma.Dockerfile" \
        -t "$image" "$repo_root/scripts"
fi
exec docker run --rm --init --network host \
    "${cpuset[@]}" \
    "${eval_fs[@]}" \
    --user "$(id -u):$(id -g)" \
    -v "$repo_root:$repo_root" -w "$repo_root" \
    -e HOME=/tmp -e USER="$(id -un)" -e TRACTFUZZ_PAR_JOBS=1 \
    -e PYTHONDONTWRITEBYTECODE=1 \
    "$image" python3 scripts/idfuzz_magma.py "$@"
