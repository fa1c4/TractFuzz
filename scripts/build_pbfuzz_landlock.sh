#!/usr/bin/env bash
# Build the rootless file-read boundary for DeepSeek PBFuzz sessions.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$root/results/pbfuzz/bin"
cc -O2 -Wall -Wextra -Werror "$root/scripts/pbfuzz_landlock.c" \
    -o "$root/results/pbfuzz/bin/pbfuzz-landlock"
printf '%s\n' "$root/results/pbfuzz/bin/pbfuzz-landlock"
