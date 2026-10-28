#!/usr/bin/env bash
set -euo pipefail
set +x
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${PBFUZZ_KEY_SCRIPT:-$HOME/api_keys/set_api_key.sh}" >/dev/null 2>&1
set +x
cd "$root"
python3 scripts/pbfuzz_probe_api.py
