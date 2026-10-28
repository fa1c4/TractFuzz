#!/usr/bin/env bash
# Build and run one fixed-entry Magma row with the pinned current author PBFuzz.
set -euo pipefail
set +x
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bug="${1:?usage: run_pbfuzz_magma.sh BUG_ID TARGET_NAME FIXED_PROGRAM}"
target="${2:?TARGET_NAME required}"
program="${3:?FIXED_PROGRAM required}"
python3 - "$root" "$bug" "$target" "$program" <<'PY'
import re, sys
from pathlib import Path
root, bug, project, entry = sys.argv[1:]
text = (Path(root) / 'docs/tractfuzz_magma_benchmarks.md').read_text()
rows = re.findall(r'^\|\s*\d+\s*\|\s*(\w+)\s*\|\s*`([A-Z]{3}\d{3})`\s*\|\s*`([^`]+)`\s*\|', text, re.M)
if (project, bug, entry) not in rows:
    raise SystemExit('BUG_ID/TARGET_NAME/FIXED_PROGRAM does not match the frozen benchmark')
PY
author="$root/results/pbfuzz/source/github"
magma="$root/results/pbfuzz/source/magma-author"
work="$root/results/pbfuzz/work"
test -f "$author/HARNESS_COMMIT" || { echo "Pinned PBFuzz source missing" >&2; exit 1; }
test -f "$magma/targets/$target/configrc" || { echo "Magma target missing" >&2; exit 1; }
export PATH="$author/.local/bin:$PATH"
export DSH_HOME="$root/results/pbfuzz/dsh-home"
export MAGMA_ROOT="$magma" WORK="$work" TARGET_NAME="$target" BUG_ID="$bug" PROGRAM="$program"
source "${PBFUZZ_KEY_SCRIPT:-$HOME/api_keys/set_api_key.sh}" >/dev/null 2>&1
set +x
export DEEPSEEK_API_KEY="$API_KEY"  # author launcher preflight; model route uses API_KEY
python3 "$root/scripts/pbfuzz_configure_dsh.py"
cp "$root/results/pbfuzz/model-config.json" "$root/results/pbfuzz/${bug}-model-config.json"
mkdir -p "$work/$target"
if [[ ! -x "$work/$target/out/$program" ]]; then
    if [[ "$target" == libsndfile ]] && ! command -v autogen >/dev/null; then
        source "$root/scripts/pbfuzz_local_autogen_env.sh"
    fi
    if [[ "$target" == sqlite3 ]]; then
        export CC="$root/scripts/pbfuzz_sqlite_cc.sh" CXX=clang++-15
    fi
    (cd "$author" && ./examples/magma/build-target.sh) > "$root/results/pbfuzz/${bug}-build.log" 2>&1
fi
campaign="$work/$target/campaigns/$bug.campaign.yaml"
(cd "$author" && ./examples/magma/generate-campaign.sh) > "$root/results/pbfuzz/${bug}-campaign.log" 2>&1
test -s "$campaign"
set +e
hard_wall_sec="${PBFUZZ_HARD_WALL_SEC:-$(( (${PBFUZZ_WALL_MIN:-10} + 5) * 60 ))}"
(cd "$author" && timeout --signal=TERM --kill-after=10s "${hard_wall_sec}s" \
    ./examples/magma/run-campaign.sh "$campaign") > "$root/results/pbfuzz/${bug}-run.log" 2>&1
status=$?
set -e
echo "PBFuzz $bug exit=$status; campaign=$campaign; log=results/pbfuzz/${bug}-run.log"
exit "$status"
