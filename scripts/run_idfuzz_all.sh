#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
seconds="${IDFUZZ_CAMPAIGN_SECONDS:-60}"
workers="${IDFUZZ_WORKERS:-6}"
mkdir -p results/idfuzz/project-logs
python3 scripts/idfuzz_magma.py matrix
python3 scripts/idfuzz_magma.py matrix --mode control
python3 - <<'PY' | xargs -P "$workers" -I '{}' bash -c '
set -euo pipefail
project="$1"
root="$2"
seconds="$3"
"$root/scripts/run_idfuzz_magma_container.sh" all --project "$project" --seconds "$seconds" --force >"$root/results/idfuzz/project-logs/${project}-idfuzz.log" 2>&1
"$root/scripts/run_idfuzz_magma_container.sh" all --mode control --project "$project" --seconds "$seconds" --force >"$root/results/idfuzz/project-logs/${project}-control.log" 2>&1
printf "%s complete\n" "$project"
' _ '{}' "$root" "$seconds"
import re
from pathlib import Path
rows=Path('docs/tractfuzz_magma_benchmarks.md').read_text().splitlines()
projects=set()
for line in rows:
    match=re.match(r'^\|\s*\d+\s*\|\s*([^|]+)\|',line)
    if match: projects.add(match.group(1).strip())
for project in sorted(projects): print(project)
PY
python3 scripts/idfuzz_reconcile.py
python3 scripts/idfuzz_audit.py
