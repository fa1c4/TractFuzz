#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d /tmp/idfuzz-boundaries.XXXXXX)"
printf '%s:%s\n' "$root/test/idfuzz-boundaries.c" 999999 > "$work/targets.txt"
for variant in TERMINAL INDIRECT MULTISITE TAIL MANY; do
    export AFLGO_TARGETS="$work/targets.txt" AFLGO_SKIP_TARGETS_CHECK=1
    export AFLGO_IDFUZZ_ENTRY="case-$variant" AFLGO_IDFUZZ_MANIFEST="$work/dom.tsv"
    export LIBAFL_EDGES_MAP_SIZE=2621440
    if [[ $variant == MANY ]]; then
        if "$root/build/install/bin/libaflgo_idfuzz_cc" -O0 -g -DIDFUZZ_MANY \
            "$root/test/idfuzz-boundaries.c" -o "$work/case-MANY" >"$work/MANY.log" 2>&1; then
            echo 'Expected 17-target link rejection' >&2; exit 1
        fi
    else
        "$root/build/install/bin/libaflgo_idfuzz_cc" -O0 -g "-DIDFUZZ_$variant" \
            "$root/test/idfuzz-boundaries.c" -o "$work/case-$variant" >"$work/$variant.log" 2>&1
        test -s "$work/dom-case-$variant.tsv"
    fi
done
rg -q 'terminal=1' "$work/dom-case-TERMINAL.tsv"
rg -q 'indirect=[1-9]' "$work/dom-case-INDIRECT.tsv"
rg -q 'chosen' "$work/dom-case-MULTISITE.tsv"
rg -q 'alternate' "$work/dom-case-MULTISITE.tsv"
rg -q 'target_calls=2' "$work/dom-case-MULTISITE.tsv"
rg -q 'at most 16 distinct targets' "$work/MANY.log"
python3 - "$work" <<'PY'
import sys
from pathlib import Path
root=Path(sys.argv[1]); print('IDFuzz boundaries:', root)
for name in ('TERMINAL','INDIRECT','MULTISITE','TAIL'):
 print(name, (root/f'dom-case-{name}.tsv').read_text().splitlines()[0])
PY
