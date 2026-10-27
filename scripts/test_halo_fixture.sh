#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d /tmp/halo-fixture.XXXXXX)"
mkdir -p "$work/seeds" "$work/findings"
python3 - "$work/seeds" <<'PY'
from pathlib import Path
import sys
root=Path(sys.argv[1])
for n in range(20):
    value=3+n%6
    data=bytes([ord('H'),value,20-value,0]) if n<5 else bytes([ord('X'),30+n,30+n,0])
    (root/f'seed{n:02d}').write_bytes(data)
PY
# Use an intentionally absent static target: the fixture reports its exact
# target hit through the runtime callback inside the three-condition branch.
printf '%s:%s\n' "$root/test/halo-fixture.c" 999999 > "$work/targets.txt"
AFLGO_TARGETS="$work/targets.txt" AFLGO_SKIP_TARGETS_CHECK=1 \
AFLGO_HALO_ENTRY=halo-fixture LIBAFL_EDGES_MAP_SIZE=2621440 \
"$root/build/install/bin/libaflgo_halo_cc" -O0 -g "$root/test/halo-fixture.c" -o "$work/halo-fixture"
set +e
/usr/bin/timeout --signal=INT --kill-after=3 10 \
    "$work/halo-fixture" --input "$work/seeds" --output "$work/findings" \
    --logfile "$work/fuzzer.log" --halo-seed 17 --show-target-output \
    > "$work/stdout.log" 2>&1
status=$?
set -e
if [[ $status -ne 0 && $status -ne 124 && $status -ne 130 ]]; then
    tail -50 "$work/stdout.log"
    exit "$status"
fi
python3 - "$work/findings" <<'PY'
import json,sys
from pathlib import Path
root=Path(sys.argv[1])
checkpoint=root/'halo-checkpoint-v1.json'
if not checkpoint.is_file():
    raise SystemExit('Halo fixture has no checkpoint')
state=json.loads(checkpoint.read_text())
totals=state['totals']
print(root, totals, 'candidates=', len(state['candidates']))
assert totals['observed'] > 20
assert totals['generated'] > 0
assert (root/'halo-inputs-v1.tsv').is_file()
invariants=(root/'halo-invariants-v1.tsv').read_text().splitlines()
assert any('Equal { at: 0, value: 72 }' in line for line in invariants)
assert any('Interval { at: 1,' in line for line in invariants)
assert any('SumEqual { left: 1, right: 2, value: 20 }' in line for line in invariants)
PY
