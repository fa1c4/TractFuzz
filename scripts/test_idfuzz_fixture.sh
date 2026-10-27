#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="${IDFUZZ_TEST_DIR:-$(mktemp -d /tmp/idfuzz-fixture.XXXXXX)}"
mkdir -p "$work/seeds" "$work/findings"
python3 - "$work/seeds" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1])
for i in range(64):
    raw=(bytes([72,3+i%6,17-i%6,0]) if i<16 else
         bytes([65+i%20,i%32,40-i%20,0]))
    (p/f'seed{i:03}').write_bytes(raw)
PY
printf '%s:%s\n' "$root/test/halo-fixture.c" 999999 > "$work/targets.txt"
AFLGO_TARGETS="$work/targets.txt" AFLGO_SKIP_TARGETS_CHECK=1 \
AFLGO_IDFUZZ_ENTRY=idfuzz-fixture AFLGO_IDFUZZ_MANIFEST="$work/dom.tsv" \
LIBAFL_EDGES_MAP_SIZE=2621440 \
"$root/build/install/bin/libaflgo_idfuzz_cc" -O0 -g \
    "$root/test/halo-fixture.c" -o "$work/idfuzz-fixture" >"$work/build.log" 2>&1
set +e
IDFUZZ_MODEL_SCRIPT="$root/scripts/idfuzz_model.py" \
/usr/bin/timeout --signal=INT --kill-after=3 12 \
    "$work/idfuzz-fixture" --input "$work/seeds" --output "$work/findings" \
    --logfile "$work/fuzzer.log" --idfuzz-seed 17 --show-target-output \
    >"$work/stdout.log" 2>&1
status=$?
set -e
if [[ $status -ne 0 && $status -ne 124 && $status -ne 130 ]]; then
    tail -50 "$work/stdout.log"; exit "$status"
fi
python3 - "$work" <<'PY'
import json,sys
from pathlib import Path
p=Path(sys.argv[1]); out=p/'findings'
records=[json.loads(x) for x in (out/'idfuzz-records-v1.jsonl').read_text().splitlines()]
assert any(r['target_hit'] for r in records)
assert len({tuple(r['dominators']) for r in records}) >= 2
assert any(r['operation']=='gradient-byte-enumeration' for r in records)
model=json.loads((out/'idfuzz-rankings-v1.json').read_text())
assert model['training']['samples'] >= 16
assert any(v and v[0] in (0,1,2) for v in model['rankings'].values())
assert (out/'idfuzz-model-v1.npz').is_file()
print(json.dumps(dict(work=str(p), executions=len(records),
                      model=model['training']),sort_keys=True))
PY
before=$(python3 - "$work/findings/idfuzz-totals-v1.json" <<'PY'
import json,sys
t=json.load(open(sys.argv[1])); print(t['observed'],t['retained'])
PY
)
set +e
IDFUZZ_MODEL_SCRIPT="$root/scripts/idfuzz_model.py" \
/usr/bin/timeout --signal=INT --kill-after=3 3 \
    "$work/idfuzz-fixture" --input "$work/seeds" --output "$work/findings" \
    --logfile "$work/restart.log" --idfuzz-seed 17 \
    >"$work/restart.stdout.log" 2>&1
status=$?
set -e
if [[ $status -ne 0 && $status -ne 124 && $status -ne 130 ]]; then
    tail -50 "$work/restart.stdout.log"; exit "$status"
fi
python3 - "$work/findings/idfuzz-totals-v1.json" "$before" <<'PY'
import json,sys
t=json.load(open(sys.argv[1])); observed,retained=map(int,sys.argv[2].split())
assert t['observed'] > observed and t['retained'] > retained, (t,observed,retained)
print('restart counters:', observed, retained, '->', t['observed'], t['retained'])
PY
