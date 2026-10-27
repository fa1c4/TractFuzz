#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
work="$root/results/idfuzz/port-author-fixture"
author="$root/results/idfuzz/author-fixture-full"
mkdir -p "$work"
line=$(awk '/volatile int target_marker/ {print NR; exit}' "$root/test/idfuzz-author-fixture.c")
printf '%s:%s\n' "$root/test/idfuzz-author-fixture.c" "$line" > "$work/targets.txt"
export AFLGO_TARGETS="$work/targets.txt" AFLGO_SKIP_TARGETS_CHECK=1
export AFLGO_IDFUZZ_ENTRY=fixture AFLGO_IDFUZZ_MANIFEST="$work/dom.tsv"
export LIBAFL_EDGES_MAP_SIZE=2621440
"$root/build/install/bin/libaflgo_idfuzz_cli_cc" -O0 -g \
    "$root/test/idfuzz-author-fixture.c" -o "$work/fixture" > "$work/build.log" 2>&1
test -s "$work/dom-fixture.tsv"
for mode in idfuzz control; do
    output="$work/findings_$mode"
    if [[ -d "$output" ]]; then
        mv "$output" "${output}_superseded_$(date +%s%N)"
    fi
    mkdir -p "$output"
    flags=()
    if [[ "$mode" == control ]]; then flags+=(--control); fi
    set +e
    IDFUZZ_MODEL_SCRIPT="$root/scripts/idfuzz_model.py" \
    timeout --signal=INT --kill-after=3 10 \
        "$root/target/release/idfuzz_cli" --target "$work/fixture" \
        --input "$author/seeds" --output "$output" \
        --logfile "$work/$mode.log" --idfuzz-seed 1337 "${flags[@]}" \
        -- @@ > "$work/$mode.stdout.log" 2>&1
    status=$?
    set -e
    if [[ $status -ne 0 && $status -ne 124 && $status -ne 130 ]]; then
        tail -40 "$work/$mode.stdout.log"; exit "$status"
    fi
done
python3 - "$work" <<'PY'
import json,re,sys
from pathlib import Path
work=Path(sys.argv[1]); result={}
for mode in ('idfuzz','control'):
    base=work/f'findings_{mode}'
    rows=[json.loads(line) for line in (base/'idfuzz-records-v1.jsonl').read_text().splitlines()]
    totals_path=base/'idfuzz-totals-v1.json'
    totals=json.loads(totals_path.read_text()) if totals_path.is_file() else {}
    log=(work/f'{mode}.log').read_text()
    model_calls=max([int(x) for x in re.findall(r'idfuzz_model_calls=(\d+)',log)] or [0])
    reached=max([int(x) for x in re.findall(r'idfuzz_reached=(\d+)',log)] or [0])
    initial=[row for row in rows if row['input_hex'].startswith('49444621')]
    result[mode]={'records':len(rows),'seeded_target_records':len(initial),
                  'reached':reached,
                  'model_calls':max(model_calls,totals.get('model_calls',0)),
                  'generated':totals.get('generated',0)}
assert result['idfuzz']['model_calls']>0 and result['control']['model_calls']==0
assert result['idfuzz']['reached']>=24 and result['control']['reached']>=24
raw=Path('results/idfuzz/author-fixture-full/seeds/seed074').read_bytes()
hash_value=0xcbf29ce484222325
for byte in raw: hash_value=((hash_value^byte)*0x100000001b3)&((1<<64)-1)
ranking=json.loads((work/'findings_idfuzz/idfuzz-rankings-v1.json').read_text())
result['idfuzz']['seed074_ranking']=ranking['rankings'][f'{hash_value:016x}']
assert result['idfuzz']['seed074_ranking']
print(json.dumps(result,sort_keys=True))
PY
