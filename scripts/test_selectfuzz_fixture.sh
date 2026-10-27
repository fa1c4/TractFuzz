#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fixture="$root/test/selectfuzz-fixture.c"
work="${SELECTFUZZ_FIXTURE_DIR:-$root/results/selectfuzz/fixture}"
mkdir -p "$work"
line="$(rg -n SELECTFUZZ_TARGET "$fixture" | cut -d: -f1)"
printf '%s:%s\n' "$fixture" "$line" > "$work/targets.txt"
export AFLGO_TARGETS="$work/targets.txt"
export AFLGO_SELECTFUZZ_MANIFEST="$work/blocks.tsv"
export LIBAFL_EDGES_MAP_SIZE=2621440
export RUSTUP_TOOLCHAIN=1.71.1
"$root/build/install/bin/libaflgo_selectfuzz_cc" -O0 "$fixture" \
  -o "$work/fixture" 2> "$work/build.log"
test -f "$work/blocks-fixture.tsv"
nm "$work/fixture" > "$work/symbols.txt"
rg -q '__selectfuzz_trace_bb' "$work/symbols.txt"
printf AZ > "$work/reached"
printf QX > "$work/unrelated"
"$work/fixture" "$work/reached" "$work/unrelated" > "$work/replay.log" 2>&1
python3 - "$work/blocks-fixture.tsv" <<'PY'
import csv, sys
with open(sys.argv[1]) as stream:
    blocks = list(csv.DictReader((line for line in stream if not line.startswith('#')), delimiter='\t'))
assert blocks
assert any(int(b['kind']) & 4 for b in blocks), 'target block missing'
assert any(int(b['kind']) & 1 for b in blocks), 'path-divergent block missing'
assert any(int(b['id']) == 0 for b in blocks), 'no omitted block recorded'
assert any(int(b['distance_milli']) == 1000 for b in blocks), 'target distance is not 1'
print('blocks:', len(blocks), 'selected:', sum(int(b['id']) > 0 for b in blocks))
PY
