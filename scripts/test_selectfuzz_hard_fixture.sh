#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fixture="$root/test/selectfuzz-hard-fixture.c"
work="${SELECTFUZZ_HARD_DIR:-$root/results/selectfuzz/hard-fixture}"
mkdir -p "$work"
line="$(rg -n SELECTFUZZ_HARD_TARGET "$fixture" | cut -d: -f1)"
printf '%s:%s\n' "$fixture" "$line" > "$work/targets.txt"
export AFLGO_TARGETS="$work/targets.txt"
export AFLGO_SELECTFUZZ_MANIFEST="$work/blocks.tsv"
export LIBAFL_EDGES_MAP_SIZE=2621440
export RUSTUP_TOOLCHAIN=1.71.1
"$root/build/install/bin/libaflgo_selectfuzz_cc" -O0 "$fixture" \
  -o "$work/fixture" 2> "$work/build.log"
python3 - "$work/blocks-fixture.tsv" <<'PY'
import csv, sys
with open(sys.argv[1]) as stream:
    blocks = list(csv.DictReader((line for line in stream if not line.startswith('#')), delimiter='\t'))
assert any(int(b['kind']) & 4 for b in blocks)
assert sum(int(b['kind']) & 1 != 0 for b in blocks) >= 2
print('hard constraint selected guards:', sum(int(b['kind']) & 1 != 0 for b in blocks))
PY
printf SELECTFA > "$work/near_miss"
"$work/fixture" "$work/near_miss" > "$work/replay.log" 2>&1
