#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
image=tractfuzz-idfuzz-author:86d11b3
work="${IDFUZZ_AUTHOR_WORK:-$root/results/idfuzz/author-fixture}"
seconds="${IDFUZZ_AUTHOR_SECONDS:-180}"
if ! docker image inspect "$image" >/dev/null 2>&1; then
    "$root/scripts/fetch_idfuzz_author.sh"
    docker build -f "$root/scripts/idfuzz-author.Dockerfile" \
        --build-arg GOPROXY=https://goproxy.cn,direct \
        --build-arg GO_DL_BASE=https://mirrors.aliyun.com/golang \
        -t "$image" "$root/results/idfuzz/source/author"
fi
exec docker run --rm --init --network host --user "$(id -u):$(id -g)" \
    -v "$root:$root" -w "$root" -e HOME=/tmp -e IDFUZZ=/IDFuzz \
    -e IDFUZZ_AUTHOR_WORK="$work" \
    -e IDFUZZ_AUTHOR_SECONDS="$seconds" \
    -e AFL_SKIP_CPUFREQ=1 -e AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
    "$image" bash -c '
set -euo pipefail
root="$1"
work="$IDFUZZ_AUTHOR_WORK"
mkdir -p "$work/tmp" "$work/seeds"
export TMP_DIR="$work/tmp" IDFUZZ=/IDFuzz
export IDFUZZ_LR=1e-5 IDFUZZ_EPOCHS=5 IDFUZZ_PATIENCE=0 IDFUZZ_QUALITY_GATE=0
cp "$root/test/idfuzz-author-fixture.c" "$work/fixture.c"
line=$(awk "/volatile int target_marker/ {print NR; exit}" "$work/fixture.c")
printf "fixture.c:%s\n" "$line" > "$TMP_DIR/BBtargets.txt"
gclang -g -O0 "$work/fixture.c" -o "$work/fixture-gllvm"
get-bc -o "$TMP_DIR/target.bc" "$work/fixture-gllvm"
/IDFuzz/idfuzz.sh analyze "$TMP_DIR/target.bc" > "$work/analyze.log" 2>&1
cd "$work"
CFLAGS="-g -O0" /IDFuzz/idfuzz.sh instrument -- "$root/scripts/idfuzz_author_build_fixture.sh" "$work" > "$work/instrument.log" 2>&1
/IDFuzz/idfuzz.sh finalize > "$work/finalize.log" 2>&1
python3 - "$work/seeds" <<'\''PY'\''
from pathlib import Path
import sys
p=Path(sys.argv[1])
for i in range(120):
    if i < 24: raw=bytes([i*7%256,i*11%256,i*13%256,i*17%256])
    elif i < 48: raw=bytes([73,i,0,0])
    elif i < 72: raw=bytes([73,68,i,0])
    elif i < 96: raw=bytes([73,68,70,i])
    else: raw=bytes([73,68,70,33,i])
    p.joinpath(f"seed{i:03}").write_bytes(raw)
PY
set +e
timeout --signal=INT --kill-after=5 "$IDFUZZ_AUTHOR_SECONDS" /IDFuzz/fuzz.sh fixture seeds out "" 5s "@@" > "$work/fuzz.log" 2>&1
status=$?
set -e
printf "exit=%s\n" "$status" > "$work/status.txt"
find "$work" -maxdepth 2 -type f -printf "%P\n" | sort > "$work/files.txt"
printf "%s\n" "$work"
' _ "$root"
