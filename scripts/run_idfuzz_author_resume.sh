#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="${IDFUZZ_AUTHOR_WORK:-$root/results/idfuzz/author-fixture-full}"
seconds="${IDFUZZ_AUTHOR_SECONDS:-180}"
image=tractfuzz-idfuzz-author:86d11b3
if [[ ! -f "$work/tmp/dom_bits_depth.txt" || ! -f "$work/out/fuzzer_stats" ]]; then
    echo "Author fixture has no completed preparation and fuzzing state: $work" >&2
    exit 1
fi
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
cp "$work/tmp/nn.log" "$work/tmp/nn-before-resume-$stamp.log"
archive="$work/feature-maps-before-resume-$stamp"
mkdir -p "$archive"
for directory in cur_dom_bits cur_dom_bits_backup queue_backup; do
    if [[ -d "$work/out/$directory" ]]; then
        if [[ -e "$archive/$directory" ]]; then
            echo "Refusing to overwrite preserved feature maps: $archive/$directory" >&2
            exit 1
        fi
        mv "$work/out/$directory" "$archive/$directory"
    fi
done
exec docker run --rm --init --network host --user "$(id -u):$(id -g)" \
    -v "$root:$root" -w "$work" -e HOME=/tmp -e IDFUZZ=/IDFuzz \
    -e TMP_DIR="$work/tmp" -e IDFUZZ_LR=1e-5 -e IDFUZZ_EPOCHS=5 \
    -e IDFUZZ_PATIENCE=0 -e IDFUZZ_QUALITY_GATE=0 \
    -e AFL_SKIP_CPUFREQ=1 -e AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
    "$image" bash -c '
set +e
timeout --signal=INT --kill-after=5 "$1" /IDFuzz/fuzz.sh fixture - out "" 5s "@@" > resume.log 2>&1
status=$?
printf "exit=%s\n" "$status" > resume-status.txt
tail -n 12 resume.log
' _ "$seconds"
