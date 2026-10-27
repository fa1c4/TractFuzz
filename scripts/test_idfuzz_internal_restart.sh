#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="${IDFUZZ_RESTART_TEST_DIR:-$(mktemp -d /tmp/idfuzz-internal-restart.XXXXXX)}"
mkdir -p "$work/seeds" "$work/findings"
cat > "$work/restart.c" <<'C'
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
extern void __aflgo_trace_bb_distance(uint64_t);
extern void __aflgo_trace_bb_target(uint32_t);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static unsigned count;
  static int armed = -1;
  if (armed < 0) {
    const char *marker = getenv("IDFUZZ_RESTART_MARKER");
    armed = marker && access(marker, F_OK) != 0;
  }
  if (armed && ++count == 4097) {
    int fd = open(getenv("IDFUZZ_RESTART_MARKER"), O_CREAT | O_EXCL | O_WRONLY, 0600);
    if (fd >= 0) close(fd);
    abort();
  }
  __aflgo_trace_bb_distance(size && data[0] == 'X' ? 0 : 40000);
  if (size && data[0] == 'X') __aflgo_trace_bb_target(1);
  return 0;
}
C
python3 - "$work/seeds" <<'PY'
from pathlib import Path
import sys
root=Path(sys.argv[1])
for n in range(64):
    (root/f'seed{n:03}').write_bytes(bytes([65+n%20,n%256,7,0]))
PY
printf '%s:%s\n' "$work/restart.c" 999999 > "$work/targets.txt"
(
  cd "$work"
  AFLGO_TARGETS="$work/targets.txt" AFLGO_SKIP_TARGETS_CHECK=1 \
  AFLGO_IDFUZZ_ENTRY=restart-fixture AFLGO_IDFUZZ_MANIFEST="$work/dom.tsv" \
  LIBAFL_EDGES_MAP_SIZE=2621440 \
  "$root/build/install/bin/libaflgo_idfuzz_cc" -O0 -g "$work/restart.c" \
      -o "$work/restart-fixture" >"$work/build.log" 2>&1
)
set +e
IDFUZZ_RESTART_MARKER="$work/crashed-once" \
IDFUZZ_MODEL_SCRIPT="$root/scripts/idfuzz_model.py" \
/usr/bin/timeout --signal=INT --kill-after=3 15 \
  "$work/restart-fixture" --input "$work/seeds" --output "$work/findings" \
  --logfile "$work/fuzzer.log" --idfuzz-seed 17 --show-target-output \
  >"$work/stdout.log" 2>&1
status=$?
set -e
if [[ $status -ne 0 && $status -ne 124 && $status -ne 130 ]]; then
  tail -50 "$work/stdout.log"
  exit "$status"
fi
python3 - "$work" <<'PY'
import json,re,sys
from pathlib import Path
work=Path(sys.argv[1])
assert (work/'crashed-once').is_file(), 'fixture did not crash once'
totals=json.loads((work/'findings/idfuzz-totals-v1.json').read_text())
assert totals['observed'] > 4096, totals
assert totals['retained'] > 128, totals
lines=(work/'fuzzer.log').read_text(errors='replace').splitlines()
samples=[]
for line in lines:
    executions=re.search(r'executions: (\d+)',line)
    observed=re.search(r'idfuzz_observed=(\d+)',line)
    if executions and observed:
        samples.append((int(executions.group(1)),int(observed.group(1))))
restarts=[(before,after) for before,after in zip(samples,samples[1:])
          if after[0]<before[0]]
assert restarts, 'monitor did not record an internal worker restart'
assert all(after[1]>=before[1] for before,after in restarts), restarts
print(json.dumps({'work':str(work),'observed':totals['observed'],
                  'retained':totals['retained'],'monitor_samples':len(samples),
                  'worker_restarts':len(restarts)},sort_keys=True))
PY
