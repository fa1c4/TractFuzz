#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bug_out="$repo_root/magma/work/beacon/TIF006/out"
runtime="$repo_root/build/install/lib/libBeaconCliRuntime.a"
runner="$repo_root/target/release/beacon_cli"
for required in "$bug_out/magma.o" "$bug_out/monitor" "$runtime" "$runner"; do
    if [[ ! -f "$required" ]]; then
        echo "Missing $required; build TIF006 and the BEACON CLI runner first" >&2
        exit 1
    fi
done

probe_dir="$(mktemp -d /tmp/beacon-cli-magma.XXXXXX)"
trap 'rm -rf "$probe_dir"' EXIT
mkdir "$probe_dir/inputs" "$probe_dir/findings"
printf 'seed' > "$probe_dir/inputs/seed"
cat > "$probe_dir/probe.c" <<'EOF'
#include "canary.h"
int main(int argc, char **argv) {
  (void)argc;
  (void)argv;
  MAGMA_LOG("TIF006", 1);
  return 0;
}
EOF

/usr/bin/clang-15 -fsanitize-coverage=trace-pc-guard \
    -I "$repo_root/magma/magma/src" "$probe_dir/probe.c" \
    "$bug_out/magma.o" -Wl,--whole-archive "$runtime" \
    -Wl,--no-whole-archive -lrt -o "$probe_dir/probe"
set +e
"$bug_out/monitor" --dump row --fetch watch \
    /usr/bin/timeout --signal=INT --kill-after=2 1 \
    "$runner" --target "$probe_dir/probe" --input "$probe_dir/inputs" \
    --output "$probe_dir/findings" --logfile "$probe_dir/fuzzer.log" \
    -- @@ > "$probe_dir/canaries.csv"
monitor_status=$?
set -e
if [[ $monitor_status -ne 0 && $monitor_status -ne 124 && $monitor_status -ne 130 ]]; then
    echo "Magma monitor exited with $monitor_status" >&2
    exit "$monitor_status"
fi

python3 - "$probe_dir" <<'PY'
import csv
import pathlib
import struct
import sys

probe = pathlib.Path(sys.argv[1])
with (probe / "canaries.csv").open(newline="") as stream:
    row = next(csv.DictReader(stream), {})
reached = int(row.get("TIF006_R", 0))
triggered = int(row.get("TIF006_T", 0))
with (probe / "findings/.beacon_cli_state").open("rb") as stream:
    stream.seek(2_621_440 + 16 + 256)
    executions = struct.unpack("<Q", stream.read(8))[0]
assert executions > 0, "no instrumented target child ran"
assert reached == triggered == executions, (reached, triggered, executions)
print(f"Magma CLI probe: {executions} executions, {reached} reaches, {triggered} triggers")
PY
