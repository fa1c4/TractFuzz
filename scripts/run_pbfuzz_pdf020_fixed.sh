#!/usr/bin/env bash
# Attempt PDF020 on the frozen pdf_fuzzer binary with a monitor-backed oracle.
set -euo pipefail
set +x
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${PBFUZZ_KEY_SCRIPT:-$HOME/api_keys/set_api_key.sh}" >/dev/null 2>&1
set +x
export DEEPSEEK_API_KEY="$API_KEY"
export DSH_HOME="$root/results/pbfuzz/dsh-home"
export PATH="$root/results/pbfuzz/source/github/.local/bin:$PATH"
export PBFUZZ_MAX_ROUNDS="${PBFUZZ_MAX_ROUNDS:-1}"
export PBFUZZ_WALL_MIN="${PBFUZZ_WALL_MIN:-3}"
export PBFUZZ_MAX_ITERS="${PBFUZZ_MAX_ITERS:-100}"
python3 "$root/scripts/pbfuzz_configure_dsh.py"
cp "$root/results/pbfuzz/model-config.json" "$root/results/pbfuzz/PDF020-model-config.json"
target="$root/magma/work/idfuzz/PDF020/target"
binary="$root/magma/work/idfuzz/PDF020/out/pdf_fuzzer"
monitor="$root/magma/work/idfuzz/PDF020/out/monitor"
campaign="$root/results/pbfuzz/work/pdf020-fixed/PDF020.campaign.yaml"
mkdir -p "$(dirname "$campaign")"
test -x "$binary" && test -x "$monitor" && test -d "$target/repo"
python3 - "$target/repo" "$(dirname "$campaign")/BBtargets.txt" <<'PY'
import sys
from pathlib import Path
repo, out = map(Path, sys.argv[1:])
lines = []
for path in repo.rglob('*'):
    if path.suffix not in ('.c', '.h', '.cc', '.cpp') or not path.is_file():
        continue
    for number, line in enumerate(path.read_text(errors='replace').splitlines(), 1):
        if 'MAGMA_LOG("PDF020"' in line:
            lines.append(f'{path.name}:{number}')
if not lines:
    raise SystemExit('PDF020 has no MAGMA_LOG site in fixed source')
out.write_text('\n'.join(lines) + '\n')
PY
(
    cd "$root/results/pbfuzz/source/github"
    engine/.venv/bin/python -m pbfuzz_engine.adapters.magma \
        --target-name poppler --target-repo "$target/repo" --bug-id PDF020 \
        --binary "$binary" --run-cmd "$binary @@" \
        --bbtargets "$(dirname "$campaign")/BBtargets.txt" --no-static-analysis \
        --seeds-dir "$target/corpus/pdf_fuzzer" --write "$campaign"
) > "$root/results/pbfuzz/PDF020-campaign.log" 2>&1
python3 - "$campaign" "$root" "$binary" "$monitor" <<'PY'
import shlex, sys, yaml
from pathlib import Path

campaign, root, binary, monitor = map(Path, sys.argv[1:])
data = yaml.safe_load(campaign.read_text())
shim = root / 'scripts/pbfuzz_monitor_oracle.py'
data['entry']['run_cmd'] = ' '.join(map(shlex.quote,
    ['python3', str(shim), '--monitor', str(monitor), '--binary', str(binary),
     '--bug-id', 'PDF020', '--input', '@@']))
data['tracer'] = 'off'
data['analysis']['deviation']['enabled'] = False
data['analysis']['deviation']['disabled_reason'] = 'fixed monitor oracle adaptation has no debugger trace'
data['output']['dir'] = str(root / 'magma/work/idfuzz/PDF020/target/repo/.pbfuzz/pdf020-fixed')
campaign.write_text('# Fixed-entry monitor-oracle adaptation; not standalone author Magma build.\n'
                    + yaml.safe_dump(data, sort_keys=False))
PY
patches="$root/magma/targets/poppler/patches"
hidden="$(mktemp -d /tmp/pbfuzz-pdf020-patches.XXXXXX)"
if [[ -d "$patches" ]]; then
    mv "$patches" "$hidden/patches"
    trap 'mv "$hidden/patches" "$patches"; rmdir "$hidden"' EXIT
else
    trap 'rmdir "$hidden"' EXIT
fi
set +e
MAGMA_ROOT= timeout --signal=TERM --kill-after=10s "${PBFUZZ_HARD_WALL_SEC:-360}s" \
    "$root/results/pbfuzz/source/github/examples/magma/run-campaign.sh" "$campaign" \
    > "$root/results/pbfuzz/PDF020-run.log" 2>&1
status=$?
set -e
echo "PDF020 fixed-entry adaptation exit=$status; log=results/pbfuzz/PDF020-run.log"
exit "$status"
