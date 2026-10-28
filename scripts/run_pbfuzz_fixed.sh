#!/usr/bin/env bash
# Run current author PBFuzz with a DeepSeek-compatible API on one frozen Magma row.
set -euo pipefail
set +x
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bug="${1:?usage: run_pbfuzz_fixed.sh BUG_ID}"
work="$root/results/pbfuzz/fixed/$bug"
mkdir -p "$work"
exec 9>"$work/run.lock"
flock 9
python3 "$root/scripts/pbfuzz_fixed_campaign.py" "$bug" > "$work/campaign-setup.log" 2>&1
read -r project campaign output < <(python3 - "$work/manifest.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]));print(d['project'],d['campaign'],d['output_dir'])
PY
)
if [[ "${PBFUZZ_FORCE:-0}" != 1 ]] && [[ -f "$output/state/state.json" ]]; then
    phase="$(python3 - "$output/state/state.json" <<'PY'
import json,sys
print(json.load(open(sys.argv[1])).get('phase',''))
PY
)"
    if [[ "$phase" == SUCCESS || "$phase" == STOPPED ]]; then
        echo "$bug already has terminal PBFuzz state $phase"
        exit 0
    fi
fi
source "${PBFUZZ_KEY_SCRIPT:-$HOME/api_keys/set_api_key.sh}" >/dev/null 2>&1
set +x
export DEEPSEEK_API_KEY="$API_KEY"
export DSH_HOME="${PBFUZZ_DSH_HOME:-$root/results/pbfuzz/dsh-home}"
export PATH="$root/results/pbfuzz/source/github/.local/bin:$PATH"
export PBFUZZ_MAX_ROUNDS="${PBFUZZ_MAX_ROUNDS:-1}"
export PBFUZZ_WALL_MIN="${PBFUZZ_WALL_MIN:-3}"
export PBFUZZ_MAX_ITERS="${PBFUZZ_MAX_ITERS:-100}"
export PBFUZZ_EXEC_TIMEOUT_SEC="${PBFUZZ_EXEC_TIMEOUT_SEC:-8}"
export PBFUZZ_MODEL_CONFIG_PATH="$work/model-config.json"
python3 "$root/scripts/pbfuzz_configure_dsh.py" > "$work/model-setup.log"

# Hide earlier baseline outputs for this bug while the model runs.
# The isolated campaign uses only the copied source, binary, monitor and corpus.
hidden_root="$root/results/pbfuzz/.hidden"
mkdir -p "$hidden_root"
hidden="$(mktemp -d "$hidden_root/${bug}.XXXXXX")"
original="$root/magma/work/idfuzz/$bug"
restore() {
    if [[ -d "$hidden/bug" ]]; then
        mv "$hidden/bug" "$original"
    fi
    if [[ -d "$hidden/patches" ]]; then
        mv "$hidden/patches" "$root/magma/targets/$project/patches"
    fi
    rmdir "$hidden" 2>/dev/null || true
}
trap restore EXIT
patches="$root/magma/targets/$project/patches"
if [[ "${PBFUZZ_SKIP_PATCH_HIDE:-0}" != 1 ]]; then
    [[ ! -d "$patches" ]] || mv "$patches" "$hidden/patches"
fi
if [[ "$output" == "$root/results/pbfuzz/isolated/"* ]]; then
    mv "$original" "$hidden/bug"
fi

landlock="$root/results/pbfuzz/bin/pbfuzz-landlock"
[[ -x "$landlock" ]] || bash "$root/scripts/build_pbfuzz_landlock.sh" > "$work/landlock-build.log"
allow=(
    --allow /usr --allow /etc --allow /dev --allow /proc
    --allow /tmp --allow /run --allow /sys --allow /var
    --allow /bin --allow /lib --allow /lib64
    --allow "$root/results/pbfuzz/source/github"
    --allow "$DSH_HOME"
    --allow "$root/results/pbfuzz/isolated/$bug"
    --allow "$root/scripts/pbfuzz_monitor_oracle.py"
)
for optional in "$HOME/.npm" "$HOME/.cache" "$HOME/.nvm" "$HOME/anaconda3"; do
    [[ ! -d "$optional" ]] || allow+=(--allow "$optional")
done
python_runtime="$(readlink -f "$root/results/pbfuzz/source/github/engine/.venv/bin/python")"
python_runtime_root="$(dirname "$(dirname "$python_runtime")")"
[[ ! -d "$python_runtime_root" ]] || allow+=(--allow "$python_runtime_root")

started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
hard_wall="${PBFUZZ_HARD_WALL_SEC:-360}"
set +e
MAGMA_ROOT= timeout --signal=TERM --kill-after=15s "${hard_wall}s" \
    "$landlock" "${allow[@]}" -- \
    "$root/results/pbfuzz/source/github/examples/magma/run-campaign.sh" "$campaign" \
    > "$work/run.log" 2>&1
exit_code=$?
set -e
finished="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
python3 - "$work/run.json" "$output/state/state.json" "$started" "$finished" "$exit_code" "$hard_wall" "$hidden" <<'PY'
import json,sys
from datetime import datetime
from pathlib import Path
destination,state_path,started,finished,exit_code,hard_wall,hidden=sys.argv[1:]
state={}
if Path(state_path).is_file():
    try:state=json.loads(Path(state_path).read_text())
    except ValueError:pass
record={
    'schema':1,'track':'current-author-dsh-fixed-magma-monitor',
    'started_at':started,'finished_at':finished,
    'elapsed_seconds':(datetime.fromisoformat(finished.replace('Z','+00:00'))-
                       datetime.fromisoformat(started.replace('Z','+00:00'))).total_seconds(),
    'exit_code':int(exit_code),'hard_wall_seconds':int(hard_wall),
    'phase':state.get('phase','no_state'),
    'timed_out':int(exit_code)==124,
    'original_work_hidden':(Path(hidden)/'bug').is_dir(),
    'landlock_read_boundary':True,
}
Path(destination).write_text(json.dumps(record,indent=2)+'\n')
print(json.dumps(record,sort_keys=True))
PY
exit "$exit_code"
