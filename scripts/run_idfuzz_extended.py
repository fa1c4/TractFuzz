#!/usr/bin/env python3
"""Rerun both arms of rows whose 60-second campaign did not pass the seed phase."""
import csv
import json
import math
import os
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import idfuzz_magma as campaign

ROOT = Path(__file__).resolve().parents[1]
SEED_INCOMPLETE = {'seed_phase_incomplete', 'seed_import_incomplete'}
MINIMUM = {'SSL001': 300, 'SSL020': 180, 'PDF009': 180,
           'PDF006': 240, 'PDF011': 240, 'PDF019': 240}


def statuses(mode):
    path = ROOT / f'results/idfuzz/status-{mode}.csv'
    return {row['bug']: row for row in csv.DictReader(path.open())}


def budget(bug, rows):
    seconds = MINIMUM.get(bug, 180)
    for row in rows:
        config_path = campaign.WORK_ROOT / bug / 'out' / f"config_{row['mode']}.json"
        if not config_path.is_file():
            continue
        config = json.loads(config_path.read_text())
        executions = int(row.get('executions') or 0)
        previous = int(config.get('seconds') or 60)
        if executions:
            needed = config['seed_count'] * previous / executions * 1.5
            seconds = max(seconds, math.ceil(needed / 60) * 60)
        seconds = max(seconds, previous + 60)
    return min(seconds, 600)


def main():
    current = {mode: statuses(mode) for mode in ('idfuzz', 'control')}
    pending = []
    for fixed in campaign.rows():
        bug = fixed['bug']
        pair = [current[mode][bug] for mode in ('idfuzz', 'control')]
        if not any(row['status'] in SEED_INCOMPLETE for row in pair):
            continue
        pending.append((bug, budget(bug, pair)))

    def run_pair(item):
        bug, seconds = item
        for mode in ('idfuzz', 'control'):
            command = [str(ROOT / 'scripts/run_idfuzz_magma_container.sh'),
                       'run', bug, '--mode', mode, '--seconds', str(seconds), '--force']
            print(' '.join(command), flush=True)
            subprocess.run(command, check=True)

    workers = max(1, int(os.environ.get('IDFUZZ_EXTENDED_WORKERS', '2')))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(run_pair, pending))
    subprocess.run(['python3', str(ROOT / 'scripts/idfuzz_reconcile.py')], check=True)
    subprocess.run(['python3', str(ROOT / 'scripts/idfuzz_audit.py')], check=True)
    unresolved = [(mode, row['bug'], row['status'])
                  for mode in ('idfuzz', 'control')
                  for row in statuses(mode).values()
                  if row['status'] in SEED_INCOMPLETE]
    if unresolved:
        raise SystemExit(f'seed import still incomplete: {unresolved}')
    subprocess.run(['python3', str(ROOT / 'scripts/verify_idfuzz_campaign.py')], check=True)


if __name__ == '__main__':
    main()
