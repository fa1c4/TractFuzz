#!/usr/bin/env python3
"""Verify the paired fixed-entry IDFuzz pilot after all workers have exited."""
import csv
import hashlib
import json
from pathlib import Path

import idfuzz_magma as campaign


def main():
    root = campaign.ROOT / 'results/idfuzz'
    status = {mode: {row['bug']: row for row in csv.DictReader(
        (root / f'status-{mode}.csv').open())} for mode in ('idfuzz', 'control')}
    model_sha = hashlib.sha256((campaign.ROOT / 'scripts/idfuzz_model.py').read_bytes()).hexdigest()
    errors = []
    unwitnessed = []
    trained = generated = 0
    for fixed in campaign.rows():
        bug = fixed['bug']
        configs = {}
        for mode in ('idfuzz', 'control'):
            actual = status[mode].get(bug)
            if actual is None or actual['status'] != 'campaign_complete':
                errors.append(f'{bug}/{mode}: {actual["status"] if actual else "missing"}')
                continue
            if actual['entry'] != fixed['entry']:
                errors.append(f'{bug}/{mode}: entry changed')
            path = campaign.WORK_ROOT / bug / 'out' / f'config_{mode}.json'
            if not path.is_file():
                errors.append(f'{bug}/{mode}: config missing')
                continue
            config = json.loads(path.read_text())
            configs[mode] = config
            if config['model_script_sha256'] != model_sha:
                errors.append(f'{bug}/{mode}: model script hash differs')
            if config['entry'] != fixed['entry'] or config['bug'] != bug:
                errors.append(f'{bug}/{mode}: config fixed entry differs')
            if config['mode'] != mode or config['rng_seed'] != 1337:
                errors.append(f'{bug}/{mode}: mode or RNG seed differs')
            if int(actual.get('trigger_count') or 0) and not Path(actual.get('witness') or '').is_file():
                unwitnessed.append(f'{bug}/{mode}')
            if mode == 'control' and (int(actual.get('idfuzz_model_calls') or 0) or
                                      int(actual.get('idfuzz_generated') or 0)):
                errors.append(f'{bug}/control: model or guided mutation was active')
            if mode == 'idfuzz':
                trained += (campaign.WORK_ROOT / bug / 'shared/findings_idfuzz'
                            / 'idfuzz-model-v1.npz').is_file()
                generated += int(actual.get('idfuzz_generated') or 0) > 0
        if len(configs) == 2:
            for field in ('binary_sha256', 'dominators_sha256', 'seeds_sha256',
                          'magma_revision', 'seconds', 'extended_cg'):
                if configs['idfuzz'][field] != configs['control'][field]:
                    errors.append(f'{bug}: paired {field} differs')
    if not trained or not generated:
        errors.append('no completed learned model or generated candidate in the matrix')
    report = {'schema': 1, 'rows': len(campaign.rows()), 'trained_rows': trained,
              'generated_rows': generated, 'unwitnessed_trigger_rows': unwitnessed,
              'errors': errors}
    (root / 'verification.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps(report, indent=2, sort_keys=True))
    if errors:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
