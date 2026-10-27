#!/usr/bin/env python3
"""Recompute row counters from retained logs after all campaign workers exit."""
import csv
from pathlib import Path

import idfuzz_magma as campaign


def main():
    root = Path(__file__).resolve().parents[1]
    for mode in ('idfuzz', 'control'):
        campaign.STATUS = root / f'results/idfuzz/status-{mode}.csv'
        previous = {row['bug']: row for row in csv.DictReader(campaign.STATUS.open())}
        for row in campaign.rows():
            actual = previous[row['bug']]
            if actual['status'] == 'not_attempted':
                continue
            metrics = campaign.campaign_metrics(row['bug'], mode, actual.get('trial', ''))
            merged = dict(row)
            merged.update(actual)
            merged.update(metrics)
            campaign.update_status(merged)
        print(campaign.STATUS)


if __name__ == '__main__':
    main()
