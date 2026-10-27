#!/usr/bin/env python3
"""Summarize the fixed 60-row IDFuzz and same-stack AFLGo control campaigns."""
import csv
import hashlib
import json
import re
from collections import Counter
from pathlib import Path

import idfuzz_magma as campaign


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else ''


def count(path):
    return sum(p.is_file() and not p.name.startswith('.') for p in path.rglob('*')) if path.is_dir() else 0


def number(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def feedback(path):
    patterns=set(); count=0
    if path.is_file():
        for line in path.open(errors='replace'):
            try:
                record=json.loads(line)
                patterns.add((tuple(record.get('dominators', [])),
                              tuple(tuple(item) for item in record.get('branches', []))))
                count+=1
            except (TypeError, ValueError):
                continue
    return count,len(patterns)


def manifest(path):
    if not path.is_file(): return {}
    with path.open() as stream:
        header=stream.readline()
    return {name:number(value) for name,value in re.findall(r'(\w+)=(\d+)',header)}


def audit(mode):
    root = campaign.ROOT / 'results/idfuzz'
    status_path = root / f'status-{mode}.csv'
    current = {r['bug']:r for r in csv.DictReader(status_path.open())} if status_path.is_file() else {}
    output = root / f'applicability-{mode}.csv'
    fields = ('number','project','bug','entry','mode','status','detail','trial',
              'budget_seconds','end_to_end_seconds','non_campaign_seconds','executions',
              'magma_reached','magma_triggered','trigger_time_censored','queue_files',
              'crash_files','confirmed_detection','witness','model_calls','model_completed',
              'model_failures','model_training_wall_ns','model_cpu_seconds',
              'model_inference_seconds','model_generated','model_fallback',
              'long_inputs','dropped_records','retained_records',
              'distinct_label_patterns','model_status','analysis_targets',
              'analysis_target_calls','analysis_indirect_calls','analysis_omitted_probes',
              'config_sha256','binary_sha256',
              'dominator_manifest_sha256','seed_corpus_sha256','magma_revision',
              'records_sha256','rankings_sha256','checkpoint_sha256','canary_sha256')
    with output.open('w',newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=fields)
        writer.writeheader()
        for row in campaign.rows():
            bug=row['bug']; actual=current.get(bug,{})
            trial=actual.get('trial','')
            suffix=mode if not trial else f'{mode}_{trial}'
            base=campaign.WORK_ROOT/bug
            out=base/'out'
            findings=base/'shared'/f'findings_{suffix}'
            config_path=out/f'config_{suffix}.json'
            config=json.loads(config_path.read_text()) if config_path.is_file() else {}
            training_log=findings/'idfuzz-training.log'
            models=[]
            if training_log.is_file():
                for line in training_log.read_text(errors='replace').splitlines():
                    try: models.append(json.loads(line))
                    except ValueError: pass
            witness=actual.get('witness','')
            detected=bool(witness and Path(witness).is_file() and
                          'crashes' in Path(witness).parts)
            status=actual.get('status') or 'not_attempted'
            end_to_end=actual.get('seconds','')
            budget=config.get('seconds', 60)
            retained,patterns=feedback(findings/'idfuzz-records-v1.jsonl')
            analysis=manifest(findings/'idfuzz-dom-v1.tsv')
            checkpoint=findings/'idfuzz-model-v1.npz'
            if mode=='control': model_status='disabled'
            elif not retained: model_status='no_history'
            elif patterns<2: model_status='constant_labels'
            elif checkpoint.is_file(): model_status='trained'
            elif number(actual.get('idfuzz_model_failures')): model_status='training_failed'
            else: model_status='insufficient_history'
            non_campaign=(round(max(0,float(end_to_end)-budget),2)
                          if end_to_end and status=='campaign_complete' else '')
            writer.writerow(dict(number=row['number'],project=row['project'],bug=bug,
                entry=row['entry'],mode=mode,status=status,detail=actual.get('detail',''),
                trial=trial,budget_seconds=budget,end_to_end_seconds=end_to_end,
                non_campaign_seconds=non_campaign,executions=actual.get('executions',''),
                magma_reached=actual.get('reach_count',''),
                magma_triggered=actual.get('trigger_count',''),
                trigger_time_censored=int(status=='campaign_complete' and
                                          number(actual.get('trigger_count'))==0),
                queue_files=count(findings/'queue'),crash_files=count(findings/'crashes'),
                confirmed_detection=int(detected),witness=witness,
                model_calls=actual.get('idfuzz_model_calls',''),
                model_completed=actual.get('idfuzz_model_completed',''),
                model_failures=actual.get('idfuzz_model_failures',''),
                model_training_wall_ns=actual.get('idfuzz_train_ns',''),
                model_cpu_seconds=round(sum(m.get('cpu_seconds',0) for m in models),3),
                model_inference_seconds=round(sum(m.get('inference_seconds',0) for m in models),3),
                model_generated=actual.get('idfuzz_generated',''),
                model_fallback=actual.get('idfuzz_fallback',''),
                long_inputs=actual.get('idfuzz_long_inputs',''),
                dropped_records=actual.get('idfuzz_dropped_records',''),
                retained_records=retained,distinct_label_patterns=patterns,
                model_status=model_status,analysis_targets=analysis.get('targets',''),
                analysis_target_calls=analysis.get('target_calls',''),
                analysis_indirect_calls=analysis.get('indirect',''),
                analysis_omitted_probes=analysis.get('omitted',''),
                config_sha256=config.get('config_sha256',''),
                binary_sha256=config.get('binary_sha256',''),
                dominator_manifest_sha256=config.get('dominators_sha256',''),
                seed_corpus_sha256=config.get('seeds_sha256',''),
                magma_revision=config.get('magma_revision',''),
                records_sha256=sha(findings/'idfuzz-records-v1.jsonl'),
                rankings_sha256=sha(findings/'idfuzz-rankings-v1.json'),
                checkpoint_sha256=sha(findings/'idfuzz-model-v1.npz'),
                canary_sha256=sha(out/f'campaign_{suffix}_canaries.csv')))
    rows=list(csv.DictReader(output.open()))
    complete=[r for r in rows if r['status']=='campaign_complete']
    return dict(mode=mode,status=dict(Counter(r['status'] for r in rows)),
                reached=sum(number(r['magma_reached'])>0 for r in complete),
                triggered=sum(number(r['magma_triggered'])>0 for r in complete),
                confirmed_detection=sum(number(r['confirmed_detection'])>0 for r in complete),
                executions=sum(number(r['executions']) for r in complete),
                model_calls=sum(number(r['model_calls']) for r in complete),
                model_completed=sum(number(r['model_completed']) for r in complete),
                model_failures=sum(number(r['model_failures']) for r in complete),
                model_generated=sum(number(r['model_generated']) for r in complete),
                model_cpu_seconds=round(sum(float(r['model_cpu_seconds'] or 0)
                                            for r in complete),3),
                constant_label_rows=sum(r['model_status']=='constant_labels'
                                        for r in complete),
                output=str(output))


def main():
    root=campaign.ROOT/'results/idfuzz'
    root.mkdir(parents=True,exist_ok=True)
    summary={mode:audit(mode) for mode in ('idfuzz','control')}
    (root/'summary.json').write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n')
    print(json.dumps(summary,indent=2,sort_keys=True))


if __name__=='__main__':
    main()
