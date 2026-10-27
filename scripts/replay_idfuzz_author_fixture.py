#!/usr/bin/env python3
"""Export an offline replay of the pinned author's in-memory PyTorch model.

The live artifact has no checkpoint writer. This executes its unmodified
feature parser, model class, and trainer against a saved fixture queue with a
fixed replay seed, then records gradients and one byte-enumeration candidate.
"""
import ast
import hashlib
import json
import os
import random
import subprocess
import sys
from pathlib import Path

import numpy as np
import torch


def load_author(path):
    source = path.read_text()
    tree = ast.parse(source, filename=str(path))
    kept = []
    skipped = {'shm', 'shm_key', 'fuzzer_pid'}
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom, ast.FunctionDef,
                             ast.ClassDef)):
            kept.append(node)
        elif isinstance(node, ast.Assign):
            names = {target.id for target in node.targets
                     if isinstance(target, ast.Name)}
            if names and not names.intersection(skipped):
                kept.append(node)
    module = ast.fix_missing_locations(ast.Module(body=kept, type_ignores=[]))
    namespace = {'__name__': 'idfuzz_offline_replay', '__file__': str(path)}
    exec(compile(module, str(path), 'exec'), namespace)
    return namespace, hashlib.sha256(source.encode()).hexdigest()


def main():
    if len(sys.argv) != 3:
        raise SystemExit('usage: replay_idfuzz_author_fixture.py WORK AUTHOR_NN_PY')
    work = Path(sys.argv[1]).resolve()
    author = Path(sys.argv[2]).resolve()
    out = work / 'out'
    export = work / 'replay'
    export.mkdir(exist_ok=True)
    sys.argv = [str(author), str(work / 'fixture'), str(out), '0']
    os.environ.update(TMP_DIR=str(work / 'tmp'), IDFUZZ_LR='1e-5',
                      IDFUZZ_EPOCHS='5', IDFUZZ_PATIENCE='0',
                      IDFUZZ_QUALITY_GATE='0')
    namespace, source_sha = load_author(author)
    namespace['rand_seed'] = 1337
    np.random.seed(1337)
    random.seed(1337)
    torch.manual_seed(1337)
    names, x, y, outputs, labels, balanced, levels, _ = namespace['init']()
    if not balanced:
        raise RuntimeError('saved author fixture training set is unbalanced')
    namespace['DOM_BB_NUM'] = outputs
    model = namespace['S2DModel'](outputs)
    model.to(namespace['device'])
    model, accepted = namespace['train'](model, x, y)
    model.eval()
    train_x, test_x, train_y, test_y = namespace['train_test_split'](
        x, y, test_size=0.2, random_state=1337)
    with torch.no_grad():
        validation_loss = float(model.loss(model(test_x), test_y))
        prior = train_y.mean(0, keepdim=True).clamp(1e-6, 1-1e-6)
        baseline_loss = float(namespace['nn'].functional.binary_cross_entropy(
            prior.expand_as(test_y), test_y))
    checkpoint = export / 'author-replay-model.pt'
    torch.save({'source_sha256': source_sha, 'seed': 1337,
                'parameters': model.state_dict(), 'input_width': namespace['MAX_FILE_SIZE'],
                'outputs': outputs}, checkpoint)
    rows = []
    queue = out / 'queue'
    width = namespace['MAX_FILE_SIZE']
    raw_list = []
    for name, label in zip(names, labels):
        raw = (queue / name).read_bytes()
        raw_list.append(np.pad(np.frombuffer(raw[:width], dtype=np.uint8),
                               (0, max(0, width-len(raw))), 'constant'))
        rows.append({'file': name, 'input_sha256': hashlib.sha256(raw).hexdigest(),
                     'input_hex': raw[:1024].hex(), 'input_len': len(raw),
                     'dominator_label': label})
    with (export / 'author-replay-records-v1.jsonl').open('w') as stream:
        for row in rows:
            stream.write(json.dumps(row, sort_keys=True) + '\n')
    tensor = torch.as_tensor(np.asarray(raw_list), dtype=torch.float32) / 255
    rankings = {}
    for index, name in enumerate(names):
        row = tensor[index:index+1].clone().detach().requires_grad_(True)
        label = namespace['trans_vec'](labels[index], levels)
        next_neuron = next((i for i, value in enumerate(label) if value < 1),
                           outputs-1)
        next_neuron = min(next_neuron, outputs-1)
        model.zero_grad()
        result = model.pre_grad_batch(row, next_neuron)
        result.backward(torch.ones_like(result))
        scores = row.grad.abs().detach().cpu().numpy()[0]
        order = np.argsort(-scores).tolist()
        rankings[name] = {'next_neuron': next_neuron,
                          'top20_offsets': order[:20],
                          'top20_gradients': [float(scores[i]) for i in order[:20]]}
    (export / 'author-replay-rankings-v1.json').write_text(
        json.dumps(rankings, indent=2, sort_keys=True) + '\n')
    candidate = None
    enumeration = None
    for index, name in enumerate(names):
        if 'seed' not in name:
            continue
        if all(value == 1 for value in labels[index]):
            continue
        raw = bytearray((queue / name).read_bytes())
        label = rankings[name]
        if any(offset < len(raw) for offset in label['top20_offsets']):
            offset = next(offset for offset in label['top20_offsets']
                          if offset < len(raw))
            before = raw[offset]
            raw[offset] = (before + 1) % 256
            path = export / 'author-replay-candidate.bin'
            path.write_bytes(raw)
            candidate = {'parent': name, 'offset': offset, 'before': before,
                         'after': raw[offset], 'path': str(path),
                         'sha256': hashlib.sha256(raw).hexdigest()}
            parent = bytearray((queue / name).read_bytes())
            candidates = export / 'byte-enumeration'
            candidates.mkdir(exist_ok=True)
            hits = []
            for value in range(256):
                changed = bytearray(parent)
                changed[offset] = value
                variant = candidates / ('%03d.bin' % value)
                variant.write_bytes(changed)
                result = subprocess.run([str(work / 'fixture'), str(variant)],
                                        stdout=subprocess.DEVNULL,
                                        stderr=subprocess.DEVNULL)
                if result.returncode == 1:
                    hits.append({'value': value, 'path': str(variant)})
            enumeration = {'count': 256, 'target_hits': hits}
            break
    summary = {'source_sha256': source_sha, 'seed': 1337,
               'samples': len(names), 'outputs': outputs, 'width': width,
               'balanced': balanced, 'quality_gate': False, 'accepted': accepted,
               'validation_loss': validation_loss,
               'constant_baseline_loss': baseline_loss,
               'checkpoint': str(checkpoint), 'candidate': candidate,
               'enumeration': enumeration}
    (export / 'summary.json').write_text(json.dumps(summary, indent=2,
                                                   sort_keys=True) + '\n')
    print(json.dumps(summary, sort_keys=True))


if __name__ == '__main__':
    main()
