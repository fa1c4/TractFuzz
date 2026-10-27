#!/usr/bin/env python3
"""Versioned CPU MLP for the LibAFLGo IDFuzz adaptation.

The author model has 512 hidden neurons, ReLU and sigmoid. This independent
NumPy implementation keeps that architecture and uses deterministic Adam;
its fixed input normalization replaces the author's BatchNorm layers.
"""
import argparse
import json
import os
import shutil
import resource
import time
from pathlib import Path

import numpy as np


def load_records(path):
    samples = {}
    for line in path.open():
        try:
            row = json.loads(line)
            if row.get('schema') != 1:
                continue
            raw = bytes.fromhex(row['input_hex'])[:1024]
            samples[row['hash']] = (raw, row['dominators'], row.get('branches', []),
                                    row['target_hit'])
        except (ValueError, KeyError):
            continue
    if len(samples) > 2048:
        samples = dict(list(samples.items())[-2048:])
    return samples


def train(samples, seed, epochs, lr):
    keys = sorted(samples)
    width = max(1, min(1024, max(len(samples[k][0]) for k in keys)))
    outputs = max(1, max((max([*samples[k][1],
                                  *(idx for idx, _ in samples[k][2])], default=0)
                           for k in keys)))
    x = np.zeros((len(keys), width), dtype=np.float32)
    y = np.zeros((len(keys), outputs), dtype=np.float32)
    for n, key in enumerate(keys):
        raw, dom, branches, _ = samples[key]
        x[n, :min(width, len(raw))] = np.frombuffer(raw[:width], dtype=np.uint8) / 255.0
        for idx in dom:
            if 0 < idx <= outputs:
                y[n, idx - 1] = 1.0
        for idx, fraction in branches:
            if 0 < idx <= outputs and y[n, idx - 1] == 0:
                y[n, idx - 1] = float(fraction)
    if len(keys) < 16 or len(np.unique(y, axis=0)) < 2:
        raise ValueError('need at least 16 distinct inputs and two dominator labels')
    rng = np.random.default_rng(seed)
    order = rng.permutation(len(keys))
    split = min(len(keys) - 1, max(1, int(len(keys) * .8)))
    tr, te = order[:split], order[split:]
    mu = x[tr].mean(0)
    sigma = x[tr].std(0)
    sigma[sigma < .05] = .05
    x = (x - mu) / sigma
    hidden = 512
    weights = [rng.normal(0, np.sqrt(2 / width), (width, hidden)).astype(np.float32),
               np.zeros(hidden, np.float32),
               rng.normal(0, np.sqrt(2 / hidden), (hidden, outputs)).astype(np.float32),
               np.zeros(outputs, np.float32)]
    moment1 = [np.zeros_like(w) for w in weights]
    moment2 = [np.zeros_like(w) for w in weights]
    step = 0
    start = time.monotonic()
    for epoch in range(epochs):
        for batch in np.array_split(rng.permutation(tr), max(1, int(np.ceil(len(tr) / 32)))):
            z = x[batch] @ weights[0] + weights[1]
            h = np.maximum(z, 0)
            logits = h @ weights[2] + weights[3]
            p = 1 / (1 + np.exp(-np.clip(logits, -30, 30)))
            dy = (p - y[batch]) / (len(batch) * outputs)
            grads = [None] * 4
            grads[2] = h.T @ dy + .00002 * weights[2]
            grads[3] = dy.sum(0)
            dh = (dy @ weights[2].T) * (z > 0)
            grads[0] = x[batch].T @ dh + .00002 * weights[0]
            grads[1] = dh.sum(0)
            step += 1
            for j in range(4):
                moment1[j] = .9 * moment1[j] + .1 * grads[j]
                moment2[j] = .999 * moment2[j] + .001 * grads[j] ** 2
                weights[j] -= lr * (moment1[j] / (1 - .9 ** step)) / (
                    np.sqrt(moment2[j] / (1 - .999 ** step)) + 1e-8)
    def loss(pred, label):
        return float(np.mean(-(label * np.log(pred + 1e-7) +
                               (1 - label) * np.log(1 - pred + 1e-7))))
    pred = 1 / (1 + np.exp(-np.clip(np.maximum(x[te] @ weights[0] + weights[1], 0)
                                          @ weights[2] + weights[3], -30, 30)))
    baseline = np.clip(y[tr].mean(0), 1e-6, 1 - 1e-6)
    metrics = dict(samples=len(keys), width=width, outputs=outputs, hidden=hidden,
                   epochs=epochs, lr=lr, train_seconds=time.monotonic() - start,
                   validation_loss=loss(pred, y[te]), baseline_loss=loss(baseline, y[te]))
    return keys, x, y, mu, sigma, weights, metrics


def rankings(keys, x, y, sigma, weights, samples):
    w1, b1, w2, b2 = weights
    result, modes, fields = {}, {}, {}
    deepest = max(int(np.count_nonzero(label == 1)) for label in y)
    for n, key in enumerate(keys):
        raw = samples[key][0]
        if not raw:
            result[key] = []
            continue
        active = ((x[n] @ w1 + b1) > 0).astype(np.float32)
        covered = y[n]
        if np.all(covered >= 1.0):
            result[key] = []
            continue
        next_idx = next((i for i, value in enumerate(covered) if value == 0), len(covered) - 1)
        def grad(idx):
            return np.abs((w1 @ (w2[:, idx] * active)) / sigma)
        if next_idx >= deepest:
            modes[key] = 'conservative'
            protected = set(np.argsort(-grad(max(0, next_idx - 1)))[:20])
            result[key] = [int(i) for i in range(min(len(raw),len(sigma)))
                           if i not in protected][:20]
            fields[key] = []
            continue
        modes[key] = 'aggressive'
        main = grad(next_idx)
        order = np.argsort(-main, kind='stable')
        # Algorithm 2: retain bytes ranked above both distant neighbors.
        eligible = set(range(min(len(raw), len(main))))
        if next_idx >= 2 and next_idx + 2 < len(covered):
            rank_main = np.empty(len(order), dtype=np.int32)
            rank_main[order] = np.arange(len(order))
            left_order = np.argsort(-grad(next_idx - 2), kind='stable')
            right_order = np.argsort(-grad(next_idx + 2), kind='stable')
            rank_left = np.empty(len(order), dtype=np.int32)
            rank_right = np.empty(len(order), dtype=np.int32)
            rank_left[left_order] = np.arange(len(order))
            rank_right[right_order] = np.arange(len(order))
            eligible = {i for i in eligible if rank_main[i] < rank_left[i]
                        and rank_main[i] < rank_right[i]}
        result[key] = [int(i) for i in order if i in eligible][:20]
        # One-dimensional DBSCAN with eps=1/min_samples=2 on hot-byte offsets.
        hot = sorted(result[key])
        runs = []
        for offset in hot:
            if runs and offset == runs[-1][-1] + 1:
                runs[-1].append(offset)
            else:
                runs.append([offset])
        fields[key] = []
        for run in runs:
            if len(run) < 2:
                continue
            for start in range(0,len(run),4):
                chunk=run[start:start+4]
                if len(chunk)<2: continue
                size=2 if len(chunk)<=2 else 4
                field_start=max(0,min(chunk[0],len(raw)-size))
                if field_start+size<=len(raw):
                    fields[key].append(dict(start=int(field_start),length=size,
                                            score=float(sum(main[i] for i in chunk))))
        fields[key].sort(key=lambda field: -field['score'])
    return result, modes, fields


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--records', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--checkpoint', type=Path, required=True)
    p.add_argument('--seed', type=int, default=1337)
    p.add_argument('--epochs', type=int, default=int(os.getenv('IDFUZZ_EPOCHS', '5')))
    p.add_argument('--lr', type=float, default=float(os.getenv('IDFUZZ_LR', '0.001')))
    args = p.parse_args()
    samples = load_records(args.records)
    keys, x, y, mu, sigma, weights, metrics = train(samples, args.seed, args.epochs, args.lr)
    inference_start = time.monotonic()
    ranks, modes, fields = rankings(keys, x, y, sigma, weights, samples)
    metrics['inference_seconds'] = time.monotonic() - inference_start
    metrics['cpu_seconds'] = resource.getrusage(resource.RUSAGE_SELF).ru_utime
    metrics['device'] = 'cpu'
    metrics['openblas_threads'] = os.getenv('OPENBLAS_NUM_THREADS', '')
    version = int(time.time_ns())
    temp = args.output.with_suffix('.tmp')
    temp.write_text(json.dumps(dict(schema=1, version=version, rankings=ranks,
                                    modes=modes, fields=fields,
                                    training=metrics, seed=args.seed), sort_keys=True))
    temp.replace(args.output)
    shutil.copyfile(args.output, args.output.with_name(
        f'{args.output.stem}-{version}{args.output.suffix}'))
    np.savez_compressed(args.checkpoint, mean=mu, std=sigma, w1=weights[0],
                        b1=weights[1], w2=weights[2], b2=weights[3], seed=args.seed)
    shutil.copyfile(args.checkpoint, args.checkpoint.with_name(
        f'{args.checkpoint.stem}-{version}{args.checkpoint.suffix}'))
    print(json.dumps(metrics))


if __name__ == '__main__':
    main()
