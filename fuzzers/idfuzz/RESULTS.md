# IDFuzz results

## Fixed Magma pilot

The completed pilot used Magma `cec1fec38fdc510c2cb8e6ae690e738b1042cb8d`, RNG seed 1337, and the 60 fixed bug–entry pairs. The paired verifier in `results/idfuzz/verification.json` reports no entry, binary, seed, budget, model-script hash, or Magma-pin mismatches. Both arms completed all 60 rows: 55 pairs ran for 60 seconds, three for 240 seconds, one for 180 seconds, and one for 300 seconds. The longer budgets were assigned to rows whose initial run did not get past seed import, and were applied to **both** arms of each pair.

| Measure | AFLGo + IDFuzz | Same-stack AFLGo control |
| --- | ---: | ---: |
| Completed rows | 60 | 60 |
| Executions | 13,963,557 | 13,248,472 |
| Rows with Magma reached canary | 42 | 42 |
| Rows with Magma triggered canary | 18 | 17 |
| Rows with a replayed crash witness | 6 | 7 |
| Rows with a saved learned-model checkpoint | 43 | 0 |
| Rows that generated learned candidates | 36 | 0 |
| Model processes launched | 363 | 0 |
| Model processes with a retained failure traceback | 244 | 0 |
| Logged model CPU seconds for successful calls | 499.338 | 0 |

Fourteen IDFuzz rows had constant dominator labels, so repeated training attempts could not fit a discriminating model. Three more rows had too few distinct training inputs when the asynchronous model process ran; their tracebacks and fallback executions remain in the artifacts. Model checkpoints and generated candidates are present in 43 and 36 rows respectively. The control made no model calls or guided mutations. Every triggered row has a replayable queue or crash witness; the crash-witness count is narrower than the triggered-row count.

`PDF020` was run in both arms with the fixed `pdf_fuzzer` entry: 511 IDFuzz executions and 540 control executions at 60 seconds. No directed target call survived linking and neither arm recorded a Magma reach or trigger. This is an attempted, censored row, not an excluded row or proof of unreachability.

This is one short engineering trial per row, not a statistical efficacy estimate. The counts above do not establish an IDFuzz advantage. In particular, target reach, Magma trigger, and confirmed crash detection are different events and can move in different directions over a short run. The current source includes a worker-restart counter fix made after the primary Magma pilot. The primary binary hashes and append-only records are preserved in each row's config; `scripts/idfuzz_reconcile.py` reconstructs pilot counters across restarts. The rebuilt runtime passed `scripts/test_idfuzz_internal_restart.sh`, which recorded one internal worker restart with the observation counter continuing forward. The pilot was not rerun with that bookkeeping fix.

The authoritative row matrix is `results/idfuzz/status-idfuzz.csv` and the identical-stack control matrix is `results/idfuzz/status-control.csv`. Per-row raw files are under `magma/work/idfuzz/<BUG>/out/` and `magma/work/idfuzz/<BUG>/shared/findings_<mode>/`. Each completed campaign saves `idfuzz-config-v1.json`, `idfuzz-dom-v1.tsv`, canary counts, queue/crash files, mutation records, model rankings and versioned checkpoints when training succeeds.

The initial 60-second runs are engineering pilots, one RNG seed per row. Rows still importing seeds are rerun with the same longer budget in both arms; each config records its actual campaign seconds. They are not repeated statistical estimates or the author's original benchmark results. `status=campaign_complete` means the fixed harness was built and the campaign ran; a zero trigger count is a censored observation under the chosen budget, not proof that a bug is unreachable. The record writer can stop at 20,000 retained events per worker lifetime; `idfuzz_dropped_records` reports omitted observations from the latest persisted worker snapshot. `seconds` in the matrix includes setup/build/replay. `scripts/idfuzz_reconcile.py` sums monitor-counter segments across in-process restarts, and counts completed training calls from `idfuzz-training.log`; raw event and training files are retained for audit. `idfuzz_train_ns` can undercount a worker killed by a target crash, so the audit also reports model CPU and inference seconds from the training events. The baseline control uses the same binary and MOPT stage without model calls.

An earlier synchronous training pilot on PNG006 is archived in `results/idfuzz/pilots/PNG006-synchronous/`; it reached the bug code but spent most of the campaign waiting for training. Current campaigns use asynchronous training. Any later comparison must use the current `idfuzz-config-v1.json` hashes and must not pool the synchronous pilot.

The pinned original-author environment built as image `tractfuzz-idfuzz-author:86d11b3`; exact image IDs are in `results/idfuzz/image-ids.json`. `scripts/run_idfuzz_author_fixture.sh` ran the original analysis, AFL2 instrumentation, and model on the small `IDF!` file fixture. The 300-second live run is in `results/idfuzz/author-fixture-full/`: the author parser found 13 dominator edges, the adaptive trainer selected 120 samples at five feedback levels, and PyTorch completed five epochs. Its final validation loss was 0.6421 versus 0.3798 for a constant predictor. The pinned reproduction setting disables the quality gate, so the live model was retained despite that result. The author trainer keeps its checkpoint in memory and did not emit a checkpoint file.

`scripts/replay_idfuzz_author_fixture.py` runs the pinned feature parser and PyTorch model class on the saved author queue with replay seed 1337. This separate replay exported `replay/author-replay-records-v1.jsonl`, `author-replay-model.pt`, `author-replay-rankings-v1.json`, and candidate inputs. The replay ranked byte 3 first for non-target seed 074; enumerating its 256 values produced exactly one target hit, value 33 (`!`), when executed by the original instrumented fixture. Replay validation loss was 0.7530 versus a 0.3822 constant baseline. These are offline replay artifacts, not the live author's in-memory weights or a Magma result. The AFL2 fork's first in-place resume failed because it retained its custom `cur_dom_bits` directory. `scripts/run_idfuzz_author_resume.sh` now archives those maps before resume; the saved queue and a second live training pass completed, but the resumed 180-second budget ended before a non-target seed requested a byte recommendation. The offline replay supplies the inspectable ranking and candidate.
