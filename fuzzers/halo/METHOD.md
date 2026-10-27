# Halo method map

| Paper step | This implementation | Boundary |
| --- | --- | --- |
| Trace target reaching | `target::any_target_hit` for in-process entries; shared target map for CLI entries | Any fixed directed target ID counts. Magma canary reach/trigger remains a separate oracle. |
| Collect reaching/non-reaching inputs | `HaloInputObserver` and `HaloEngine::{reaching,missing}` | At most 385 unique inputs in each pool; first 256 bytes retained for inference. Every execution goes to the versioned TSV trace. |
| Rank non-reaching inputs | AFLGo basic-block distance average, where finite | A surrogate for the paper's branch-condition distance; no value means the input stays in the pool but cannot inform near/far ranking. |
| Infer input invariants | `HaloEngine::infer` | Equality, bounded interval, byte sum and byte difference, selected from up to 16 distinguishing positions. Inputs shorter than the tenth-percentile source length are excluded from that inference pass so one empty input cannot remove all byte positions. No DIG or byte-by-byte taint probe. Re-infer every 64 observations and when first reached. |
| No/one reaching input | Rank non-reaching samples by finite distance; infer relations of far samples and sample their negation | This is a heuristic surrogate for the paper's non-reaching invariant negation. |
| Select and update | Weighted by Laplace-smoothed useful/attempted ratio times discrimination; useful means reaching or improved distance | Utility is updated after each generated input. Unlike paper similarity, improvement of distance also counts. |
| Sample | Directly project one predicate onto bytes, or violate it for a negated candidate; random byte mutation fallback | No Vaidya walk or simultaneous polytope sampling. Input length stays fixed, except empty input receives one byte. A regular LibAFL havoc stage with crossover follows unless `--halo-only` is given. There is no separate AFL++ splice cycle or MOPT stage. |
| Corpus and restart | AFLGo weighted queue and coverage/time/distance/target feedback, forced seed import; JSON checkpoint and versioned TSV traces | The corpus retains only interesting cases, while the Halo pools observe all executed cases. `--halo-seed` fixes RNG initialization; the checkpoint restores pools/counters but not the exact RNG position. |

`libaflgo/src/halo.rs` owns inference, selection, sampling, metadata, and trace files. `fuzzers/halo/src/lib.rs` runs in-process fixed entries; `fuzzers/halo_cli/src/main.rs` runs fixed CLI entries with `runtime/halo_cli.c`. The normal AFLGo compiler/linker pass supplies directed target and distance callbacks. CLI children receive their Magma environment and a shared memory map.

`fuzzers/halo_control_cli/src/main.rs` is a comparison runner on the same CLI target binary and shared-memory layout. It retains LibAFLGo's distance feedback and distance-power havoc stage, uses the same fixed corpus and forced seed import, and omits Halo inference. It is an ablation control; it does not reproduce the original in-process AFLGo CmpLog/MOPT sequence.

Every retained testcase can carry `HaloInputMetadata` schema 1: input hash and length, reached flag, finite distance, parent hash, selected invariant ID, and generation time. Each run also writes `halo-checkpoint-v1.json`, `halo-inputs-v1.tsv`, and `halo-invariants-v1.tsv`. An interrupted campaign may lose fewer than 64 buffered observations since the last checkpoint.

The sampler preserves the parent input length, except that an empty parent becomes one byte. It does not parse file formats or discard invalid-format mutations in advance. Such executions enter the non-reaching observation pool and are retained in the LibAFL corpus only if ordinary coverage, time, distance, or target feedback admits them. Inputs without a finite AFLGo distance are recorded with no distance and do not participate in near/far ranking.

The inferred relations are empirical, so Halo never prunes target paths. The standard campaign includes Halo sampling plus LibAFL havoc with crossover; `--halo-only` isolates the inference stage for a control run. The paper's separate AFL++ splice cycle is not reproduced. This stack and its distance/feedback choices must be compared with the same fixed-entry AFLGo baseline before attributing outcome differences to Halo.
