# SelectFuzz method in this fork

| Paper component | Fork implementation | Reproduction boundary |
| --- | --- | --- |
| Target basic blocks | `AFLGoTargetDetectionAnalysis` | Reuses compiler target line injection and its target callback. |
| Interprocedural graph | `SelectFuzzAnalysis::run` | Direct calls and return continuations are represented. `AFLGO_SELECTFUZZ_EXTEND_CG=1` enables SVF indirect-call edges. It is used for CLI Magma rows and for TIF002, TIF004, and SSL007, whose direct-call manifests had no probes during their pilots. The pass log counts callsites without a direct callee even when SVF resolves some of them. Calls inside a basic block share the block node. |
| Path-divergent code | `SelectFuzzAnalysis::run` | A block is selected when its successor set contains both target-reachable and target-unreachable blocks. Multiple target blocks are combined. |
| Data-dependent code | `SelectFuzzAnalysis::run` | Backward SSA operand slice from annotated target instructions, direct stores to the same stripped pointer, call results and formal/actual arguments. Aliasing and indirect data calls are approximated; unknown loads and slice truncation are reported. This is not the author's unavailable pointer-analysis pass. |
| Target probability | `SelectFuzzAnalysis::run` | Target probability 1; predecessor probability is the mean of successor probabilities. At most 64 deterministic Bellman rounds approximate the paper's one-unroll DFS on cycles. Zero probability yields no finite distance probe. |
| Selected feedback | `SelectFuzzInstrumentationPass::run` | Only relevant blocks get `__selectfuzz_trace_bb`. Their transitions populate the LibAFL edge map; ordinary PCGuard coverage is disabled in this mode. A TSV manifest records IDs and omitted blocks (`id=0`). |
| Input distance | `libaflgo_targets::selectfuzz` and CLI runtime | Minimum visited finite `1/P`, in thousandths. The observer resets before every input. |
| Queue and energy | `libaflgo::selectfuzz` | Relevant-edge novelty boosts weighted queue selection and mutation energy. AFLGo's annealing distance score is retained; finite shorter-distance inputs are favored when novelty is absent. This is a documented policy approximation of the author's AFL modifications. |
| Target hit | Existing LibAFLGo target feedback | Independent target map remains active even when selected coverage is sparse. |

The CLI runner forces admission of the supplied initial corpus. A fixed-entry program can have no selected block before it enters target-related code; discarding every initial seed would leave an empty queue. Mutation then starts from those seeds even when their observed distance is unknown.

PDF020 is the fixed-entry case where no directed target call survives linking. The workflow still builds and fuzzes that entry. Its zero-selected-block manifest and zero selected feedback are recorded as the result for that row.

Magma's PHP build links `sapi/fuzzer/php-fuzz-<entry>` and copies it to `out/<entry>`. The link filter matches the linked name, and the workflow requires the corresponding `selectfuzz-blocks-php-fuzz-<entry>.tsv` with selected blocks before accepting a PHP campaign. This check was added after the first PHP attempts had no SelectFuzz probes; those attempts were invalidated and rebuilt.

The Magma workflow records whether extended call graph analysis was used in `status.csv` and incorporates that choice into the build stamp. `--extended-cg` forces the option for an in-process row; CLI rows always use it. This choice changes the selected-block set and must be considered when comparing rows.

The manifest is `selectfuzz-blocks-v1`, sorted in module/function/basic-block order. `kind` bits are 1 (divergent), 2 (data), and 4 (target). The pass log reports selected/total blocks, indirect callsites lacking a direct callee, unknown memory loads, and slice truncation. Missing debug locations are written `?`; multiple annotated target instructions are all sliced. The manifest is per final linked binary, avoiding IDs from intermediate modules.
