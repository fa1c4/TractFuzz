# Fixed Magma applicability and pilot results

`results/selectfuzz/status.csv` records the selected trial for each of the 60 fixed entry–bug rows in `docs/tractfuzz_magma_benchmarks.md`. `results/selectfuzz/applicability.csv` adds binary, target, seed, manifest, and method-configuration hashes, linked block counts, invocation, campaign timing, feedback counters, and replay evidence. Raw builds, manifests, monitor rows, fuzzer logs, and findings are under `magma/work/selectfuzz/<bug>/`.

| Outcome in selected trials | Rows |
| --- | ---: |
| Campaign complete | 60 |
| Reached target canary | 42 |
| Triggered bug canary | 17 |
| Crash artifact recorded | 10 |

All 60 completed rows have a hashed binary and a linked SelectFuzz manifest, and reported executions beyond the initial seed count. Fifty-nine rows have selected and target blocks with active feedback: 44 in-process rows recorded selected probes, and 15 command-line rows recorded selected edge entries and child executions. Every row with a trigger has a replay witness. Across the selected trials, the row logs report 426,623 executions. Budgets vary from 28 to 300 seconds because several larger seed corpora needed longer to enter mutation; these are engineering pilots, not normalized effectiveness results.

PDF020 was built and run on its specified `pdf_fuzzer` entry for 300 seconds. The linked manifest has 0 selected and 0 target blocks out of 256,931; no directed target call survived linking. Its campaign reported 10,803 executions beyond the 392 initial seed files, 0 selected probes, 0 reach events, and 0 trigger events. It saved one crash artifact without a PDF020 canary trigger, so that artifact is not evidence of detecting PDF020. This records the fixed-entry outcome without skipping the row.

The initial PHP pilots were invalid: their build linked `php-fuzz-<entry>`, whereas the instrumentation filter matched the copied entry name. Seven PHP rows were rebuilt with the corrected filter and each now has a linked manifest and nonzero probes. TIF002, TIF004, and SSL007 initially recorded no selected probes with the direct call graph. SVF indirect-call analysis produced active feedback for all three. Five OpenSSL rows were rerun with longer budgets after their first pilots ended during seed import. PDF010 was also rerun with a separate 300-second trial after its first pilot spent most of its budget on the seed corpus. Its earlier trial triggered the canary; the selected longer trial did not, so the table above counts only the latter.

This is an independent paper-based LLVM 15 port. The pinned author repository lacks source for its analysis and instrumentation passes, and its bundled shared objects fail to load in LLVM 15. No exact author selected-block trace or same-stack repeated AFLGo comparison is available. The 60-row matrix establishes implementation applicability and short-run observations; it does not establish comparative SelectFuzz effectiveness.
