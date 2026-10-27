# Validation record

## Small program

`scripts/test_selectfuzz_fixture.sh` builds `test/selectfuzz-fixture.c` and saves the linked manifest in `results/selectfuzz/fixture/blocks-fixture.tsv`. On LLVM 15 at `-O0`, the SelectFuzz port selected 4/12 blocks: the target, two guarding branches, and a data-dependent entry. It omitted the unrelated `Q/X` branch. The target distance is 1; the preceding guards have distances 2 and 4, and entry has distance 8. The pass reported 0 unresolved calls, 0 unknown loads, and no slice truncation. Both target and unrelated inputs replayed through the in-process runner.

Two consecutive fixture links produced the same manifest SHA-256, `3ce30c92dc6ce36abca985ff4dbd2a33224ef1fac085e9ddd3a6431e28bb003d`.

The same fixture built with DAFL. Its output `results/selectfuzz/fixture/dafl-dafl-fixture.csv` lists only the entry (`line 4`) and target (`line 8`), showing the two methods select different control blocks. This comparison is against this fork's DAFL pass; it is not an author SelectFuzz trace comparison because the author's analysis pass source is absent.

The bundled author analysis and instrumentation libraries were tried with LLVM 15 `opt-15`. Both failed to load with the same missing LLVM symbol, so no author fixture trace was produced. The exact diagnostics are archived in `results/selectfuzz/author-*-opt-help.txt`.

## Fixed Magma smoke rows

PNG006/libpng_read_fuzzer completed a 30-second campaign. The linked manifest selected 5,294/20,926 blocks. The seed replay recorded 3 reach and 0 trigger events; the campaign monitor recorded 11,928 reach and 0 trigger events, with 10,647 fuzzer executions. Its target map registered hits and the selected edge map registered 844 entries. Logs are under `magma/work/selectfuzz/PNG006/out/`.

TIF006/tiffcp initially failed to configure on the host because libtiff development libraries were absent. In the dependency container, the first selective analysis selected only 10 target-function blocks and no `main` blocks. All initial seeds were rejected as irrelevant and the campaign exited with an empty corpus. Enabling SVF indirect-call edges and forcing initial-seed admission resolved this: the final linked manifest selected 13,686/51,635 blocks, including 52 `main` blocks and 3 target blocks. The 30-second CLI pilot recorded 1,584 selected edge entries and 820 child executions; no reach or trigger event was observed. Its initial replay and campaign canary records are under `magma/work/selectfuzz/TIF006/out/`.

The two-seed fixture queue trace is `results/selectfuzz/fixture/queue_scores_forced.csv`. The target-reaching seed had distance 1, four novel selected edges, and queue score 5. The lesser seed had distance 2, no new selected edges, and score 0 after both were admitted. The trace contains two target-seed selections before the lesser-seed score was evaluated. This confirms the intended priority in the small program; corpus power metadata and elapsed annealing time can affect larger runs.

`scripts/test_selectfuzz_hard_fixture.sh` builds a separate eight-byte exact-match guard. Its manifest selected nine divergent guard blocks and the target block. A near-miss seed replayed without reaching the target. This checks that failure to hit a tight input constraint can coexist with a valid relevance set.

The first 60-row audit found seven PHP campaigns without linked SelectFuzz manifests. PHP links `php-fuzz-<entry>` before copying the binary to the fixed entry name; the original link filter matched only the copied name. Those row statuses were changed to `instrumentation_invalid`. The filter now matches the linked name and refuses to count a PHP campaign without a nonempty selected-block manifest. A small fixture linked as `php-fuzz-exif` confirmed that this name receives SelectFuzz instrumentation. All seven PHP rows were rebuilt and rerun; each now has a linked manifest, target blocks, and nonzero runtime probes.

Direct-call analysis selected only 22 and 6 blocks for TIF002 and TIF004, respectively, and their first pilots recorded no selected probes. Rebuilding with SVF indirect-call edges selected 15,541 and 15,539 blocks, including three target blocks each. Their 30-second `extendedcg` trials recorded 9,426,307 and 12,492,111 probes. SSL007 had the same zero-probe symptom: its SVF build selected 64,872/266,158 blocks. A 120-second `long` trial imported its 2,310 seeds, entered mutation, and recorded 5,866 reported executions and 5,761,743,553 probes.

The first 30-second OpenSSL pilots for SSL001, SSL002, SSL009, SSL016, and SSL020 ended during initial-seed import. Longer `complete` trials ran past their seed counts. SSL002 and SSL009 recorded canary triggers with replay witnesses. SSL002's saved crash input also replayed against the rebuilt binary with `SSL002_T=1`; the raw row is `magma/work/selectfuzz/SSL002/out/replay_saved_witness_complete.csv`. The workflow now checks that the peak reported executions exceeds the number of initial seed files before accepting a campaign.

PDF020 was built for the fixed `pdf_fuzzer` entry and fuzzed for 300 seconds. Its manifest contains 0 selected blocks out of 256,931, and no directed target call survived linking. The campaign reported 10,803 executions and 0 reach or trigger events. The row is `campaign_complete`; the absence of target feedback is recorded as an outcome, not used to skip the run.
