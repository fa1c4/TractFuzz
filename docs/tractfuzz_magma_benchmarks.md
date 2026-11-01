# TractFuzz Magma Benchmark: 50 Observed-Reachable + 10 Reachability-Unknown Bug IDs

**List frozen:** 2026-10-27. **Experimental unit:** one fixed Magma entry point (harness/program) per unique bug ID. The 60 IDs below are distinct and cover all 9 projects and 21 entry points in our Magma v1.2.1 inventory. Every baseline and TractFuzz should use the same listed entry point for a given ID in the primary comparison.

## Evidence and labels

- **Observed reachable (50):** the selected entry–bug pair has at least one recorded reach in the public [*In Bugs We Trust?* Magma v1.2.0 data](https://github.com/ardier/in_bugs_we_trust). This is experimental evidence of a reaching input in that configuration; it is not a proof that every path is satisfiable, nor a replay on our v1.2.1 binaries. See the local [pair audit](../exploration/magma_pairs_audit.csv) and [classification table](../exploration/magma_338_constraint_classes.csv).
- **Reachability unknown (10):** no positive reach observation for the bug ID appears in our v1.2.0 pair audit, and none of these ten IDs has a positive entry in the consulted [Lyso Table 2](https://www.usenix.org/system/files/usenixsecurity25-bao-andrew.pdf) or [PBFuzz Tables 2/8](https://arxiv.org/pdf/2512.04611). The current v1.2.1 ELF contains a canary reference for each selected entry. “Unknown” means evidence is missing, **not** that the bug is unreachable or unsatisfiable. The literature check is limited to these sources and should be refreshed before publication.
- **Static column:** `direct_call_candidate_path` means only that a static candidate call chain was recovered. `canary_function_reference_only` means the canary was found, but this analysis did not recover a direct call chain. Neither label establishes a complete entry-to-bug constraint formula or solver tractability.
- The IDs and entries are fixed for this benchmark. Before measuring fuzzers, rebuild and replay on one pinned Magma revision and record any evidence-driven status correction. Keep such corrections in the results; do not silently replace cases after seeing fuzzer performance.

## A. 50 observed-reachable bug IDs

All 50 rows have a reach observation in the cited Magma v1.2.0 data for the **specified** entry point.

| # | Project | Bug ID | Fixed entry point | Local canary predicate class | Static call evidence |
| ---: | --- | --- | --- | --- | --- |
| 1 | libpng | `PNG001` | `libpng_read_fuzzer` | `OVERFLOW` | `direct_call_candidate_path` |
| 2 | libpng | `PNG003` | `libpng_read_fuzzer` | `NUM_BOUND` | `direct_call_candidate_path` |
| 3 | libpng | `PNG005` | `libpng_read_fuzzer` | `OFFSET_SPAN` | `direct_call_candidate_path` |
| 4 | libpng | `PNG006` | `libpng_read_fuzzer` | `STATE_FLAG` | `direct_call_candidate_path` |
| 5 | libpng | `PNG007` | `libpng_read_fuzzer` | `NULLNESS` | `direct_call_candidate_path` |
| 6 | libsndfile | `SND001` | `sndfile_fuzzer` | `NUM_BOUND` | `direct_call_candidate_path` |
| 7 | libsndfile | `SND006` | `sndfile_fuzzer` | `NUM_BOUND` | `canary_function_reference_only` |
| 8 | libsndfile | `SND016` | `sndfile_fuzzer` | `NUM_BOUND` | `direct_call_candidate_path` |
| 9 | libsndfile | `SND017` | `sndfile_fuzzer` | `NUM_BOUND` | `direct_call_candidate_path` |
| 10 | libsndfile | `SND020` | `sndfile_fuzzer` | `NUM_BOUND` | `direct_call_candidate_path` |
| 11 | libtiff | `TIF001` | `tiff_read_rgba_fuzzer` | `MODULAR` | `canary_function_reference_only` |
| 12 | libtiff | `TIF002` | `tiff_read_rgba_fuzzer` | `NUM_BOUND` | `canary_function_reference_only` |
| 13 | libtiff | `TIF006` | `tiffcp` | `STATE_FLAG` | `canary_function_reference_only` |
| 14 | libtiff | `TIF009` | `tiffcp` | `NULLNESS` | `direct_call_candidate_path` |
| 15 | libtiff | `TIF012` | `tiff_read_rgba_fuzzer` | `NULLNESS` | `canary_function_reference_only` |
| 16 | libtiff | `TIF014` | `tiffcp` | `OFFSET_SPAN` | `direct_call_candidate_path` |
| 17 | libxml2 | `XML001` | `xmllint` | `OFFSET_SPAN` | `direct_call_candidate_path` |
| 18 | libxml2 | `XML002` | `libxml2_xml_read_memory_fuzzer` | `CONST` | `direct_call_candidate_path` |
| 19 | libxml2 | `XML003` | `libxml2_xml_read_memory_fuzzer` | `STATE_FLAG` | `direct_call_candidate_path` |
| 20 | libxml2 | `XML009` | `xmllint` | `NUM_BOUND` | `direct_call_candidate_path` |
| 21 | libxml2 | `XML017` | `libxml2_xml_read_memory_fuzzer` | `BYTE_TEXT` | `direct_call_candidate_path` |
| 22 | lua | `LUA002` | `lua` | `NULLNESS` | `direct_call_candidate_path` |
| 23 | lua | `LUA004` | `lua` | `CALL_RESULT` | `direct_call_candidate_path` |
| 24 | openssl | `SSL001` | `asn1` | `NUM_BOUND` | `direct_call_candidate_path` |
| 25 | openssl | `SSL002` | `client` | `OFFSET_SPAN` | `canary_function_reference_only` |
| 26 | openssl | `SSL009` | `x509` | `NULLNESS` | `canary_function_reference_only` |
| 27 | openssl | `SSL010` | `bignum` | `OVERFLOW` | `direct_call_candidate_path` |
| 28 | openssl | `SSL016` | `client` | `BYTE_TEXT` | `canary_function_reference_only` |
| 29 | openssl | `SSL020` | `server` | `CALL_RESULT` | `canary_function_reference_only` |
| 30 | php | `PHP002` | `exif` | `OVERFLOW` | `canary_function_reference_only` |
| 31 | php | `PHP004` | `exif` | `OFFSET_SPAN` | `canary_function_reference_only` |
| 32 | php | `PHP009` | `exif` | `OFFSET_SPAN` | `canary_function_reference_only` |
| 33 | php | `PHP011` | `exif` | `OVERFLOW` | `canary_function_reference_only` |
| 34 | poppler | `PDF002` | `pdfimages` | `CALL_RESULT` | `canary_function_reference_only` |
| 35 | poppler | `PDF003` | `pdfimages` | `NULLNESS` | `canary_function_reference_only` |
| 36 | poppler | `PDF006` | `pdftoppm` | `OFFSET_SPAN` | `canary_function_reference_only` |
| 37 | poppler | `PDF009` | `pdf_fuzzer` | `OVERFLOW` | `direct_call_candidate_path` |
| 38 | poppler | `PDF010` | `pdf_fuzzer` | `NULLNESS` | `canary_function_reference_only` |
| 39 | poppler | `PDF011` | `pdftoppm` | `NUM_BOUND` | `direct_call_candidate_path` |
| 40 | poppler | `PDF012` | `pdfimages` | `OVERFLOW` | `direct_call_candidate_path` |
| 41 | poppler | `PDF018` | `pdf_fuzzer` | `NULLNESS` | `canary_function_reference_only` |
| 42 | poppler | `PDF019` | `pdftoppm` | `OFFSET_SPAN` | `canary_function_reference_only` |
| 43 | poppler | `PDF021` | `pdfimages` | `NUM_BOUND` | `canary_function_reference_only` |
| 44 | sqlite3 | `SQL002` | `sqlite3_fuzz` | `STATE_FLAG` | `canary_function_reference_only` |
| 45 | sqlite3 | `SQL003` | `sqlite3_fuzz` | `STATE_FLAG` | `direct_call_candidate_path` |
| 46 | sqlite3 | `SQL010` | `sqlite3_fuzz` | `ALIAS_IDENTITY` | `direct_call_candidate_path` |
| 47 | sqlite3 | `SQL012` | `sqlite3_fuzz` | `STATE_FLAG` | `direct_call_candidate_path` |
| 48 | sqlite3 | `SQL013` | `sqlite3_fuzz` | `NUM_BOUND` | `direct_call_candidate_path` |
| 49 | sqlite3 | `SQL014` | `sqlite3_fuzz` | `STATE_FLAG` | `direct_call_candidate_path` |
| 50 | sqlite3 | `SQL020` | `sqlite3_fuzz` | `NULLNESS` | `direct_call_candidate_path` |

## B. 10 reachability-unknown bug IDs

These cases have no positive reach observation in the evidence set above. Each selected canary is present in the local v1.2.1 ELF. Do not count a timeout as proof of unreachability.

| # | Project | Bug ID | Fixed entry point | Local canary predicate class | Static call evidence |
| ---: | --- | --- | --- | --- | --- |
| 51 | libsndfile | `SND004` | `sndfile_fuzzer` | `NUM_BOUND` | `direct_call_candidate_path` |
| 52 | libsndfile | `SND014` | `sndfile_fuzzer` | `FLOAT_SPECIAL` | `canary_function_reference_only` |
| 53 | libtiff | `TIF004` | `tiff_read_rgba_fuzzer` | `STATE_FLAG` | `canary_function_reference_only` |
| 54 | libxml2 | `XML005` | `xmllint` | `OVERFLOW` | `canary_function_reference_only` |
| 55 | openssl | `SSL007` | `client` | `OVERFLOW` | `canary_function_reference_only` |
| 56 | openssl | `SSL011` | `asn1parse` | `NULLNESS` | `canary_function_reference_only` |
| 57 | poppler | `PDF020` | `pdf_fuzzer` | `OFFSET_SPAN` | `canary_function_reference_only` |
| 58 | php | `PHP006` | `json` | `NUM_BOUND` | `canary_function_reference_only` |
| 59 | php | `PHP007` | `unserialize` | `OFFSET_SPAN` | `canary_function_reference_only` |
| 60 | php | `PHP012` | `parser` | `NUM_BOUND` | `canary_function_reference_only` |

## C. Distribution by project

| Project | Observed reachable | Unknown | Total |
| --- | ---: | ---: | ---: |
| libpng | 5 | 0 | 5 |
| libsndfile | 5 | 2 | 7 |
| libtiff | 6 | 1 | 7 |
| libxml2 | 5 | 1 | 6 |
| lua | 2 | 0 | 2 |
| openssl | 6 | 2 | 8 |
| php | 4 | 3 | 7 |
| poppler | 10 | 1 | 11 |
| sqlite3 | 7 | 0 | 7 |
| **Total** | **50** | **10** | **60** |

## D. Rules for the paper's comparison

1. **One target definition per row.** Pin the Magma commit, bug patch, harness build, command-line arguments, initial corpus, instrumentation, and exact canary target location. A bug ID exercised through a different harness is a different experiment and must be reported separately.
2. **Common primary protocol.** The experimental target is to run TractFuzz and all seven planned baselines on these same 60 fixed rows, from the same starting corpus and under the same execution and wall-clock budgets. Count solver/preprocessing, training, LLM/API calls, build/analysis, and fuzzing costs separately; report end-to-end time as well. Do not supply a solver-generated witness to TractFuzz alone without counting its production time.
3. **Comparable outcomes.** Report target reach, canary trigger, and detected fault separately; retain per-run time-to-reach and time-to-exposure with timeouts as censored observations. A campaign may stop after its selected bug first triggers; reaching alone does not end it. The 24-hour fuzzing budget is a timeout, not a required runtime after exposure. Preserve the final Magma counters and replay any retained triggering input; distinguish an observed trigger without a replay witness from a confirmed witness. For the ten unknown cases, report discovered witnesses and replay evidence, but do not turn unsuccessful campaigns into “unreachable” labels.

   The evaluation scheduler keeps one bug per campaign and runs up to `--parallel-worker` campaigns from the current baseline arm. When a campaign ends, its CPU slot starts the next queued bug in that arm. The container baselines poll the selected Magma canary every 250 ms and record `first_reach_seconds`, `first_trigger_seconds`, `fuzz_elapsed_seconds`, and `stop_reason` in the per-bug status CSV. PBFuzz already stops its engine fuzz session when it triggers; its matrix records the engine's `fuzz_elapsed_seconds` and `stop_reason`. Its engine does not emit separate first-reach or first-trigger timestamps, so do not infer them from campaign completion time. `summary.csv` counts `early_stopped_rows` for each arm.
4. **Method applicability.** Record build failures and unsupported harnesses as such rather than as fuzzing timeouts. PBFuzz's published artifact has prepared material for only nine Magma bug IDs and its paper sometimes changes the harness; any custom-harness result belongs in a separate adaptation comparison. If a baseline cannot be run on all 60 under the fixed entries, publish the complete applicability matrix and use common supported subsets for pairwise comparisons.
5. **No outcome-based substitutions.** Keep the 60 IDs in this file even if a later replay changes a reachability label or a baseline cannot run. Document the correction, configuration, and reason. Analyze reachability strata and program projects separately, and include ablations for TractFuzz's prefix solving, constrained mutation, and difficulty estimate.

### Source notes

- The local [Magma study](../exploration/magma_study.md) documents the 361 initial pairs, 23 source-level exclusion candidates, and 338 retained pairs. Its 140 positive reaches are from v1.2.0 experiments; these are not v1.2.1 replay results.
- [Lyso's Magma evaluation](https://www.usenix.org/system/files/usenixsecurity25-bao-andrew.pdf) uses 62 entry–bug cases (45 distinct bug IDs). Published cases that triggered in its environment are not placed in the unknown group.
- [PBFuzz's Magma evaluation](https://arxiv.org/pdf/2512.04611) provides additional reach/trigger evidence. In particular, LUA001 and XML010 cannot be labeled unknown merely because the older local audit lacks a positive; PHP014 uses a different harness in PBFuzz and is not in this fixed-entry benchmark.
