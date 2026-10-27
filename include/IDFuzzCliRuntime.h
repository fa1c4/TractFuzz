#ifndef IDFUZZ_CLI_RUNTIME_H
#define IDFUZZ_CLI_RUNTIME_H
#include <stdint.h>
#define IDFUZZ_CLI_MAP_SIZE 2621440u
#define IDFUZZ_CLI_TARGETS_SIZE 256u
#define IDFUZZ_CLI_DOM_SIZE 256u
#define IDFUZZ_CLI_SHM_ENV "IDFUZZ_CLI_SHM"
typedef struct {
  uint8_t edges[IDFUZZ_CLI_MAP_SIZE];
  uint64_t distance_sum;
  uint64_t distance_count;
  uint8_t targets[IDFUZZ_CLI_TARGETS_SIZE];
  uint64_t executions;
  uint8_t dominators[IDFUZZ_CLI_DOM_SIZE];
} IDFuzzCliShared;
#endif
