#ifndef SELECTFUZZ_CLI_RUNTIME_H
#define SELECTFUZZ_CLI_RUNTIME_H
#include <stdint.h>

#define SELECTFUZZ_CLI_MAP_SIZE 2621440u
#define SELECTFUZZ_CLI_TARGETS_SIZE 256u
#define SELECTFUZZ_CLI_SHM_ENV "SELECTFUZZ_CLI_SHM"

typedef struct {
  uint8_t edges[SELECTFUZZ_CLI_MAP_SIZE];
  uint64_t min_distance;
  uint64_t reserved;
  uint8_t targets[SELECTFUZZ_CLI_TARGETS_SIZE];
  uint64_t executions;
} SelectFuzzCliShared;
#endif
