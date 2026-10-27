#ifndef HALO_CLI_RUNTIME_H
#define HALO_CLI_RUNTIME_H

#include <stdint.h>

#define HALO_CLI_MAP_SIZE 2621440u
#define HALO_CLI_TARGETS_SIZE 256u
#define HALO_CLI_SHM_ENV "HALO_CLI_SHM"

typedef struct {
  uint8_t edges[HALO_CLI_MAP_SIZE];
  uint64_t distance_sum;
  uint64_t distance_count;
  uint8_t targets[HALO_CLI_TARGETS_SIZE];
  uint64_t executions;
} HaloCliShared;

#endif
