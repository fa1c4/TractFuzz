#ifndef BEACON_CLI_RUNTIME_H
#define BEACON_CLI_RUNTIME_H

#include <stdint.h>

#define BEACON_CLI_MAP_SIZE 2621440u
#define BEACON_CLI_TARGETS_SIZE 256u
#define BEACON_CLI_SHM_ENV "BEACON_CLI_SHM"

typedef struct {
  uint8_t edges[BEACON_CLI_MAP_SIZE];
  uint64_t distance_sum;
  uint64_t distance_count;
  uint8_t targets[BEACON_CLI_TARGETS_SIZE];
  uint64_t executions;
} BeaconCliShared;

#endif
