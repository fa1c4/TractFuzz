#include "BeaconCliRuntime.h"

#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static BeaconCliShared fallback;
static BeaconCliShared *shared;
static uint32_t next_guard = 1;

static BeaconCliShared *state(void) {
  if (shared)
    return shared;
  const char *path = getenv(BEACON_CLI_SHM_ENV);
  if (!path || !*path) {
    shared = &fallback;
    return shared;
  }
  int fd = open(path, O_RDWR);
  if (fd < 0)
    _exit(77);
  struct stat st;
  if (fstat(fd, &st) != 0 || st.st_size < (off_t)sizeof(BeaconCliShared))
    _exit(77);
  void *mapping = mmap(NULL, sizeof(BeaconCliShared), PROT_READ | PROT_WRITE,
                       MAP_SHARED, fd, 0);
  close(fd);
  if (mapping == MAP_FAILED)
    _exit(77);
  shared = (BeaconCliShared *)mapping;
  __sync_fetch_and_add(&shared->executions, 1);
  return shared;
}

void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop) {
  if (start == stop || *start)
    return;
  for (uint32_t *guard = start; guard < stop; ++guard) {
    uint32_t id = __sync_fetch_and_add(&next_guard, 1);
    *guard = id % (BEACON_CLI_MAP_SIZE - 1) + 1;
  }
}

void __sanitizer_cov_trace_pc_guard(uint32_t *guard) {
  uint32_t id = *guard;
  if (id)
    ++state()->edges[id];
}

void __aflgo_trace_bb_distance(uint64_t distance) {
  __sync_fetch_and_add(&state()->distance_sum, distance);
  __sync_fetch_and_add(&state()->distance_count, 1);
}

void __aflgo_trace_bb_target(uint32_t id) {
  if (id < BEACON_CLI_TARGETS_SIZE)
    ++state()->targets[id];
}

void __aflgo_trace_fun_distance(double distance) { (void)distance; }
int __beacon_should_prune(uint32_t id) {
  (void)id;
  return 0;
}

void __sanitizer_cov_trace_cmp1(uint8_t a, uint8_t b) { (void)a; (void)b; }
void __sanitizer_cov_trace_cmp2(uint16_t a, uint16_t b) { (void)a; (void)b; }
void __sanitizer_cov_trace_cmp4(uint32_t a, uint32_t b) { (void)a; (void)b; }
void __sanitizer_cov_trace_cmp8(uint64_t a, uint64_t b) { (void)a; (void)b; }
void __sanitizer_cov_trace_const_cmp1(uint8_t a, uint8_t b) { (void)a; (void)b; }
void __sanitizer_cov_trace_const_cmp2(uint16_t a, uint16_t b) { (void)a; (void)b; }
void __sanitizer_cov_trace_const_cmp4(uint32_t a, uint32_t b) { (void)a; (void)b; }
void __sanitizer_cov_trace_const_cmp8(uint64_t a, uint64_t b) { (void)a; (void)b; }
void __sanitizer_cov_trace_switch(uint64_t value, uint64_t *cases) {
  (void)value;
  (void)cases;
}
