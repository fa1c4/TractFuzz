#include "IDFuzzCliRuntime.h"

#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static IDFuzzCliShared fallback;
static IDFuzzCliShared *shared;
static uint32_t next_guard = 1;

static IDFuzzCliShared *state(void) {
  if (shared)
    return shared;
  const char *path = getenv(IDFUZZ_CLI_SHM_ENV);
  if (!path || !*path) {
    shared = &fallback;
    return shared;
  }
  int fd = open(path, O_RDWR);
  if (fd < 0)
    _exit(77);
  struct stat st;
  if (fstat(fd, &st) != 0 || st.st_size < (off_t)sizeof(IDFuzzCliShared))
    _exit(77);
  void *mapping = mmap(NULL, sizeof(IDFuzzCliShared), PROT_READ | PROT_WRITE,
                       MAP_SHARED, fd, 0);
  close(fd);
  if (mapping == MAP_FAILED)
    _exit(77);
  shared = (IDFuzzCliShared *)mapping;
  __sync_fetch_and_add(&shared->executions, 1);
  return shared;
}

void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop) {
  if (start == stop || *start)
    return;
  for (uint32_t *guard = start; guard < stop; ++guard) {
    uint32_t id = __sync_fetch_and_add(&next_guard, 1);
    *guard = id % (IDFUZZ_CLI_MAP_SIZE - 1) + 1;
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
  if (id < IDFUZZ_CLI_TARGETS_SIZE)
    ++state()->targets[id];
}

void __aflgo_trace_fun_distance(double distance) { (void)distance; }

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

void __idfuzz_trace_dom(uint32_t id) {
  if (id < IDFUZZ_CLI_DOM_SIZE) state()->dominators[id] = 255;
}
void __idfuzz_trace_branch(uint32_t id, uint8_t value) {
  if (id < IDFUZZ_CLI_DOM_SIZE && value && !state()->dominators[id])
    state()->dominators[id] = value;
}
