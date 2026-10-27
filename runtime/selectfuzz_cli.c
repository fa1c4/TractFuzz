#include "SelectFuzzCliRuntime.h"

#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static SelectFuzzCliShared fallback;
static SelectFuzzCliShared *shared;
static uint32_t previous;

static SelectFuzzCliShared *state(void) {
  if (shared) return shared;
  const char *path = getenv(SELECTFUZZ_CLI_SHM_ENV);
  if (!path || !*path) {
    fallback.min_distance = UINT64_MAX;
    shared = &fallback;
    return shared;
  }
  int fd = open(path, O_RDWR);
  if (fd < 0) _exit(77);
  struct stat st;
  if (fstat(fd, &st) != 0 || st.st_size < (off_t)sizeof(SelectFuzzCliShared))
    _exit(77);
  void *mapping = mmap(NULL, sizeof(SelectFuzzCliShared), PROT_READ | PROT_WRITE,
                       MAP_SHARED, fd, 0);
  close(fd);
  if (mapping == MAP_FAILED) _exit(77);
  shared = (SelectFuzzCliShared *)mapping;
  __sync_fetch_and_add(&shared->executions, 1);
  return shared;
}

__attribute__((constructor)) static void count_cli_execution(void) { (void)state(); }

void __selectfuzz_trace_bb(uint32_t id, uint64_t distance_milli) {
  if (!id) return;
  SelectFuzzCliShared *s = state();
  if (distance_milli && distance_milli < s->min_distance)
    s->min_distance = distance_milli;
  uint32_t rotated = (previous << 5) | (previous >> 27);
  size_t index = (rotated ^ (id * 0x9e3779b1u)) % SELECTFUZZ_CLI_MAP_SIZE;
  if (s->edges[index] != UINT8_MAX) ++s->edges[index];
  previous = id;
}

void __aflgo_trace_bb_target(uint32_t id) {
  if (id < SELECTFUZZ_CLI_TARGETS_SIZE) ++state()->targets[id];
}

// LLVM's comparison callbacks can survive other sanitizer passes in Magma.
void __sanitizer_cov_trace_cmp1(uint8_t a, uint8_t b) { (void)a; (void)b; }
void __sanitizer_cov_trace_cmp2(uint16_t a, uint16_t b) { (void)a; (void)b; }
void __sanitizer_cov_trace_cmp4(uint32_t a, uint32_t b) { (void)a; (void)b; }
void __sanitizer_cov_trace_cmp8(uint64_t a, uint64_t b) { (void)a; (void)b; }
void __sanitizer_cov_trace_const_cmp1(uint8_t a, uint8_t b) { (void)a; (void)b; }
void __sanitizer_cov_trace_const_cmp2(uint16_t a, uint16_t b) { (void)a; (void)b; }
void __sanitizer_cov_trace_const_cmp4(uint32_t a, uint32_t b) { (void)a; (void)b; }
void __sanitizer_cov_trace_const_cmp8(uint64_t a, uint64_t b) { (void)a; (void)b; }
void __sanitizer_cov_trace_switch(uint64_t value, uint64_t *cases) {
  (void)value; (void)cases;
}
