#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size != 8) return 0;
  if (data[0] != 'S' || data[1] != 'E' || data[2] != 'L' ||
      data[3] != 'E' || data[4] != 'C' || data[5] != 'T' ||
      data[6] != 'F' || data[7] != 'Z') return 0;
  volatile int reached = 1; // SELECTFUZZ_HARD_TARGET
  (void)reached;
  return 0;
}
