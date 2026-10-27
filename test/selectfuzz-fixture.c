#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 2) return 0;
  if (data[0] == 'A') {
    if (data[1] == 'Z') {
      volatile int reached = 1; // SELECTFUZZ_TARGET
      (void)reached;
    }
  }
  // These unrelated branches must not create selected coverage.
  if (data[0] == 'Q') {
    if (data[1] == 'X') return 17;
  }
  return 0;
}
