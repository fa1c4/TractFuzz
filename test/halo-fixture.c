#include <stddef.h>
#include <stdint.h>

extern void __aflgo_trace_bb_distance(uint64_t distance);
extern void __aflgo_trace_bb_target(uint32_t id);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 4) return 0;
  int equal = data[0] == 'H';
  int interval = data[1] >= 3 && data[1] <= 8;
  int linear = data[1] + data[2] == 20;
  uint64_t distance = (uint64_t)(!equal) * 40 +
                      (uint64_t)(!interval) * 20 +
                      (uint64_t)(!linear) * 10;
  __aflgo_trace_bb_distance(distance * 1000);
  if (equal && interval && linear) __aflgo_trace_bb_target(1);
  return 0;
}
