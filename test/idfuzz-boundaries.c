#include <stddef.h>
#include <stdint.h>
extern void __aflgo_trace_bb_target(uint32_t);

static void chosen(const uint8_t *p, size_t n) {
  if (n > 0 && p[0] == 'K') __aflgo_trace_bb_target(1);
}
#if defined(IDFUZZ_MULTISITE)
static void alternate(const uint8_t *p, size_t n) {
  if (n > 1 && p[1] == 'Z') __aflgo_trace_bb_target(1);
}
#endif
#if defined(IDFUZZ_TERMINAL)
static int terminal_target(void) {
  __aflgo_trace_bb_target(1);
  return 1;
}
#endif
int LLVMFuzzerTestOneInput(const uint8_t *p, size_t n) {
#if defined(IDFUZZ_TERMINAL)
  if (n > 0 && p[0] == 'K') {
    return terminal_target();
  }
#elif defined(IDFUZZ_INDIRECT)
  void (*volatile call)(const uint8_t *, size_t) = chosen;
  call(p, n);
#elif defined(IDFUZZ_MULTISITE)
  chosen(p, n);
  alternate(p, n);
#elif defined(IDFUZZ_TAIL)
  if (n > 1050 && p[1050] == 'K') __aflgo_trace_bb_target(1);
#elif defined(IDFUZZ_MANY)
  for (int i = 0; i < 17; ++i) {
    switch (i) {
      case 0: __aflgo_trace_bb_target(0); break;
      case 1: __aflgo_trace_bb_target(1); break;
      case 2: __aflgo_trace_bb_target(2); break;
      case 3: __aflgo_trace_bb_target(3); break;
      case 4: __aflgo_trace_bb_target(4); break;
      case 5: __aflgo_trace_bb_target(5); break;
      case 6: __aflgo_trace_bb_target(6); break;
      case 7: __aflgo_trace_bb_target(7); break;
      case 8: __aflgo_trace_bb_target(8); break;
      case 9: __aflgo_trace_bb_target(9); break;
      case 10: __aflgo_trace_bb_target(10); break;
      case 11: __aflgo_trace_bb_target(11); break;
      case 12: __aflgo_trace_bb_target(12); break;
      case 13: __aflgo_trace_bb_target(13); break;
      case 14: __aflgo_trace_bb_target(14); break;
      case 15: __aflgo_trace_bb_target(15); break;
      case 16: __aflgo_trace_bb_target(16); break;
    }
  }
#else
  chosen(p, n);
#endif
  return 0;
}
