#include <stdio.h>
#include <stdint.h>
int main(int argc, char **argv) {
  if (argc != 2) return 2;
  FILE *f = fopen(argv[1], "rb");
  if (!f) return 2;
  uint8_t data[1024] = {0};
  size_t n = fread(data, 1, sizeof(data), f);
  fclose(f);
  if (n >= 4 && data[0] == 'I' && data[1] == 'D') {
    if (data[2] == 'F' && data[3] == '!') {
      volatile int target_marker = 1;
      return target_marker;
    }
  }
  return 0;
}
