/* Positive-fixture roundtrips against Vere's unmodified pkg/ur serializer.
 * Input: <exact-bit-length> <canonical-jam-hex> per line. This driver compares
 * canonical output; it is not a hostile-input safety endorsement of libur. */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ur.h"

static int nibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  return -1;
}
static int check(char *line) {
  char *end;
  errno = 0;
  unsigned long long bits = strtoull(line, &end, 10);
  if (errno || end == line || *end != ' ' || bits == 0 || bits > 524288) return 0;
  char *hex = end + 1;
  size_t chars = strlen(hex);
  if (chars && hex[chars - 1] == '\n') hex[--chars] = 0;
  if (!chars || chars % 2 || chars / 2 != (bits + 7) / 8) return 0;
  size_t size = chars / 2;
  uint8_t *bytes = malloc(size);
  if (!bytes) return 0;
  for (size_t i = 0; i < size; ++i) {
    int a = nibble(hex[2 * i]), b = nibble(hex[2 * i + 1]);
    if (a < 0 || b < 0) { free(bytes); return 0; }
    bytes[i] = (uint8_t)((a << 4) | b);
  }
  ur_root_t *root = ur_root_init();
  ur_nref noun;
  int ok = ur_cue(root, size, bytes, &noun) == ur_cue_good;
  if (ok) {
    uint64_t size_out;
    uint8_t *out;
    uint64_t bits_out = ur_jam(root, noun, &size_out, &out);
    ok = bits_out == bits && size_out == size && memcmp(bytes, out, size) == 0;
    free(out);
  }
  ur_root_free(root);
  free(bytes);
  return ok;
}
int main(int argc, char **argv) {
  if (argc != 2) return 1;
  FILE *file = fopen(argv[1], "r");
  if (!file) return 1;
  char *line = NULL;
  size_t capacity = 0, count = 0;
  int ok = 1;
  while (getline(&line, &capacity, file) >= 0) {
    if (!check(line)) { ok = 0; break; }
    ++count;
  }
  if (ferror(file)) ok = 0;
  free(line);
  fclose(file);
  if (!ok || count == 0) return 1;
  printf("%zu Vere canonical noun cases passed\n", count);
  return 0;
}
