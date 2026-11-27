#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
key_flags=()
if [[ "${MESA_SUITE_C:-0}" == 1 ]]; then
  cargo build -p mesa-ffi --features suite-c
  key_flags+=(-DMESA_TEST_SUITE_C)
else
  cargo build -p mesa-ffi
fi
target_dir="${CARGO_TARGET_DIR:-target}"
libs=(-lpthread -ldl -lm)
if [[ $(uname -s) == Darwin ]]; then libs+=(-framework Security -framework CoreFoundation -liconv); fi
"${CC:-cc}" -std=c11 -Wall -Wextra -Werror \
  -I crates/mesa-ffi/include crates/mesa-ffi/tests/smoke.c \
  "$target_dir/debug/libmesa_ffi.a" "${libs[@]}" -o "$target_dir/mesa-ffi-smoke"
"$target_dir/mesa-ffi-smoke"
echo 'C ABI smoke test passed'

"${CC:-cc}" -std=c11 -Wall -Wextra -Werror \
  -I crates/mesa-ffi/include crates/mesa-ffi/tests/embedding.c \
  "$target_dir/debug/libmesa_ffi.a" "${libs[@]}" -o "$target_dir/mesa-ffi-embedding"
"$target_dir/mesa-ffi-embedding"

"${CC:-cc}" -std=c11 -Wall -Wextra -Werror \
  -I crates/mesa-ffi/include crates/mesa-ffi/tests/raw_udp.c \
  "$target_dir/debug/libmesa_ffi.a" "${libs[@]}" -o "$target_dir/mesa-ffi-raw-udp"
"$target_dir/mesa-ffi-raw-udp" 16

"${CC:-cc}" -std=c11 -Wall -Wextra -Werror \
  -I crates/mesa-ffi/include crates/mesa-ffi/tests/pki.c \
  "$target_dir/debug/libmesa_ffi.a" "${libs[@]}" -o "$target_dir/mesa-ffi-pki"
"$target_dir/mesa-ffi-pki"

"${CC:-cc}" -std=c11 -Wall -Wextra -Werror \
  "${key_flags[@]}" -I crates/mesa-ffi/include crates/mesa-ffi/tests/keys.c \
  "$target_dir/debug/libmesa_ffi.a" "${libs[@]}" -o "$target_dir/mesa-ffi-keys"
"$target_dir/mesa-ffi-keys"

"${CC:-cc}" -std=c11 -Wall -Wextra -Werror -DMESA_TEST_MESA \
  -I crates/mesa-ffi/include crates/mesa-ffi/tests/raw_udp.c \
  "$target_dir/debug/libmesa_ffi.a" "${libs[@]}" -o "$target_dir/mesa-ffi-mesa-udp"
"$target_dir/mesa-ffi-mesa-udp" 16
