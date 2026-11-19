#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build -p mesa-ffi
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
