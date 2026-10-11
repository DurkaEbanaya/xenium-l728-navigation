#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="$root/build"
mkdir -p "$out"
cc="${CC:-clang}"
objcopy="${OBJCOPY:-objcopy}"
flags=(--target=armv7a-none-eabi -mcpu=cortex-a7 -mthumb -Oz
  -ffreestanding -fno-builtin -mno-unaligned-access -Wall -Wextra -Werror
  -nostdlib -fuse-ld=lld "-Wl,-T,$root/tools/l728-reader.ld")

for name in l728-diagnostic l728-encode l728-cache-test l728-block-io; do
  "$cc" "${flags[@]}" "$root/tools/$name.c" "$root/tools/l728-reader.s" \
    -o "$out/$name.elf"
  "$objcopy" -O binary "$out/$name.elf" "$out/$name.bin"
done

printf 'Built ARM helpers in %s\n' "$out"
