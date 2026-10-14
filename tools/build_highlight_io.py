#!/usr/bin/env python3
"""Reuse the verified NAND protocol with an explicit highlight-only allowlist."""
from pathlib import Path
import hashlib
import json
import subprocess
import struct

ROOT = Path(__file__).resolve().parents[1]
FOLDER = ROOT / "experimental/highlight"
READ = (0x13d, 0x13f, 0x143, 0x145, 0x14c, 0x155, 0x172, 0x173, 0x17a, 0x17c)
WRITE = (0x13d, 0x13f, 0x14c, 0x155, 0x173, 0x17c)


def main():
    existing = None
    if (FOLDER / "transition/plan.json").exists():
        from highlight_transition import configure
        transition = configure()
        existing, _, _ = transition.load()
        if existing["hardware_validated"]:
            raise RuntimeError("Do not rebuild a hardware-validated helper")
    source = (ROOT / "tools/l728-block-io.c").read_text()
    begin = source.index("static int allowed(unsigned block, unsigned operation) {")
    end = source.index("\nvoid helper(void)", begin)
    original = source[begin:end]
    if original.count("#ifdef L728_SOS_TRANSITION") != 1 or original.count("#endif") != 1:
        raise RuntimeError("Unexpected shared IO source")
    expression = lambda blocks: " || ".join(f"block == {b:#x}" for b in blocks)
    replacement = ("static int allowed(unsigned block, unsigned operation) {\n"
                   f"    if (operation) return {expression(WRITE)};\n"
                   f"    return {expression(READ)};\n}}\n")
    generated = source[:begin] + replacement + source[end:]
    path = FOLDER / "highlight-block-io.c"
    path.write_text(generated)
    elf = FOLDER / "highlight-block-io.elf"
    subprocess.run(["clang", "--target=armv7a-none-eabi", "-mcpu=cortex-a7",
        "-mthumb", "-Oz", "-ffreestanding", "-fno-builtin", "-mno-unaligned-access",
        "-mfpu=none", "-mfloat-abi=soft", "-nostdlib", "-fuse-ld=lld",
        f"-Wl,-T,{ROOT / 'tools/l728-reader.ld'}", str(path),
        str(ROOT / "tools/l728-reader.s"), "-o", str(elf)], check=True)
    if struct.unpack_from("<I", elf.read_bytes(), 24)[0] != 0x10000:
        raise RuntimeError("Incorrect helper ELF entry")
    binary = FOLDER / "highlight-block-io.bin"
    subprocess.run(["objcopy", "-O", "binary", "-j", ".text", str(elf), str(binary)], check=True)
    if binary.stat().st_size > 0x1000:
        raise RuntimeError("IO helper crosses control mailbox at 0x11000")
    code = binary.read_bytes()
    if code[:0x200] != bytes(0x200) or code[0x200:0x208] != bytes.fromhex("00c09fe51cff2fe1"):
        raise RuntimeError("Missing FDL +0x200 ARM-to-Thumb entry stub")
    helper = struct.unpack_from("<I", code, 0x208)[0]
    if not helper & 1 or not 0x1020c <= (helper & ~1) < 0x10000 + len(code):
        raise RuntimeError("Incorrect Thumb helper entry")
    (FOLDER / "io-manifest.json").write_text(json.dumps({
        "shared_source_sha256": hashlib.sha256(source.encode()).hexdigest(),
        "generated_source_sha256": hashlib.sha256(generated.encode()).hexdigest(),
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "fdl_execution_address": 0x10200,
        "read_blocks": READ, "write_blocks": WRITE}, indent=2)+"\n")
    if existing:
        # Update only the helper pin in an offline/unvalidated plan. Candidate
        # NAND bytes, before/after hashes and rollback stay unchanged and are
        # rechecked by load(); a fresh device validation is mandatory.
        existing["helpers_sha256"] = transition.helpers()
        transition.previous.save(FOLDER / "transition/plan.json", existing)
        transition.load()
    print("Built highlight IO helper: six writable blocks, ten readable footprint blocks.")


if __name__ == "__main__":
    main()
