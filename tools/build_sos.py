#!/usr/bin/env python3
"""Build SOS variants offline on v0.2.0; --no-flash reproduces release v0.3.0."""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import argparse

ROOT = Path(__file__).resolve().parents[1]
BASE = 0x88000000
VERIFIED = "011843e8608f8cd2da0e4f812554db6be59219109e844905ed347eb70a3554ed"
ENTRY = 0x6a2a84
PROLOGUE = bytes.fromhex("f0b58db00c462821")
VERIFIED_FINAL = "41aba70fd84346095a756ccc97dcbb33b23dcca4c9dba686351622c93f1a7f34"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    from elftools.elf.elffile import ELFFile

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--screen", action="store_true", help="build separate screen-off SOS variant")
    parser.add_argument("--no-flash", action="store_true", help="screen variant without release/hold wake flash")
    args = parser.parse_args()
    if args.no_flash:
        args.screen = True
    source = (ROOT / "experimental/l728-user-navigation-UNTESTED.bin").read_bytes()
    if sha(source) != VERIFIED or source[ENTRY:ENTRY + 8] != PROLOGUE:
        raise SystemExit("Expected the exact phone-tested v0.2.0 image and keypad entry")
    end = struct.unpack_from("<I", source, 0x30)[0] + 0x200
    payload_offset = (end + 15) & ~15
    if source[end:] != b"\xff" * (len(source) - end):
        raise SystemExit("Unexpected data after v0.2.0 payload")
    output = ROOT / ("experimental/sos-no-flash" if args.no_flash else "experimental/sos-screen" if args.screen else "experimental/sos")
    output.mkdir(exist_ok=True)
    elf, binary = output / "sos.elf", output / "sos.bin"
    subprocess.run([
        "clang", "--target=armv7a-none-eabi", "-mcpu=cortex-a7", "-mthumb",
        *(["-Wa,-defsym,SOS_SCREEN=1"] if args.screen else []),
        *(["-Wa,-defsym,SOS_NO_FLASH=1"] if args.no_flash else []),
        "-nostdlib", "-fuse-ld=lld", f"-Wl,-Ttext,{BASE + payload_offset:#x}",
        "-Wl,-e,sos_wrapper", str(ROOT / "tools/sos.s"), "-o", str(elf),
    ], check=True)
    subprocess.run(["objcopy", "-O", "binary", "-j", ".text", str(elf), str(binary)], check=True)
    io_elf = output / "sos-block-io.elf"
    subprocess.run([
        "clang", "--target=armv7a-none-eabi", "-mcpu=cortex-a7", "-mthumb", "-Oz",
        "-ffreestanding", "-fno-builtin", "-mno-unaligned-access", "-Wall", "-Wextra", "-Werror",
        "-nostdlib", "-fuse-ld=lld", "-DL728_SOS_TRANSITION=1",
        f"-Wl,-T,{ROOT / 'tools/l728-reader.ld'}", str(ROOT / "tools/l728-block-io.c"),
        str(ROOT / "tools/l728-reader.s"), "-o", str(io_elf),
    ], check=True)
    subprocess.run(["objcopy", "-O", "binary", str(io_elf), str(output / "sos-block-io.bin")], check=True)
    with elf.open("rb") as stream:
        symbols = {s.name: s["st_value"] for s in ELFFile(stream).get_section_by_name(".symtab").iter_symbols()}
    payload = binary.read_bytes()
    if payload_offset + len(payload) > len(source):
        raise SystemExit("SOS payload does not fit the existing final user page")
    patched = bytearray(source)
    patched[payload_offset:payload_offset + len(payload)] = payload
    struct.pack_into("<I", patched, 0x30, payload_offset + len(payload) - 0x200)
    # Aligned Thumb LDR.W PC, [PC, #0], followed by the Thumb target pointer.
    patched[ENTRY:ENTRY + 8] = bytes.fromhex("dff800f0") + struct.pack("<I", symbols["sos_wrapper"])
    pages = [p for p in range(len(source) // 2048)
             if source[p * 2048:(p + 1) * 2048] != patched[p * 2048:(p + 1) * 2048]]
    report = {
        "status": "OFFLINE BUILD ONLY; NOT A NAND WRITE PACKAGE; DO NOT FLASH",
        "safe_to_flash": False, "device_accessed": False, "device_write_performed": False,
        "source_sha256": VERIFIED, "output_sha256": sha(patched),
        "matches_phone_verified_image": sha(patched) == VERIFIED_FINAL,
        "historical_device_test": {
            "version": "v0.3.0", "image_sha256": VERIFIED_FINAL, "date": "2026-10-12",
            "scope": "One matching Philips Xenium L728; hardware ECC validation, per-block and seven-block final readback",
            "owner_feedback": "Да, работает всё что было задумано.",
        },
        "entry_offset": ENTRY, "entry_original_hex": PROLOGUE.hex(),
        "entry_patch_hex": patched[ENTRY:ENTRY + 8].hex(),
        "payload_offset": payload_offset, "payload_bytes": len(payload),
        "symbols": {k: v for k, v in symbols.items() if k in ("sos_wrapper", "original_key_entry")},
        "changed_pages": [{"user_page": p, "physical_page": 0x4f40 + p,
                           "block": (0x4f40 + p) // 64, "page_in_block": (0x4f40 + p) % 64}
                          for p in pages],
        "behavior": "logical 0x64: FA toggles ordinary lock; all five SOS classes bypass window/default dispatch",
        "screen_off_with_lock": args.screen,
        "suppress_locked_sos_trailing_wake": args.no_flash,
        "limitations": [
            "Recorded phone verification applies only to the final v0.3.0 image hash on one matching device",
            "This builder performs no device access; each installation needs current readback and hardware ECC validation",
            "Per-device NAND/OOB snapshots and rollback plans are private and are not distributed",
            "Default and --screen builds reproduce intermediate variants; use --no-flash for v0.3.0",
            "Original emergency SOS behavior is replaced; home-center-to-phonebook is not implemented",
        ],
    }
    (output / "l728-user-sos-CANDIDATE.bin").write_bytes(patched)
    (output / "manifest.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
