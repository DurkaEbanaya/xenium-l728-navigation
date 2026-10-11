#!/usr/bin/env python3
"""Build an OFFLINE experimental image. Does not access USB or flash."""
import hashlib
import json
import struct
import subprocess
from pathlib import Path

from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
OUTPUT = ROOT / "experimental"
EXPECTED = "f4bae9cf5677e4e26bfe8718a81976a1b5bce6cbb6e1d0ae06a863bc029dc8a9"
BASE = 0x88000000
PAYLOAD = 0x7e13c0
CALLBACKS = [
    (0x1f29c8, 0x881f1fdb, "list_wrapper"),
    (0xce988, 0x880ce5d5, "icon_wrapper"),
    (0xd6f48, 0x880d6dab, "main_wrapper"),
    (0x110900, 0x881102d5, "matrix_wrapper"),
    (0x7b0b8c, 0x886bffcd, "contact_wrapper"),
    (0x7b0c28, 0x886bffcd, "contact_wrapper"),
    (0x7b09e4, 0x886c2ac3, "search_contact_wrapper"),
]

def main():
    original = (ROOT / "backup/l728-user-ecc.bin").read_bytes()
    if hashlib.sha256(original).hexdigest() != EXPECTED:
        raise SystemExit("Input firmware hash mismatch")
    if original[:8] != b"DHTB\x01\0\0\0":
        raise SystemExit("Unexpected DHTB header")
    for offset, expected, _ in CALLBACKS:
        if struct.unpack_from("<I", original, offset)[0] != expected:
            raise SystemExit(f"Callback mismatch at {offset:#x}")
    OUTPUT.mkdir(exist_ok=True)
    elf = OUTPUT / "navigation.elf"
    binary = OUTPUT / "navigation.bin"
    subprocess.run([
        "clang", "--target=armv7a-none-eabi", "-mcpu=cortex-a7", "-mthumb",
        "-nostdlib", "-fuse-ld=lld", f"-Wl,-T,{TOOLS / 'navigation.ld'}",
        str(TOOLS / "navigation.s"), "-o", str(elf),
    ], check=True)
    subprocess.run(["objcopy", "-O", "binary", str(elf), str(binary)], check=True)
    with elf.open("rb") as stream:
        table = ELFFile(stream).get_section_by_name(".symtab")
        symbols = {s.name: s["st_value"] for s in table.iter_symbols()}
    size = struct.unpack_from("<I", original, 0x30)[0]
    meaningful = size + 0x200
    if PAYLOAD < meaningful or any(x != 0xff for x in original[meaningful:]):
        raise SystemExit("Unexpected data after firmware payload")
    payload = binary.read_bytes()
    patched = bytearray(original[:meaningful])
    patched.extend(b"\xff" * (PAYLOAD - meaningful))
    patched.extend(payload)
    new_size = len(patched) - 0x200
    struct.pack_into("<I", patched, 0x30, new_size)
    edits = []
    for offset, old, name in CALLBACKS:
        new = symbols[name]
        if not BASE + PAYLOAD <= (new & ~1) < BASE + PAYLOAD + len(payload):
            raise SystemExit("Wrapper outside appended code")
        struct.pack_into("<I", patched, offset, new)
        edits.append({"offset": hex(offset), "old": hex(old), "new": hex(new), "wrapper": name})
    patched.extend(b"\xff" * (-len(patched) % 2048))
    (OUTPUT / "l728-user-navigation-UNTESTED.bin").write_bytes(patched)
    report = {
        "status": "OFFLINE ONLY; NOT VERIFIED ON PHONE; DO NOT FLASH",
        "source_sha256": EXPECTED,
        "output_sha256": hashlib.sha256(patched).hexdigest(),
        "mapping_base": hex(BASE), "payload_offset": hex(PAYLOAD),
        "old_dhtb_size": hex(size), "new_dhtb_size": hex(new_size),
        "callbacks": edits, "symbols": {k: hex(v) for k, v in symbols.items() if k.endswith("_wrapper") or k == "remap_event"},
        "limitations": [
            "DHTB signature/checksum acceptance and runtime mapping not yet verified",
            "Contact navigation forces list focus; actual UI routing still needs phone testing",
            "Only key-down events are remapped; long-press repeat is not added",
            "No NAND programming or FTL-aware restoration tool implemented",
        ],
    }
    (OUTPUT / "manifest.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main()
