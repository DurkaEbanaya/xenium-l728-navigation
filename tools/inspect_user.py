#!/usr/bin/env python3
"""Print Thumb disassembly and literal-pointer references from the L728 dump."""
import argparse
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN

parser = argparse.ArgumentParser()
parser.add_argument("image", type=Path)
parser.add_argument("address", type=lambda x: int(x, 0))
parser.add_argument("--base", type=lambda x: int(x, 0), default=0x88000000)
parser.add_argument("--size", type=lambda x: int(x, 0), default=0x200)
parser.add_argument("--refs", action="store_true")
parser.add_argument("--arm", action="store_true", help="decode ARM rather than Thumb instructions")
args = parser.parse_args()
data = args.image.read_bytes()
if args.refs:
    needle = struct.pack("<I", args.address)
    offset = 0
    while (offset := data.find(needle, offset)) >= 0:
        print(f"pointer at file +0x{offset:x}, mapped 0x{args.base + offset:08x}")
        offset += 1
else:
    offset = args.address - args.base
    if not 0 <= offset < len(data):
        parser.error("address outside image")
    mode = CS_MODE_ARM if args.arm else CS_MODE_THUMB
    decoder = Cs(CS_ARCH_ARM, mode | CS_MODE_LITTLE_ENDIAN)
    for ins in decoder.disasm(data[offset:offset + args.size], args.address):
        print(f"{ins.address:08x}: {ins.bytes.hex():10} {ins.mnemonic:8} {ins.op_str}")
