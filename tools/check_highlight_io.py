#!/usr/bin/env python3
"""Execute the actual FDL +0x200 entry; check every block/op before MMIO."""
from pathlib import Path
import struct
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_MEM_WRITE
from unicorn.arm_const import UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC
from build_highlight_io import READ, WRITE


def main():
    code = (Path(__file__).resolve().parents[1] /
            "experimental/highlight/highlight-block-io.bin").read_bytes()
    assert len(code) < 0x1000 and code[:0x200] == bytes(0x200)
    count = 0
    for op in (0, 1, 2):
        for block in (*sorted(set(READ) | set(WRITE)), 0, 0x1c6, 0x200):
            for magic in (0x4c373238, 0):
                uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
                for address, size in ((0x10000,0x2000),(0x20000,0x1000),
                                      (0x30000,0x1000),(0x21500000,0x1000)):
                    uc.mem_map(address, size)
                uc.mem_write(0x10000, code)
                uc.mem_write(0x11000, struct.pack("<9I",magic,op,block,0,0,0,0,0,0))
                uc.reg_write(UC_ARM_REG_SP,0x30800)
                uc.reg_write(UC_ARM_REG_LR,0x20000)
                mmio = []
                def first_mmio(u, access, address, size, value, data):
                    mmio.append((address,value))
                    u.emu_stop()
                uc.hook_add(UC_HOOK_MEM_WRITE, first_mmio, begin=0x21500000,end=0x21500fff)
                uc.emu_start(0x10200,0x20000,count=10000)
                allowed = magic == 0x4c373238 and op in (0,1) and block in (WRITE if op else READ)
                if allowed:
                    assert mmio == [(0x21500060,0x308)], (op,block,mmio)
                else:
                    assert not mmio and uc.reg_read(UC_ARM_REG_PC)==0x20000
                    assert struct.unpack("<I",uc.mem_read(0x11010,4))[0]==1
                count += 1
    print(f"PASS: {count} cases from real FDL entry 0x10200; allowed operations reach initialization; others return before MMIO")


if __name__ == "__main__":
    main()
