#!/usr/bin/env python3
"""Emulate ARM wrapper code and check offline-image edit boundaries."""
import hashlib
import json
import struct
from pathlib import Path

from unicorn import Uc, UC_ARCH_ARM, UC_HOOK_CODE, UC_MODE_THUMB
from unicorn.arm_const import (
    UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
    UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
    UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11,
    UC_ARM_REG_LR, UC_ARM_REG_SP, UC_ARM_REG_PC,
)

ROOT = Path(__file__).resolve().parents[1]
report = json.loads((ROOT / "experimental/manifest.json").read_text())
original = (ROOT / "backup/l728-user-ecc.bin").read_bytes()
patched = (ROOT / "experimental/l728-user-navigation-UNTESTED.bin").read_bytes()
assert hashlib.sha256(original).hexdigest() == report["source_sha256"]
assert hashlib.sha256(patched).hexdigest() == report["output_sha256"]
allowed = set(range(0x30, 0x34))
for edit in report["callbacks"]:
    allowed.update(range(int(edit["offset"], 0), int(edit["offset"], 0) + 4))
meaningful = struct.unpack_from("<I", original, 0x30)[0] + 0x200
changed = {i for i in range(meaningful) if original[i] != patched[i]}
assert changed <= allowed, "Unexpected changes to original firmware"
assert len(patched) == len(original), "Patch must fit within original final page"
assert patched[meaningful:int(report["payload_offset"], 0)] == b"\xff" * 16

mapping = {0xfa09: 0xfa01, 0xfa0b: 0xfa03, 0xfa0d: 0xfa04, 0xfa0f: 0xfa02}
registers = [UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
             UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
             UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11]
emu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
emu.mem_map(0x88000000, 0x800000)
emu.mem_write(0x88000000, patched)
emu.mem_map(0x100000, 0x10000)
events = list(range(0xf000, 0xff00)) + [0, 1, 2, 0xffffffff]
checks = 0
for edit in report["callbacks"]:
    if edit["wrapper"] in ("contact_wrapper", "search_contact_wrapper"):
        continue
    target = int(edit["old"], 0) & ~1
    seen = []
    def stop(uc, address, size, user_data):
        seen.append(address)
        uc.emu_stop()
    hook = emu.hook_add(UC_HOOK_CODE, stop, begin=target, end=target)
    for event in events:
        expected = [0x10203040 + i * 0x100 for i in range(12)]
        expected[1] = event
        for reg, value in zip(registers, expected):
            emu.reg_write(reg, value)
        emu.reg_write(UC_ARM_REG_SP, 0x10f000)
        emu.reg_write(UC_ARM_REG_LR, 0x100101)
        seen.clear()
        emu.emu_start(int(edit["new"], 0), 0, count=50)
        assert seen == [target], (edit["wrapper"], hex(event), seen)
        expected[1] = mapping.get(event, event)
        assert [emu.reg_read(r) for r in registers] == expected
        assert emu.reg_read(UC_ARM_REG_SP) == 0x10f000
        assert emu.reg_read(UC_ARM_REG_LR) == 0x100101
        checks += 1
    emu.hook_del(hook)

# Stub only the firmware focus/query APIs. Execute the real wrapper code.
# Deliberately clobber volatile registers like an ordinary firmware call.
window = 0x10203040
controls = {0x000d006f: 0x103000, 0x000d0078: 0x104000,
            0x000d00b8: 0x105000, 0x000d00b3: 0x106000}
queries = []
def api(uc, address, size, user_data):
    assert uc.reg_read(UC_ARM_REG_R0) == window
    assert uc.reg_read(UC_ARM_REG_SP) % 8 == 0
    if address == 0x881ecd64:
        result = 1
        focused.append(uc.reg_read(UC_ARM_REG_R1))
    else:
        control_id = uc.reg_read(UC_ARM_REG_R1)
        assert control_id in controls
        result = available.get(control_id, 0)
        queries.append(control_id)
    uc.reg_write(UC_ARM_REG_R0, result)
    for reg in (UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3):
        uc.reg_write(reg, 0xabcdef01)
    uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))

api_hooks = [emu.hook_add(UC_HOOK_CODE, api, begin=a, end=a)
             for a in (0x881ecd64, 0x881ecba8)]
for edit in report["callbacks"]:
    if edit["wrapper"] not in ("contact_wrapper", "search_contact_wrapper"):
        continue
    target = int(edit["old"], 0) & ~1
    seen = []
    hook = emu.hook_add(UC_HOOK_CODE, stop, begin=target, end=target)
    list_ids = ((0x000d006f, 0x000d0078) if edit["wrapper"] == "contact_wrapper"
                else (0x000d00b8,))
    for available in (controls, {0x000d0078: controls[0x000d0078]}, {}):
        chosen = next((available[i] for i in list_ids if i in available), 0)
        for event in events:
            expected = [0x10203040 + i * 0x100 for i in range(12)]
            expected[1] = event
            for reg, value in zip(registers, expected):
                emu.reg_write(reg, value)
            emu.reg_write(UC_ARM_REG_SP, 0x10f000)
            emu.reg_write(UC_ARM_REG_LR, 0x100101)
            seen.clear()
            queries.clear()
            focused = []
            emu.emu_start(int(edit["new"], 0), 0, count=100)
            assert seen == [target], (edit["wrapper"], hex(event), seen)
            if chosen:
                expected[1] = mapping.get(event, event)
            assert [emu.reg_read(r) for r in registers] == expected
            assert emu.reg_read(UC_ARM_REG_SP) == 0x10f000
            assert emu.reg_read(UC_ARM_REG_LR) == 0x100101
            if event not in mapping:
                assert not queries, "Non-navigation events must not query controls"
            assert focused == ([chosen] if event in mapping and chosen else [])
            checks += 1
    emu.hook_del(hook)
for hook in api_hooks:
    emu.hook_del(hook)
print(f"PASS: {checks} emulated wrapper calls; register preservation, event mapping, edit boundaries")
print("This verifies machine code only, not phone UI, boot acceptance or NAND writing.")
