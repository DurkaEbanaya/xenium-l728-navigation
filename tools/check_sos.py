#!/usr/bin/env python3
"""Execute the candidate hook and real hardware-slot lifecycle offline.

Window presence and external services are controlled boundaries. This is not
phone validation. In particular the power controller is not emulated.
"""
import hashlib
import json
from pathlib import Path
import struct

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn.arm_const import (
    UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
    UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
    UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11,
    UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC,
)

ROOT = Path(__file__).resolve().parents[1]
REGS = [UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
        UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
        UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11]
ENTRY, RESUME, RETURN = 0x886a2a84, 0x886a2a8c, 0x100100
SLOTS, SIGNAL, LOCK = 0x81911de0, 0x102000, 0x81708030


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    folder = ROOT / "experimental/sos"
    report = json.loads((folder / "manifest.json").read_text())
    source = (ROOT / "experimental/l728-user-navigation-UNTESTED.bin").read_bytes()
    candidate = (folder / "l728-user-sos-CANDIDATE.bin").read_bytes()
    assert sha(source) == report["source_sha256"]
    assert sha(candidate) == report["output_sha256"]
    assert not report["safe_to_flash"] and not report["device_write_performed"]
    assert len(source) == len(candidate)
    start = report["payload_offset"]
    allowed = set(range(0x30, 0x34)) | set(range(0x6a2a84, 0x6a2a8c)) | set(range(start, start + report["payload_bytes"]))
    assert all(a == b or i in allowed for i, (a, b) in enumerate(zip(source, candidate)))
    assert candidate[0x6a2a84:0x6a2a8c].hex() == report["entry_patch_hex"]
    emu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    for address, size in ((0x88000000, 0x800000), (0x81704000, 0x2000),
                          (0x81708000, 0x2000), (0x81911000, 0x2000), (0x100000, 0x10000)):
        emu.mem_map(address, size)
    emu.mem_write(0x88000000, candidate)
    calls, services, stopped, resumed = [], [], [], []
    present, mode, guard = False, 0, False
    through_resume = False
    real_service = False
    predicates = {
        0x88091c00: 0, 0x88091be0: 0, 0x8834cfaa: 0x52, 0x887161ac: 1,
        0x8871644e: 0, 0x881c59cc: 0, 0x880be5fa: 0,
        0x881878d4: 0, 0x881aed72: 0, 0x881e74c4: 0,
        0x886d1f9e: 0, 0x881766bc: 0, 0x881763fe: 0,
        0x881aeeec: 0,
    }

    def external(uc, address, size, data):
        nonlocal present
        if address == 0x881768e6 and real_service:
            return
        if address in (0x881c219e, 0x881c281c, 0x8834ea36, 0x880a0a00):
            raise AssertionError(f"Unexpected SOS/window/default side effect: {address:#x}")
        if address == RETURN:
            stopped.append("return")
            uc.emu_stop()
            return
        if address == RESUME:
            if not through_resume:
                stopped.append("original")
                uc.emu_stop()
            return
        args = tuple(uc.reg_read(r) for r in REGS[:4])
        if address == 0x881768e6:
            services.append(args[:2])
            result = 0  # A denied gate must not prevent the SOS toggle.
        elif address == 0x8809df7e:
            result = int(present) if args[0] == 0x52 else 0
        elif address == 0x881c59cc:
            result = int(guard)
        elif address == 0x8809d2f4:
            assert args[:2] == (0x887a6eec, 0)
            present = True
            calls.append("lock")
            result = 1
        elif address == 0x8834d13a:
            assert args[0] == 0x52
            calls.append("unlock")
            present = False
            # F022 cleanup was separately executed against stock firmware;
            # keep the manager boundary explicit rather than fake a full UI.
            result = 1
        elif address == 0x881aeeec:
            resumed.append(struct.unpack("<I", uc.mem_read(LOCK + 8, 4))[0])
            result = 0
        else:
            result = predicates[address]
        assert uc.reg_read(UC_ARM_REG_SP) % 8 == 0, hex(address)
        for reg in REGS[:4]:
            uc.reg_write(reg, 0xabcdef00)
        uc.reg_write(UC_ARM_REG_R0, result)
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))

    boundaries = set(predicates) | {RETURN, RESUME, 0x881768e6, 0x8809df7e,
        0x8809d2f4, 0x8834d13a, 0x881c219e, 0x881c281c, 0x8834ea36, 0x880a0a00}
    for address in boundaries:
        emu.hook_add(UC_HOOK_CODE, external, begin=address, end=address)

    def run(entry, r0, r1=0):
        stopped.clear()
        initial = [0x12340000 + i * 0x111 for i in range(12)]
        initial[:2] = [r0, r1]
        for reg, value in zip(REGS, initial):
            emu.reg_write(reg, value)
        emu.reg_write(UC_ARM_REG_SP, 0x10f000)
        emu.reg_write(UC_ARM_REG_LR, RETURN | 1)
        emu.emu_start(entry | 1, 0, count=3000)
        assert len(stopped) == 1, (hex(entry), stopped, hex(emu.reg_read(UC_ARM_REG_PC)))
        return initial

    checks = 0
    events = (0, 1, 0xf900, 0xfa00, 0xfb00, 0xfc00, 0xfd00, 0xfe00, 0xff00, 0xffffffff)
    for key in range(256):
        for event in events:
            present, guard, mode = False, False, 0
            emu.mem_write(LOCK + 8, struct.pack("<I", mode))
            calls.clear()
            services.clear()
            initial = run(ENTRY, event, key)
            handled = key == 0x64 and event in events[3:8]
            actual = [emu.reg_read(r) for r in REGS]
            if handled:
                assert stopped == ["return"]
                initial[0] = 1
                assert actual == initial
                assert emu.reg_read(UC_ARM_REG_SP) == 0x10f000
                assert emu.reg_read(UC_ARM_REG_LR) == RETURN | 1
                assert services == [(event, key)]
                assert calls == (["lock"] if event == 0xfa00 else [])
            else:
                assert stopped == ["original"]
                initial[4], initial[1] = key, 0x28
                assert actual == initial
                assert emu.reg_read(UC_ARM_REG_SP) == 0x10f000 - 0x48
                assert not calls and not services
                assert emu.mem_read(0x10f000 - 20, 20) == struct.pack("<5I", *[0x12340000 + i * 0x111 for i in range(4, 8)], RETURN | 1)
            checks += 1
    for present_before in (False, True):
        for mode in (0, 1, 2, 3):
            for guard in (False, True):
                present = present_before
                calls.clear()
                resumed.clear()
                emu.mem_write(LOCK + 8, struct.pack("<I", mode))
                run(ENTRY, 0xfa00, 0x64)
                expected = (["unlock"] if mode != 3 else []) if present_before else (
                    [] if guard else (["unlock", "lock"] if mode == 3 else ["lock"]))
                assert calls == expected, (present_before, mode, guard, calls)
                assert resumed == ([2] if present_before and mode != 3 else [])
                checks += 1

    # Real upstream hardware-message and timer functions, with the installed
    # entry detour. This is where duplicate-down prevention actually happens.
    for slot in range(3):
        for held in (False, True):
            present, mode, guard = False, 0, False
            emu.mem_write(LOCK + 8, struct.pack("<I", 0))
            emu.mem_write(SLOTS, bytes(0x60))
            for i in range(3):
                emu.mem_write(SLOTS + 12 * i + 1, bytes([i + 1]))
                if i != slot:
                    emu.mem_write(SLOTS + 12 * i, b"\x01")
                    emu.mem_write(SLOTS + 12 * i + 3, bytes([8 + i]))
            emu.mem_write(SLOTS + 0x2a, b"\x09")
            emu.mem_write(SIGNAL, struct.pack("<I", 0x201) + bytes(12) + struct.pack("<I", 0x27))
            calls.clear()
            services.clear()
            run(0x886a2d08, SIGNAL)
            assert calls == ["lock"]
            for _ in range(10):
                run(0x886a2d08, SIGNAL)
            assert calls == ["lock"] and services == [(0xfa00, 0x64)]
            if held:
                run(0x886a2f1c, slot + 1)
                for _ in range(20):
                    run(0x886a2f4c, 0)
                assert calls == ["lock"]
                assert services[-1] == (0xfe00, 0x64)
            emu.mem_write(SIGNAL, struct.pack("<I", 0x202))
            run(0x886a2d08, SIGNAL)
            assert services[-1] == (0xfd00 if held else 0xfb00, 0x64)
            assert emu.mem_read(SLOTS + slot * 12, 1) == b"\x00"
            assert emu.mem_read(SLOTS + 0x2b, 1) == b"\x00"
            assert calls == ["lock"]
            emu.mem_write(SIGNAL, struct.pack("<I", 0x201))
            run(0x886a2d08, SIGNAL)
            assert calls == ["lock", "unlock"]
            assert not present
            checks += 1
    # Execute the real entire input-service function rather than model its
    # return value. Stop only at external scheduler/window/power boundaries.
    extra = {0x88091c18: 0, 0x880903ea: 0, 0x88177fd8: 0,
             0x881a6878: 0, 0x8831238a: 0, 0x88031f7e: 0,
             0x881dcd20: 0, 0x88176886: 0, 0x88176472: 0,
             0x881af488: 0}
    predicates.update(extra)
    for address in extra:
        emu.hook_add(UC_HOOK_CODE, external, begin=address, end=address)
    real_service = True
    for power_mode in (0, 1, 2):
        for gate in (0, 1):
            predicates[0x881af488] = gate
            for event in (0xfa00, 0xfb00, 0xfc00, 0xfd00, 0xfe00):
                present, guard = False, False
                emu.mem_write(0x81704114 + 0x24, struct.pack("<I", power_mode))
                emu.mem_write(0x81704114 + 2, bytes([gate]))
                calls.clear()
                initial = run(ENTRY, event, 0x64)
                initial[0] = 1
                assert [emu.reg_read(r) for r in REGS] == initial
                assert calls == (["lock"] if event == 0xfa00 else [])
                assert stopped == ["return"]
                checks += 1
    real_service = False
    # Independently execute the SRAM helper's actual compiled rejection path.
    # Allowed commands stop at the first controller write; NAND is not modeled.
    helper = (folder / "sos-block-io.bin").read_bytes()
    guard_emu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    guard_emu.mem_map(0x10000, 0x10000)
    guard_emu.mem_map(0x21500000, 0x1000)
    guard_emu.mem_write(0x10000, helper)
    from unicorn import UC_HOOK_MEM_WRITE
    allowed_seen = []
    def stop_io(uc, access, address, size, value, user):
        allowed_seen.append(address)
        uc.emu_stop()
    guard_emu.hook_add(UC_HOOK_MEM_WRITE, stop_io, begin=0x21500060, end=0x21500063)
    def stop_guard(uc, address, size, user):
        uc.emu_stop()
    guard_emu.hook_add(UC_HOOK_CODE, stop_guard, begin=0x12000, end=0x12000)
    for operation in (0, 1, 2):
        for block in range(1024):
            guard_emu.mem_write(0x11000, struct.pack("<9I", 0x4c373238, operation, block, *([0] * 6)))
            guard_emu.reg_write(UC_ARM_REG_SP, 0x1f000)
            guard_emu.reg_write(UC_ARM_REG_LR, 0x12001)
            allowed_seen.clear()
            guard_emu.emu_start(0x10200, 0, count=1000)
            expected = (block in {0x13d, 0x143, 0x145, 0x14c, 0x172, 0x17a, 0x17c}
                        if operation == 0 else block in {0x13d, 0x172, 0x17c} if operation == 1 else False)
            assert bool(allowed_seen) == expected, (operation, block)
            if not expected:
                assert struct.unpack("<I", guard_emu.mem_read(0x11010, 4))[0] == 1
            checks += 1
    print(f"PASS: {checks} SOS candidate cases; detour, registers/stack, guards, real duplicate/hold/release paths")
    print("External input/window/power services stubbed; this check does not itself verify live behavior.")


if __name__ == "__main__":
    main()
