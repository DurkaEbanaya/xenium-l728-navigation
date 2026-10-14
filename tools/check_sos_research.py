#!/usr/bin/env python3
"""Offline trace checks for the stock SOS route; never accesses a phone.

Execute existing firmware, stopping at external side effects. Lock-window and
NV predicates are controlled stubs, so these checks do not prove live hardware
events or that calling a lock API from a new hook would be correct.
"""
import hashlib
from pathlib import Path
import struct

from unicorn import Uc, UcError, UC_ARCH_ARM, UC_HOOK_CODE, UC_MODE_THUMB
from unicorn.arm_const import (
    UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_LR,
    UC_ARM_REG_PC, UC_ARM_REG_SP,
)

ROOT = Path(__file__).resolve().parents[1]
SOURCE_SHA = "f4bae9cf5677e4e26bfe8718a81976a1b5bce6cbb6e1d0ae06a863bc029dc8a9"
STATE = 0x81704114
RETURN = 0x100100
SOS_SETTING = 0x881c219e
SOS_OPEN = 0x881c281c
KEY_DISPATCH = 0x886a2a84


def main():
    image = (ROOT / "backup/l728-user-ecc.bin").read_bytes()
    if hashlib.sha256(image).hexdigest() != SOURCE_SHA:
        raise SystemExit("Unsupported firmware image")
    emu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    emu.mem_map(0x88000000, 0x800000)
    emu.mem_write(0x88000000, image)
    emu.mem_map(0x81704000, 0x2000)
    emu.mem_map(0x81708000, 0x2000)
    emu.mem_map(0x100000, 0x10000)
    predicates = {}
    calls = []
    stopped = []
    arguments = []
    trace_dispatch = False
    recent = []
    def trace(uc, address, size, data):
        recent.append(hex(address))
        del recent[:-20]
    emu.hook_add(UC_HOOK_CODE, trace)

    def intercept(uc, address, size, data):
        if address == KEY_DISPATCH and trace_dispatch:
            return
        if address in (RETURN, SOS_OPEN, 0x8834ea36, KEY_DISPATCH):
            stopped.append(address)
            uc.emu_stop()
        elif address in predicates:
            calls.append(address)
            arguments.append((address, uc.reg_read(UC_ARM_REG_R0),
                              uc.reg_read(UC_ARM_REG_R1), uc.reg_read(UC_ARM_REG_R2)))
            response = predicates[address]
            uc.reg_write(UC_ARM_REG_R0, response(uc) if callable(response) else response)
            uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))

    boundaries = (RETURN, SOS_OPEN, 0x8834ea36, KEY_DISPATCH, SOS_SETTING,
                  0x88091be0, 0x880903ea, 0x881af488, 0x88176886, 0x88176472)
    for address in boundaries:
        emu.hook_add(UC_HOOK_CODE, intercept, begin=address, end=address)

    def run(entry, r0=0, r1=0, r2=0):
        calls.clear()
        arguments.clear()
        stopped.clear()
        emu.reg_write(UC_ARM_REG_R0, r0)
        emu.reg_write(UC_ARM_REG_R1, r1)
        emu.reg_write(UC_ARM_REG_R2, r2)
        emu.reg_write(UC_ARM_REG_SP, 0x10f000)
        emu.reg_write(UC_ARM_REG_LR, RETURN | 1)
        try:
            emu.emu_start(entry | 1, 0, count=2000)
        except UcError as exc:
            raise AssertionError((hex(entry), hex(emu.reg_read(UC_ARM_REG_PC)),
                                  [hex(address) for address in calls], recent)) from exc
        assert len(stopped) == 1, (hex(entry), stopped)
        if stopped == [RETURN]:
            assert emu.reg_read(UC_ARM_REG_SP) == 0x10f000
        return emu.reg_read(UC_ARM_REG_R0)

    mapping = image[0x3da8c2:0x3da8c2 + 0x69]
    remaps = dict(zip(image[0x3da92b:0x3da943:2], image[0x3da92c:0x3da943:2]))
    checks = 0
    for physical in range(256):
        physical_normalized = {0x24: 0x0a, 0x25: 0x0b, 0x66: 0x5f}.get(physical, physical)
        logical = next((i for i, key in enumerate(mapping) if key == physical_normalized), 0)
        expected = remaps.get(logical, logical)
        assert run(0x881771c0, physical) == expected, hex(physical)
        checks += 1
    assert run(0x881771c0, 0x27) == 0x64

    # Existing default-action dispatcher: FC64, not FA64/FB64/FD64, opens SOS.
    predicates.update({0x88091be0: 0, 0x880903ea: 0, SOS_SETTING: 1})
    for event in (0xfa64, 0xfb64, 0xfc63, 0xfc64, 0xfc65, 0xfd64, 0xfe64):
        run(0x88176e1a, event)
        assert stopped == ([SOS_OPEN] if event == 0xfc64 else [RETURN]), hex(event)
        assert (SOS_SETTING in calls) == (event == 0xfc64)
        checks += 1
    predicates[SOS_SETTING] = 0
    run(0x88176e1a, 0xfc64)
    assert stopped == [0x8834ea36], "Disabled SOS takes the existing alternate UI path"
    checks += 1

    # FC is a long-press timer event: the matching existing timer slot returns
    # its stored logical key; an unrelated timer must return zero.
    emu.mem_map(0x81911000, 0x2000)
    slots = 0x81911de0
    emu.mem_write(slots, bytes([1, 7, 0, 0x64, 0, 0, 0, 0]) + struct.pack("<I", 0))
    assert run(0x886a31f2, 7) == 0x64
    assert run(0x886a31f2, 8) == 0
    checks += 2
    run(0x886a2f1c, 7)
    assert stopped == [KEY_DISPATCH]
    assert emu.reg_read(UC_ARM_REG_R0) == 0xfc00
    assert emu.reg_read(UC_ARM_REG_R1) == 0x64
    assert emu.reg_read(UC_ARM_REG_SP) == 0x10f000
    run(0x886a2f1c, 8)
    assert stopped == [RETURN]
    checks += 2

    # Do not confuse the deferred lock request (byte +3) with the mode at +24
    # or the keypad-window predicate. Test both filters' actual return values.
    predicates.update({0x88176886: 0, 0x88176472: 0})
    for mode, enabled in ((0, 1), (1, 1), (2, 0)):
        emu.mem_write(STATE + 0x24, struct.pack("<I", mode))
        for locked in (0, 1):
            predicates[0x881af488] = locked
            for saved_gate in (0, 1):
                emu.mem_write(STATE + 2, bytes([saved_gate]))
                for event in (0xfa00, 0xfb00, 0xfc00, 0xfd00):
                    assert run(0x88177f5e, event, 0x64, 0x101000) == 0
                    expected = (1 if locked else saved_gate) if enabled else (
                        0 if event == 0xfa00 else saved_gate)
                    result = run(0x88177eee, event, 0x64)
                    assert result == expected, (mode, locked, saved_gate, hex(event), result, expected)
                    checks += 2

    # Actual immediate lock constructor and window close wrapper. Model only
    # external window/app guards; execute their internal mode changes.
    lock_state = 0x81708030
    external = {
        0x8809df7e: 0, 0x881c59cc: 0, 0x880be5fa: 0,
        0x8834d13a: 1, 0x881e74c4: 0, 0x881878d4: 0,
        0x881aed72: 0, 0x8809d2f4: 1, 0x8809e4de: 0,
        0x8871644e: 0, 0x886d1f9e: 0, 0x881766bc: 0,
        0x881763fe: 0,
    }
    predicates.update(external)
    for address in external:
        emu.hook_add(UC_HOOK_CODE, intercept, begin=address, end=address)
    for mode in (0, 1, 2, 3):
        emu.mem_write(lock_state, b"\x07\x08" + bytes(6) + struct.pack("<I", mode))
        assert run(0x881aedbe) == 1
        assert struct.unpack("<I", emu.mem_read(lock_state + 8, 4))[0] == 0
        assert emu.mem_read(lock_state + 12, 5) == bytes(5)
        opened = [args for args in arguments if args[0] == 0x8809d2f4]
        assert opened == [(0x8809d2f4, 0x887a6eec, 0, 0)], opened
        assert (0x8834d13a in calls) == (mode == 3)
        checks += 1
    for guard in (0x881c59cc, 0x880be5fa):
        predicates[guard] = 1
        assert run(0x881aedbe) == 0
        assert 0x8809d2f4 not in calls
        predicates[guard] = 0
        checks += 1
    for present in (0, 1):
        predicates[0x8809df7e] = present
        assert run(0x881aee4a) == 1
        closing = [args for args in arguments if args[0] == 0x8834d13a]
        assert closing == ([(0x8834d13a, 0x52, 0, 0)] if present else []), closing
        checks += 1
    emu.mem_write(lock_state + 8, struct.pack("<I", 2))
    predicates[0x8809df7e] = lambda uc: int(uc.reg_read(UC_ARM_REG_R0) == 0x52)
    assert run(0x881aedbe) == 1
    assert 0x8809d2f4 not in calls
    assert [(args[0], args[1]) for args in arguments if args[0] == 0x8809e4de] == [
        (0x8809e4de, 0x52)]
    assert struct.unpack("<I", emu.mem_read(lock_state + 8, 4))[0] == 0
    checks += 1

    # Real lock predicate distinguishes special window mode 3 from ordinary
    # keypad locking. Stub only the window-presence query for this check.
    del predicates[0x881af488]
    predicates[0x8809e51a] = 0
    emu.hook_add(UC_HOOK_CODE, intercept, begin=0x8809e51a, end=0x8809e51a)
    for present in (0, 1):
        predicates[0x8809e51a] = present
        for mode in (0, 1, 2, 3):
            emu.mem_write(lock_state + 8, struct.pack("<I", mode))
            assert run(0x881af488) == int(present and mode != 3)
            assert arguments[0][1] == 0x52
            checks += 1
    predicates[0x881af488] = 0

    # Window callback F022: timers are cancelled, mode becomes 2, and the
    # deferred-lock service is restarted except in special window mode 3.
    for mode in (0, 1, 2, 3):
        emu.mem_write(lock_state, b"\x07\x08" + bytes(6) + struct.pack("<I", mode))
        assert run(0x881af02c, 0x52, 0xf022) == 1
        assert emu.mem_read(lock_state, 2) == bytes(2)
        assert struct.unpack("<I", emu.mem_read(lock_state + 8, 4))[0] == (3 if mode == 3 else 2)
        cancelled = [args[1] for args in arguments if args[0] == 0x8871644e]
        assert cancelled == [8, 7], cancelled
        assert (0x881763fe in calls) == (mode != 3)
        checks += 1

    # A held key still owns its timer slot after FC. On release, the stock
    # cleanup returns the long-press flag and removes both timer/key state.
    for index in range(3):
        for long_press in (0, 1):
            emu.mem_write(slots, bytes(0x60))
            slot = slots + index * 12
            emu.mem_write(slot, bytes([1, 7, 1, 0x64, long_press, 0, 0, 0])
                          + struct.pack("<I", 0x10203040))
            emu.mem_write(slots + 0x29, bytes([index, 8, 1]))
            assert run(0x886a2bda, 0x64, 0x101000) == 1
            assert emu.mem_read(0x101000, 1) == bytes([long_press])
            assert emu.mem_read(slot, 5) == b"\x00\x07\x00\x00\x00"
            assert emu.mem_read(slots + 0x2b, 1) == b"\x00"
            assert struct.unpack("<I", emu.mem_read(slots + 0x24, 4))[0] == 0x10203040
            assert emu.mem_read(slots + 0x28, 1) == b"\x64"
            cancelled = [args[1] for args in arguments if args[0] == 0x8871644e]
            assert cancelled == [8, 7], cancelled
            checks += 1

    # The real hardware-message path admits one FA per occupied key slot.
    # Execute registration/release and timer callbacks, not a model of them.
    external = {0x8834cfaa: 0x52, 0x887161ac: 1, 0x88091c00: 0}
    predicates.update(external)
    for address in external:
        emu.hook_add(UC_HOOK_CODE, intercept, begin=address, end=address)
    signal = 0x102000
    for index in range(3):
        for held in (False, True):
            emu.mem_write(slots, bytes(0x60))
            for i in range(3):
                emu.mem_write(slots + 12 * i + 1, bytes([i + 1]))
                if i != index:
                    emu.mem_write(slots + 12 * i, b"\x01")
                    emu.mem_write(slots + 12 * i + 3, bytes([8 + i]))
            emu.mem_write(slots + 0x2a, b"\x09")
            emu.mem_write(signal, struct.pack("<I", 0x201) + bytes(12) + struct.pack("<I", 0x27))
            run(0x886a2d08, signal)
            assert stopped == [KEY_DISPATCH]
            assert emu.reg_read(UC_ARM_REG_R0) == 0xfa00
            assert emu.reg_read(UC_ARM_REG_R1) == 0x64
            assert emu.mem_read(slots + 12 * index, 5) == bytes([1, index + 1, 1, 0x64, 0])
            # Ten repeated hardware downs cannot reach the common dispatcher.
            for _ in range(10):
                run(0x886a2d08, signal)
                assert stopped == [RETURN]
            if held:
                run(0x886a2f1c, index + 1)
                assert stopped == [KEY_DISPATCH]
                assert emu.reg_read(UC_ARM_REG_R0) == 0xfc00
                for _ in range(3):
                    run(0x886a2f4c)
                    assert stopped == [KEY_DISPATCH]
                    assert emu.reg_read(UC_ARM_REG_R0) == 0xfe00
            emu.mem_write(signal, struct.pack("<I", 0x202))
            run(0x886a2d08, signal)
            assert stopped == [KEY_DISPATCH]
            assert emu.reg_read(UC_ARM_REG_R0) == (0xfd00 if held else 0xfb00)
            assert emu.mem_read(slots + 12 * index, 1) == b"\x00"
            emu.mem_write(signal, struct.pack("<I", 0x201))
            run(0x886a2d08, signal)
            assert stopped == [KEY_DISPATCH]
            assert emu.reg_read(UC_ARM_REG_R0) == 0xfa00
            checks += 1

    # The lock-window callback returns zero for these SOS events without opening
    # SOS itself. Default dispatch still depends on the caller and input gates.
    for mode in (0, 1, 2, 3):
        for event in (0xfa64, 0xfb64, 0xfc64, 0xfd64, 0xfe64):
            emu.mem_write(lock_state, bytes(8) + struct.pack("<I", mode))
            assert run(0x881af02c, 0x52, event) == 0
            assert stopped == [RETURN]
            assert SOS_SETTING not in calls
            checks += 1

    # Trace the complete stock entry up to the window-dispatch boundary, not
    # just two individual filters. A hook here sees SOS before either gate.
    trace_dispatch = True
    external = {0x88091c18: 0, 0x88091c00: 0, 0x88177fd8: 0,
                0x881a6878: 0, 0x8831238a: 0, 0x88031f7e: 0,
                0x881dcd20: 0, 0x886a2a30: 0, 0x880a0a00: 1}
    predicates.update(external)
    for address in external:
        emu.hook_add(UC_HOOK_CODE, intercept, begin=address, end=address)
    for mode in (0, 1, 2):
        for locked in (0, 1):
            predicates[0x881af488] = locked
            for event in (0xfa00, 0xfb00, 0xfc00, 0xfd00, 0xfe00):
                emu.mem_write(STATE + 0x24, struct.pack("<I", mode))
                emu.mem_write(STATE + 2, bytes([0]))
                assert run(KEY_DISPATCH, event, 0x64) == 1
                dispatched = [args for args in arguments if args[0] == 0x880a0a00]
                # Record the caller's actual decision under these predicates.
                expected_dispatch = mode in (0, 1) and (locked or event == 0xfa00)
                assert bool(dispatched) == expected_dispatch, (
                    mode, locked, hex(event), dispatched)
                if dispatched:
                    assert dispatched[0][1] == event + 0x64
                checks += 1
    print(f"PASS: {checks} stock firmware trace checks (offline, controlled predicates)")
    print("Physical-code 0x27 -> logical 0x64; default FC64 -> SOS setting -> SOS window.")
    print("Immediate lock/close paths, F022 cleanup, release timers and upstream dispatch checked.")
    print("No live key capture, new lock/unlock patch, or device writes performed.")


if __name__ == "__main__":
    main()
