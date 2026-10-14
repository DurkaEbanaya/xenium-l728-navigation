#!/usr/bin/env python3
"""One targeted lock/hold/release/unlock sequence for the screen variant."""
import json
import struct
import argparse
from pathlib import Path
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_PC, UC_ARM_REG_LR, UC_ARM_REG_SP

ROOT = Path(__file__).resolve().parents[1]
STATE, LOCK = 0x81704114, 0x81708030


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--no-flash", action="store_true")
    args = parser.parse_args()
    folder = ROOT / ("experimental/sos-no-flash" if args.no_flash else "experimental/sos-screen")
    report = json.loads((folder / "manifest.json").read_text())
    emu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    for address, size in ((0x88000000, 0x800000), (0x81704000, 0x2000),
                          (0x81708000, 0x2000), (0x100000, 0x10000)):
        emu.mem_map(address, size)
    emu.mem_write(0x88000000, (folder / "l728-user-sos-CANDIDATE.bin").read_bytes())
    present, guard, light, lcd = False, False, True, True
    effects = []
    # Run actual lock/close/mode, close-all-light and wake wrapper code;
    # model only external windows, hardware and service/NV boundaries.
    zeros = {0x88091be0, 0x88091c00, 0x880915e8, 0x8871644e,
             0x881878d4, 0x881aed72, 0x881e74c4, 0x880be5fa,
             0x881abd60, 0x881765f4, 0x882fdb14, 0x8809e4ec, 0x880a0744,
             0x881aeeec, 0x8831ba74, 0x8831bab6, 0x88091a70, 0x881764f6}
    def intercept(uc, address, size, data):
        nonlocal present, light, lcd
        r0, r1 = uc.reg_read(UC_ARM_REG_R0), uc.reg_read(UC_ARM_REG_R1)
        if address == 0x100100:
            uc.emu_stop()
            return
        result = 0
        if address == 0x881768e6:
            # Model the already proven input service waking on every SOS
            # event, to catch release/hold accidentally leaving light on.
            light = lcd = True
            effects.append("input-wake")
            uc.mem_write(STATE + 0x24, struct.pack("<I", 0))
        elif address == 0x8809df7e:
            result = int(present and r0 == 0x52)
        elif address == 0x881c59cc:
            result = int(guard)
        elif address == 0x8809d2f4:
            present = True
            effects.append("lock")
            result = 1
        elif address == 0x8834d13a:
            present = False
            effects.append("unlock")
            result = 1
        elif address == 0x881ee570:
            light = bool(r0)
            effects.append("light-on" if light else "light-off")
        elif address == 0x881ede98:
            assert r0 == 0
            # Stock CloseAllLight calls LCD_SetSleep(..., 1); wake uses 0.
            lcd = not bool(r1)
            effects.append("lcd-on" if lcd else "lcd-off")
        elif address in (0x881edebe, 0x881ee3a0):
            assert r0 == 1, "Wake must enable the backlight"
            light = True
        elif address == 0x881766bc:
            # This state-machine has hardware/window dependencies. Its normal
            # wake restores LCD, then the real 88176886 enables backlight.
            lcd = True
            uc.mem_write(STATE + 0x24, struct.pack("<I", 0))
            effects.append("wake-lcd")
        elif address == 0x881e687e:
            uc.mem_write(r0, bytes(12))
        elif address not in zeros:
            raise AssertionError(hex(address))
        assert uc.reg_read(UC_ARM_REG_SP) % 8 == 0
        uc.reg_write(UC_ARM_REG_R0, result)
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
    addresses = zeros | {0x100100, 0x881768e6, 0x8809df7e, 0x881c59cc,
        0x8809d2f4, 0x8834d13a, 0x881ee570, 0x881ede98, 0x881edebe, 0x881ee3a0,
        0x881766bc, 0x881e687e}
    for a in addresses:
        emu.hook_add(UC_HOOK_CODE, intercept, begin=a, end=a)
    def event(event_class):
        uc = emu
        uc.reg_write(UC_ARM_REG_R0, event_class)
        uc.reg_write(UC_ARM_REG_R1, 0x64)
        uc.reg_write(UC_ARM_REG_SP, 0x10f000)
        uc.reg_write(UC_ARM_REG_LR, 0x100101)
        uc.emu_start(report["symbols"]["sos_wrapper"], 0, count=2000)
        assert uc.reg_read(UC_ARM_REG_PC) == 0x100100
        assert uc.reg_read(UC_ARM_REG_SP) == 0x10f000
    emu.mem_write(LOCK + 8, struct.pack("<I", 2))
    for cls in (0xfa00, 0xfc00, 0xfe00, 0xfd00):
        previous_wakes = effects.count("input-wake")
        event(cls)
        assert present and not light and not lcd, (hex(cls), present, light, lcd, effects)
        if args.no_flash and cls != 0xfa00:
            assert effects.count("input-wake") == previous_wakes, "Trailing event must not wake even briefly"
    if args.no_flash:
        previous_wakes = effects.count("input-wake")
        event(0xfb00)
        assert effects.count("input-wake") == previous_wakes and not light and not lcd
    assert effects.count("lock") == 1 and "unlock" not in effects
    event(0xfa00)
    assert not present and light and lcd
    event(0xfb00)
    assert not present and light and lcd
    assert effects.count("unlock") == 1
    guard = True
    event(0xfa00)
    assert not present and light and lcd, "Refused lock must not blank screen"
    present = True
    emu.mem_write(LOCK + 8, struct.pack("<I", 3))
    event(0xfa00)
    assert present and light and lcd, "Preview must remain untouched"
    print("PASS: targeted lock -> screen off -> hold/release stays off -> unlock/wake; refused lock and preview unchanged")
    print("LCD/power boundaries modeled; this offline check is separate from recorded owner testing.")


if __name__ == "__main__":
    main()
