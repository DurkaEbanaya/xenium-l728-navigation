#!/usr/bin/env python3
"""Exercise transition validation/refusal/rollback using simulated FDL boundaries.

Calls the real package logic and exact prepared blobs. No USB is accessed.
"""
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import sos_transition as transition
from l728_ecc import encode_page


def main():
    plan, before, data = transition.load()
    writes, checkpoints, reads = [], [], []
    current = dict(before)

    def read_matching(block, choices, work, folder):
        reads.append(block)
        if current[block] not in choices:
            raise RuntimeError("Injected current NAND mismatch")
        return current[block]

    def write_block(block, source, work):
        assert block in transition.CHANGES
        writes.append(block)
        current[block] = source.read_bytes()

    def ram(packed, helper, work):
        if str(helper) == str(transition.previous.ENCODE):
            return b"".join(encode_page(packed[i:i + 2112]) for i in range(0, len(packed), 2112))
        # Modeled decoder restores only the deliberately injected validation
        # errors; real hardware correction is required by --validate-device.
        for block in transition.ORDER:
            target = data[block, "after"]
            page = target[transition.CHANGES[block][0] * 2112:(transition.CHANGES[block][0] + 1) * 2112]
            damaged = bytearray(page)
            damaged[123] ^= 1
            damaged[1147] ^= 1
            if packed == damaged:
                return page
        return packed

    def save(path, value):
        checkpoints.append(value)

    def reset():
        writes.clear()
        checkpoints.clear()
        reads.clear()
        current.clear()
        current.update(before)

    def refused(action, work):
        try:
            transition.operate(action, work)
        except RuntimeError:
            assert not writes
            return
        raise AssertionError("Expected fail-closed transition")

    with TemporaryDirectory(dir="/tmp/opencode", prefix="l728-sos-test-") as temporary:
        work = Path(temporary)
        with patch.object(transition, "load", lambda: (plan, before, data)), \
             patch.object(transition.io, "read_matching", read_matching), \
             patch.object(transition.io, "write_block", write_block), \
             patch.object(transition.previous, "ram", ram), \
             patch.object(transition.previous, "save", save), \
             patch.object(transition.previous, "durable_blob", lambda *args: None):
            plan["hardware_validated"] = False
            refused("apply", work)
            transition.operate("validate-device", work)
            assert not writes and plan["hardware_validated"]
            assert set(reads) == set(before)
            reset()
            current[0x172] = bytes(64 * 2112)
            refused("apply", work)
            reset()
            with patch.object(transition.previous, "ram", lambda *args: b"bad"):
                refused("apply", work)
            reset()
            transition.operate("apply", work)
            assert writes == transition.ORDER
            assert set(reads) == set(before)
            assert checkpoints[-1]["records"][-1] == {"completed": True}
            for block in transition.ORDER:
                assert current[block] == data[block, "after"]
            # Second apply is idempotent, all current blocks already target.
            writes.clear()
            transition.operate("apply", work)
            assert not writes
            # Rollback recovers a partially erased allowed block, restores the
            # exact installed version, and never touches the other four blocks.
            current[0x172] = bytes(64 * 2112)
            transition.operate("restore", work)
            assert writes == transition.ORDER
            assert current == before
            reset()
            current[0x143] = bytes(64 * 2112)
            refused("restore", work)
            # Incomplete apply can resume: target code exists, entry/header old.
            reset()
            current[0x17c] = data[0x17c, "after"]
            transition.operate("apply", work)
            assert writes == [0x172, 0x13d]
    print("PASS: validation/refusal, all-block preflight, ECC failure, write order, idempotence, damaged rollback and resume")
    print("Simulated FDL only; no device access or NAND writes.")


if __name__ == "__main__":
    main()
