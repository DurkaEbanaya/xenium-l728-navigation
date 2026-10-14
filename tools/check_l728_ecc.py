#!/usr/bin/env python3
"""Cross-check software BCH against private corrected and BootROM-encoded data."""
from pathlib import Path
import hashlib
import random
import json

from l728_ecc import GENERATOR, parity, validate_block

ROOT = Path(__file__).resolve().parents[1]


def reference(main):
    value = int.from_bytes(main, "little") << 168
    while value.bit_length() > 168:
        value ^= GENERATOR << (value.bit_length() - 169)
    return value.to_bytes(21, "big")


def main():
    raw = (ROOT / "backup/l728-nand-ecc.raw").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == "76aef2f60b8f64610012f43dadd49f638d3ea2b727a2c413de45fa5df00b8326"
    files = sorted((ROOT / "experimental/blocks").glob("*.raw"))
    files += sorted((ROOT / "experimental/keyboard-transition").glob("block-*.raw"))
    count, discrepancies = 0, 0
    for path in files:
        if "mismatch" in path.name:
            continue
        # The stock hardware decoder corrected main bytes but retained some
        # one-bit errors in parity OOB. These snapshots are not strict codewords.
        discrepancies += len(validate_block(path.read_bytes(), parity_error_limit=12))
        count += 128
    # Changed pages have fresh hardware-generated ECC and must match exactly.
    plan = json.loads((ROOT / "experimental/keyboard-transition/plan.json").read_text())
    generated = 0
    for entry in plan["blocks"]:
        data = (ROOT / "experimental/keyboard-transition" / entry["after_file"]).read_bytes()
        for page in entry["pages"]:
            for sector in (0, 1):
                main = data[page * 2112 + sector * 1024:page * 2112 + (sector + 1) * 1024]
                ecc = data[page * 2112 + 2048 + sector * 32 + 4:page * 2112 + 2048 + sector * 32 + 25]
                assert parity(main) == ecc
                generated += 1
    # Corrected pages spanning all NAND regions, independent of the images
    # used to infer the generator and byte order.
    rng = random.Random(728)
    for block in rng.sample(range(1024), 64):
        discrepancies += len(validate_block(raw[block * 64 * 2112:(block + 1) * 64 * 2112], parity_error_limit=12))
        count += 128
    for i in range(32):
        main = bytes(rng.randrange(256) for _ in range(1024))
        expected = reference(main)
        assert parity(main) == expected
        changed = bytearray(main)
        changed[i * 17] ^= 1
        assert parity(changed) != expected
    print(f"PASS: {count} snapshot/random NAND sectors; {generated} freshly hardware-encoded sectors exact; 32 independent divisions")
    print(f"Retained stock parity-OOB bit discrepancies: {discrepancies} sectors (at most 12 bits each).")
    print("Parity verification only; pre-write hardware decode remains required.")


if __name__ == "__main__":
    main()
