#!/usr/bin/env python3
"""Prepare/verify/apply/restore the exact three-block L728 keyboard update.

Requires an already running FDL with DRAM/controller initialized. Preparation
reads NAND and encodes/decodes ECC in RAM; only --apply/--restore program NAND.
Rollback restores the previously working 2/4/6/8 patch, not stock firmware.
"""
import argparse
import json
import os
from pathlib import Path
import struct
import tempfile
import time

import navigation_blocks as io

ROOT = Path(__file__).resolve().parents[1]
OLD = "058b5cb1ce2bf985a218a9729d2adaeefe5006e8ad1ec3d396fad148e1737021"
NEW = "011843e8608f8cd2da0e4f812554db6be59219109e844905ed347eb70a3554ed"
RAW = "76aef2f60b8f64610012f43dadd49f638d3ea2b727a2c413de45fa5df00b8326"
STOCK = "f4bae9cf5677e4e26bfe8718a81976a1b5bce6cbb6e1d0ae06a863bc029dc8a9"
PAGE, MAIN, START = 2112, 2048, 0x4f40
CHANGES = {0x13d: [0], 0x17a: [33], 0x17c: [2]}
ORDER = [0x17c, 0x17a, 0x13d]
FOLDER = ROOT / "experimental/keyboard-transition"
io.IO = str(ROOT / "build/l728-block-io.bin")
io.CORRECT = str(ROOT / "build/l728-correct.bin")
ENCODE = ROOT / "build/l728-encode.bin"


def save(path, value):
    """Durable checkpoint before any destructive device operation."""
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w") as stream:
        stream.write(json.dumps(value, indent=2) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def blob(path, expected, size):
    content = path.read_bytes()
    if len(content) != size or io.sha(content) != expected:
        raise RuntimeError(f"Size/hash mismatch: {path}")
    return content


def legacy():
    directory = ROOT / "experimental/blocks"
    plan = json.loads((directory / "plan.json").read_text())
    if (plan["raw_sha256"], plan["original_user_sha256"], plan["modified_user_sha256"]) != (RAW, STOCK, OLD):
        raise RuntimeError("Unexpected legacy image identity")
    if (plan["page_main"], plan["page_oob"], plan["pages_per_block"], plan["physical_user_start_page"]) != (2048, 64, 64, START):
        raise RuntimeError("Unexpected legacy geometry")
    if len(plan["blocks"]) != 6 or {e["block"] for e in plan["blocks"]} != io.ALLOWED:
        raise RuntimeError("Unexpected legacy block allowlist")
    raw = blob(ROOT / "backup/l728-nand-ecc.raw", RAW, PAGE * 65536)
    stock = blob(ROOT / "backup/l728-user-ecc.bin", STOCK, 0x7e1800)
    candidate = blob(ROOT / "experimental/l728-user-navigation-UNTESTED.bin", NEW, len(stock))
    extracted = b"".join(raw[p * PAGE:p * PAGE + MAIN] for p in range(START, START + len(stock) // MAIN))
    if extracted != stock:
        raise RuntimeError("Logical/physical mapping mismatch")
    before = {}
    reconstructed = bytearray(stock)
    for entry in plan["blocks"]:
        block = entry["block"]
        for kind in ("original", "modified"):
            name = entry[f"{kind}_file"]
            if Path(name).name != name:
                raise RuntimeError("Legacy path outside plan")
            content = blob(directory / name, entry[f"{kind}_sha256"], io.BLOCK_BYTES)
            if kind == "original":
                if content != raw[block * io.BLOCK_BYTES:(block + 1) * io.BLOCK_BYTES]:
                    raise RuntimeError("Legacy original differs from NAND backup")
            else:
                before[block] = content
                for p in range(64):
                    logical = block * 64 + p - START
                    if 0 <= logical < len(stock) // MAIN:
                        reconstructed[logical * MAIN:(logical + 1) * MAIN] = content[p * PAGE:p * PAGE + MAIN]
    if io.sha(reconstructed) != OLD:
        raise RuntimeError("Legacy blocks do not reconstruct installed version")
    actual = {}
    for p in range(len(stock) // MAIN):
        if reconstructed[p * MAIN:(p + 1) * MAIN] != candidate[p * MAIN:(p + 1) * MAIN]:
            physical = START + p
            actual.setdefault(physical // 64, []).append(physical % 64)
    if actual != CHANGES:
        raise RuntimeError(f"Unexpected transition pages: {actual}")
    return before, candidate


def ram(packed, helper, work):
    if not packed or len(packed) % PAGE or len(packed) // PAGE > 128:
        raise RuntimeError("Invalid RAM ECC input")
    source, output, status = (work / n for n in ("input.raw", "output.raw", "ecc-status.bin"))
    source.write_bytes(packed)
    pages = len(packed) // PAGE
    io.run("write_data", "0x80400000", 0, len(packed), source,
           "write_word", "0x21500060", 8, "write_word", "0x11004", pages,
           "fdl", helper, "0x10000", "read_mem", "0x11000", 24, status,
           "read_mem", "0x80400000", len(packed), output)
    values = struct.unpack("<6I", status.read_bytes())
    result = output.read_bytes()
    if values[1:4] != (pages, pages * 2, 0) or len(result) != len(packed):
        raise RuntimeError(f"RAM ECC failure: {values}")
    return result


def durable_blob(path, content):
    with path.open("xb") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())


def prepare(work):
    before, candidate = legacy()
    FOLDER.mkdir(exist_ok=False)
    plan = {"status": "PREPARING; NO NAND WRITES", "old_user_sha256": OLD,
            "new_user_sha256": NEW, "blocks": [], "preflight": [],
            "device_write_performed": False}
    save(FOLDER / "preparation.json", plan)
    # Check all six blocks of the installed patch, including three unchanged
    # blocks. Retain every fresh corrected read before making target images.
    for block in sorted(before):
        current = io.read_matching(block, [before[block]], work, FOLDER)
        durable_blob(FOLDER / f"block-{block:03x}-installed.raw", current)
        plan["preflight"].append({"block": block, "sha256": io.sha(current)})
        save(FOLDER / "preparation.json", plan)
        print(f"Installed block {block:#x} matches known working patch", flush=True)
    for block, pages in CHANGES.items():
        original = before[block]
        # Hardware encoder must reproduce known valid ECC before its output
        # is trusted for the new main data.
        packed = b"".join(original[p * PAGE:(p + 1) * PAGE] for p in pages)
        if ram(packed, ENCODE, work) != packed:
            raise RuntimeError("Encoder did not reproduce installed ECC")
        target = bytearray(original)
        for p in pages:
            logical = block * 64 + p - START
            target[p * PAGE:p * PAGE + MAIN] = candidate[logical * MAIN:(logical + 1) * MAIN]
        packed = b"".join(target[p * PAGE:(p + 1) * PAGE] for p in pages)
        encoded = ram(packed, ENCODE, work)
        allowed = set(range(MAIN + 4, MAIN + 25)) | set(range(MAIN + 36, MAIN + 57))
        for j, p in enumerate(pages):
            page = encoded[j * PAGE:(j + 1) * PAGE]
            expected = packed[j * PAGE:(j + 1) * PAGE]
            if any(x != y and i not in allowed for i, (x, y) in enumerate(zip(page, expected))):
                raise RuntimeError("Encoder changed non-ECC data")
            target[p * PAGE:(p + 1) * PAGE] = page
        if ram(encoded, io.CORRECT, work) != encoded:
            raise RuntimeError("Target ECC decode changed data")
        damaged = bytearray(encoded)
        for j in range(len(pages)):
            damaged[j * PAGE + 123] ^= 1
            damaged[j * PAGE + 1024 + 123] ^= 1
        if ram(damaged, io.CORRECT, work) != encoded:
            raise RuntimeError("Target ECC cannot correct injected RAM errors")
        # Decode all 64 target pages; this also validates untouched sectors.
        if ram(target, io.CORRECT, work) != target:
            raise RuntimeError("Complete target block ECC validation failed")
        for p in (0, 1, 63):
            if target[p * PAGE + MAIN] != 255:
                raise RuntimeError("Non-erased bad-block marker")
        name = f"block-{block:03x}-target.raw"
        durable_blob(FOLDER / name, target)
        plan["blocks"].append({"block": block, "pages": pages,
                               "before_file": f"block-{block:03x}-installed.raw",
                               "before_sha256": io.sha(original), "after_file": name,
                               "after_sha256": io.sha(target)})
        save(FOLDER / "preparation.json", plan)
        print(f"Prepared and RAM ECC-validated block {block:#x}", flush=True)
    plan["status"] = "ECC VALIDATED; INSTALLED BACKUPS SAVED; NO NAND WRITES"
    plan["helpers_sha256"] = {str(p): io.sha(Path(p).read_bytes()) for p in (io.IO, io.CORRECT, ENCODE)}
    save(FOLDER / "plan.json", plan)
    print("Transition and rollback ready; NAND has not been programmed.", flush=True)


def load():
    before, candidate = legacy()
    plan = json.loads((FOLDER / "plan.json").read_text())
    if (plan["old_user_sha256"], plan["new_user_sha256"]) != (OLD, NEW):
        raise RuntimeError("Transition image identity mismatch")
    if len(plan["blocks"]) != 3 or {e["block"] for e in plan["blocks"]} != set(CHANGES):
        raise RuntimeError("Transition block allowlist mismatch")
    for path in (io.IO, io.CORRECT, ENCODE):
        if io.sha(Path(path).read_bytes()) != plan["helpers_sha256"][str(path)]:
            raise RuntimeError("Helper changed after ECC validation")
    data = {}
    for entry in plan["blocks"]:
        block = entry["block"]
        if entry["pages"] != CHANGES[block]:
            raise RuntimeError("Transition page allowlist mismatch")
        for kind in ("before", "after"):
            name = entry[f"{kind}_file"]
            if Path(name).name != name:
                raise RuntimeError("Transition path outside plan")
            data[block, kind] = blob(FOLDER / name, entry[f"{kind}_sha256"], io.BLOCK_BYTES)
        if data[block, "before"] != before[block]:
            raise RuntimeError("Rollback is not the installed working version")
        for p in range(64):
            old = before[block][p * PAGE:(p + 1) * PAGE]
            new = data[block, "after"][p * PAGE:(p + 1) * PAGE]
            if p not in CHANGES[block]:
                if old != new:
                    raise RuntimeError("Untouched page changed")
            else:
                logical = block * 64 + p - START
                if new[:MAIN] != candidate[logical * MAIN:(logical + 1) * MAIN]:
                    raise RuntimeError("Target main differs from candidate")
                allowed = set(range(MAIN + 4, MAIN + 25)) | set(range(MAIN + 36, MAIN + 57))
                if any(old[i] != new[i] for i in range(MAIN, PAGE) if i not in allowed):
                    raise RuntimeError("FTL/OOB metadata changed")
    return plan, before, data


def operate(mode, work):
    plan, before, data = load()
    records = []
    journal = FOLDER / f"{mode}-{time.time_ns()}.json"
    def checkpoint():
        save(journal, {"mode": mode, "old_user_sha256": OLD, "new_user_sha256": NEW, "records": records})
    current = {}
    for block in sorted(before):
        choices = [before[block]] if block not in CHANGES else [data[block, "before"], data[block, "after"]]
        try:
            content = io.read_matching(block, choices, work, FOLDER)
        except RuntimeError:
            if mode != "restore" or block not in CHANGES:
                raise
            content = None
        current[block] = content
        records.append({"block": block, "preflight_sha256": io.sha(content) if content else None})
        checkpoint()
        print(f"Preflight block {block:#x}: {'matches plan' if content else 'requires recovery'}", flush=True)
    if mode == "verify":
        print("Verified installed/target transition states. No NAND writes.")
        return
    target = "after" if mode == "apply" else "before"
    entries = {e["block"]: e for e in plan["blocks"]}
    # Repeat RAM decode just before erase/program; source files are immutable
    # checked snapshots. No changes to boot, NV, resources or other blocks.
    for block in ORDER:
        if ram(data[block, target], io.CORRECT, work) != data[block, target]:
            raise RuntimeError("Destination block failed RAM ECC check")
    for block in ORDER:
        if current[block] == data[block, target]:
            print(f"Block {block:#x} already target; skipped", flush=True)
            continue
        records.append({"block": block, "write_started": target})
        checkpoint()
        print(f"Writing block {block:#x}: {target}", flush=True)
        io.write_block(block, FOLDER / entries[block][f"{target}_file"], work)
        verified = io.read_matching(block, [data[block, target]], work, FOLDER)
        records.append({"block": block, "readback_verified": target, "sha256": io.sha(verified)})
        checkpoint()
        print(f"Readback verified block {block:#x}", flush=True)
    # Verify the full six-block patched footprint again after writing.
    for block in sorted(before):
        expected = data[block, target] if block in CHANGES else before[block]
        verified = io.read_matching(block, [expected], work, FOLDER)
        records.append({"block": block, "final_verified": True, "sha256": io.sha(verified)})
        checkpoint()
    records.append({"completed": True, "target_user_sha256": NEW if mode == "apply" else OLD})
    checkpoint()
    print(f"Completed {mode}; all three writes and six final block readbacks verified.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    for action in ("prepare", "verify", "apply", "restore", "check-plan"):
        group.add_argument(f"--{action}", action="store_true")
    parser.add_argument("--confirm-destructive-write", action="store_true")
    args = parser.parse_args()
    if (args.apply or args.restore) != args.confirm_destructive_write:
        parser.error("--apply/--restore require --confirm-destructive-write, and vice versa")
    if args.check_plan:
        load()
        print("Offline transition/rollback plan boundaries and hashes verified.")
        return
    for path in (io.IO, io.CORRECT, ENCODE):
        if not Path(path).is_file():
            raise RuntimeError(f"Missing helper {path}")
    with tempfile.TemporaryDirectory(prefix="l728-transition-", dir="/tmp/opencode") as tmp:
        if args.prepare:
            prepare(Path(tmp))
        else:
            mode = "apply" if args.apply else "restore" if args.restore else "verify"
            operate(mode, Path(tmp))


if __name__ == "__main__":
    main()
