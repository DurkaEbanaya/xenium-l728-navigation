#!/usr/bin/env python3
"""Prepare original/modified physical blocks; generate ECC in phone RAM only.

Requires the already running L728 FDL session and /tmp/opencode/l728-encode.bin.
Never sends NAND programming or erase commands.
"""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
RAW_SHA = "76aef2f60b8f64610012f43dadd49f638d3ea2b727a2c413de45fa5df00b8326"
PAGE = 2112
MAIN = 2048
BLOCK_PAGES = 64
START = 0x4f40

def sha(data):
    return hashlib.sha256(data).hexdigest()

def main():
    raw = (ROOT / "backup/l728-nand-ecc.raw").read_bytes()
    original = (ROOT / "backup/l728-user-ecc.bin").read_bytes()
    modified = (ROOT / "experimental/l728-user-navigation-UNTESTED.bin").read_bytes()
    manifest = json.loads((ROOT / "experimental/manifest.json").read_text())
    if sha(raw) != RAW_SHA or len(raw) != PAGE * 65536:
        raise SystemExit("NAND backup mismatch")
    if sha(original) != manifest["source_sha256"] or sha(modified) != manifest["output_sha256"]:
        raise SystemExit("Firmware/manifest mismatch")
    if len(original) != len(modified) or len(original) % MAIN:
        raise SystemExit("Unexpected image lengths")
    extracted = b"".join(raw[p * PAGE:p * PAGE + MAIN]
                         for p in range(START, START + len(original) // MAIN))
    if extracted != original:
        raise SystemExit("Logical-to-physical correspondence not established")
    changed = [p for p in range(len(original) // MAIN)
               if original[p * MAIN:(p + 1) * MAIN] != modified[p * MAIN:(p + 1) * MAIN]]
    if len(changed) != 7:
        raise SystemExit(f"Unexpected changed page count: {len(changed)}")
    blocks = sorted({(START + p) // BLOCK_PAGES for p in changed})
    output = ROOT / "experimental/blocks"
    if output.exists() and any(output.iterdir()):
        raise SystemExit("Refusing to overwrite an existing block plan")
    output.mkdir(exist_ok=True)
    plan = {"status": "RAM ECC PREPARATION ONLY; NO NAND WRITES", "raw_sha256": RAW_SHA,
            "original_user_sha256": sha(original), "modified_user_sha256": sha(modified),
            "page_main": MAIN, "page_oob": 64, "pages_per_block": BLOCK_PAGES,
            "physical_user_start_page": START, "blocks": []}
    with tempfile.TemporaryDirectory(prefix="l728-encode-", dir="/tmp/opencode") as work:
        work = Path(work)
        for block in blocks:
            start = block * BLOCK_PAGES
            before = raw[start * PAGE:(start + BLOCK_PAGES) * PAGE]
            # The first spare byte is the model's bad-block marker; byte 1
            # holds FTL information on programmed L728 pages and is not a BBM.
            if any(before[p * PAGE + MAIN] != 255 for p in (0, 1, 63)):
                raise SystemExit(f"Block {block:#x} has a non-erased marker")
            after = bytearray(before)
            changed_in_block = []
            for p in changed:
                physical = START + p
                if physical // BLOCK_PAGES != block:
                    continue
                index = physical - start
                after[index * PAGE:index * PAGE + MAIN] = modified[p * MAIN:(p + 1) * MAIN]
                changed_in_block.append(index)
            # Encode only changed pages; all other OOB bytes remain exactly
            # as in the corrected backup, including page/block metadata.
            packed = b"".join(after[p * PAGE:(p + 1) * PAGE] for p in changed_in_block)
            input_file = work / "input.raw"
            result_file = work / "result.bin"
            output_file = work / "output.raw"
            input_file.write_bytes(packed)
            command = ["/tmp/opencode/spreadtrum_flash/spd_dump", "--wait", "0", "--fdl-loaded",
                       "blk_size", "512", "write_data", "0x80400000", "0", str(len(packed)), str(input_file),
                       "write_word", "0x11004", str(len(changed_in_block)),
                       "fdl", "/tmp/opencode/l728-encode.bin", "0x10000",
                       "read_mem", "0x11000", "24", str(result_file),
                       "read_mem", "0x80400000", str(len(packed)), str(output_file)]
            run = subprocess.run(command, capture_output=True, timeout=30)
            if run.returncode:
                raise SystemExit(run.stderr.decode(errors="replace"))
            values = struct.unpack("<6I", result_file.read_bytes())
            encoded = output_file.read_bytes()
            if values[2:4] != (len(changed_in_block) * 2, 0) or len(encoded) != len(packed):
                raise SystemExit(f"ECC incomplete: {values}")
            for index, p in enumerate(changed_in_block):
                page = encoded[index * PAGE:(index + 1) * PAGE]
                expected = after[p * PAGE:(p + 1) * PAGE]
                allowed = set(range(MAIN + 4, MAIN + 25)) | set(range(MAIN + 36, MAIN + 57))
                if any(x != y and i not in allowed for i, (x, y) in enumerate(zip(page, expected))):
                    raise SystemExit("ECC helper changed data outside ECC fields")
                after[p * PAGE:(p + 1) * PAGE] = page
            before_name = f"block-{block:03x}-original.raw"
            after_name = f"block-{block:03x}-navigation.raw"
            (output / before_name).write_bytes(before)
            (output / after_name).write_bytes(after)
            plan["blocks"].append({"block": block, "first_page": start,
                                   "changed_pages_in_block": changed_in_block,
                                   "original_file": before_name, "modified_file": after_name,
                                   "original_sha256": sha(before), "modified_sha256": sha(after)})
            print(f"Prepared block {block:#x}, changed pages {changed_in_block}", flush=True)
    (output / "plan.json").write_text(json.dumps(plan, indent=2) + "\n")
    print("Block plan ready; NAND has not been modified.")

if __name__ == "__main__":
    main()
