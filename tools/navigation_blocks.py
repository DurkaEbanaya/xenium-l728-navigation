#!/usr/bin/env python3
"""Verify, apply, or restore the six L728 navigation blocks in a running FDL.

Default operation verifies the current NAND against the original backup.
--apply / --restore explicitly erase and rewrite those six physical blocks.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
TOOL = "/tmp/opencode/spreadtrum_flash/spd_dump"
IO = "/tmp/opencode/l728-block-io.bin"
CORRECT = "/tmp/opencode/l728-correct.bin"
BLOCK_BYTES = 64 * 2112
ALLOWED = {0x13d, 0x143, 0x145, 0x14c, 0x17a, 0x17c}

def sha(data):
    return hashlib.sha256(data).hexdigest()

def run(*commands):
    proc = subprocess.run([TOOL, "--wait", "0", "--fdl-loaded", "timeout", "15000",
                           "blk_size", "512", *map(str, commands)],
                          capture_output=True, timeout=60)
    if proc.returncode:
        raise RuntimeError(proc.stderr.decode(errors="replace"))

def read_block(block, work):
    status = work / "status.bin"
    result = work / "read.raw"
    run("write_word", "0x11000", "0x4c373238",
        "write_word", "0x11004", 0, "write_word", "0x11008", block,
        "fdl", IO, "0x10000", "read_mem", "0x11000", 36, status)
    values = struct.unpack("<9I", status.read_bytes())
    if values[:5] != (0x4c373238, 0, block, 64, 0):
        raise RuntimeError(f"NAND read incomplete: {values}")
    run("write_word", "0x21500060", 8, "write_word", "0x11004", 64,
        "fdl", CORRECT, "0x10000", "read_mem", "0x11000", 24, status,
        "read_mem", "0x80400000", BLOCK_BYTES, result)
    values = struct.unpack("<6I", status.read_bytes())
    if values[1:4] != (64, 128, 0):
        raise RuntimeError(f"NAND ECC failed: {values}")
    data = result.read_bytes()
    if len(data) != BLOCK_BYTES:
        raise RuntimeError("Short NAND read")
    return data

def write_block(block, source, work):
    status = work / "status.bin"
    run("write_data", "0x80400000", 0, BLOCK_BYTES, source,
        "write_word", "0x11000", "0x4c373238",
        "write_word", "0x11004", 1, "write_word", "0x11008", block,
        "fdl", IO, "0x10000", "read_mem", "0x11000", 36, status)
    values = struct.unpack("<9I", status.read_bytes())
    if values[:5] != (0x4c373238, 1, block, 64, 0):
        raise RuntimeError(f"NAND write failed: {values}")

def read_matching(block, candidates, work, folder):
    last_error = None
    for attempt in range(3):
        try:
            content = read_block(block, work)
        except RuntimeError as exc:
            last_error = exc
            continue
        if content in candidates:
            return content
        # Retain mismatches for diagnosis, including OOB. Do not silently
        # treat successful ECC as proof that every spare byte is identical.
        (folder / f"block-{block:03x}-mismatch-{time.time_ns()}.raw").write_bytes(content)
        differences = min(sum(x != y for x, y in zip(content, candidate))
                          for candidate in candidates)
        last_error = RuntimeError(f"Block {block:#x} mismatch ({differences} bytes), read {attempt + 1}")
    raise last_error

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument("--apply", action="store_true")
    actions.add_argument("--restore", action="store_true")
    parser.add_argument("--confirm-destructive-write", action="store_true",
                        help="required with --apply/--restore; erases and rewrites NAND blocks")
    args = parser.parse_args()
    if (args.apply or args.restore) and not args.confirm_destructive_write:
        parser.error("--apply/--restore require --confirm-destructive-write")
    if args.confirm_destructive_write and not (args.apply or args.restore):
        parser.error("--confirm-destructive-write requires --apply or --restore")
    folder = ROOT / "experimental/blocks"
    plan = json.loads((folder / "plan.json").read_text())
    entries = plan["blocks"]
    if len(entries) != 6 or {e["block"] for e in entries} != ALLOWED:
        raise SystemExit("Unexpected physical block plan")
    data = {}
    for entry in entries:
        for kind in ("original", "modified"):
            filename = entry[f"{kind}_file"]
            if Path(filename).name != filename:
                raise SystemExit("Block path outside plan folder")
            content = (folder / filename).read_bytes()
            if len(content) != BLOCK_BYTES or sha(content) != entry[f"{kind}_sha256"]:
                raise SystemExit(f"Block hash mismatch: {filename}")
            data[entry["block"], kind] = content
    for helper in (IO, CORRECT):
        if not Path(helper).is_file():
            raise SystemExit(f"Missing helper: {helper}")
    mode = "apply" if args.apply else "restore" if args.restore else "verify"
    journal = folder / f"{mode}-{time.time_ns()}.json"
    records = []
    def checkpoint():
        journal.write_text(json.dumps({"mode": mode, "records": records}, indent=2) + "\n")
    with tempfile.TemporaryDirectory(prefix="l728-blocks-", dir="/tmp/opencode") as tmp:
        work = Path(tmp)
        # Verify all blocks before the first erase. A partially completed
        # apply/restore can be resumed when every block matches either image.
        current = {}
        for entry in entries:
            block = entry["block"]
            candidates = [data[block, "original"], data[block, "modified"]]
            try:
                content = read_matching(block, candidates, work, folder)
            except RuntimeError:
                if mode != "restore":
                    raise
                # Restoration must also recover a block interrupted after
                # erase/program, rather than rejecting that very condition.
                # Destinations remain the exact six-block allowlist; originals
                # were size/hash checked above before any NAND operation.
                current[block] = None
                records.append({"block": block, "preflight": "damaged-or-incomplete"})
                checkpoint()
                print(f"Block {block:#x} needs restoration from verified backup", flush=True)
                continue
            current[block] = content
            matches = [kind for kind in ("original", "modified") if content == data[block, kind]]
            if not matches:
                raise RuntimeError(f"Block {block:#x} differs from both prepared images")
            if mode == "verify" and matches != ["original"]:
                raise RuntimeError(f"Block {block:#x} is not the original firmware")
            records.append({"block": block, "preflight": matches[0], "sha256": sha(content)})
            checkpoint()
            print(f"Verified block {block:#x}: {matches[0]}", flush=True)
        if mode == "verify":
            print("All six current NAND blocks match the corrected backup. No NAND writes.")
            return
        target = "modified" if mode == "apply" else "original"
        # Append/code pages first, callback pages next, image-size header last.
        order = [0x17c, 0x17a, 0x14c, 0x145, 0x143, 0x13d]
        by_block = {e["block"]: e for e in entries}
        for block in order:
            if current[block] == data[block, target]:
                print(f"Block {block:#x} already {target}; skipped", flush=True)
                continue
            records.append({"block": block, "write_started": target})
            checkpoint()
            print(f"Writing block {block:#x} ({target})", flush=True)
            write_block(block, folder / by_block[block][f"{target}_file"], work)
            verified = read_matching(block, [data[block, target]], work, folder)
            if verified != data[block, target]:
                raise RuntimeError(f"Readback mismatch after writing block {block:#x}")
            records.append({"block": block, "readback_verified": target, "sha256": sha(verified)})
            checkpoint()
            print(f"Readback verified block {block:#x}", flush=True)
    print(f"Completed {mode}; all six target blocks verified.")

if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, subprocess.TimeoutExpired) as exc:
        raise SystemExit(f"STOPPED: {exc}. Keep the phone in FDL mode for diagnosis/restoration.")
