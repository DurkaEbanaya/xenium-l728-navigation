#!/usr/bin/env python3
"""SOS transition from v0.2.0: offline preparation, FDL validation and rollback.

--prepare is entirely offline. --validate-device checks current blocks and ECC
in phone RAM. Only --apply/--restore with confirmation erase/program NAND.
"""
import argparse
import json
from pathlib import Path
import tempfile
import time

import navigation_transition as previous
import navigation_blocks as io
from l728_ecc import encode_page, parity, validate_block

ROOT = Path(__file__).resolve().parents[1]
VERIFIED = previous.NEW
PAGE, MAIN, START = 2112, 2048, 0x4f40
CHANGES = {0x13d: [0], 0x172: [5], 0x17c: [2]}
ORDER = [0x17c, 0x172, 0x13d]
FOLDER = ROOT / "experimental/sos/transition"
IO = ROOT / "experimental/sos/sos-block-io.bin"


def inputs():
    # Reconstruct all of v0.2.0 using the verified old transition and original
    # raw NAND. No assertion here is evidence of the current device state.
    _, old_blocks, old_targets = previous.load()
    raw = previous.blob(ROOT / "backup/l728-nand-ecc.raw", previous.RAW, PAGE * 65536)
    before = dict(old_blocks)
    for block in previous.CHANGES:
        before[block] = old_targets[block, "after"]
    before[0x172] = raw[0x172 * io.BLOCK_BYTES:0x173 * io.BLOCK_BYTES]
    verified = previous.blob(ROOT / "experimental/l728-user-navigation-UNTESTED.bin", VERIFIED, 0x7e1800)
    reconstructed = bytearray((ROOT / "backup/l728-user-ecc.bin").read_bytes())
    for block, packed in before.items():
        for p in range(64):
            logical = block * 64 + p - START
            if 0 <= logical < len(reconstructed) // MAIN:
                reconstructed[logical * MAIN:(logical + 1) * MAIN] = packed[p * PAGE:p * PAGE + MAIN]
    if bytes(reconstructed) != verified:
        raise RuntimeError("Snapshots do not reconstruct the exact phone-tested v0.2.0")
    report = json.loads((ROOT / "experimental/sos/manifest.json").read_text())
    if report["source_sha256"] != VERIFIED:
        raise RuntimeError("Incorrect SOS source identity")
    candidate = previous.blob(ROOT / "experimental/sos/l728-user-sos-CANDIDATE.bin", report["output_sha256"], len(verified))
    allowed_bytes = set(range(0x30, 0x34)) | set(range(0x6a2a84, 0x6a2a8c)) | set(range(
        report["payload_offset"], report["payload_offset"] + report["payload_bytes"]))
    if any(a != b and i not in allowed_bytes for i, (a, b) in enumerate(zip(verified, candidate))):
        raise RuntimeError("Unexpected changes outside SOS hook/header/payload")
    actual = {}
    for p in range(len(verified) // MAIN):
        if verified[p * MAIN:(p + 1) * MAIN] != candidate[p * MAIN:(p + 1) * MAIN]:
            actual.setdefault((START + p) // 64, []).append((START + p) % 64)
    if actual != CHANGES:
        raise RuntimeError(f"Unexpected SOS page transition: {actual}")
    return before, candidate, report


def helpers():
    return {str(p): io.sha(Path(p).read_bytes()) for p in (IO, io.CORRECT, previous.ENCODE)}


def prepare():
    before, candidate, report = inputs()
    FOLDER.mkdir(exist_ok=False)
    plan = {"status": "OFFLINE BCH PACKAGE; DEVICE VALIDATION REQUIRED",
            "old_user_sha256": VERIFIED, "new_user_sha256": report["output_sha256"],
            "device_accessed": False, "device_write_performed": False,
            "hardware_validated": False, "helpers_sha256": helpers(), "blocks": []}
    for block, pages in CHANGES.items():
        target = bytearray(before[block])
        for p in pages:
            logical = block * 64 + p - START
            start = p * PAGE
            page = bytearray(target[start:start + PAGE])
            page[:MAIN] = candidate[logical * MAIN:(logical + 1) * MAIN]
            target[start:start + PAGE] = encode_page(page)
        # Stock OOB parity errors are preserved on unchanged sectors; this
        # verification checks them separately from fresh exact changed ECC.
        validate_block(target, parity_error_limit=12)
        for kind, data in (("before", before[block]), ("after", target)):
            previous.durable_blob(FOLDER / f"block-{block:03x}-{kind}.raw", data)
        plan["blocks"].append({"block": block, "pages": pages,
            "before_file": f"block-{block:03x}-before.raw", "after_file": f"block-{block:03x}-after.raw",
            "before_sha256": io.sha(before[block]), "after_sha256": io.sha(target)})
    previous.save(FOLDER / "plan.json", plan)
    load()
    print(f"Prepared {len(CHANGES)} offline ECC blocks and exact source-version rollback; device validation still required.")


def load():
    before, candidate, report = inputs()
    plan = json.loads((FOLDER / "plan.json").read_text())
    if (plan["old_user_sha256"], plan["new_user_sha256"]) != (VERIFIED, report["output_sha256"]):
        raise RuntimeError("SOS plan is stale or belongs to another candidate")
    if len(plan["blocks"]) != len(CHANGES) or {e["block"] for e in plan["blocks"]} != set(CHANGES):
        raise RuntimeError("Unexpected SOS block allowlist")
    if helpers() != plan["helpers_sha256"]:
        raise RuntimeError("ECC/IO helpers changed after preparation")
    data = {}
    for entry in plan["blocks"]:
        block = entry["block"]
        if entry["pages"] != CHANGES[block]:
            raise RuntimeError("Wrong page allowlist")
        for kind in ("before", "after"):
            name = entry[f"{kind}_file"]
            if Path(name).name != name:
                raise RuntimeError("Path outside SOS plan")
            data[block, kind] = previous.blob(FOLDER / name, entry[f"{kind}_sha256"], io.BLOCK_BYTES)
        if data[block, "before"] != before[block]:
            raise RuntimeError("Rollback is not v0.2.0")
        for p in range(64):
            old = before[block][p * PAGE:(p + 1) * PAGE]
            new = data[block, "after"][p * PAGE:(p + 1) * PAGE]
            if p not in CHANGES[block]:
                if new != old:
                    raise RuntimeError("Untouched page changed")
                continue
            logical = block * 64 + p - START
            if new[:MAIN] != candidate[logical * MAIN:(logical + 1) * MAIN]:
                raise RuntimeError("Target main differs from SOS candidate")
            for s in range(2):
                if new[MAIN + s * 32 + 4:MAIN + s * 32 + 25] != parity(new[s * 1024:(s + 1) * 1024]):
                    raise RuntimeError("Incorrect changed-page BCH")
            allowed = set(range(MAIN + 4, MAIN + 25)) | set(range(MAIN + 36, MAIN + 57))
            if any(old[i] != new[i] for i in range(MAIN, PAGE) if i not in allowed):
                raise RuntimeError("FTL/OOB metadata changed")
        for p in (0, 1, 63):
            if data[block, "after"][p * PAGE + MAIN] != 255:
                raise RuntimeError("Bad-block marker not erased")
    return plan, before, data


def operate(action, work):
    plan, before, data = load()
    if action == "apply" and not plan["hardware_validated"]:
        raise RuntimeError("Run --validate-device before --apply")
    io.IO = str(IO)
    records = []
    journal = FOLDER / f"{action}-{time.time_ns()}.json"
    def checkpoint():
        previous.save(journal, {"action": action, "old_user_sha256": VERIFIED,
                               "new_user_sha256": plan["new_user_sha256"], "records": records})
    current = {}
    for block in sorted(before):
        choices = [before[block]]
        if block in CHANGES and action in ("apply", "restore", "verify"):
            choices.append(data[block, "after"])
        try:
            current[block] = io.read_matching(block, choices, work, FOLDER)
        except RuntimeError:
            if action != "restore" or block not in CHANGES:
                raise
            current[block] = None
        records.append({"block": block, "preflight_sha256": io.sha(current[block]) if current[block] else None})
        checkpoint()
    if action == "verify":
        print("Seven current blocks match the transition states; no NAND writes.")
        return
    if action == "validate-device":
        for block in ORDER:
            packed = b"".join(data[block, "after"][p * PAGE:(p + 1) * PAGE] for p in CHANGES[block])
            if previous.ram(packed, previous.ENCODE, work) != packed:
                raise RuntimeError("Software ECC differs from BootROM hardware encoder")
            damaged = bytearray(packed)
            for offset in (123, 1147):
                damaged[offset] ^= 1
            if previous.ram(damaged, io.CORRECT, work) != packed:
                raise RuntimeError("Hardware failed to correct injected RAM errors")
            if previous.ram(data[block, "after"], io.CORRECT, work) != data[block, "after"]:
                raise RuntimeError("Full target block failed hardware ECC decode")
            previous.durable_blob(FOLDER / f"block-{block:03x}-fresh-{time.time_ns()}.raw", current[block])
            records.append({"block": block, "hardware_ecc_verified": True})
            checkpoint()
        plan.update(hardware_validated=True, device_accessed=True,
                    status="HARDWARE ECC VALIDATED; SOURCE-VERSION READBACK VERIFIED; NO NAND WRITES")
        previous.save(FOLDER / "plan.json", plan)
        return
    target = "after" if action == "apply" else "before"
    for block in ORDER:
        if previous.ram(data[block, target], io.CORRECT, work) != data[block, target]:
            raise RuntimeError("Destination failed pre-write RAM decode")
    entries = {e["block"]: e for e in plan["blocks"]}
    for block in ORDER:
        if current[block] == data[block, target]:
            continue
        records.append({"block": block, "write_started": target})
        checkpoint()
        io.write_block(block, FOLDER / entries[block][f"{target}_file"], work)
        verified = io.read_matching(block, [data[block, target]], work, FOLDER)
        records.append({"block": block, "readback_verified": target, "sha256": io.sha(verified)})
        checkpoint()
    for block in sorted(before):
        expected = data[block, target] if block in CHANGES else before[block]
        io.read_matching(block, [expected], work, FOLDER)
        records.append({"block": block, "final_verified": True})
        checkpoint()
    records.append({"completed": True})
    checkpoint()
    print(f"Completed {action}; {len(CHANGES)} target blocks and {len(before)} final readbacks verified.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    for action in ("prepare", "check-plan", "validate-device", "verify", "apply", "restore"):
        group.add_argument(f"--{action}", action="store_true")
    parser.add_argument("--confirm-destructive-write", action="store_true")
    args = parser.parse_args()
    if (args.apply or args.restore) != args.confirm_destructive_write:
        parser.error("--apply/--restore require --confirm-destructive-write, and vice versa")
    if args.prepare:
        prepare()
    elif args.check_plan:
        plan, _, _ = load()
        print(f"Offline plan/rollback checks passed. Hardware validated: {plan['hardware_validated']}")
    else:
        action = next(n for n in ("validate-device", "verify", "apply", "restore") if getattr(args, n.replace("-", "_")))
        with tempfile.TemporaryDirectory(prefix="l728-sos-", dir="/tmp/opencode") as temporary:
            operate(action, Path(temporary))


if __name__ == "__main__":
    main()
