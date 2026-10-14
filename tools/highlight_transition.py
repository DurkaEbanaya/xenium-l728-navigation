#!/usr/bin/env python3
"""Highlight candidate: offline BCH preparation, device validation and rollback."""
import json
from pathlib import Path
import sos_no_flash_transition as installed
from build_highlight import VERIFIED, HOOKS, CALLS
from build_highlight_io import READ, WRITE
from navigation_transition import blob


def configure():
    installed.configure()
    transition = installed.screen.transition
    plan, before, data = transition.load()
    if plan["new_user_sha256"] != VERIFIED:
        raise RuntimeError("Expected owner-tested no-flash source")
    before = dict(before)
    for block in transition.CHANGES:
        before[block] = data[block, "after"]
    root = transition.ROOT
    raw = blob(root / "backup/l728-nand-ecc.raw", transition.previous.RAW, 2112 * 65536)
    for block in READ:
        if block not in before:
            before[block] = raw[block * 64 * 2112:(block + 1) * 64 * 2112]
    if set(before) != set(READ):
        raise RuntimeError("Unexpected source footprint")
    source = blob(root / "experimental/sos-no-flash/l728-user-sos-CANDIDATE.bin", VERIFIED, 0x7e1800)
    folder = root / "experimental/highlight"
    report = json.loads((folder / "manifest.json").read_text())
    checks = json.loads((folder / "checks.json").read_text())
    if checks["output_sha256"] != report["output_sha256"] or not checks["focused_execution_passed"]:
        raise RuntimeError("Exact candidate has not passed execution checks")
    candidate = blob(folder / "l728-user-highlight-CANDIDATE.bin", report["output_sha256"], report["output_bytes"])
    if report["source_sha256"] != VERIFIED or report["payload_offset"] != 0x7e1630:
        raise RuntimeError("Wrong highlight source or layout")
    reconstructed = bytearray(source + b"\xff" * (len(candidate) - len(source)))
    for block, packed in before.items():
        for p in range(64):
            logical = block * 64 + p - transition.START
            if 0 <= logical < len(candidate) // 2048:
                reconstructed[logical*2048:(logical+1)*2048] = packed[p*2112:p*2112+2048]
    if reconstructed != source + b"\xff" * (len(candidate) - len(source)):
        raise RuntimeError("Source snapshots/extension pages are not exact installed image plus erased main data")
    allowed = set(range(0x30, 0x34)) | set(range(0x31be64, 0x31be68)) | set(range(
        report["payload_offset"], report["payload_offset"] + report["payload_bytes"]))
    expected = set(HOOKS) | set(CALLS)
    if {h["offset"] for h in report["hooks"]} != expected:
        raise RuntimeError("Unexpected highlight hook allowlist")
    for hook in report["hooks"]:
        offset = hook["offset"]
        replacement = bytes.fromhex(hook["replacement"])
        original = bytes.fromhex(hook["original"])
        if source[offset:offset+len(original)] != original or candidate[offset:offset+len(replacement)] != replacement:
            raise RuntimeError("Hook bytes differ from manifest")
        allowed.update(range(offset, offset+len(replacement)))
    if any(a != b and i not in allowed for i, (a, b) in enumerate(zip(reconstructed, candidate))):
        raise RuntimeError("Unexpected highlight byte modifications")
    changes = {}
    for p in range(len(candidate)//2048):
        if reconstructed[p*2048:(p+1)*2048] != candidate[p*2048:(p+1)*2048]:
            changes.setdefault((transition.START+p)//64, []).append((transition.START+p)%64)
    if changes != {0x13d:[0], 0x13f:[1], 0x14c:[26], 0x155:[55], 0x173:[12,15], 0x17c:[2,3,4,5,6]}:
        raise RuntimeError(f"Unexpected highlight pages: {changes}")
    helper = json.loads((folder / "io-manifest.json").read_text())
    if helper["read_blocks"] != list(READ) or helper["write_blocks"] != list(WRITE):
        raise RuntimeError("IO helper allowlist mismatch")
    io = folder / "highlight-block-io.bin"
    blob(io, helper["binary_sha256"], io.stat().st_size)
    transition.VERIFIED = VERIFIED
    transition.CHANGES = changes
    transition.ORDER = [0x17c, 0x13f, 0x14c, 0x173, 0x155, 0x13d]
    transition.FOLDER = folder / "transition"
    transition.IO = io
    transition.io.TOOL = str(root / "build/spreadtrum_flash/spd_dump")
    transition.inputs = lambda: (before, candidate, report)
    return transition


if __name__ == "__main__":
    # Disposable exchange buffers only; executable helpers live under build/.
    Path("/tmp/opencode").mkdir(exist_ok=True)
    configure().main()
