#!/usr/bin/env python3
"""Two-block screen update from the owner-tested SOS image, exact rollback."""
import json

import sos_transition as transition
from navigation_transition import blob

INSTALLED = "61edf9a3a9206d8f59baac6b4e3f7b55e5ab1d1f9cd88746777bfe2f15416681"
ORIGINAL_INPUTS = transition.inputs
ORIGINAL_LOAD = transition.load


def configure():
    # Resolve and validate the old SOS plan before replacing its module config.
    old_plan, old_before, old_data = ORIGINAL_LOAD()
    if old_plan["new_user_sha256"] != INSTALLED:
        raise RuntimeError("Expected the exact installed SOS version")
    before = dict(old_before)
    for block in transition.CHANGES:
        before[block] = old_data[block, "after"]
    root = transition.ROOT
    source = blob(root / "experimental/sos/l728-user-sos-CANDIDATE.bin", INSTALLED, 0x7e1800)
    folder = root / "experimental/sos-screen"
    report = json.loads((folder / "manifest.json").read_text())
    candidate = blob(folder / "l728-user-sos-CANDIDATE.bin", report["output_sha256"], len(source))
    if not report.get("screen_off_with_lock"):
        raise RuntimeError("Not a screen-off candidate")
    reconstructed = bytearray((root / "backup/l728-user-ecc.bin").read_bytes())
    for block, packed in before.items():
        for p in range(64):
            logical = block * 64 + p - transition.START
            if 0 <= logical < len(source) // 2048:
                reconstructed[logical * 2048:(logical + 1) * 2048] = packed[p * 2112:p * 2112 + 2048]
    if bytes(reconstructed) != source:
        raise RuntimeError("Stored blocks do not reconstruct installed SOS image")
    offset = report["payload_offset"]
    allowed = set(range(0x30, 0x34)) | set(range(offset, offset + report["payload_bytes"]))
    if any(a != b and i not in allowed for i, (a, b) in enumerate(zip(source, candidate))):
        raise RuntimeError("Screen variant changes outside payload/header")
    changes = {}
    for p in range(len(source) // 2048):
        if source[p * 2048:(p + 1) * 2048] != candidate[p * 2048:(p + 1) * 2048]:
            changes.setdefault((transition.START + p) // 64, []).append((transition.START + p) % 64)
    if changes != {0x13d: [0], 0x17c: [2]}:
        raise RuntimeError(f"Unexpected screen transition: {changes}")
    transition.VERIFIED = INSTALLED
    transition.CHANGES = changes
    transition.ORDER = [0x17c, 0x13d]
    transition.FOLDER = folder / "transition"
    # The validated SOS helper already permits these two destinations. Keep
    # its binary identity and the old rollback plan intact.
    transition.inputs = lambda: (before, candidate, report)


if __name__ == "__main__":
    configure()
    transition.main()
