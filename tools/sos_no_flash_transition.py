#!/usr/bin/env python3
"""No-flash two-block update from the owner-tested screen SOS image."""
import json
import sos_screen_transition as screen
from navigation_transition import blob

INSTALLED = "af9d36b31a0f160ad57aa60daa1ecbf80c5be8a07730cddf76ebbd28c6436046"


def configure():
    screen.configure()
    transition = screen.transition
    plan, before, data = transition.load()
    if plan["new_user_sha256"] != INSTALLED:
        raise RuntimeError("Expected exact owner-tested screen version")
    before = dict(before)
    for block in transition.CHANGES:
        before[block] = data[block, "after"]
    root = transition.ROOT
    source = blob(root / "experimental/sos-screen/l728-user-sos-CANDIDATE.bin", INSTALLED, 0x7e1800)
    folder = root / "experimental/sos-no-flash"
    report = json.loads((folder / "manifest.json").read_text())
    candidate = blob(folder / "l728-user-sos-CANDIDATE.bin", report["output_sha256"], len(source))
    if not report.get("suppress_locked_sos_trailing_wake"):
        raise RuntimeError("Expected no-flash candidate")
    offset = report["payload_offset"]
    allowed = set(range(0x30, 0x34)) | set(range(offset, offset + report["payload_bytes"]))
    if any(a != b and i not in allowed for i, (a, b) in enumerate(zip(source, candidate))):
        raise RuntimeError("Unexpected changes outside header/payload")
    changes = {}
    for p in range(len(source) // 2048):
        if source[p * 2048:(p + 1) * 2048] != candidate[p * 2048:(p + 1) * 2048]:
            changes.setdefault((transition.START + p) // 64, []).append((transition.START + p) % 64)
    if changes != {0x13d: [0], 0x17c: [2]}:
        raise RuntimeError(f"Unexpected no-flash transition: {changes}")
    transition.VERIFIED = INSTALLED
    transition.CHANGES = changes
    transition.ORDER = [0x17c, 0x13d]
    transition.FOLDER = folder / "transition"
    transition.inputs = lambda: (before, candidate, report)


if __name__ == "__main__":
    configure()
    screen.transition.main()
