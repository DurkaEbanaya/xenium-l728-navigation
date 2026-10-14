#!/usr/bin/env python3
"""Display title fix, starting from the installed ARM-interworking fix."""
import json
from pathlib import Path
import highlight_arm_fix_transition as previous
from navigation_transition import blob

INSTALLED = "d0db149565c8a7e163c1d402ddbcd9bc0196b47d3709396689bc415e3495cabf"
FIXED = "57d62712c24d8d62221c295f28ec28467d8b00b7638a68a6a3a7da2e4c2ff894"
CHANGES = {0x13d:[0], 0x13f:[1], 0x14c:[26], 0x155:[55],
           0x173:[12,15], 0x17c:[2,3,4,5,6]}


def configure():
    transition = previous.configure()
    plan, before, data = transition.load()
    if plan["new_user_sha256"] != INSTALLED:
        raise RuntimeError("Expected installed ARM-fix image")
    before = dict(before)
    for block in transition.CHANGES:
        before[block] = data[block, "after"]
    if transition.io.sha(before[0x17c]) != "03f1a45fadf95f95ab0059436cb87a2e2d189c60676a6007e3fc7bc2e03a368d":
        raise RuntimeError("Unexpected installed ARM-fix payload block")
    root = transition.ROOT
    folder = root / "experimental/highlight-display-fix"
    source = blob(root / "experimental/highlight-arm-fix/l728-user-highlight-CANDIDATE.bin",
                  INSTALLED, 0x7e3800)
    candidate = blob(folder / "l728-user-highlight-CANDIDATE.bin", FIXED, len(source))
    report = json.loads((folder / "manifest.json").read_text())
    checks = json.loads((folder / "checks.json").read_text())
    if report["output_sha256"] != FIXED or report.get("allocator_entry_mode") != "ARM":
        raise RuntimeError("Wrong Display-fix manifest")
    if (checks["output_sha256"] != FIXED or not checks["focused_execution_passed"]
            or not checks.get("allocator_interworking_checked")
            or not checks.get("native_selector_initialization_checked")):
        raise RuntimeError("Exact image must pass native selector and ARM veneer checks")
    reconstructed = bytearray(source)
    for block, packed in before.items():
        for p in range(64):
            logical = block * 64 + p - transition.START
            if 0 <= logical < len(source)//2048:
                reconstructed[logical*2048:(logical+1)*2048] = packed[p*2112:p*2112+2048]
    if reconstructed != source:
        raise RuntimeError("Snapshots do not reconstruct installed ARM-fix image")
    old_report = json.loads((root / "experimental/highlight-arm-fix/manifest.json").read_text())
    allowed = set(range(0x30,0x34)) | set(range(0x31be64,0x31be68))
    for manifest in (old_report, report):
        allowed.update(range(manifest["payload_offset"],
                             manifest["payload_offset"]+manifest["payload_bytes"]))
        for hook in manifest["hooks"]:
            allowed.update(range(hook["offset"],hook["offset"]+len(bytes.fromhex(hook["replacement"]))))
    if any(a != b and p not in allowed for p,(a,b) in enumerate(zip(source,candidate))):
        raise RuntimeError("Unexpected changes outside highlight hooks/header/payload")
    actual = {}
    for p in range(len(source)//2048):
        if source[p*2048:(p+1)*2048] != candidate[p*2048:(p+1)*2048]:
            actual.setdefault((transition.START+p)//64,[]).append((transition.START+p)%64)
    if actual != CHANGES:
        raise RuntimeError(f"Unexpected Display-fix page allowlist: {actual}")
    transition.VERIFIED = INSTALLED
    transition.CHANGES = CHANGES
    transition.ORDER = [0x17c,0x13f,0x14c,0x173,0x155,0x13d]
    transition.FOLDER = folder / "transition"
    transition.inputs = lambda: (before, candidate, report)
    return transition


if __name__ == "__main__":
    Path("/tmp/opencode").mkdir(exist_ok=True)
    configure().main()
