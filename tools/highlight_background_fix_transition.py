#!/usr/bin/env python3
"""Preserve sabm stretch semantics, starting from installed Display-fix."""
import json
from pathlib import Path
import highlight_display_fix_transition as previous
from navigation_transition import blob

INSTALLED = "57d62712c24d8d62221c295f28ec28467d8b00b7638a68a6a3a7da2e4c2ff894"
FIXED = "34a2d7ab0a09ea41faabd5b232d25f0a8e6dbc8dcd01eeb3aa4bd41625d8b41c"
CHANGES = {0x13d:[0],0x155:[55],0x17c:[3,4,5,6]}


def configure():
    transition=previous.configure()
    plan,before,data=transition.load()
    if plan["new_user_sha256"]!=INSTALLED:
        raise RuntimeError("Expected installed Display-fix image")
    before=dict(before)
    for block in transition.CHANGES:
        before[block]=data[block,"after"]
    root=transition.ROOT
    folder=root/"experimental/highlight-background-fix"
    source=blob(root/"experimental/highlight-display-fix/l728-user-highlight-CANDIDATE.bin",INSTALLED,0x7e3800)
    candidate=blob(folder/"l728-user-highlight-CANDIDATE.bin",FIXED,len(source))
    report=json.loads((folder/"manifest.json").read_text())
    old_report=json.loads((root/"experimental/highlight-display-fix/manifest.json").read_text())
    checks=json.loads((folder/"checks.json").read_text())
    if report["output_sha256"]!=FIXED or report["hooks"]!=old_report["hooks"]:
        raise RuntimeError("Wrong image or unexpectedly changed renderer hooks")
    if checks["output_sha256"]!=FIXED or not all(checks.get(k) for k in (
            "focused_execution_passed","allocator_interworking_checked",
            "native_selector_initialization_checked","native_background_geometry_checked")):
        raise RuntimeError("Exact candidate must pass native background and selector checks")
    reconstructed=bytearray(source)
    for block,packed in before.items():
        for p in range(64):
            logical=block*64+p-transition.START
            if 0<=logical<len(source)//2048:
                reconstructed[logical*2048:(logical+1)*2048]=packed[p*2112:p*2112+2048]
    if reconstructed!=source:
        raise RuntimeError("Snapshots do not reconstruct installed Display-fix")
    allowed=set(range(0x30,0x34))|set(range(0x31be64,0x31be68))
    for m in (old_report,report):
        allowed.update(range(m["payload_offset"],m["payload_offset"]+m["payload_bytes"]))
    if any(a!=b and p not in allowed for p,(a,b) in enumerate(zip(source,candidate))):
        raise RuntimeError("Changes outside image header, Display pointer and payload")
    actual={}
    for p in range(len(source)//2048):
        if source[p*2048:(p+1)*2048]!=candidate[p*2048:(p+1)*2048]:
            actual.setdefault((transition.START+p)//64,[]).append((transition.START+p)%64)
    if actual!=CHANGES:
        raise RuntimeError(f"Unexpected background fix pages: {actual}")
    transition.VERIFIED=INSTALLED
    transition.CHANGES=CHANGES
    transition.ORDER=[0x17c,0x155,0x13d]
    transition.FOLDER=folder/"transition"
    transition.inputs=lambda:(before,candidate,report)
    return transition


if __name__=="__main__":
    Path("/tmp/opencode").mkdir(exist_ok=True)
    configure().main()
