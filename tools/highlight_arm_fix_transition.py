#!/usr/bin/env python3
"""One-byte ARM interworking fix from the installed highlight candidate."""
import json
from pathlib import Path
import highlight_transition as previous
from navigation_transition import blob

INSTALLED = "6ae6b34e4551a7fe0e6232542b83cd770f4164bc094b69fe66f851dc28ed63a0"
FIXED = "d0db149565c8a7e163c1d402ddbcd9bc0196b47d3709396689bc415e3495cabf"


def configure():
    transition = previous.configure()
    plan, before, data = transition.load()
    if plan["new_user_sha256"] != INSTALLED:
        raise RuntimeError("Expected exact installed highlight candidate")
    before = dict(before)
    for block in transition.CHANGES:
        before[block] = data[block, "after"]
    root = transition.ROOT
    folder = root / "experimental/highlight-arm-fix"
    source = blob(root / "experimental/highlight/l728-user-highlight-CANDIDATE.bin", INSTALLED, 0x7e3800)
    candidate = blob(folder / "l728-user-highlight-CANDIDATE.bin", FIXED, len(source))
    if source[0x7e1904] != 0x61 or candidate != source[:0x7e1904] + b"\x60" + source[0x7e1905:]:
        raise RuntimeError("Fix must change only allocator entry bit at user offset 0x7e1904")
    checks = json.loads((folder / "checks.json").read_text())
    if checks["output_sha256"] != FIXED or not checks["focused_execution_passed"] or not checks.get("allocator_interworking_checked"):
        raise RuntimeError("Fixed candidate has not passed actual ARM veneer regression")
    report = json.loads((folder / "manifest.json").read_text())
    if report["output_sha256"] != FIXED or report.get("allocator_entry_mode") != "ARM":
        raise RuntimeError("Incorrect fixed manifest")
    if transition.io.sha(before[0x17c]) != "e2da4674f89382008d3634c87fb4cdb691abd44435766224dee945ba4a2e59e3":
        raise RuntimeError("Wrong installed payload block")
    transition.VERIFIED = INSTALLED
    transition.CHANGES = {0x17c: [3]}
    transition.ORDER = [0x17c]
    transition.FOLDER = folder / "transition"
    transition.inputs = lambda: (before, candidate, report)
    return transition


if __name__ == "__main__":
    Path("/tmp/opencode").mkdir(exist_ok=True)
    configure().main()
