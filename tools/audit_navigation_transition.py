#!/usr/bin/env python3
"""Offline-only audit of the previous navigation image to the current candidate.

This reconstructs the previously prepared user image from local backups and
computes the changed logical/physical pages. It does not create ECC, NAND block
images, commands, or write to a device; its report is explicitly non-flashable.
"""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PAGE_BYTES = 2112
MAIN_BYTES = 2048
PAGES_PER_BLOCK = 64
USER_START_PAGE = 0x4F40
EXPECTED_OLD_PATCH = "058b5cb1ce2bf985a218a9729d2adaeefe5006e8ad1ec3d396fad148e1737021"
EXPECTED_RAW = "76aef2f60b8f64610012f43dadd49f638d3ea2b727a2c413de45fa5df00b8326"
LEGACY_BLOCKS = {0x13d, 0x143, 0x145, 0x14c, 0x17a, 0x17c}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    backup = ROOT / "backup"
    blocks_dir = ROOT / "experimental/blocks"
    original = (backup / "l728-user-ecc.bin").read_bytes()
    raw = (backup / "l728-nand-ecc.raw").read_bytes()
    manifest = json.loads((ROOT / "experimental/manifest.json").read_text())
    plan = json.loads((blocks_dir / "plan.json").read_text())
    candidate = (ROOT / "experimental/l728-user-navigation-UNTESTED.bin").read_bytes()

    if sha(original) != manifest["source_sha256"]:
        raise SystemExit("Original user image hash does not match candidate manifest")
    if sha(candidate) != manifest["output_sha256"]:
        raise SystemExit("Candidate image hash does not match its manifest")
    if sha(original) != plan["original_user_sha256"]:
        raise SystemExit("Legacy plan uses a different original image")
    if len(original) != len(candidate) or len(original) % MAIN_BYTES:
        raise SystemExit("Unexpected user image size")
    if len(raw) != 65536 * PAGE_BYTES or sha(raw) != EXPECTED_RAW:
        raise SystemExit("Unexpected raw NAND size")
    if len(plan["blocks"]) != 6 or {e["block"] for e in plan["blocks"]} != LEGACY_BLOCKS:
        raise SystemExit("Unexpected legacy block allowlist")

    # Independently verify the logical-to-physical page mapping from backup.
    extracted = b"".join(
        raw[p * PAGE_BYTES:p * PAGE_BYTES + MAIN_BYTES]
        for p in range(USER_START_PAGE, USER_START_PAGE + len(original) // MAIN_BYTES)
    )
    if extracted != original:
        raise SystemExit("Backup NAND no longer matches the original user image")

    old_installed = bytearray(original)
    for entry in plan["blocks"]:
        block = entry["block"]
        if Path(entry["modified_file"]).name != entry["modified_file"]:
            raise SystemExit("Legacy block path outside plan folder")
        content = (blocks_dir / entry["modified_file"]).read_bytes()
        if len(content) != PAGES_PER_BLOCK * PAGE_BYTES or sha(content) != entry["modified_sha256"]:
            raise SystemExit(f"Invalid legacy modified block {block:#x}")
        block_first_page = block * PAGES_PER_BLOCK
        for page_in_block in range(PAGES_PER_BLOCK):
            physical_page = block_first_page + page_in_block
            user_page = physical_page - USER_START_PAGE
            if 0 <= user_page < len(old_installed) // MAIN_BYTES:
                start = page_in_block * PAGE_BYTES
                dst = user_page * MAIN_BYTES
                old_installed[dst:dst + MAIN_BYTES] = content[start:start + MAIN_BYTES]

    old_hash = sha(old_installed)
    if old_hash != EXPECTED_OLD_PATCH or old_hash != plan["modified_user_sha256"]:
        raise SystemExit("Legacy block snapshots do not reconstruct the known old patch")

    # The old apply journal is evidence only of historical writes/readback, not
    # a current-device read. Keep that distinction explicit in the report.
    apply_journals = sorted(blocks_dir.glob("apply-*.json"))
    verified_journals = []
    expected_blocks = {e["block"] for e in plan["blocks"]}
    for path in apply_journals:
        journal = json.loads(path.read_text())
        completed = {
            record["block"]: record.get("sha256")
            for record in journal.get("records", [])
            if record.get("readback_verified") == "modified"
        }
        if journal.get("mode") == "apply" and set(completed) == expected_blocks:
            if all(completed[e["block"]] == e["modified_sha256"] for e in plan["blocks"]):
                verified_journals.append(path.name)

    changed_pages = []
    for user_page in range(len(candidate) // MAIN_BYTES):
        old_page = old_installed[user_page * MAIN_BYTES:(user_page + 1) * MAIN_BYTES]
        new_page = candidate[user_page * MAIN_BYTES:(user_page + 1) * MAIN_BYTES]
        if old_page != new_page:
            physical_page = USER_START_PAGE + user_page
            changed_pages.append({
                "user_page": user_page,
                "physical_page": physical_page,
                "physical_page_hex": hex(physical_page),
                "page_in_block": physical_page % PAGES_PER_BLOCK,
                "block": physical_page // PAGES_PER_BLOCK,
                "block_hex": hex(physical_page // PAGES_PER_BLOCK),
                "old_main_sha256": sha(old_page),
                "new_main_sha256": sha(new_page),
            })

    report = {
        "status": "OFFLINE TRANSITION AUDIT ONLY; NO NEW ECC; NOT FLASHABLE",
        "device_accessed": False,
        "original_user_sha256": sha(original),
        "reconstructed_previous_patch_sha256": old_hash,
        "candidate_user_sha256": sha(candidate),
        "legacy_apply_journal_readbacks": verified_journals,
        "journal_scope_note": "Historical journal evidence only; no current-device readback was performed.",
        "logical_to_physical_map_verified_from_private_backup": True,
        "changed_user_pages": changed_pages,
        "changed_blocks": sorted({p["block"] for p in changed_pages}),
        "safe_to_flash": False,
        "missing_requirements": [
            "This offline audit does not read the current device or generate/validate its target ECC blocks.",
            "Use navigation_transition.py and private per-device snapshots for actual transition preparation.",
        ],
        "historical_device_test_note": "Applied and owner-tested on one L728 on 2026-10-12; this script does not reproduce that device verification.",
    }
    out = ROOT / "experimental/transition-audit.json"
    out.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
