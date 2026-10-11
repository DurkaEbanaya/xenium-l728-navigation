#!/usr/bin/env python3
"""Export only the reviewed 32-KiB BootROM dump; omit all NAND partitions."""
import hashlib
from pathlib import Path
import re
import shutil

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "backup/l728-brom.bin"
DEST = ROOT / "artifacts/l728-bootrom.bin"
EXPECTED_SHA256 = "1c633df8793137d49b50c3ebb853ba491a29186ae613af3a4ab33fe992b02e7c"

def main():
    data = SOURCE.read_bytes()
    if len(data) != 32768 or hashlib.sha256(data).hexdigest() != EXPECTED_SHA256:
        raise SystemExit("BootROM source size/hash mismatch")
    if re.search(rb"(?<!\d)\d{15}(?!\d)", data):
        raise SystemExit("Possible IMEI pattern; refusing export")
    dest = DEST
    dest.parent.mkdir(exist_ok=True)
    if dest.exists() and dest.read_bytes() != data:
        raise SystemExit("Refusing to overwrite different artifact")
    shutil.copyfile(SOURCE, dest)
    print(f"Exported {dest.relative_to(ROOT)} ({len(data)} bytes, SHA256 {EXPECTED_SHA256})")

if __name__ == "__main__":
    main()
