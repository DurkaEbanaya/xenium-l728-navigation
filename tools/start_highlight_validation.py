#!/usr/bin/env python3
"""Start FDL, verify device identity and highlight ECC package without NAND writes."""
import hashlib
import argparse
import os
from pathlib import Path
import pwd
import struct
import subprocess
import sys
ROOT = Path(__file__).resolve().parents[1]
TMP = ROOT / "build"


def run(command, log):
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as proc:
        for line in proc.stdout:
            sys.stdout.buffer.write(line)
            sys.stdout.buffer.flush()
            log.write(line)
            log.flush()
        if proc.wait():
            raise SystemExit(f"Stopped; see {TMP / 'l728-highlight-validation.log'}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-tools", action="store_true", help="offline preflight; no root or USB required")
    variant = parser.add_mutually_exclusive_group()
    variant.add_argument("--arm-fix", action="store_true", help="validate one-byte allocator fix from installed highlight image")
    variant.add_argument("--display-fix", action="store_true", help="validate Display title fix from installed ARM-fix image")
    variant.add_argument("--background-fix", action="store_true", help="validate background stretch fix from installed Display-fix image")
    args = parser.parse_args()
    tool = TMP / "spreadtrum_flash/spd_dump"
    fdl = TMP / "spreadtrum_flash/t117_fdl/t117_fdl1.bin"
    init, diagnostic = ROOT / "build/l728-nand-init.bin", ROOT / "build/l728-diagnostic.bin"
    transition = ROOT / ("tools/highlight_background_fix_transition.py" if args.background_fix else
                         "tools/highlight_display_fix_transition.py" if args.display_fix else
                         "tools/highlight_arm_fix_transition.py" if args.arm_fix else "tools/highlight_transition.py")
    for path in (tool, fdl, init, diagnostic):
        if not path.is_file():
            raise SystemExit(f"Missing helper: {path}")
    if not os.access(tool, os.X_OK):
        raise SystemExit(f"Helper is not executable: {tool}")
    preflight = subprocess.run([sys.executable, "-B", str(transition), "--check-plan"])
    if preflight.returncode:
        raise SystemExit("Highlight package preflight failed; USB session has not been started.")
    if args.check_tools:
        print(f"Offline preflight passed; tools are in {TMP}. No USB access.")
        return
    if os.geteuid() != 0 or not os.environ.get("SUDO_UID"):
        raise SystemExit("Run with sudo python3 in the owner's terminal")
    with (TMP / "l728-highlight-validation.log").open("wb") as log:
        run([str(tool), "--wait", "120", "--verbose", "1", "fdl", str(fdl), "0x6200",
             "read_mem", "0xffff0000", "0x8000", str(TMP / "l728-brom.bin")], log)
        if hashlib.sha256((TMP / "l728-brom.bin").read_bytes()).hexdigest() != "1c633df8793137d49b50c3ebb853ba491a29186ae613af3a4ab33fe992b02e7c":
            raise SystemExit("Unexpected BootROM identity")
        status = TMP / "l728-highlight-diagnostic-status.bin"
        run([str(tool), "--wait", "0", "--fdl-loaded", "timeout", "15000", "blk_size", "512",
             "write_data", "0x80400000", "0", "4", str(init), "fdl", str(init), "0x10000",
             "fdl", str(diagnostic), "0x10000", "read_mem", "0x11000", "256", str(status)], log)
        values = struct.unpack("<64I", status.read_bytes())
        if values[0] != 0x4c373238 or any(values[i] for i in (1,2,3,4,5,6,7,20)) or values[21] != 1:
            raise SystemExit(f"RAM NAND/ECC diagnostic failed: {values}")
        run([sys.executable, "-B", str(transition), "--validate-device"], log)
    nodes = []
    for device in Path("/sys/bus/usb/devices").iterdir():
        try:
            if (device / "idVendor").read_text().strip() == "1782" and (device / "idProduct").read_text().strip() == "4d00":
                nodes.append(f"/dev/bus/usb/{int((device/'busnum').read_text()):03d}/{int((device/'devnum').read_text()):03d}")
        except (FileNotFoundError, ValueError):
            continue
    if len(nodes) != 1:
        raise SystemExit("Expected one remaining FDL connection")
    user = pwd.getpwuid(int(os.environ["SUDO_UID"])).pw_name
    subprocess.run(["setfacl", "-m", f"u:{user}:rw", nodes[0]], check=True)
    print(f"Highlight device/ECC validation complete; no NAND writes. USB access for {user}: {nodes[0]}")


if __name__ == "__main__":
    main()
