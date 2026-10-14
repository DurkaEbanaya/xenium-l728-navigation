#!/usr/bin/env python3
"""Run the proven FDL startup and read-only/RAM SOS package validation."""
import hashlib
import os
from pathlib import Path
import pwd
import struct
import subprocess
import sys
import argparse

ROOT = Path(__file__).resolve().parents[1]
TMP = Path("/tmp/opencode")


def run(command, log):
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as proc:
        for line in proc.stdout:
            sys.stdout.buffer.write(line)
            sys.stdout.buffer.flush()
            log.write(line)
            log.flush()
        if proc.wait():
            raise SystemExit("Stopped; see /tmp/opencode/l728-sos-validation.log")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--screen", action="store_true", help="validate screen-off update from installed SOS")
    parser.add_argument("--no-flash", action="store_true", help="validate no-flash update from installed screen variant")
    args = parser.parse_args()
    transition = ROOT / ("tools/sos_no_flash_transition.py" if args.no_flash else "tools/sos_screen_transition.py" if args.screen else "tools/sos_transition.py")
    if os.geteuid() != 0 or not os.environ.get("SUDO_UID"):
        raise SystemExit("Run with sudo python3 in the owner's terminal")
    tool, fdl = TMP / "spreadtrum_flash/spd_dump", TMP / "t117_fdl1.bin"
    init, diagnostic = ROOT / "build/l728-nand-init.bin", ROOT / "build/l728-diagnostic.bin"
    for path in (tool, fdl, init, diagnostic):
        if not path.is_file():
            raise SystemExit(f"Missing helper: {path}")
    preflight = subprocess.run([sys.executable, str(transition), "--check-plan"])
    if preflight.returncode:
        raise SystemExit("SOS package preflight failed; USB session has not been started.")
    with (TMP / "l728-sos-validation.log").open("wb") as log:
        # The same first exchange as the previous successful flashing session.
        run([str(tool), "--wait", "120", "--verbose", "1", "fdl", str(fdl), "0x6200",
             "read_mem", "0xffff0000", "0x8000", str(TMP / "l728-brom.bin")], log)
        if hashlib.sha256((TMP / "l728-brom.bin").read_bytes()).hexdigest() != "1c633df8793137d49b50c3ebb853ba491a29186ae613af3a4ab33fe992b02e7c":
            raise SystemExit("Unexpected BootROM identity")
        status = TMP / "l728-sos-diagnostic-status.bin"
        run([str(tool), "--wait", "0", "--fdl-loaded", "timeout", "15000", "blk_size", "512",
             "write_data", "0x80400000", "0", "4", str(init),
             "fdl", str(init), "0x10000", "fdl", str(diagnostic), "0x10000",
             "read_mem", "0x11000", "256", str(status)], log)
        values = struct.unpack("<64I", status.read_bytes())
        if values[0] != 0x4c373238 or any(values[i] for i in (1, 2, 3, 4, 5, 6, 7, 20)) or values[21] != 1:
            raise SystemExit(f"RAM NAND/ECC diagnostic failed: {values}")
        run([sys.executable, str(transition), "--validate-device"], log)
    nodes = []
    for device in Path("/sys/bus/usb/devices").iterdir():
        try:
            if (device / "idVendor").read_text().strip() == "1782" and (device / "idProduct").read_text().strip() == "4d00":
                bus = int((device / "busnum").read_text())
                number = int((device / "devnum").read_text())
                nodes.append(f"/dev/bus/usb/{bus:03d}/{number:03d}")
        except (FileNotFoundError, ValueError):
            continue
    if len(nodes) != 1:
        raise SystemExit("Expected one remaining FDL connection")
    user = pwd.getpwuid(int(os.environ["SUDO_UID"])).pw_name
    subprocess.run(["setfacl", "-m", f"u:{user}:rw", nodes[0]], check=True)
    print(f"SOS device/ECC validation complete; no NAND writes. USB access for {user}: {nodes[0]}")


if __name__ == "__main__":
    main()
