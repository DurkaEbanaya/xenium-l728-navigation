#!/usr/bin/env python3
"""Load the SRAM diagnostic and grant access to this USB connection only."""
import os
from pathlib import Path
import pwd
import subprocess
import sys

if os.geteuid() != 0 or not os.environ.get("SUDO_UID"):
    sys.exit("Run this script with sudo python3")

command = [
    "/tmp/opencode/spreadtrum_flash/spd_dump", "--wait", "120", "--verbose", "1",
    "fdl", "/tmp/opencode/spreadtrum_flash-nand/t117_fdl/t117_fdl1.bin", "0x6200",
    # This loader initializes DRAM while reading its diagnostic pseudo-address.
    "read_mem", "0xf0000002", "32", "/tmp/opencode/l728-session-init.bin",
    "fdl", "/tmp/opencode/l728-diagnostic.bin", "0x10000",
    "read_mem", "0x11000", "256", "/tmp/opencode/l728-diagnostic-result.bin",
    "read_mem", "0x80400000", "0x3500", "/tmp/opencode/l728-diagnostic-data.bin",
]
with Path("/tmp/opencode/l728-diagnostic.log").open("wb") as log:
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as proc:
        for line in proc.stdout:
            sys.stdout.buffer.write(line)
            sys.stdout.buffer.flush()
            log.write(line)
            log.flush()
        code = proc.wait()
if code:
    sys.exit(code)

nodes = []
for device in Path("/sys/bus/usb/devices").iterdir():
    try:
        if (device / "idVendor").read_text().strip() != "1782":
            continue
        if (device / "idProduct").read_text().strip() != "4d00":
            continue
        bus = int((device / "busnum").read_text())
        number = int((device / "devnum").read_text())
        nodes.append(f"/dev/bus/usb/{bus:03d}/{number:03d}")
    except (FileNotFoundError, ValueError):
        continue
if len(nodes) != 1:
    sys.exit(f"Expected one diagnostic USB connection, found {len(nodes)}")
user = pwd.getpwuid(int(os.environ["SUDO_UID"])).pw_name
subprocess.run(["setfacl", "-m", f"u:{user}:rw", nodes[0]], check=True)
print(f"Temporary diagnostic USB access for {user}: {nodes[0]}")
