#!/usr/bin/env python3
import argparse
import hashlib
from pathlib import Path
import struct
import subprocess
import time

parser = argparse.ArgumentParser()
parser.add_argument("output", type=Path)
parser.add_argument("--first", type=lambda s: int(s, 0), default=0)
parser.add_argument("--pages", type=lambda s: int(s, 0), required=True)
args = parser.parse_args()
tool = "/tmp/opencode/spreadtrum_flash/spd_dump"
helper = "/tmp/opencode/l728-reader.bin"
result = Path("/tmp/opencode/l728-chunk-result.bin")
chunk = Path("/tmp/opencode/l728-chunk.bin")
if args.output.exists():
    raise SystemExit(f"Refusing to overwrite {args.output}")
with args.output.open("xb") as out:
    started = time.monotonic()
    for first in range(args.first, args.first + args.pages, 128):
        count = min(128, args.first + args.pages - first)
        command = [tool, "--wait", "0", "--fdl-loaded",
                   "write_word", "0x11000", str(first),
                   "write_word", "0x11004", str(count),
                   "fdl", helper, "0x10000",
                   "read_mem", "0x11000", "24", str(result),
                   "read_mem", "0x80400000", str(count * 2560), str(chunk)]
        run = subprocess.run(command, capture_output=True, timeout=60)
        if run.returncode:
            raise SystemExit(run.stderr.decode(errors="replace"))
        values = struct.unpack("<6I", result.read_bytes())
        if values[:4] != (first, count, count, 0):
            raise SystemExit(f"Incomplete chunk: {values!r}")
        data = chunk.read_bytes()
        if len(data) != count * 2560:
            raise SystemExit("Incorrect chunk length")
        for page in range(count):
            out.write(data[page * 2560:page * 2560 + 2112])
        out.flush()
        elapsed = time.monotonic() - started
        print(f"Pages {first:#x}..{first + count - 1:#x}, saved {out.tell()} bytes, {elapsed:.1f}s", flush=True)
print("SHA256", hashlib.file_digest(args.output.open("rb"), "sha256").hexdigest())
