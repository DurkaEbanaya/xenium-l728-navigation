import argparse
import hashlib
import pathlib
import struct
import subprocess
import time

p = argparse.ArgumentParser()
p.add_argument('source', type=pathlib.Path)
p.add_argument('output', type=pathlib.Path)
p.add_argument('--pages', type=int)
p.add_argument('--resume', action='store_true')
a = p.parse_args()
pages = a.pages or a.source.stat().st_size // 2112
assert a.source.stat().st_size % 2112 == 0
chunk = pathlib.Path('/tmp/opencode/l728-ecc-chunk.raw')
status = pathlib.Path('/tmp/opencode/l728-ecc-chunk-status.bin')
corrected = pathlib.Path('/tmp/opencode/l728-ecc-chunk-corrected.raw')
start = time.monotonic()
failures = []
first_page = a.output.stat().st_size // 2112 if a.resume else 0
if a.resume: assert a.output.stat().st_size % (2112 * 128) == 0
with a.source.open('rb') as src, a.output.open('ab' if a.resume else 'xb') as dst:
    src.seek(first_page * 2112)
    for first in range(first_page, pages, 128):
        n = min(128, pages - first)
        data = src.read(n * 2112)
        assert len(data) == n * 2112
        chunk.write_bytes(data)
        cmd = ['/tmp/opencode/spreadtrum_flash/spd_dump', '--wait', '0', '--fdl-loaded',
               'blk_size', '512',
               'write_data', '0x80400000', '0', str(len(data)), str(chunk),
               'write_word', '0x11004', str(n),
               'fdl', '/tmp/opencode/l728-correct.bin', '0x10000',
               'read_mem', '0x11000', '24', str(status),
               'read_mem', '0x80400000', str(len(data)), str(corrected)]
        for attempt in range(5):
            r = subprocess.run(cmd, capture_output=True, timeout=60)
            if not r.returncode: break
            print('Retry', first, attempt, r.stderr.decode(errors='replace'), flush=True)
            for _ in range(2):
                subprocess.run(['/tmp/opencode/spreadtrum_flash/spd_dump', '--wait', '0',
                                'read_mem', '0x11000', '24', str(status)], capture_output=True, timeout=5)
        if r.returncode:
            raise RuntimeError(r.stdout.decode(errors='replace') + r.stderr.decode(errors='replace'))
        st = struct.unpack('<6I', status.read_bytes())
        assert st[1] == n and st[2] == n * 2, st
        out = corrected.read_bytes()
        assert len(out) == len(data)
        dst.write(out)
        if st[3]: failures.append((first, st[3], st[5]))
        changes = sum(x != y for x, y in zip(data, out))
        print(f'{first:04x} pages={n} errors={st[3]} erased={st[4]} changed_bytes={changes} elapsed={time.monotonic()-start:.1f}s', flush=True)
print('Uncorrectable chunks:', failures, flush=True)
print('SHA256', hashlib.sha256(a.output.read_bytes()).hexdigest(), flush=True)
