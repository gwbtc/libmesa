#!/usr/bin/env python3
"""Exercise v2 fixtures and malformed packets against the v2 CLI, not Vere."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
from conformance import ROOT, invoke, rehash


def main():
    subprocess.run(['python3', 'tools/v2-vectors.py', '--check'], cwd=ROOT, check=True)
    subprocess.run(['cargo', 'build', '-p', 'mesa-wire', '--example', 'pact-v2-check'], cwd=ROOT, check=True)
    target = Path(os.environ.get('CARGO_TARGET_DIR', ROOT / 'target'))
    if not target.is_absolute():
        target = ROOT / target
    binary = target / 'debug/examples/pact-v2-check'
    vectors = json.loads((ROOT / 'vectors/pact/v2-basic.json').read_text())
    cases = []
    for v in vectors:
        name, wire = v['name'], bytes.fromhex(v['wire'])
        cases.append((name, wire))
        for n in range(len(wire)):
            cases.append((f'reject:{name}-truncated-{n}', rehash(wire[:n])))
        cases.append((f'reject:{name}-trailing', rehash(wire + b'\0')))
        for bit in [1, 2]:
            bad = bytearray(wire)
            bad[8] |= bit
            cases.append((f'reject:{name}-reserved-{bit}', rehash(bad)))
        for version in [0, 1, 3, 4, 5, 6, 7]:
            bad = bytearray(wire)
            bad[0] = (bad[0] & ~0x70) | (version << 4)
            cases.append((f'reject:{name}-version-{version}', bytes(bad)))
    for v in json.loads((ROOT / 'vectors/pact/v0-basic.json').read_text()):
        cases.append(('reject:legacy-' + v['name'], bytes.fromhex(v['wire'])))
    with tempfile.TemporaryDirectory(prefix='mesa-v2-conformance-') as tmp:
        path = Path(tmp) / 'cases.txt'
        path.write_text(''.join(f'{name} {wire.hex()}\n' for name, wire in cases))
        invoke(binary, path)
        for text in ['', 'not-a-vector\n', 'x 0\n', 'x zz\n', 'x ' + '00' * 5000 + '\n',
                     'reject:valid ' + cases[0][1].hex() + '\n']:
            path.write_text(text)
            invoke(binary, path, should_pass=False)
    print(f'v2: {len(cases)} packet cases and 6 harness-failure checks passed')


if __name__ == '__main__':
    main()
