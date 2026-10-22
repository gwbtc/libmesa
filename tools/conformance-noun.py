#!/usr/bin/env python3
"""Check canonical noun fixtures; optionally compile and compare Vere pkg/ur.

Only positive, bounded fixtures and small harness-failure probes reach the C
reference. Rust's tests separately exercise hostile parsing and resource caps.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent


def run(command):
    subprocess.run(command, cwd=ROOT, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--vere-root', type=Path)
    args = parser.parse_args()
    run(['python3', 'tools/noun-vectors.py', '--check'])
    run(['cargo', 'build', '-p', 'mesa-noun', '--example', 'noun-check'])
    rows = []
    for case in json.loads((ROOT / 'vectors/noun/jam.json').read_text())['cases']:
        rows.append(f'{case["bits"]} {case["encoded"]}')
    for case in json.loads((ROOT / 'vectors/pact/v0-basic.json').read_text()):
        bits = int.from_bytes(bytes.fromhex(case['jam']), 'little').bit_length()
        rows.append(f'{bits} {case["jam"]}')
    with tempfile.TemporaryDirectory(prefix='libmesa-noun-') as directory:
        temp = Path(directory)
        binaries = [ROOT / 'target/debug/examples/noun-check']
        if args.vere_root:
            vere = args.vere_root.resolve()
            ur = vere / 'pkg/ur'
            murmur = vere / 'ext/murmur3/vendor'
            sources = [ur / f'{name}.c' for name in ('bitstream', 'hashcons', 'serial')]
            sources.append(murmur / 'murmur3.c')
            binary = temp / 'noun-reference'
            run(shlex.split(os.environ.get('CC', 'cc')) + ['-std=gnu11', '-O2', '-I', str(ur), '-I', str(murmur),
                str(ROOT / 'tools/noun-reference.c')] + [str(s) for s in sources] + ['-o', str(binary)])
            for source in sources:
                print(f'{source.relative_to(vere)} sha256 {hashlib.sha256(source.read_bytes()).hexdigest()}', flush=True)
            binaries.append(binary)
        corpus = temp / 'cases.txt'
        corpus.write_text('\n'.join(rows) + '\n')
        for binary in binaries:
            run([str(binary), str(corpus)])
            # Empty input, malformed framing, false bit length, noncanonical
            # [0 0] via reference, and garbage must fail, not silently pass.
            for index, text in enumerate(['', 'garbage\n', '0 02\n', '3 02\n', '12 3909\n', '2 zz\n']):
                bad = temp / f'bad-{index}.txt'
                bad.write_text(text)
                result = subprocess.run([str(binary), str(bad)], cwd=ROOT, capture_output=True)
                if result.returncode == 0:
                    raise SystemExit(f'{binary.name}: accepted invalid corpus {index}')
            print(f'{binary.name}: 6 harness-failure checks passed', flush=True)


if __name__ == '__main__':
    main()
