#!/usr/bin/env python3
"""Boot a fresh fake Urbit, install the Hoon endpoint, and run the UDP suite."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import select
import shutil
import socket
import subprocess
import sys
import tempfile
import time

from run import ROOT

ANSI = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def port(kind):
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--vere', type=Path, required=True)
    parser.add_argument('--pill', type=Path, required=True)
    parser.add_argument('--output', type=Path, default=ROOT / 'target/urbit-interop')
    parser.add_argument('--keep-pier', action='store_true')
    args = parser.parse_args()
    binary, pill, output = args.vere.resolve(), args.pill.resolve(), args.output.resolve()
    pin = json.loads((ROOT / 'interop/reference.json').read_text())
    if sha(pill) != pin['pill_sha256']:
        raise ValueError('pill differs from the pinned fixture; see interop/reference.json')
    output.mkdir(parents=True, exist_ok=True)
    subprocess.run(['cargo', 'build', '-p', 'mesa-udp', '--bin', 'interop-peer'], cwd=ROOT, check=True)
    home = Path(tempfile.mkdtemp(prefix='lmv2-', dir='/tmp'))
    pier = home / 'zod'
    master, slave = os.openpty()
    cmd = [str(binary), '-F', 'zod', '-B', str(pill), '--loom', '31', '--http-port',
           str(port(socket.SOCK_STREAM)), '-p', str(port(socket.SOCK_DGRAM)), '--no-dock', '-c', str(pier)]
    process = subprocess.Popen(cmd, stdin=slave, stdout=slave, stderr=slave, start_new_session=True)
    os.close(slave)
    buffer = ''
    passed = False
    log = (output / 'ship.log').open('w')

    def pump():
        nonlocal buffer
        if select.select([master], [], [], .1)[0]:
            try:
                text = ANSI.sub('', os.read(master, 65536).decode(errors='replace')).replace('\r', '')
            except OSError:
                text = ''
            log.write(text)
            log.flush()
            buffer = (buffer + text)[-65536:]

    def wait(predicate, seconds, label):
        end = time.monotonic() + seconds
        report = time.monotonic() + 30
        while not predicate():
            pump()
            if process.poll() is not None or time.monotonic() > end:
                raise RuntimeError(f'{label} failed; see {output / "ship.log"}\n{buffer[-2000:]}')
            if time.monotonic() > report:
                print(f'{label}: still waiting', flush=True)
                report += 30

    def dojo(command):
        os.write(master, (command + '\n').encode())

    try:
        print(f'Booting isolated fixture at {pier}', flush=True)
        wait(lambda: 'pier (31): live' in buffer, 600, 'ship boot')
        dojo('|mount %base')
        wait(lambda: (pier / 'base/lib/default-agent.hoon').exists(), 60, 'desk mount')
        for name in ('app', 'lib'):
            shutil.copy2(ROOT / f'interop/desk/{name}/mesa-v2.hoon', pier / f'base/{name}/mesa-v2.hoon')
        buffer = ''
        dojo('|commit %base')
        wait(lambda: '/app/mesa-v2/hoon' in buffer and '/lib/mesa-v2/hoon' in buffer, 60, 'desk commit')
        dojo('|rein %base [%.y %mesa-v2]')
        wait(lambda: (pier / '.urb/dev/mesa-v2/mesa-v2').is_socket(), 120, 'agent install')
        print('Hoon endpoint installed; running bidirectional acceptance suite', flush=True)
        suite = subprocess.Popen([sys.executable, str(ROOT / 'interop/run.py'), '--pier', str(pier),
                                  '--suite', '--output', str(output / 'results.json'), '--capture', str(output / 'packets')])
        until = time.monotonic() + 180
        while suite.poll() is None:
            pump()
            if time.monotonic() > until:
                suite.kill()
                suite.wait()
                raise TimeoutError('acceptance suite deadline')
        if suite.returncode != 0:
            raise RuntimeError('acceptance suite failed')
        receipt = {'pill_sha256': sha(pill), 'vere_sha256': sha(binary),
                   'vere_version': subprocess.check_output([str(binary), '--version'], text=True).strip(),
                   'libmesa_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
                   'git_dirty': bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT)),
                   'rust_binary_sha256': sha(ROOT / 'target/debug/interop-peer'),
                   'sources': {str(p.relative_to(ROOT)): sha(p) for p in [
                       *(ROOT / 'interop/desk').rglob('*.hoon'), *(ROOT / 'interop').glob('*.py'),
                       ROOT / 'crates/mesa-udp/src/bin/interop-peer.rs', ROOT / 'Cargo.lock']},
                   'results_sha256': sha(output / 'results.json'),
                   'boundary': 'Hoon Gall endpoint over byte-only UDP/Lick bridge; native Ames unchanged'}
        (output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
        passed = True
        print(f'PASS: acceptance results, ship log, and source receipts in {output}', flush=True)
    finally:
        if process.poll() is None:
            dojo('|exit')
            end = time.monotonic() + 20
            while process.poll() is None and time.monotonic() < end:
                pump()
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
        process.wait()
        log.close()
        os.close(master)
        if passed and not args.keep_pier:
            shutil.rmtree(home)
        else:
            print(f'Fixture retained at {pier}', flush=True)


if __name__ == '__main__':
    main()
