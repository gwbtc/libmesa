#!/usr/bin/env python3
"""Evaluate a Hoon strand on an explicitly named disposable native fixture."""
import argparse
import re
import socket
import subprocess
from pathlib import Path


def run(vere, pier, source):
    escaped = source.replace('\\', '\\\\').replace("'", "\\'").replace('\n', '\\0a')
    command = "[0 %fyrd %base %khan-eval %noun %ted-eval '" + escaped + "']\n"
    data = subprocess.run([str(vere), 'eval', '-jn'], input=command.encode(),
                          capture_output=True, check=True, timeout=120).stdout
    with socket.socket(socket.AF_UNIX) as sock:
        sock.settimeout(120)
        sock.connect(str(pier / '.urb/conn.sock'))
        sock.sendall(data)

        def read(n):
            out = b''
            while len(out) < n:
                chunk = sock.recv(n - len(out))
                if not chunk:
                    raise EOFError('control socket closed')
                out += chunk
            return out

        header = read(5)
        response = header + read(int.from_bytes(header[1:], 'little'))
    result = subprocess.run([str(vere), 'eval', '-cn'], input=response,
                            capture_output=True, check=True, timeout=120).stdout.decode()
    if '%avow 0' not in result:
        result = re.sub(r'\[%leaf ([0-9 .]+) 0\]',
                        lambda m: repr(''.join(chr(int(n.replace('.', '')))
                                                for n in m[1].split())), result)
        raise RuntimeError(result)
    return result


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--vere', type=Path, required=True)
    p.add_argument('--pier', type=Path, required=True)
    p.add_argument('source', type=Path)
    p.add_argument('--install', help='Clay path, e.g. /app/native-publish/hoon')
    a = p.parse_args()
    source = a.source.read_text()
    if a.install:
        if not re.fullmatch(r'/[a-z0-9/-]+', a.install):
            p.error('install path must contain only lower-case Clay path segments')
        cord = source.replace('\\', '\\\\').replace("'", "\\'").replace('\n', '\\0a')
        source = ("=/  m  (strand ,vase)\n"
                  ";<  ~  bind:m  (send-raw-card [%pass /write %arvo %c %info %base %& ~[["
                  + a.install + " %ins %hoon !>('" + cord + "')]]])\n"
                  "(pure:m !>('written'))")
    print(run(a.vere.resolve(), a.pier.resolve(), source))
