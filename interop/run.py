#!/usr/bin/env python3
"""Exercise a Rust peer and the Hoon v2 agent over UDP/Lick, with packet faults."""
import argparse
import hashlib
import json
from pathlib import Path
import select
import socket
import subprocess
import sys
import time

from newt import Frames, connect, cord, send

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from conformance import gum

FAULTS = ('clean', 'loss', 'duplicate', 'reorder', 'signature', 'spine', 'pair',
          'data', 'context', 'checksum', 'framing', 'timeout', 'bad-signature', 'cancel')


def payload(peer, length):
    return bytes(0 if i % 29 >= 24 else (i + peer) % 251 for i in range(length))


def shape(data):
    """Locate fields in this fixed, preconfigured test profile; no verification."""
    tip = (int.from_bytes(data[:4], 'little') >> 7) & 3
    proof, index = bool(data[8] & 32), data[34]
    if tip == 2:
        return tip, proof, index, None, None, None
    meta = data[50]
    kind = (meta >> 2) & 3
    auth = 51 + (1 << (meta & 3))
    fragment = auth + (66 if kind == 0 else 64 if kind == 3 else 0) + (meta >> 6)
    return tip, proof, index, kind, auth, fragment


def corrupt(data, fault):
    _, proof, _, kind, auth, fragment = shape(data)
    out = bytearray(data)
    if fault in ('signature', 'bad-signature'):
        assert proof and kind == 0
        out[auth + 2] ^= 1
    elif fault in ('spine', 'data'):
        out[fragment] ^= 1
    elif fault == 'pair':
        assert kind == 3
        out[auth] ^= 1
    elif fault == 'context':
        out[37] ^= 1  # exact path; keep the original signature
    elif fault == 'checksum':
        out[-1] ^= 1
        return bytes(out)
    else:
        raise ValueError(fault)
    head = int.from_bytes(out[:4], 'little') & 0xfff
    out[:4] = (head | (gum(out[8:]) << 12)).to_bytes(4, 'little')
    return bytes(out)


class FaultLink:
    """Only move or mutate datagrams. Keys, LSS, reads and binds live at endpoints."""
    def __init__(self, fault, transmit, cancel):
        self.fault, self.transmit, self.cancel = fault, transmit, cancel
        self.changed, self.repaired, self.pending = {}, set(), {}
        self.trace = hashlib.sha256()
        self.counts = [0, 0]
        self.cancel_sent = False
        self.late = []

    def deliver(self, direction, data):
        self.counts[direction] += 1
        self.trace.update(bytes([direction]) + len(data).to_bytes(2, 'little') + data)
        tip, proof, index, kind, auth, fragment = shape(data)
        key = (tip, proof, index)
        if self.fault in ('timeout', 'cancel') and tip == 1 and not proof and index >= 1:
            if self.fault == 'cancel':
                self.late.append((direction, data))
                if direction == 0 and not self.cancel_sent:
                    self.cancel_sent = True
                    self.cancel()
            return
        if self.fault == 'bad-signature' and tip == 1 and proof:
            self.changed[direction] = key
            self.transmit(direction, corrupt(data, self.fault))
            return
        if self.fault == 'loss' and direction not in self.changed:
            self.changed[direction] = key
            return
        if self.fault == 'duplicate' and tip == 1:
            self.changed[direction] = key
            self.transmit(direction, data)
        if self.fault == 'reorder' and tip == 1 and not proof:
            if direction == 1 and index == 0 and direction not in self.changed:
                self.changed[direction] = key
                self.pending[direction] = data
                return
            if direction == 0 and index == 0 and direction not in self.changed:
                # Stop-and-wait Hoon cannot request page 1 before page 0. Delay
                # a duplicate of 0 until after 1, exercising stale-page handling.
                self.changed[direction] = key
                self.pending[direction] = data
            if index == 1 and direction in self.pending:
                self.transmit(direction, data)
                self.transmit(direction, self.pending.pop(direction))
                self.repaired.add(direction)
                return
        target = (tip == 1 and (
            (proof and self.fault in ('signature', 'spine', 'context', 'checksum', 'framing')) or
            (kind == 3 and self.fault == 'pair') or
            (not proof and index == 0 and self.fault == 'data')))
        if target and direction not in self.changed:
            self.changed[direction] = key
            if self.fault == 'framing':
                for size in (0, 7, 49, 51, len(data) - 1):
                    self.transmit(direction, data[:size])
                self.transmit(direction, data + b'\0')
                self.transmit(direction, data + bytes(1473))
                noncanonical = bytearray(data)
                noncanonical[auth:auth + 2] = (65535).to_bytes(2, 'little')
                head = int.from_bytes(noncanonical[:4], 'little') & 0xfff
                noncanonical[:4] = (head | (gum(noncanonical[8:]) << 12)).to_bytes(4, 'little')
                self.transmit(direction, bytes(noncanonical))
            else:
                self.transmit(direction, corrupt(data, self.fault))
            return
        if direction in self.changed and self.changed[direction] == key:
            self.repaired.add(direction)
        self.transmit(direction, data)


def run(pier, length, fault='clean', capture=None):
    if not 0 <= length <= 65536 or fault not in FAULTS:
        raise ValueError('unsupported fixture')
    if fault != 'clean' and length < 4097:
        raise ValueError('fault cases require at least five leaves')
    mode = 'timeout' if fault in ('timeout', 'bad-signature') else 'cancel' if fault == 'cancel' else 'complete'
    with connect(pier / '.urb/dev/mesa-v2/mesa-v2') as lick, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.bind(('127.0.0.1', 0))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reserve:
            reserve.bind(('127.0.0.1', 0))
            remote = reserve.getsockname()
        frames = Frames()
        delivered_trace = hashlib.sha256()
        pages = {}
        def transmit(direction, data):
            delivered_trace.update(bytes([direction]) + len(data).to_bytes(2, 'little') + data)
            if fault == 'clean' and direction == 1 and shape(data)[0] == 1:
                pages[(not shape(data)[1], shape(data)[2])] = data.hex()
            if direction == 0:
                send(lick, (cord('datagram'), (len(data), int.from_bytes(data, 'little'))))
            else:
                udp.sendto(data, remote)
        link = FaultLink(fault, transmit, lambda: send(lick, (cord('cancel'), 0)))
        send(lick, (cord('start'), length))
        process, done, rust_out, terminal, status = None, None, None, None, None
        rejected = 0
        started = time.monotonic()
        try:
            while time.monotonic() - started < 28:
                for sock in select.select([lick, udp], [], [], .02)[0]:
                    if sock is udp:
                        data, source = udp.recvfrom(1473)
                        if source == remote and 50 <= len(data) <= 1472:
                            link.deliver(0, data)
                    else:
                        for mark, noun in frames.read(lick):
                            if mark == cord('ready'):
                                assert noun == length and process is None
                                process = subprocess.Popen([str(ROOT / 'target/debug/interop-peer'), '1',
                                    f'{remote[0]}:{remote[1]}', f'127.0.0.1:{udp.getsockname()[1]}', str(length), mode],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                            elif mark == cord('datagram'):
                                size, atom = noun
                                assert 50 <= size <= 1472
                                link.deliver(1, atom.to_bytes(size, 'little'))
                            elif mark == cord('done'):
                                assert mode == 'complete' and done is None, 'unexpected/repeated Hoon delivery'
                                assert 0 not in link.changed or 0 in link.repaired or fault == 'duplicate'
                                size, atom = noun
                                done = atom.to_bytes(size, 'little')
                                assert done == payload(1, length), 'Hoon delivered incorrect bytes'
                                terminal = time.monotonic()
                                send(lick, (cord('status'), 0))
                            elif mark in (cord('timeout'), cord('cancelled')):
                                if process is None:
                                    continue
                                assert mode != 'complete' and terminal is None and done is None
                                assert mark == cord('cancelled' if mode == 'cancel' else 'timeout')
                                terminal = time.monotonic()
                                # Previously valid pages arriving after cancellation cannot deliver.
                                for direction, data in link.late:
                                    if direction == 0:
                                        transmit(direction, data)
                                send(lick, (cord('status'), 0))
                            elif mark == cord('status'):
                                assert noun == (1, 0), ('Hoon read state not released', noun)
                                status = noun
                            elif mark == cord('rejected'):
                                rejected += 1
                if mode == 'cancel' and terminal and time.monotonic() - terminal > .5 and link.late:
                    for direction, data in link.late:
                        if direction == 1:
                            transmit(direction, data)
                    link.late.clear()
                if process is not None and process.poll() is not None and rust_out is None:
                    rust_out, err = process.communicate()
                    assert process.returncode == 0, (rust_out, err, link.counts, rejected)
                    if mode == 'complete':
                        expected = f'peer=1 bytes={length} sha256={hashlib.sha256(payload(2, length)).hexdigest()} signature=verified lss=verified'
                    else:
                        expected = f'peer=1 outcome={mode} delivered=0'
                    assert rust_out.strip() == expected, (rust_out, expected)
                if rust_out is not None and terminal and status and time.monotonic() - terminal >= .5:
                    if fault not in ('clean', 'cancel', 'timeout', 'bad-signature'):
                        assert set(link.changed) == {0, 1}, 'fault missed a direction'
                        if fault != 'duplicate':
                            assert link.repaired == {0, 1}, 'no successful repair/reorder in a direction'
                    if fault in ('signature', 'spine', 'pair', 'data', 'context', 'checksum', 'framing', 'bad-signature'):
                        assert rejected > 0, 'Hoon did not reject mutation'
                    if capture is not None and fault == 'clean':
                        capture.mkdir(parents=True, exist_ok=True)
                        (capture / f'{length}.json').write_text(json.dumps({
                            'length': length, 'pages': [pages[key] for key in sorted(pages)]
                        }, indent=2) + '\n')
                    return {'bytes': length, 'fault': fault, 'rust_receipt': rust_out.strip(),
                            'hoon_sha256': hashlib.sha256(done).hexdigest() if done is not None else None,
                            'hoon_terminal': mode, 'released': True, 'packets': link.counts,
                            'hoon_rejected': rejected, 'emitted_trace_sha256': link.trace.hexdigest(),
                            'delivered_trace_sha256': delivered_trace.hexdigest()}
            raise TimeoutError((link.counts, rejected, mode, rust_out, terminal))
        finally:
            if status is None:
                send(lick, (cord('cancel'), 0))
                deadline = time.monotonic() + 3
                ack = False
                while not ack and time.monotonic() < deadline:
                    if select.select([lick], [], [], .1)[0]:
                        ack = any(mark == cord('cancelled') for mark, _ in frames.read(lick))
            if process is not None:
                if process.poll() is None:
                    process.kill()
                process.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pier', type=Path, required=True)
    parser.add_argument('--length', type=int, default=17425)
    parser.add_argument('--fault', choices=FAULTS, default='clean')
    parser.add_argument('--suite', action='store_true')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--capture', type=Path)
    args = parser.parse_args()
    cases = [(n, 'clean') for n in [0, 1, 29, 1024, 1025, 3072, 17425, 65536]] if args.suite else []
    if args.suite:
        cases += [(17425, f) for f in FAULTS if f != 'clean']
    else:
        cases = [(args.length, args.fault)]
    results = []
    for length, fault in cases:
        result = run(args.pier, length, fault, args.capture)
        results.append(result)
        print(json.dumps(result), flush=True)
    if args.output:
        args.output.write_text(json.dumps(results, indent=2) + '\n')


if __name__ == '__main__':
    main()
