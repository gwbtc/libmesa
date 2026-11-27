#!/usr/bin/env python3
"""Check preserved process-crash evidence; does not run live peers."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess


def main():
    root = Path(__file__).resolve().parent
    repo = root.parents[2]
    reference = json.loads((root / 'reference.json').read_text())
    assert reference['files_sha256'], 'empty evidence inventory'
    for name, expected in reference['files_sha256'].items():
        assert hashlib.sha256((root / name).read_bytes()).hexdigest() == expected, name

    def rows(name):
        return [json.loads(x) for x in (root / 'evidence' / name).read_text().splitlines()]

    actions = rows('actions.jsonl')
    by_name = {(x['label'], x['name']): x for x in actions}

    def result(label, name):
        return by_name[label, name]['result'].strip()

    def counts(label, name, expected):
        match = re.fullmatch(r'\[0 %avow 0 %noun (\d+) (\d+) (\d+)\]', result(label, name))
        assert match and tuple(map(int, match.groups())) == expected, (label, name)

    for label, name, expected in [
        ('a', 'pre-crash', (0, 1, 0)),
        ('b', 'pre-crash', (1, 0, 1)),
        ('b', 'after-receiver-kill', (2, 0, 2)),
        ('a', 'ack-still-lost', (0, 1, 0)),
        ('a', 'receiver-ack-recovered', (0, 2, 0)),
        ('b', 'receiver-duplicate-suppressed', (2, 0, 2)),
        ('b', 'after-sender-kill', (3, 0, 3)),
        ('a', 'sender-outbox-recovered', (0, 4, 0)),
        ('b', 'sender-message-once', (4, 0, 4)),
        ('a', 'nack-still-lost', (0, 4, 0)),
        ('b', 'rejection-restored', (4, 0, 4)),
        ('a', 'after-closure-restart-counts', (0, 9, 0)),
        ('b', 'after-closure-restart-counts', (5, 0, 5)),
        ('b', 'closed-replay-no-delivery', (5, 0, 5)),
        ('a', 'positive-control-result', (0, 11, 0)),
        ('b', 'positive-control-delivered', (6, 0, 6)),
        ('a', 'final-counts', (0, 11, 0)),
        ('b', 'final-counts', (6, 0, 6)),
    ]:
        counts(label, name, expected)
    # Hoon %.y is atom 0: the fifth sender result is a negative poke ACK.
    assert result('a', 'rejection-confirmed') == '[0 %avow 0 %noun 5 0]'
    for label in 'ab':
        before = result(label, 'before-closure-kill')
        assert before == result(label, 'after-closure-restart')
        assert '12' in before and '16' in before
    assert result('b', 'final-closed') == result('b', 'before-closure-kill')

    lifecycle = rows('lifecycle.jsonl')
    kills = [x for x in lifecycle if x['action'] == 'SIGKILL-on-udp']
    assert [x['label'] for x in kills] == ['b', 'a', 'b']
    assert len([x for x in lifecycle if x['action'] == 'SIGKILL-after-closed-snapshot']) == 2
    packets = rows('packets.jsonl')
    assert len(packets) == 56
    for kill in kills:
        assert kill['dropped']
        assert any(p['hex'] == kill['packet_hex'] and p['dropped']
                   and p['time_ns'] < kill['time_ns'] for p in packets)
        assert any(x['action'] == 'start' and x['label'] == kill['label']
                   and x['time_ns'] > kill['time_ns'] for x in lifecycle)
    injected = [x for x in packets if x.get('injected')]
    original = json.loads((root / 'evidence/closed-replay-packet.json').read_text())
    assert len(injected) == 4 and all(x['hex'] == original['hex'] for x in injected)
    assert any(x['hex'] == original['hex'] and not x.get('injected') for x in packets)
    assert sum(x['time_ns'] > by_name['b', 'positive-control-delivered']['time_ns']
               for x in injected) == 3

    env = dict(os.environ, CARGO_TARGET_DIR=str(repo / 'target/native-check'))
    output = subprocess.check_output([
        'cargo', 'run', '--locked', '--quiet', '--manifest-path',
        str(root.parent / 'check/Cargo.toml'), '--bin', 'contact-summary', '--',
        str(root / 'evidence/packets.jsonl'),
        str(root.parent / 'contact/evidence/public-keys.json'),
    ], cwd=repo, env=env)
    parsed = json.loads(output)
    assert parsed == json.loads((root / 'evidence/packet-summary.json').read_text())
    assert len(parsed) == 56
    assert all(p['type'] in {'peek', 'page', 'poke'} for p in parsed)
    print('PASS: four recorded crash/recovery cases; five SIGKILLs; '
          '56 Mesa-v1 datagrams; closed replay plus new-flow positive control.')
    print('Offline evidence check only; no new live crash run or independent private MAC check.')


if __name__ == '__main__':
    main()
