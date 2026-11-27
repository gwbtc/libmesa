#!/usr/bin/env python3
"""Check captured phase-6 outcomes and exact artifact hashes, without a ship."""
import hashlib
import json
from pathlib import Path
root = Path(__file__).resolve().parent
reference = json.loads((root / 'reference.json').read_text())
for name, expected in reference['files'].items():
    assert hashlib.sha256((root / name).read_bytes()).hexdigest() == expected, name

def report(name):
    return json.loads((root / 'evidence' / name).read_text())

for name in ['comet-session-4100.json', 'd-first-contact.json', 'fragment2-live.json',
             'rekey-live.json', 'recovery-live.json']:
    data = report(name)
    assert any(s['outcome'] == 'Accepted' for s in data['settlements']), name
assert [len(r['hex']) // 2 for r in report('public-read.json')['results']] == [24, 4115]
assert '%noun %octs 3 7' in (root / 'evidence/public-serve-result.txt').read_text()
assert any(len(e['hex']) // 2 == 4100 for e in report('reverse-fragment.json')['effects'])
assert any(s['outcome'].startswith('Rejected(') for s in report('reject2-live.json')['settlements'])
assert any(p['direction'] == 'injected-loss' for p in report('recovery-live.json')['packets'])
final = report('final-build.json')
assert len(final['settlements']) == 1 and final['settlements'][0]['outcome'] == 'Accepted'
closure = report('final-closure.json')
assert closure['flows'] == []
assert closure['closed'] == [{'class': 0, 'backward': False, 'first': 2, 'last': 2}]
assert not report('peek-long-before-fix.json')['settlements']
assert 'Profile(Encoding)' in report('peek-long-before-fix.json')['errors']
historical = json.loads((root.parent.parent / 'vectors/urbit-mesa/historical-proof.json').read_text())
assert historical['generator_sha256'] == hashlib.sha256((root / 'fixtures/historical-proof.hoon').read_bytes()).hexdigest()
trace = (root / 'evidence/comet-network.log').read_text()
assert 'cork received; delete [bone=4.120' in trace
assert 'weird poke lifes=[2 1]' in trace  # negative control: no implicit rekey
print('Pinned live artifacts: reads, messages, rejection, closure and rekey outcomes verified')
