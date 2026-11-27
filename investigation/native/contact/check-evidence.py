#!/usr/bin/env python3
"""Replay the saved first-contact evidence. This does not start native ships."""
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
EVIDENCE = HERE / 'evidence'
reference = json.loads((HERE / 'reference.json').read_text())
for relative, expected in reference['files_sha256'].items():
    assert hashlib.sha256((HERE / relative).read_bytes()).hexdigest() == expected, relative

summaries = {}
for case, filename, summary in [
    ('held-verifier', 'packets.jsonl', 'packet-summary.json'),
    ('migration', 'packets.jsonl', 'packet-summary.json'),
    ('proof-first', 'packets.jsonl', 'packet-summary.json'),
    ('request-first', 'packets.jsonl', 'packet-summary.json'),
    ('request-first', 'public-proof.jsonl', 'public-proof-summary.json'),
]:
    result = subprocess.run([
        'cargo', 'run', '--locked', '--quiet', '--manifest-path',
        str(HERE.parent / 'check/Cargo.toml'), '--bin', 'contact-summary', '--',
        str(EVIDENCE / case / filename), str(EVIDENCE / 'public-keys.json'),
    ], capture_output=True, text=True, check=True,
        env=dict(os.environ, CARGO_TARGET_DIR=str(REPO / 'target/native-check')))
    parsed = json.loads(result.stdout)
    assert parsed == json.loads((EVIDENCE / case / summary).read_text()), case
    summaries[(case, filename)] = parsed

ids_ab = json.loads((EVIDENCE / 'identities-a-b.json').read_text())
ids_ac = json.loads((EVIDENCE / 'identities-a-c.json').read_text())
a_hex = hex(ids_ab[0]['who'])

def actions(case):
    return {(row['label'], row['name']): row['result'] for row in
            map(json.loads, (EVIDENCE / case / 'actions.jsonl').read_text().splitlines())}

def deliveries(file):
    pattern = (r'\[\s*%native-delivery\s+(~\S+)\s+(~\S+)\s+%noun\s+'
               r'\[([\d.]+)\s+(\d+)\]\s*\]')
    result = []
    for match in re.finditer(pattern, file.read_text()):
        tag = int(match[3].replace('.', ''))
        text = tag.to_bytes((tag.bit_length()+7)//8, 'little').decode('ascii')
        result.append((match[1], match[2], text, int(match[4])))
    return result

held = actions('held-verifier')
assert a_hex not in held['b', 'initial']
assert a_hex + ' %chum %alien' in held['b', 'verifier-held']
assert a_hex not in held['b', 'after-rejection']
assert a_hex + ' %chum %known' in held['b', 'after-accept-retry']
b_log = (EVIDENCE / 'held-verifier/b.log').read_text()
assert b_log.index('attestation writ failed; dropping candidate') < b_log.index('%mode %accept') < b_log.index('%native-delivery')
assert len(deliveries(EVIDENCE / 'held-verifier/b.log')) == 3
assert len(deliveries(EVIDENCE / 'held-verifier/a.log')) == 1
assert (EVIDENCE / 'held-verifier/a.log').read_text().count('[%native-result /delivery [%poke-ack p=~]]') == 3
assert b_log.count('[%native-result /delivery [%poke-ack p=~]]') == 1
assert all(r['type'] != 'not-mesa-v1' for r in summaries['held-verifier', 'packets.jsonl'])

migration = actions('migration')
for name in ['existing-legacy-state', 'legacy-after-default-change']:
    assert a_hex + ' %peer %known' in migration['b', name]
assert a_hex + ' %chum %known' in migration['b', 'after-local-migration']
migration_log = (EVIDENCE / 'migration/b.log').read_text()
assert 'no op; ignore /ge/native-receive plea' in migration_log
assert any(row[2:] == ('after-regression', 46) for row in deliveries(EVIDENCE / 'migration/b.log'))
assert 'ack missing seq=1' in (EVIDENCE / 'migration/a.log').read_text()

bad = actions('proof-first')
assert a_hex not in bad['b', 'initial']
assert a_hex + ' %peer %known' in bad['b', 'proof-only-accepted']
assert not deliveries(EVIDENCE / 'proof-first/b.log')
assert 'no op; ignore /ge/native-receive plea' in (EVIDENCE / 'proof-first/b.log').read_text()

good = actions('request-first')
assert good['b', 'before-public-proof-read'] == good['b', 'after-public-proof-read']
assert a_hex not in good['b', 'after-public-proof-read']
assert a_hex + ' %chum %known' in good['b', 'request-first-accepted']
for command in (EVIDENCE / 'request-first/commands').glob('*-b-*.hoon'):
    assert not any(task in command.read_text() for task in ['%load', '%mate', '%rege', '%ahoy'])
rows = summaries['request-first', 'packets.jsonl']
forwarded = [r for r in rows if not r.get('dropped')]
assert forwarded[0]['type'] == 'poke' and forwarded[0]['auth'] == 'mac'
assert all(r['type'] != 'not-mesa-v1' for r in forwarded)
assert any(r['type'] == 'peek' and '/pawn/proof/' in r['name']['path'] for r in forwarded)
assert any(r['type'] == 'page' and r.get('proof_signature_valid') for r in forwarded)
assert all(not (r['type'] == 'poke' and r.get('proof_signature_valid')) for r in forwarded)
assert len([r for r in rows if r.get('dropped')]) == 9
assert len(deliveries(EVIDENCE / 'request-first/b.log')) == 1
assert (ids_ac[0]['name'], ids_ac[1]['name'], 'request-first-return', 47) in deliveries(EVIDENCE / 'shared-sender.log')
assert (EVIDENCE / 'request-first/b.log').read_text().count('[%native-result /delivery [%poke-ack p=~]]') == 1
blackholes = list(map(json.loads, (EVIDENCE / 'request-first/blackholes.jsonl').read_text().splitlines()))
assert len(blackholes) == 21
assert {r['port'] for r in blackholes} == {31402, 31463}
print('Evidence replay passed: signatures, admission gates, ordering, routes, migration boundaries, and application receipts')
