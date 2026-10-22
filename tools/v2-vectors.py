#!/usr/bin/env python3
"""Hand-specified v2 body bytes + independent Python checksum; never calls Rust.

Use --check to compare the checked-in fixtures, or no arguments to write them.
Short signature fixtures test framing only, not cryptographic validity.
"""
import argparse
import json
from pathlib import Path
from conformance import gum

ROOT = Path(__file__).resolve().parent.parent


def fixtures():
    zero = '00' * 16
    one = '01' + '00' * 15
    two = '02' + '00' * 15
    high = '00' * 15 + '80'
    # meta, domain length/tag, fixed name, rift, bloq, optional index, path.
    a = '10 06 67772d627463 ' + zero + ' 01 0d 0100 61'
    one_a = '10 06 67772d627463 ' + one + ' 01 0d 0100 61'
    cases = [
        ('peek-zero', 2, 0, 0, a),
        ('peek-high-unknown-domain', 2, 0, 7,
         '40 07 6e65772d706b69 ' + high + ' ff 0d 0001 0100 7a'),
        ('peek-max-fields', 2, 0, 0,
         'ec 3f 61' + '62' * 62 + ' ' + 'ff' * 16 + ' ffffffff ff '
         + 'ff' * 8 + ' 0300 726177'),
        ('page-short-signature', 1, 0, 0,
         one_a + ' 40 03 0300 112233 03 aabb00'),
        ('page-mac-zero-trailer', 1, 1, 3,
         one_a + ' 48 02 000102030405060708090a0b0c0d0e0f 02 4400 0100007f5000'),
        ('page-empty-none', 1, 0, 0, a + ' 04 00'),
        ('page-pair', 1, 0, 0, a + ' 4c 01 ' + 'ab' * 64 + ' 01 00'),
        ('poke-distinct-domains', 3, 0, 1,
         '10 07 617a696d757468 ' + two + ' 01 0d 0300 61636b '
         + one_a + ' 44 01 01 42'),
    ]
    result = []
    for name, kind, next_tag, hop, body_hex in cases:
        body = bytes.fromhex(body_hex)
        word = (next_tag << 2) | (2 << 4) | (kind << 7) | (hop << 9) | (gum(body) << 12)
        wire = word.to_bytes(4, 'little') + bytes.fromhex('0002e067') + body
        result.append(dict(name=name, type={1: 'page', 2: 'peek', 3: 'poke'}[kind],
                           hop=hop, len=len(wire), body=body.hex(), wire=wire.hex()))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    path = ROOT / 'vectors/pact/v2-basic.json'
    content = json.dumps(fixtures(), indent=2) + '\n'
    if args.check:
        if path.read_text() != content:
            raise SystemExit('v2 fixture bytes differ from the independent reference')
        print('8 v2 byte fixtures match the independent reference')
    else:
        path.write_text(content)
        print(f'Wrote {path}')


if __name__ == '__main__':
    main()
