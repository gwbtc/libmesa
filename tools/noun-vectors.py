#!/usr/bin/env python3
"""Source-derived mat, jam, and suite-C fixtures; does not call Rust or a ship.

The arithmetic below transcribes ++mat at the pinned kernel revision. Keys
and evidence in the suite-C layout cases are synthetic, not crypto vectors.
Use --check to verify the fixtures or omit it to regenerate them.
"""
import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REVISION = '734ac17cfb88e571081b84406319a17d3d5e79dd'


def mat(value):
    if value == 0:
        return 1, 1
    width = value.bit_length()
    length_width = width.bit_length()
    # cat (bex c) (mix (end (c-1) b) (lsh (c-1) a))
    prefix = 1 << length_width
    suffix = (width & ((1 << (length_width - 1)) - 1)) | (value << (length_width - 1))
    return 2 * length_width + width, prefix | (suffix << (length_width + 1))


def le(value, bits=None):
    if bits is None:
        bits = value.bit_length()
    return value.to_bytes((bits + 7) // 8, 'little').hex()


def concat(fields):
    size, value = 0, 0
    for width, field in fields:
        assert field.bit_length() <= width
        value |= field << size
        size += width
    return size, value


def jam(noun):
    """Transcribe Hoon's noun-to-first-bit-offset map and atom size choice."""
    seen = {}

    def visit(value, offset):
        previous = seen.get(value)
        if previous is not None:
            if not isinstance(value, int) or value.bit_length() > previous.bit_length():
                return concat([(2, 3), mat(previous)])
        else:
            seen[value] = offset
        if isinstance(value, int):
            return concat([(1, 0), mat(value)])
        head = visit(value[0], offset + 2)
        tail = visit(value[1], offset + 2 + head[0])
        return concat([(2, 1), head, tail])

    return visit(noun, 0)


def noun_json(noun):
    return le(noun) if isinstance(noun, int) else [noun_json(n) for n in noun]


def fixtures():
    values = [0, 1, 2, 3, 4, 7, 8, 15, 16, 127, 128, 255, 256,
              int.from_bytes(b'gw-btc', 'little'), (1 << 256) - 1]
    for bit in (31, 32, 63, 64, 255, 256, 1023, 1024):
        values.append(1 << bit)
    fields = []
    for value in values:
        size, encoded = mat(value)
        fields.append(dict(atom=le(value), bits=size, encoded=le(encoded, size)))
    layouts = []
    genesis = int.from_bytes(bytes(range(32)), 'little')
    live = int.from_bytes(bytes(range(32, 64)), 'little')
    seed = int.from_bytes(bytes(range(64, 96)), 'little')
    for name, domain, evidence in [('no-evidence', 'gw-btc', 0),
                                   ('unaligned-evidence', 'gw-btc', 0x1234),
                                   ('other-domain', 'test-pki', 0x80)]:
        domain_value = int.from_bytes(domain.encode(), 'little')
        domain_field = mat(domain_value)
        # An opaque domain tail, deliberately not a claimed valid custody format.
        tail = concat([mat(9), mat(0xdeadbeef)])
        dat_bits, dat = concat([domain_field, tail])
        data_field = mat(dat)
        offset = 8 + 256 + 256 + data_field[0]
        total, public = concat([(8, ord('c')), (256, genesis), (256, live),
                                data_field, (evidence.bit_length(), evidence)])
        ring_bits, ring = concat([(8, ord('C')), (256, seed), (256, genesis),
                                  data_field, (evidence.bit_length(), evidence)])
        assert ring_bits == total
        layouts.append(dict(name=name, pass_atom=le(public), bits=total,
                            genesis=le(genesis, 256), live=le(live, 256),
                            ring_atom=le(ring), live_seed=le(seed, 256),
                            dat=le(dat), dat_bits=dat_bits, domain=domain,
                            domain_field_bits=domain_field[0],
                            domain_tail=le(tail[1]), domain_tail_bits=tail[0],
                            xtr=le(evidence), xtr_offset=offset))
    provenance = dict(kernel_revision=REVISION,
                      source='pkg/arvo/sys/hoon.hoon ++mat; pkg/arvo/sys/zuse.hoon ++pub:ex:cric/++sec:ex:cric/++nol:nu:cric',
                      method='Independent Python transcription; not live Hoon extraction or cryptographic evidence')
    big = (1 << 256) - 1
    shared = (big, (0, 1))
    nouns = [0, 1, 2, 255, big, (0, 0), (1, 1), (big, big),
             ((0, 1), (0, 1)), (shared, shared),
             ((big, big), (big, (0, big))), ((1, 2), (3, (1, 2)))]
    jams = []
    for noun in nouns:
        size, encoded = jam(noun)
        jams.append(dict(noun=noun_json(noun), bits=size, encoded=le(encoded)))
    return {'vectors/noun/mat.json': dict(provenance=provenance, cases=fields),
            'vectors/pass/suite-c-layout.json': dict(provenance=provenance, cases=layouts),
            'vectors/noun/jam.json': dict(provenance=dict(provenance,
                source='pkg/arvo/sys/hoon.hoon ++jam/++cue/++mat'), cases=jams)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    for relative, data in fixtures().items():
        path = ROOT / relative
        content = json.dumps(data, indent=2) + '\n'
        if args.check:
            if path.read_text() != content:
                raise SystemExit(f'{relative}: fixture mismatch')
            print(f'{relative}: {len(data["cases"])} source-derived fixtures match')
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)


if __name__ == '__main__':
    main()
