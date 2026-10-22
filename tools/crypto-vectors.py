#!/usr/bin/env python3
"""Run pinned Hoon in Vere eval, independently decode jam, record public vectors.

Requires a local Vere executable with `eval --jam --newt` and a checkout of the
pinned kernel. No pier, network, or real identity secrets are used. The evaluator
may use jets; this is execution of pinned Hoon with Vere, not a jet-free proof.
"""
import argparse
import hashlib
import json
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
PIN = "734ac17cfb88e571081b84406319a17d3d5e79dd"
FIELDS = ["seed", "genesis", "live", "dat", "evidence", "ring", "pass",
          "name_key", "name128", "message", "signature", "octets_signature",
          "peer_public", "shared", "reverse_shared"]
WIDTHS = {"seed": 32, "genesis": 32, "live": 32, "name_key": 32,
          "name128": 16, "signature": 64, "octets_signature": 64,
          "peer_public": 32, "shared": 32, "reverse_shared": 32}


def cue(data):
    """Small independent decoder used only for bounded trusted fixture output."""
    atom = int.from_bytes(data, "little")
    pos, memo = 0, {}

    def bits(count):
        nonlocal pos
        if count < 0 or pos + count > len(data) * 8:
            raise ValueError("truncated jam")
        value = (atom >> pos) & ((1 << count) - 1)
        pos += count
        return value

    def rub():
        zeros = 0
        while bits(1) == 0:
            zeros += 1
        if zeros == 0:
            return 0
        length = (1 << (zeros - 1)) | bits(zeros - 1)
        return bits(length)

    def noun():
        start = pos
        if bits(1) == 0:
            value = rub()
        elif bits(1) == 0:
            value = (noun(), noun())
        else:
            return memo[rub()]
        memo[start] = value
        return value

    result = noun()
    if pos != atom.bit_length():
        raise ValueError("trailing jam data")
    return result


def items(noun):
    result = []
    while isinstance(noun, tuple):
        value, noun = noun
        result.append(value)
    if noun != 0:
        raise ValueError("improper list")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--urbit-source", type=pathlib.Path, required=True)
    parser.add_argument("--vere-binary", type=pathlib.Path, required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    sources = {}
    expression = b""
    for name in ("lull", "zuse"):
        path = "pkg/arvo/sys/" + name + ".hoon"
        # Read the commit itself; a dirty checkout cannot change the oracle.
        data = subprocess.check_output(["git", "-C", str(args.urbit_source),
                                        "show", PIN + ":" + path])
        sources[path] = hashlib.sha256(data).hexdigest()
        expression += b"=>\n" + data + b"\n"
    body = (ROOT / "tools/suite-c-reference.hoon").read_bytes()
    expression += body
    output = subprocess.run([str(args.vere_binary.resolve()), "eval", "--loom", "31",
                             "--jam", "--newt"], input=expression,
                            capture_output=True, timeout=180, check=True)
    raw = output.stdout
    if len(raw) < 5 or raw[0] != 0 or int.from_bytes(raw[1:5], "little") != len(raw) - 5:
        raise RuntimeError("invalid evaluator output: " + output.stderr.decode(errors="replace"))
    if len(raw) > 1024 * 1024:
        raise ValueError("oversized evaluator output")
    rows = []
    for row in items(cue(raw[5:])):
        values = items(row)
        if len(values) != len(FIELDS):
            raise ValueError("wrong row schema")
        rows.append({field: value.to_bytes(WIDTHS.get(field, (value.bit_length() + 7) // 8),
                                          "little").hex()
                     for field, value in zip(FIELDS, values)})
    result = {"provenance": {"kernel_commit": PIN, "source_sha256": sources,
                            "generator_hoon_sha256": hashlib.sha256(body).hexdigest(),
                            "vere_sha256": hashlib.sha256(args.vere_binary.read_bytes()).hexdigest(),
                            "method": "pinned Lull and Zuse evaluated by Vere; jets permitted"},
              "encoding": "hex bytes in little-endian order; seed/key/signature/name fields fixed width",
              "warning": "Public test seeds. Synthetic domain payload; no authority verification.",
              "vectors": rows}
    target = ROOT / "vectors/crypto/suite-c.json"
    if args.check:
        expected = json.loads(target.read_text())
        # Different Vere builds can reproduce the bytes; report their hash separately.
        for key in ("kernel_commit", "source_sha256", "generator_hoon_sha256"):
            assert result["provenance"][key] == expected["provenance"][key], key
        assert rows == expected["vectors"], "crypto vectors differ"
        print(f"{len(rows)} Hoon crypto cases match; Vere sha256={result['provenance']['vere_sha256']}")
    else:
        target.write_text(json.dumps(result, indent=2) + "\n")
        print(f"Wrote {len(rows)} Hoon crypto cases to {target}")


if __name__ == "__main__":
    main()
