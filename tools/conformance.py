#!/usr/bin/env python3
"""Run a shared exact-byte corpus against Rust and an explicitly supplied C binary.

Build the patched Vere pact-test first. This runner never substitutes a cached
binary. Optional --output preserves the generated cases for inspection.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent


def rotate(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def murmur(data, seed):
    def mix(k):
        return rotate(k * 0xCC9E2D51 & 0xFFFFFFFF, 15) * 0x1B873593 & 0xFFFFFFFF
    h = seed
    full = len(data) // 4 * 4
    for i in range(0, full, 4):
        h ^= mix(int.from_bytes(data[i:i + 4], "little"))
        h = (rotate(h, 13) * 5 + 0xE6546B64) & 0xFFFFFFFF
    if data[full:]:
        h ^= mix(int.from_bytes(data[full:], "little"))
    h ^= len(data)
    h ^= h >> 16
    h = h * 0x85EBCA6B & 0xFFFFFFFF
    h ^= h >> 13
    h = h * 0xC2B2AE35 & 0xFFFFFFFF
    return h ^ (h >> 16)


def gum(data):
    for seed in range(0xCAFEBABE, 0xCAFEBABE + 8):
        h = murmur(data, seed)
        folded = (h >> 31) ^ (h & 0x7FFFFFFF)
        if folded:
            return folded & 0xFFFFF
    return 0x7FFF


def rehash(data):
    data = bytearray(data)
    if len(data) >= 8:
        word = int.from_bytes(data[:4], "little") & 0xFFF
        data[:4] = (word | (gum(data[8:]) << 12)).to_bytes(4, "little")
    return bytes(data)


def corpus():
    vectors = json.loads((ROOT / "vectors/pact/v0-basic.json").read_text())
    assert len(vectors) == 10
    result = []
    for vector in vectors:
        name, wire = vector["name"], bytes.fromhex(vector["wire"])
        # This independent checksum implementation must agree with live Hoon fixtures.
        assert gum(wire[8:]) == int.from_bytes(wire[:4], "little") >> 12
        result.append((name, wire))
        for n in range(len(wire)):
            result.append((f"reject:{name}-truncated-{n}", rehash(wire[:n])))
        result.append((f"reject:{name}-trailing", rehash(wire + b"\xff")))
        for flags in [0x20, 0x40, 0x80]:
            # Only init names have these reserved flags.
            if wire[8] & 0x10:
                bad = bytearray(wire)
                bad[8] |= flags
                result.append((f"reject:{name}-init-flags-{flags}", rehash(bad)))
        for field, offset, mask in [("reserved", 0, 1), ("cookie", 4, 1), ("version", 0, 0x10)]:
            bad = bytearray(wire)
            bad[offset] ^= mask
            result.append((f"reject:{name}-{field}", bytes(bad)))
        for nex in [2, 3]:
            bad = bytearray(wire)
            bad[0] = (bad[0] & ~12) | (nex << 2)
            result.append((f"reject:{name}-next-{nex}", bytes(bad)))
        bad = bytearray(wire)
        bad[0] &= 0x7F
        bad[1] &= 0xFE
        result.append((f"reject:{name}-type-zero", bytes(bad)))
        if vector["type"] != "page":
            bad = bytearray(wire)
            bad[0] |= 4
            result.append((f"reject:{name}-unexpected-lane", bytes(bad)))
    for vector in json.loads((ROOT / "vectors/pact/v0-divergence.json").read_text()):
        result.append((vector["name"], bytes.fromhex(vector["wire"])))
    for vector in json.loads((ROOT / "vectors/pact/v1-checksum.json").read_text()):
        prefix = "" if vector["checksum"] == "vere" else "reject:"
        result.append((prefix + vector["name"], bytes.fromhex(vector["wire"])))
    return result


def invoke(binary, path, should_pass=True):
    proc = subprocess.run([str(binary), str(path)], capture_output=True, text=True)
    if (proc.returncode == 0) != should_pass:
        raise RuntimeError(f"{binary} returned {proc.returncode}\n{proc.stdout}\n{proc.stderr}")
    return proc


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--c-binary", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    c_binary = args.c_binary.resolve(strict=True)
    subprocess.run(["cargo", "build", "-p", "mesa-wire", "--example", "pact-check"], cwd=ROOT, check=True)
    target = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target"))
    if not target.is_absolute():
        target = ROOT / target
    rust_binary = target / "debug/examples/pact-check"
    cases = corpus()
    contents = "".join(f"{name} {wire.hex()}\n" for name, wire in cases)
    if args.output:
        args.output.write_text(contents)
    with tempfile.TemporaryDirectory(prefix="mesa-conformance-") as tmp:
        path = Path(tmp) / "cases.txt"
        path.write_text(contents)
        for binary in [rust_binary, c_binary]:
            invoke(binary, path)
            for text in ["", "not-a-vector\n", "x 0\n", "x zz\n", "x " + "00" * 5000 + "\n"]:
                bad = Path(tmp) / "bad.txt"
                bad.write_text(text)
                invoke(binary, bad, should_pass=False)
            # A false expectation must produce a failing exit status.
            bad.write_text("reject:valid " + cases[0][1].hex() + "\n")
            invoke(binary, bad, should_pass=False)
            print(f"{binary.name}: {len(cases)} packet cases and 6 harness-failure checks passed")


if __name__ == "__main__":
    main()
