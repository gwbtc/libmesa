#!/usr/bin/env python3
"""Read two public fixture publications through Vere's native UDP driver.

This is a capture client, not a Mesa engine. It has no keys, signs nothing,
and does not implement admission, reassembly, congestion control, or retries.
Run check/ afterward to verify the captured signatures and LSS data.
"""
import argparse
import json
import socket
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from conformance import rehash


def request(path, fragment=None):
    path = path.encode("ascii")
    # Fake ~zod, rift 0, bloq 13. This fixture has one-byte fragment indices.
    name = (b"\x10\0\0\0\r" if fragment is None
            else b"\0\0\0\0\r" + bytes([fragment]))
    name += len(path).to_bytes(2, "little") + path
    return rehash(bytes.fromhex("100100000002e067") + name)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    base = "publ/1/g/x/1/native-publish//1/"
    cases = [("public-read", request(base + "value")),
             ("multi-init", request(base + "multi"))]
    cases += [(f"multi-data-{i}", request(base + "multi", i)) for i in range(5)]
    records = []
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(("127.0.0.1", 0))
            sock.settimeout(4)
            for label, data in cases:
                sock.sendto(data, ("127.0.0.1", args.port))
                records.append({"case": label, "direction": "send", "hex": data.hex()})
                data, source = sock.recvfrom(65535)
                if source != ("127.0.0.1", args.port):
                    raise ValueError(f"unexpected source: {source}")
                records.append({"case": label, "direction": "receive",
                                "source": list(source), "width": len(data), "hex": data.hex()})
    finally:
        args.output.write_text(json.dumps(records, indent=2) + "\n")
    print("Captured seven native UDP responses")


if __name__ == "__main__":
    main()
