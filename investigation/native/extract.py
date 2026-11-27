#!/usr/bin/env python3
"""Extract packet bytes from the preserved Hoon trace, without signing them."""
import argparse
import hashlib
import json
import re
from pathlib import Path


def extract(text):
    pattern = (r"\[\s*%native-packet\s+(~\S+)\s+%(\S+)\s+([\d.]+)"
               r"\s+(0x[0-9a-f.]+)\s*\]")
    packets = []
    for match in re.finditer(pattern, text):
        cases = re.findall(r"\[%native-case %(\S+)\]", text[:match.start()])
        width = int(match[3].replace(".", ""))
        data = int(match[4].replace(".", ""), 16).to_bytes(width, "little")
        packets.append({"case": cases[-1], "sender": match[1], "kind": match[2],
                        "width": width, "hex": data.hex(),
                        "sha256": hashlib.sha256(data).hexdigest()})
    if not packets:
        raise ValueError("no packet captures")
    return packets


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.write_text(json.dumps(extract(args.trace.read_text()), indent=2) + "\n")
