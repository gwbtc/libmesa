#!/usr/bin/env python3
"""Measure the compiled raw UDP host; run tools/test-ffi.sh first."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess

root = Path(__file__).resolve().parent.parent
parser = argparse.ArgumentParser()
parser.add_argument("--output", type=Path)
args = parser.parse_args()
target = root / os.environ.get("CARGO_TARGET_DIR", "target")
binary = target / "mesa-ffi-raw-udp"
sources = [p for p in (root / "crates").rglob("*") if p.suffix in (".rs", ".h", ".c")]
sources += [root / "Cargo.lock", root / "Cargo.toml"]
report = {
    "schema": 1,
    "platform": platform.platform(),
    "rustc": subprocess.check_output(["rustc", "--version"], text=True).strip(),
    "profile": "debug; preconfigured v2 signed public; not Shrine or native Urbit",
    "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
    "source_sha256": {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
                      for p in sorted(sources)},
    "runs": [],
}
for batch in (1, 16):
    output = subprocess.check_output([str(binary), str(batch)], text=True, timeout=60)
    result = json.loads(output.strip())
    assert result["completed"] == 7
    report["runs"].append(result)
text = json.dumps(report, indent=2) + "\n"
if args.output:
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(text)
else:
    print(text, end="")
