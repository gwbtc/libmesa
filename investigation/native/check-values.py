#!/usr/bin/env python3
"""Check the decoded native gages, including the explicit octet width."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "interop"))
from newt import cord, cue

small = cue(Path(sys.argv[1]).read_bytes())
large = cue(Path(sys.argv[2]).read_bytes())
assert small == (cord("noun"), (cord("native-probe"), (5, 0x1234)))
assert large == (cord("noun"), (cord("octs"), (4100, 1 << 32768)))
print("Both native gages match; logical widths preserve the terminal zeros")
