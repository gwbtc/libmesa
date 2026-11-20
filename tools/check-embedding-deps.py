#!/usr/bin/env python3
"""Reject noun/identity dependencies in the embedding's normal Rust graph."""
import subprocess

result = subprocess.check_output([
    "cargo", "tree", "--locked", "--edges", "normal",
    "-p", "mesa-keys", "-p", "mesa-pki", "-p", "mesa-jael", "-p", "mesa-core", "-p", "mesa-flow", "-p", "mesa-ffi",
], text=True)
assert "mesa-noun " not in result, result
assert "mesa-identity " not in result, result
print("Keys, PKI, Jael, core, flow, and embedding normal dependencies contain no noun/identity crate")
