# pact vectors: provenance and findings

## Provenance

`v0-basic.json` was extracted 2026-10-13 from a live zuse-**408** ship via
dojo (urbit-mcp): for each pact `p`, wire bytes are
`(fax:plot (en:pact:ames p))` (the `p`/`r` of its product, value and byte
length) and `jam` is `(jam p)`. Roundtrip verified on-ship with
`-:((de:pact:ames 0) wire)` — note `de:pact` takes a `bite` offset first
(ames calls it through the bunt: `($:de:pact blob)`); passing a length there
reads from a wrong offset and trips the header asserts.

JSON fields: `wire`/`jam` are hex **in wire-byte order** (the atom's LE
bytes, `wire` zero-padded to `len`). `tools/ux2vec.py` regenerates the file
from dojo `@ux` output.

## Encoder findings (spec inputs, lull.hoon cites @ 408)

1. **Empty path is rejected by assertion** (`en:name` line ~2073,
   `?> ?=(^ pat)`, comment "XX truncate instead?"). Spec: a name MUST carry
   a non-empty path; path cord < 2^16 bytes.
2. **Rift 0 encodes fine** (`?~(rif 0 ...)` line ~2065, comment "XX is rift
   always non-zero?"). The all-bunt pact crashes only for its empty path.
3. **Hop clamps at encode**: `(min 7 hop)`; `peek-hop-saturate` was built
   with hop=9 and carries 7 on the wire — encode-only vector
   (`roundtrip: false`).
4. **Gum is `mug` of the body *atom*** (`en:pact` ~1927, de ~1950), so
   high/trailing zero bytes of the body do not contribute. Differential
   target: confirm vere's C recompute agrees for bodies ending in 0x00.
5. **Fragment atoms are zero-stripped**: `data` carries no independent
   length — `len = (met 3 dat)`. `page-short-final-frag` has `tob=4` but a
   1-byte fragment on the wire; trailing-zero fragment bytes are
   unrepresentable in the Hoon noun. Differential + spec question: what
   does C emit/accept, and how does reassembly treat the implied zeros?
6. **Trailing garbage**: `de` parses to a cursor and ignores bytes beyond
   it (gum covers only the parsed extent). Differential target: does C
   enforce exact-length sifts?

## Still to extract (v1+)

C-side vectors from `pact.c` `PACT_TEST`; name↔beam vectors; adversarial
sifts (truncations at every field boundary, oversize path length, reserved
`next` kinds 0b10/0b11, bad gum); jumbo bloq variants; `%is` (IPv6) lanes;
multi-lane `next`.
