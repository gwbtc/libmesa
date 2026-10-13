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

## C differential results (2026-10-13, vere @ gw/next/kelvin/408)

Driver: vere branch `libmesa/pact-vec` (fixes `u3_ship` bit-rot in the
`PACT_TEST` block and adds a vector-mode `main`). Built inside vere's
`nix develop` shell (zig 0.15.2; the homebrew zig on this host cannot link
against the current macOS SDK). Run:
`zig build pact-test && zig-out/bin/pact-test wires.txt`.

**Headline: all 10 golden vectors sift in C and re-etch byte-identically.**
The Hoon `plot` encoder and the hand-rolled C codec agree on every covered
feature (ship widths, rift widths, wan coordinates, all three auth shapes,
`%if` lanes, hop values, the short final fragment).

Divergences, confirmed empirically:

- **C1 — trailing-zero fragments cannot cross the C↔Hoon boundary.**
  `u3_mesa_data` carries an explicit `len_w`, so C can emit a page whose
  fragment ends in `0x00` and mugs it over the exact bytes
  (`u3r_mug_bytes` does not strip). Hoon's `$data` fragment is an *atom*
  (zero-stripped, `len = met3`), and the de-side gum recompute mugs the
  stripped cut. Proof: the C-built `page-zero-tail-frag` wire
  (`v0-divergence.json`) self-sifts in C and is rejected by
  `de:pact:ames` with gum mismatch `[869.230 555.738]` =
  `0xd436e` (exact) vs `0x87ada` (stripped). The reverse also holds: Hoon
  cannot represent that wire at all. **Spec decision needed** — proposed:
  zero-stripped canonical form is normative (`len = met3(frag)`, receivers
  reconstruct positionally and pad to the leaf; matches Hoon and the
  existing `page-short-final-frag` behavior), and C's etch/jumbo-cache
  path gets an upstream fix to strip before writing `len_w`.
- **C2 — trailing garbage.** `mesa_sift_pact_from_buf` rejects any wire
  with bytes past the parse cursor ("trailing bytes"; confirmed on all 10
  vectors +1 byte). Hoon's `de:pact` parses to a cursor and ignores the
  rest (finding 6). Proposed: exact-length (C) is normative; Hoon's
  tolerance is flagged upstream.
- Finding 4 (gum over the parsed extent only) holds on both sides; the
  disagreement is C1's strip semantics, not the extent.

## Still to extract (v1+)

Name↔beam vectors; adversarial sifts (truncations at every field boundary,
oversize path length, reserved `next` kinds 0b10/0b11, bad gum); jumbo bloq
variants; `%is` (IPv6) lanes; multi-lane `next`; C-emitted golden set once
C1's canonical form is settled.
