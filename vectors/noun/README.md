# Noun and suite-C layout fixtures

`mat.json` contains 23 length-prefixed atom cases, including zero, numeric
width boundaries, `%gw-btc`, and values above 1,024 bits.
`../pass/suite-c-layout.json` contains three public-pass layouts covering an
empty evidence tail, unaligned evidence, and a different domain selector.

The source is `gwbtc/urbit` commit
`734ac17cfb88e571081b84406319a17d3d5e79dd`: `++mat`/`++rub` in
`pkg/arvo/sys/hoon.hoon` and `++pub:ex:cric` in `pkg/arvo/sys/zuse.hoon`.
`tools/noun-vectors.py` transcribes the source using Python integer arithmetic;
it never invokes the Rust implementation. These are source-derived fixtures,
not results extracted from a running Hoon kernel.

Run `python3 tools/noun-vectors.py --check` to compare the checked-in bytes,
or omit `--check` to regenerate them. `cargo test -p mesa-noun` checks both
Rust directions against the fixtures and exercises hostile inputs.

All integers and bit spans use little-endian order, least significant bit
first. The public pass begins with `'c'`, 32 bytes of genesis public-key
material, and 32 bytes of live public-key material. `mat(dat)` begins at bit
520. The evidence begins immediately after that field, without byte alignment.
Within `dat`, the initial `mat(domain)` leaves the remaining bits to the domain.

Keys are deterministic byte sequences, not validated curve points. Domain
tails and evidence are arbitrary test atoms, not valid Groundwire custody
records. These fixtures establish no name derivation, signature validity,
key agreement, or authorization. Executed kernel crypto vectors remain a
separate milestone requirement.

The Rust parser deliberately rejects inputs that would rely on Hoon's implicit
zero extension, and rejects nonminimal atom payloads. `rub` consumes one field;
`decode` requires its exact bit span. Neither strips byte padding or validates
jam/cue structure. Enclosing parsers must bound input and preserve explicit
field lengths before invoking these primitives.
