# Golden vectors

Normative cross-implementation test vectors (Hoon kernel / C runtime /
libmesa in whatever language(s) — doc/07-language.md). Empty pending
milestone 1. Planned classes:

- `pact/` — packet etch/sift roundtrip + adversarial (extract via `pact.c`
  `PACT_TEST` and fakeship dojo `++etch`/`++sift`)
- `name/` — name↔beam mapping
- `lss/` — blake3 lockstep-streaming Merkle proofs
- `pass/` — suite %a/%b/%c pass + `dat` canonical and non-canonical encodings
- `mnemonyms/` — shared with the `mnemonyms` repo's `test-vectors.json`
- `attestation/` — accept/reject cases against a fake `%test-pki` domain
- `space/` — %publ/%chum/%shut seal/open

Aligns with `groundwire@hd/cc-snob`'s `vectors/gw-kelvin-9.json` pin.
