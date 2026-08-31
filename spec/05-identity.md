# libmesa spec — 5: Identity

> **Skeleton.** Mirrors the kernel's pluggable-comet-PKI contract
> (`pkg/arvo/doc/spec/pluggable-comet-pki.md`, status: implemented) and the
> `%gw-btc` reference domain. See `../doc/01-architecture.md` §5.

## Outline

1. **Names.** `@p` = hash of pass (fig); ranks as legacy width classes; every
   native libmesa peer is a pawn. Mnemonyms as primary display form (BIP39
   variant, dotted, tweak-prefix flag; vectors shared with the mnemonyms
   repo).
2. **Passes and suites.** %a/%b/%c layouts; suite-%c: encryption key +
   untweaked signing key + tweak; tweak commits to
   `dat = mat(domain) ++ mat(kelvin) ++ mat(jam(spawn-satpoint))`;
   **canonicality:** parse must re-encode and byte-compare; foreign kelvin is
   parseable-but-unjudgable. `xtr = jam(custody-log)`, excluded from the
   tweak; `%anew` refresh changes `xtr`, never the name.
3. **Attestation.** open-packet shape; recognition by shape (not peer state);
   life-1 rule relaxed for suite-%c; re-attest to all peers on rekey;
   single-flight verification per ship.
4. **PKI domains.** Domain term = verifier name = tweak prefix (threefold
   equality, no routing table). The verdict contract: `$verdict`,
   `%full`/`%fail`/`%lost`/`%stale`/`%anew`, `stale-notice`;
   **three-valued outcomes** (verdict / no-verdict / stale) — an unevaluable
   check is not a verdict; `%fail`⇒additive snub, `%full`⇒additive un-snub +
   fief install, `%stale`⇒demote to alien, never snub.
5. **Trust modes.** verified · provisional (sponsor-pushed, re-verified on
   sync, demote-don't-snub on failure — the `%gevulot` model) · pinned
   (operator-configured).
6. **Reference domains.** `%gw-btc` (custody-log walk over a BIP-158
   light-client backend; normative summary + pointer to groundwire repo);
   `%azimuth` gateway resolver + the cash-out linkage attestation
   (`../doc/03-azimuth.md`).
7. **Breach & staleness.** rift/life monotonicity; open upstream gaps this
   spec must take positions on (equal-or-lower-life re-attestation, `%lost`,
   `%anew` persistence).
