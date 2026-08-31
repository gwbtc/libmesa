# libmesa spec — 5: Identity

> **Skeleton.** Mirrors the kernel's pluggable-comet-PKI contract
> (`pkg/arvo/doc/spec/pluggable-comet-pki.md`, status: implemented) and the
> `%gw-btc` reference domain. See `../doc/01-architecture.md` §5.

## Outline

1. **Names.** `@p` = hash of pass (fig); ranks as legacy width classes; every
   native libmesa peer is a pawn. Mnemonyms as primary display form (BIP39
   variant, dotted, tweak-prefix flag; vectors shared with the mnemonyms
   repo).
2. **Passes and suites.** %a/%b/%c layouts. Suite-%c is **two-keyed**: `ugn`
   (signing) is tweaked, hashed into the `@p`, and **immutable for the life
   of the name** — rotating it renames the comet; `cry` (messaging/ECDH) is
   *not* in the tweak and rotates per snapshot/life without changing the
   name. Tweak commits to
   `dat = mat(domain) ++ mat(kelvin) ++ mat(jam(spawn-satpoint))`;
   **canonicality:** parse must re-encode and byte-compare; foreign kelvin is
   parseable-but-unjudgable. `xtr = jam(custody-log)`, excluded from the
   tweak; `%anew` refresh changes `xtr`, never the name.
3. **Attestation.** open-packet shape; recognition by shape (not peer state);
   life-1 rule relaxed for suite-%c; re-attest to all peers on rekey;
   single-flight verification per ship. **Bearer-token caveat (normative):**
   because `ugn` is immutable, every attestation ever signed verifies
   forever; signature validity alone establishes *authorship*, never
   *currency*. **Key-currency** = validly signed ∧ name-matching ∧ the
   pass's `cry` equals the messaging key of the newest *chain-established*
   state (custody chain verified to a tip positively proven unspent and
   where the sat actually is). Non-current packets are ignored (silence),
   never punished.
3a. **Soft-block ladder (snob doctrine — pending upstream, adopted here).**
   `%snob` state per peer with reasons `%moved` (sat moved; cleared by any
   valid key-current attestation) and `%strike` (key-current packet failed
   attributably; cleared only by a key-current log proving a sat move with a
   rift bump ⇒ breach + unsnob). Snob blocks all inbound *except*
   attestations and requests for them; the point and flows are retained.
   `%poof` solicitation with rate limiting; solicit on tick/decrypt mismatch
   from known suite-%c peers; serve `%keys` responses at the requester's
   actual life; accept same-life re-attestation from snobbed peers.
   Attribution before judgment: only in-log life/rift regression, custody
   fork against a verified prefix, or a malformed tip strike; our own
   knowledge gaps (unknown sponsor, unscanned/lagging index, policy
   declines) are silence.
4. **PKI domains.** Domain term = verifier name = tweak prefix (threefold
   equality, no routing table). The verdict contract: `$verdict`,
   `%full`/`%fail`/`%lost`/`%stale`/`%anew`, `stale-notice`;
   **three-valued outcomes** (verdict / no-verdict / snob) — an unevaluable
   check is not a verdict; `%fail`⇒additive snub, `%full`⇒additive un-snub +
   fief install, `%snob`⇒soft-block + solicit (§3a; supersedes the deleted
   `%stale` demotion).
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
