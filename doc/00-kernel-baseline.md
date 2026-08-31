# Kernel/runtime baseline libmesa tracks

Snapshot of the gwbtc forks libmesa conforms to, and the upstream findings
surfaced while writing these docs. Not libmesa design — a fixed reference
point (and a short list of things worth fixing upstream regardless of
libmesa).

## Branches / specs of record

| Repo | Branch | Spec / ground truth |
|---|---|---|
| `urbit` (kernel) | `hd/cc-kernel` | `pkg/arvo/doc/spec/pluggable-comet-pki.md` (status: implemented). Base kernel names no vendor/domain. |
| `vere` (runtime) | `gw/next/kelvin/408` | `pkg/vere/io/mesa/{mesa,pact}.c`; gateway-PKI boot (`-W`), galaxies = "lamp". |
| `groundwire` (verifier) | `hd/cc-snob` | `gw-btc/app/gw-btc.hoon` (%gw-btc), `gw-btc/lib/gw-btc-pass.hoon`, `gw-btc/lib/lc-attestation.hoon`. |
| `mnemonyms` | — | `test-vectors.json`; BIP39-variant `@p` respelling. |
| Protocol kelvin | **9** | committed in every suite-%c `dat`. |

## Contract facts libmesa mirrors (current, code-verified)

- **Threefold name equality**: verifier agent name = Jael domain = tweak
  prefix, enforced structurally (domain derived from registrant's duct; verdict
  poke sent to the agent *named by* the tweak; verdict accepted only from that
  name; ames drops passes whose prefix doesn't decode to a term).
- **`dat` layout** (`gw-btc-pass.hoon`, supersedes prose docs):
  `dat = (can 0 ~[(mat %gw-btc) (mat 9) (mat (jam spawn-satpoint))])` —
  plaintext satpoint (hiding commitment reverted 2026-08-18); canonicality
  enforced on parse (re-encode + byte-compare); foreign kelvin parses but is
  refused *for its kelvin*, not judged fraudulent. `xtr = jam(custody-log)`,
  outside the tweak; `%anew` changes `xtr`, never the `@p`.
- **Liveness via Clay `%tire`** (the earlier Gall `%view` was removed): desk
  `%dead`/`%held` ⇒ `%gost` (snub domain's peers, additively), `%live` ⇒
  `%ghul` (un-snub, additively); `%bane` is the sole destructive path.
- **Verdicts**: `$verdict [dom ship (unit point)]`; `writ-result`
  `%full`/`%fail`/`%lost`/`%stale`/`%anew`; unprompted `stale-notice`.
  `%full` installs point **and fief** (verdict is the only route-carrier for
  confidential identities) and additively un-snubs; `%fail` additively snubs;
  `%stale` demotes to fresh alien (no snub); **unevaluable ⇒ no verdict**
  (unknown kelvin / unsynced / undecodable emit nothing — a false negative
  would become a sticky snub, and kelvin-mismatch snubs would partition the
  network on upgrade).
- **Snub is additive/set-based** (`%add`/`%del`/`%set`), never wholesale.
- **Attestations recognized by packet shape, not peer state**; life-1 rule
  relaxed for suite-%c; comet re-attests to all peers on rekey; single-flight
  verification per ship.
- **Bootstrap** (`%gevulot`): sponsor-mediated attestation push with
  provisional trust (install now, re-verify on light-client sync, demote — not
  snub — on failure).
- **Verification backend** (`%gw-btc`): custody-log walk, oldest-first, every
  byte from a local Bitcoin light client (`gwbtc/node`), BIP-158 compact-filter
  tip-liveness scan. No Bitcoin Core. `max-custody-log` 1024.

## Upstream findings worth fixing regardless of libmesa

Surfaced during exploration; filed here so they aren't lost. Bug-class items
also appear in `04-crypto.md` (crypto) and `05-open-questions.md` (agenda).

**Correctness / migration**
- **`dek` added to `dom-state` inside Jael `state-5` without a version bump** —
  a ship already on the earlier `%5` with a populated `dos` hits a mold
  mismatch on load. Wants a `%5`→`%6` migration (bundle the deferred `%bane`
  tombstone).
- **`+pass-pki-dom` (ames) and `%dome` scry (jael) hand-duplicated**, `mat`
  bound copied verbatim, sync by comment only — drift hazard.
- **Stale groundwire docs**: `confidential-comets.md` still describes `dat` as
  a hiding commitment; `confidential-comets-todo.md` asks for a `dat` layout
  never adopted. Code is authority.

**Crypto (detail in `04-crypto.md`)**
- `%publ` is the plaintext default for scry with no `sec` — should be opt-out,
  `%chum` the default for known peers.
- Attestation / `%muth` broadcast `(comet-pass, comet-life, target, target-
  life)` in cleartext — closable via one-sided ECIES to the recipient's pass.
- `peek-shut` scries with the fully-privileged gang `[~ ~]` — group-key holders
  get omniscient local scry (privilege escalation).
- `%peek` packets unauthenticated — amplification/DoS primitive.
- `const-cmp` still marked "XX jet for constant-time"; `chacha 8` is 8-round.
- XChaCha IV = sealed path: nonce-reuse safety is an unenforced invariant.
- No forward secrecy (static ECDH, rotated only on life change).

**Known accepted gaps (tracked upstream)**
- `%anew`-refreshed pass not persisted to the boot keyfile (reboot needs
  another `%anew` round-trip).
- `%lost` verdict still a no-op.
- Breach recovery at equal-or-lower life still `XX` (partly mooted by
  "every snapshot change increments life", not closed).
- Domain names not tombstoned after `%bane`.
- Mesa-path attestation scenarios not yet rerun (only the ames path is
  covered); cross-repo golden vectors unpublished.
