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

**Pending (not merged, will change this baseline):** the **snob doctrine** —
`groundwire@hd/cc-snob` (PR #129) + `urbit@hd/cc-snob` (PR #67), spec
`ops/doc/snob-doctrine.md` in the groundwire repo. Summary below (§ "Pending:
snob doctrine"). libmesa should implement the *post-snob* semantics and treat
the pre-snob `%stale` behavior as a transitional detail, since `%stale` is
slated for deletion, not aliasing.

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
  `%stale` demotes to fresh alien (no snub — **being deleted**, see snob
  doctrine below); **unevaluable ⇒ no verdict** (unknown kelvin / unsynced /
  undecodable emit nothing — a false negative would become a sticky snub, and
  kelvin-mismatch snubs would partition the network on upgrade).
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

## Pending: snob doctrine (in-process; PRs groundwire#129 / urbit#67)

`ops/doc/snob-doctrine.md` replaces the `%stale` demotion with a soft-block +
re-solicitation ladder. What libmesa must mirror once it lands:

- **`%stale` is deleted** (decision 2026-08-28, not aliased). The old
  demote-to-alien was a one-sided breach: flows/bones/subscriptions dropped
  with no notice to vanes, and the demoted side never re-solicited.
- **New vocabulary:** `writ-result` gains `[%snob dom ship]` (replacing
  `%stale`); `stale-notice` → `snob-notice`; new Ames tasks `%snob`
  (grammar identical to `%snub`) and `%poof` (solicit an attestation
  regardless of peer state).
- **`snob` list semantics:** exactly `%snub` except attestations, and
  requests for them, pass. Inbound-only. The point is **retained** while
  snobbed — which is what lets a later higher-rift `%verdict` trigger the
  existing rift-bump `%breach` rule instead of needing new breach machinery,
  and lets a plain rekey (life+1, same rift) preserve flows.
- **Key-currency** (§1.1 there — load-bearing for any reimplementation): the
  suite-%c *signing* key (`ugn`) is immutable and every attestation it ever
  signed verifies forever — **a captured attestation is a bearer token**.
  "Current" therefore means: validly signed, name-matching, **and** the
  pass's messaging key (`cry`) equals the key of the newest
  *chain-established* state — custody chain verified to a tip that is
  provably where the sat actually is (`tip-unspent` positively passes). A
  replayed or pre-move pass is not key-current ⇒ **silence**, not
  punishment.
- **Attribution before judgment:** only attributable failures strike
  (in-log life/rift regression, custody fork against our verified prefix,
  malformed non-P2TR tip). Everything reflecting *our* knowledge gaps
  (unknown sponsor, unscanned tip, lagging index, policy declines) stays
  silence. Pre-verification drops `%undecodable`/`%empty-log`/`%log-too-long`
  change from `%fail` to drop — they can't establish the key, so rule-1
  silence applies.
- **Two snob reasons** with different exits: `%moved` (scanner saw the sat
  move; cleared by any valid key-current attestation) vs `%strike`
  (key-current packet failed attributably; cleared only by a key-current log
  proving a sat move **with a rift bump** → breach + unsnob; a post-strike
  plain rekey ⇒ permanent snub + forget).
- **Solicitation fixes** libmesa should implement from day one rather than
  reproduce the bugs: respond to a `%keys` request with the requester's
  *actual* life (not hardcoded 1 — the current bug makes a rekeyed comet
  reject the attestation it solicited); on tick/decrypt mismatch from a
  known suite-%c peer, drop + solicit (rate-limited); accept same-life
  re-attestation from a snobbed peer (a pure custody move carries no
  opening).
- **Jael on `%fail` for a previously-vouched ship** becomes per-ship
  `%bane`: delete point + `hep`, `%fail`, `%breach` — so "remove the name"
  is true in every vane at once, and a later domain revive can't
  accidentally lift the snub.

Still open there (WG items, mirrored in `05-open-questions.md`): accept the
key-current definition; unknown-class-silence evaluated *before* attribution;
confirm the two sharp rows (post-strike plain rekey = permanent snub; clean
re-send with sat unmoved = ignored).

## Upstream program: findings worth fixing regardless of libmesa

Surfaced during exploration; filed here so they aren't lost. Bug-class items
also appear in `04-crypto.md` (crypto) and `05-open-questions.md` (agenda).

Each item carries a proposed **disposition**: *(file)* = open an upstream
issue now; *(snob)* = natural to ride or follow the `hd/cc-snob` kernel PR,
which is the active kernel-change vehicle and already fixes adjacent bugs
(the `rcvr-life=1` attestation bug, the sndr-tick stall); *(spec)* = libmesa
implements the hardened behavior and the spec documents the divergence until
upstream catches up. Dispositions are proposals for the WG, not filed yet.

**Correctness / migration**
- **`dek` added to `dom-state` inside Jael `state-5` without a version bump** —
  a ship already on the earlier `%5` with a populated `dos` hits a mold
  mismatch on load. Wants a `%5`→`%6` migration (bundle the deferred `%bane`
  tombstone). *(snob — that PR already bumps Ames state `%31`→`%32`; a Jael
  bump belongs in the same landing, or file separately.)*
- **`+pass-pki-dom` (ames) and `%dome` scry (jael) hand-duplicated**, `mat`
  bound copied verbatim, sync by comment only — drift hazard. *(file)*
- **Stale groundwire docs**: `confidential-comets.md` still describes `dat` as
  a hiding commitment; `confidential-comets-todo.md` asks for a `dat` layout
  never adopted. Code is authority. *(file — doc fix)*

**Crypto (detail in `04-crypto.md`)**
- `peek-shut` scries with the fully-privileged gang `[~ ~]` — group-key holders
  get omniscient local scry (privilege escalation). *(file — security,
  highest urgency of the crypto set)*
- `%publ` is the plaintext default for scry with no `sec` — should be opt-out,
  `%chum` the default for known peers. *(file; libmesa defaults hardened
  regardless — spec)*
- Attestation / `%muth` broadcast `(comet-pass, comet-life, target, target-
  life)` in cleartext — closable via one-sided ECIES to the recipient's pass.
  *(spec first — needs a wire-visible design; then upstream)*
- `%peek` packets unauthenticated — amplification/DoS primitive. *(file as
  known-limitation; mitigation design in spec ch. 2)*
- `const-cmp` still marked "XX jet for constant-time"; `chacha 8` is 8-round.
  *(file — the compare is a one-liner; the round count needs a WG decision
  that it's intended)*
- XChaCha IV = sealed path: nonce-reuse safety is an unenforced invariant.
  *(spec — libmesa documents and enforces the invariant; upstream comment)*
- No forward secrecy (static ECDH, rotated only on life change — and for a
  gw comet a life rotation is an on-chain transaction, so epochs are priced
  in sats). Full design space in `06-forward-secrecy.md`; proposed lane:
  namespace-published signed epoch prekeys (FS2). *(spec-led, driven
  upstream — the flagship of "fix upstream over compromise")*

**Known accepted gaps (tracked upstream)**
- `%anew`-refreshed pass not persisted to the boot keyfile (reboot needs
  another `%anew` round-trip).
- `%lost` verdict still a no-op.
- Breach recovery at equal-or-lower life still `XX` (partly mooted by
  "every snapshot change increments life", not closed).
- Domain names not tombstoned after `%bane`.
- Mesa-path attestation scenarios not yet rerun (only the ames path is
  covered); cross-repo golden vectors unpublished.
