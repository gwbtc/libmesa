# Azimuth as a second-class domain: native resolution vs cash-out

**Status:** discussion draft. The working decision (soft) is: Groundwire
suite-%c comets are ground truth; Azimuth is supported but second-class. This
document specifies what "second-class" can mean, sketches how an Azimuth ship
would *cash out* to a suite-%c comet, and compares the options on complexity,
running requirements, and usability.

## Background: what the kernel branch already does

The gwbtc kernel made identity pluggable: Jael holds a registry of PKI
domains (`dos`), each owned 1:1 by a verifier agent; Ames defers suite-%c
attestations to the domain named inside the key's tweak, and acts on
`%sybl` verdicts. Azimuth, meanwhile, is still structurally privileged: the
`%dawn` boot path, the `state-eth-node` field, the `%azimuth` agent
hardcoding, `sein:title`/`saxo:title` rank-derived sponsorship, and
galaxy-terminated routing all assume it. Separately, the gwbtc **vere** fork
already removed Ethereum from boot: dawn resolves keys, the galaxy table,
turf, and sponsorship over HTTP from a **gateway node** (`-W`, scry-shaped
endpoints `=pynt=`/`=lamp=`/`=turf=`/`=saxo=`).

libmesa starts from a cleaner slate: the core knows only the domain-verdict
contract (`verify(ship, pass) → unit point`, plus `%anew` refresh). The
question is what an implementation of that contract for Azimuth looks like —
and whether we'd rather route around it entirely.

## Model N: native Azimuth resolution (as a domain module)

libmesa ships an optional `azimuth` domain resolver. Three implementation
tiers, in ascending self-sufficiency:

- **N1 — gateway client.** Resolve points over HTTP from a gateway node,
  exactly as gw-vere dawn does. ~A few hundred lines: HTTP + noun/json
  decode + point cache + rift/life monotonicity checks.
- **N2 — peer scry.** Resolve points by peeking a trusted Urbit ship's Jael
  namespace over mesa itself (`/j/=pynt=/...`). No HTTP dependency, but
  bootstraps circularly (you need a verified peer to verify peers) — fine as
  a refresh path, not as a root.
- **N3 — chain watcher.** Full Ethereum L1 + naive-rollup L2 indexer.
  Rejected: this is the thing we are demoting, reimplemented in Rust at
  maximal cost.

**Trust model:** N1/N2 trust the gateway/peer for *liveness and recency*, but
not for *key substitution* — a point's key material is self-authenticating
against the ship's attestation signature, and rift/life can only move
forward once first seen (trust-on-first-use for the initial point, as with
any light client that skips header proofs). A gateway can lie by omission
(hide a breach) — same class of risk as an SPV server hiding a
transaction. Mitigation: query k>1 gateways; the spec should say so.

## Model C: cash-out to a suite-%c comet

An Azimuth ship mints a Groundwire comet and *binds* the two identities.
Roughly:

1. **Mint.** The owner mines/derives a suite-%c keypair; the tweak commits, as
   always, to `mat(domain) ++ satpoint` — the comet's name (hash of pass) is
   domain-committed on Bitcoin like any other Groundwire comet.
2. **Link.** The owner produces a **linkage attestation**: a statement
   `[comet=@p azimuth-ship=@p]` signed *both* ways — by the comet's suite-%c
   networking key and by the Azimuth ship's current networking key (the same
   ed25519 key attested in Azimuth's PKI). Either direction alone is
   forgeable-by-half; both together bind the pair.
3. **Publish.** The linkage rides in the comet's `xtr` custody log (the
   off-chain, kernel-opaque extension data that `%anew` refreshes without
   changing the name) and/or is committed on-chain alongside a custody entry
   for permanence.
4. **Resolve.** A libmesa peer that encounters the comet verifies it purely as
   a Groundwire comet (Bitcoin custody-log walk). The Azimuth *alias* is
   extra, display-level metadata — but verifying the linkage's Azimuth-side
   signature requires knowing the Azimuth ship's key at signing time, i.e.
   **some** Azimuth resolution (Model N, at least once, by someone).

Two variants:

- **C-soft (dual identity):** the Azimuth ship keeps operating on Azimuth;
  the comet is its face toward the Groundwire/libmesa world. Revocable,
  re-linkable on rekey.
- **C-hard (migration):** the linkage is declared terminal (e.g. the Azimuth
  ship's final act, ideally recorded as an Azimuth breach/factory-reset or a
  documented convention), after which the comet is the identity and Azimuth
  state is historical. Verification of *historical* linkage still needs a
  snapshot of Azimuth at migration time — which suggests the ecosystem
  should pin one canonical snapshot (a jammed point-map with a well-known
  hash) rather than each verifier trusting a live gateway forever.

## Comparison

| | N: native (gateway) | C: cash-out |
|---|---|---|
| **libmesa core impact** | None (domain module) | None (domain module + linkage verify) |
| **New protocol surface** | None | Linkage attestation format; xtr layout convention; (C-hard) snapshot pinning |
| **Runtime deps for a verifying peer** | HTTP gateway(s) (or a peer ship) | Bitcoin backend **only** — already required for the Groundwire domain; plus a one-time Azimuth snapshot for linkage checks |
| **Trust model** | Gateway liveness/recency (breach-hiding risk); TOFU on first point | Bitcoin light-client assumptions, same as all Groundwire comets; snapshot hash for legacy linkage |
| **Who must act** | Nobody; existing ships work as-is | Every Azimuth ship that wants to be reachable must mint + link (adoption friction, key ceremony) |
| **Name continuity** | Full: `~sampel-palnet` resolves natively | Broken at the wire level: the reachable identity is a 128-bit comet; `~sampel-palnet` becomes an *alias* proven by linkage |
| **Mnemonyms** | Don't apply (planets/stars aren't pawns) | Uniform: every native peer is a comet, every peer has a mnemonym |
| **Sponsorship/routing** | Must also import rank-based sponsor semantics (sein/saxo) or gateway `=saxo=` — Azimuth leaks into routing | Uniform fief-based routing; zero rank semantics in core |
| **Moons, stars, galaxies** | Resolvable like any point | No equivalent; each would cash out to its own comet |
| **Usability for existing urbiters** | Best — nothing changes | Worst-to-mixed — new name, new ceremony, but same key custody can be reused |
| **Usability for target users (phones, Nostr, LND)** | Irrelevant — they never touch Azimuth either way | Identical | 

## Assessment and proposed position

The models are not exclusive, and the cost structure says: **do C's protocol
work in the spec, ship N1 as the compatibility module, and let usage decide
the long run.**

- The libmesa **core** stays domain-only either way — that decision is free
  and already made.
- **N1 is cheap and unblocks interop** with the existing network from day
  one (and gw-vere has field-tested the gateway pattern). Without it, a
  libmesa peer cannot verify any planet/star/galaxy, which in practice means
  it cannot verify most current relays either.
- **C is where the design work is** (linkage format, xtr conventions,
  snapshot pinning) and it is *spec* work more than code: the verification
  path reuses the Groundwire walk plus two signature checks. It also yields
  the uniformity wins — one identity algebra, universal mnemonyms, rank-free
  routing — that the ChatControl/normie story wants.
- The honest caveat on C: it doesn't eliminate Azimuth resolution, it
  *freezes* it (linkage checks need Azimuth keys as-of-signing). C-hard with
  a pinned snapshot turns a live dependency into a static artifact — that's
  the actual demotion, and it's a strong end-state: Azimuth becomes one
  historical fact rather than one running service.

**Proposed for WG:** adopt N1 as mandatory-to-implement-optional (module
present in the reference implementation, not required by the spec core);
specify the linkage attestation in the identity chapter; take C-hard snapshot
pinning as a separate later decision once there's operational experience.

## Open questions

1. Does the linkage attestation belong in `xtr` (refreshable, off-chain,
   free) or on-chain beside the spawn (permanent, costs sats, breach-visible)?
   Both? (Lean: xtr for C-soft, inscription for C-hard.)
2. Should a cashed-out comet's mnemonym display incorporate the alias (e.g.
   UI shows `~sampel-palnet ⇒ ..motifs.adage...`), and is the alias part of
   the spec or purely a client concern? (Lean: client concern; spec defines
   only the verifiable linkage.)
3. Sponsor continuity: can a cashed-out planet keep its star as relay? Under
   fief routing yes — if the star publishes a fief and the comet names it as
   sponsor. Does anything check that relationship, or is sponsorship pure
   configuration in the post-rank world? (Needs a WG answer; interacts with
   the relay-role spec in 02-rina.md §7.4.)
4. Breach semantics across the link: if the Azimuth side breaches after
   C-soft linkage, what happens to the comet's alias claim? (Lean: alias is
   life/rift-scoped; a breach voids it until re-signed.)
