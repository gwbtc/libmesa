# libmesa architecture

**Status:** discussion draft. Records the proposed decomposition and the
kernel/runtime contract it must honor. See `02-rina.md` for the architectural
rationale, `03-azimuth.md` and `04-crypto.md` for the two big policy
discussions, `05-open-questions.md` for the working-group agenda.

## 1. What libmesa is

A standalone Rust implementation, exposing a C ABI (decision record:
`07-language.md`), of:

- the **Mesa** ("directed messaging") network protocol — the `|mesa` core of
  `ames.hoon` *plus* the runtime half in `vere/pkg/vere/io/mesa/` (packet
  codec, retransmission, congestion, LSS verification, forwarding, caching),
  unified as one engine;
- **Groundwire identity** — suite-%c comet keys, attestation
  verification, and the pluggable PKI-domain verdict contract that the gwbtc
  kernel branch (`hd/cc-kernel`) now implements vendor-neutrally;
- **mnemonym** naming as the primary human-facing name form.

Target embedders: Nostr clients, LND nodes, Shrubbery ships, mobile clients —
peers that want Urbit-network reachability and identity without Arvo.

Explicit non-goals (settled):

- **No legacy interop.** No pre-mesa ames packets, no Fine, no `%ahoy`
  migration. libmesa speaks Mesa only.
- **No wire-format redesign.** v1 is wire-compatible with ships on the gwbtc
  kernel branch.
- **No Nock.** libmesa is identity + namespace + flows; payloads are bytes
  (noun-encoded where Arvo interop requires it).

## 2. The one-sentence model

> A mesa peer is a cryptographic name that binds paths to authenticated data;
> everything else — messages, acks, attestations, even peer management — is
> reading and writing those bindings.

This is why libmesa cannot be "a packet library": acks are pages the receiver
binds and the sender peeks; naxplanations are pages; attestations are pages.
The minimum viable artifact is a small solid-state peer: **identity + namespace
+ flow engine**, with transports and PKI domains plugged in at the edges.

## 3. Engine decomposition

Following the RINA IPCP task split (see `02-rina.md` §2 — this is the
deliberate unification of the Arvo/Vere division of labor):

**Layer management (slow path)**
- *Enrollment:* attestation intake (`+sift-open-packet` / `+al-take-proof`
  semantics: name = hash-of-pass, signature, life monotonicity, suite
  dispatch), PKI-domain verdict handling (the Jael contract, below), peer
  table (`chum-state` equivalent).
- *RIB / namespace:* path → page bindings; the `/flow`, `/publ`, `/chum`,
  `/shut`, `/pawn/proof`, `/muth` regions; host-facing publish/bind API.
- *Flow allocation:* bone/side allocation, per-flow policy selection.
- *Routing:* `SponsorResolver` (fief-based; ranks are a legacy detail, not a
  routing input), lane cache, relay/forwarding role.

**Data transfer control (loss path — policy-gated per N-1 transport)**
- Retransmission control, congestion gauge (port of the C driver's
  cwnd/rtt machinery), PIT/interest state, the delta-t timer set.

**Data transfer (fast path)**
- Pact codec (bit-exact with `pact.c`/`lull.hoon`'s `plot`), delimiting
  policy (bloq per N-1 class), LSS blake3 Merkle build/verify, SDU
  protection (spaces; E2E-by-default per `04-crypto.md`).

## 4. Module sketch

Language-neutral decomposition (names are illustrative; in Rust these are
crates, in C libraries/translation units — see `07-language.md`):

| Module | Contents | Depends on |
|---|---|---|
| `mesa-noun` | jam/cue, mug (murmur3), `+mat`/`+rub` (with the bounded-scan hardening from kernel commit `382243cd7c`), `@p`/`@q`/`@uv` rendering | — |
| `mesa-crypto` | ed25519, X25519, blake3 (KDF / keyed-MAC / LSS tree), XChaCha8, secp256k1 Schnorr + tweaks (suite-%c), constant-time compares | — |
| `mesa-wire` | pact codec: header/name/data/auth etch+sift; golden-vector driven | noun |
| `mesa-ident` | pass/suite codec (%a/%b/%c), `dat` build/parse with canonicality check (see §6), point model, attestation state machine, `PkiDomain` trait, mnemonyms | noun, crypto |
| `mesa-core` | namespace, flow engine (state vector + policy modules), peer/enrollment state machine, `Transport` (N-1 DIF) + `SponsorResolver` + storage traits, forwarding/relay role | all above |
| `mesa-udp` / `mesa-tcp` / `mesa-ws` | N-1 adapters; UDP gets STUN + hole-punch + forwarding parity with `mesa.c` | core |
| `mesa-dom-gwbtc` | Groundwire domain verifier: custody-log walk over a Bitcoin light-client backend trait (BIP-158 scan model, per `gw-btc/lib/lc-attestation.hoon`) | ident |
| `mesa-dom-azimuth` | Gateway-backed Azimuth resolver (optional; see `03-azimuth.md`) | ident |
| `mesa-ffi` | C ABI over core + ident | all |

**Integrator requirements** (relayed from a prospective embedder,
2026-10-13): *C bindings, nix flake, reasonably simple API.* All three are
commitments: the C ABI ships from day one (language decision), the repo
carries a flake (dev shell now; a `packages.default` exporting the staticlib
+ generated header lands with `mesa-ffi`), and "reasonably simple" is the
design bar for the FFI surface — the embedder-facing API is the mini-ship
model of §2 (make an identity, bind paths, peek paths, send/receive
messages, pump the transport), not the engine internals of §3.

## 5. The kernel contract libmesa mirrors (as of `hd/cc-kernel` / `hd/cc-snob`)

The kernel spec is `pkg/arvo/doc/spec/pluggable-comet-pki.md` (status:
implemented; the base kernel now "names no vendor and no domain"). Points
libmesa must mirror precisely:

- **Domain identity is threefold-equal by construction:** verifier name =
  Jael domain = the term at the head of the key tweak. In Jael this is
  enforced by deriving the domain from the registering agent's own duct, by
  poking the agent *named by* the tweak's domain, and by accepting verdicts
  only from that same name. In libmesa terms: the `PkiDomain`
  implementation's registered name **is** the tweak-prefix term (`%gw-btc`),
  and dispatch is by that term. No routing table.
- **Suite-%c `dat` layout** (from `gw-btc/lib/gw-btc-pass.hoon`, which
  supersedes older docs):
  `dat = (can 0 ~[(mat domain) (mat kelvin) (mat (jam spawn-satpoint))])` —
  domain term, **protocol kelvin** (currently 9), and the *plaintext*
  canonical jam of the spawn satpoint. The earlier hiding-commitment design
  was reverted (pass and attestation are one object; every pass-holder holds
  the opening). **Canonicality must be enforced on parse** — re-encode and
  compare byte-for-byte — because `cue` tolerates trailing bits and a
  non-canonical `dat` would otherwise yield unboundedly many names per sat.
- **Verdict vocabulary:** `$verdict` (`[dom ship (unit point)]`),
  `writ-result` `%full` / `%fail` / `%lost` / **`%stale`** / `%anew`, and the
  unprompted `stale-notice`. *(Pending: the snob doctrine deletes `%stale` in
  favor of `[%snob dom ship]` + `snob-notice` + a `%poof` solicitation task —
  libmesa targets the post-snob vocabulary; see `00-kernel-baseline.md`
  § "Pending".)* Semantics libmesa adopts:
  - `%full` installs the point *and its fief* (the verdict is the only
    route-carrier for confidential identities);
  - `%fail` snubs **additively** (and `%full` un-snubs additively — exact
    inverses; snub state is a set with `%add`/`%del`, never wholesale);
  - `%stale`→`%snob`: soft-block the peer *keeping its point and flows*,
    solicit a fresh attestation, and let attestation traffic through the
    block — *staleness is not fraud*: no snub, no forgetting;
  - **an unevaluable check is not a verdict** — the `%gw-btc` agent's
    doctrine. Unknown protocol kelvin, unsynced chain view, undecodable
    input: emit nothing rather than `%fail`, because a false negative
    becomes a sticky snub (and kelvin-mismatch snubs would partition the
    network on upgrade). libmesa's `PkiDomain` trait must expose this
    three-valued result (verdict / no-verdict / stale), not a boolean.
- **Re-attestation on rekey:** a comet has no chain peers can read passively,
  so on a life change it pushes fresh self-attestations to all known peers;
  attestations are recognized by packet *shape*, not peer state, so
  re-attestation works post-rekey.
- **Known accepted gaps** (upstream, tracked there, mirrored here so the spec
  can take positions): `%anew`-refreshed pass not persisted to the boot
  keyfile; `%lost` still a no-op; breach recovery at equal-or-lower life
  still `XX`; domain names not tombstoned after `%bane`.

**Enrollment bootstrap (from `%gevulot`):** sponsor-mediated attestation
push with **provisional trust** — install now, re-verify through the ordinary
on-chain path when the light client syncs, demote (never snub) on failure.
This is directly the story for phone-class libmesa peers that can't complete
a BIP-158 sync before first use, and belongs in the identity chapter of the
spec as a named trust mode rather than an app behavior.

## 6. Conformance strategy

At least three implementations of this protocol will exist (the Hoon kernel,
the C runtime driver, libmesa — four if the dual-implementation path of
`07-language.md` is taken). The spec repo is where they agree:

1. **Golden vectors** — `vectors/` here, shared with the groundwire repo's
   `vectors/gw-kelvin-9.json` pin (the cross-repo vector set is an open item
   on the groundwire todo; this repo is the natural home). Classes: pact
   etch/sift, name↔beam, LSS proofs, pass/`dat` canonical + adversarial
   encodings, mnemonyms (`test-vectors.json` already exists there),
   attestation accept/reject, space seal/open.
2. **Differential harnesses** — `pact.c`'s built-in `PACT_TEST` roundtrip;
   fakeship-driven vector extraction via urbit-mcp (dojo access to
   `++etch`/`++sift` and the crypt core).
3. **Loopback interop** — milestone gate: libmesa peer ↔ gwbtc fakeship over
   localhost UDP: mutual attestation, peek each way, poke each way, rekey,
   stale, snub/readmit.

## 7. Roadmap

| Milestone | Deliverable | Gate |
|---|---|---|
| 0 | Spec skeleton + this doc set + WG review | today |
| 1 | noun/crypto/wire modules + golden vectors extracted | vectors pass in every implementation |
| 2 | ident: pass/dat/attestation + mnemonyms + `PkiDomain` | adversarial vector set passes |
| 3 | core: namespace + enrollment + peek/page over UDP | loopback peek interop vs fakeship |
| 4 | flow engine (state vector + policies) | loopback poke/ack/rekey interop |
| 5 | TCP/WSS N-1s + relay role | phone-class client through a relay |
| 6 | domains: gw-btc walker + azimuth gateway | verdict parity vs `%gw-btc` on vectors |
| 7 | FFI + first embedding (Nostr client) | demo |
