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
  key-rotation/snob stack implements through registered domain authorities;
- **mnemonym** naming as the primary human-facing name form.

Target embedders: Nostr clients, LND nodes, Shrubbery ships, mobile clients —
peers that want Urbit-network reachability and identity without Arvo.

Explicit non-goals (settled):

- **No legacy interop.** No pre-mesa ames packets, no Fine, no `%ahoy`
  migration. libmesa speaks Mesa only.
- **Standardize fixed 128-bit names.** The target protocol removes Mesa v1's
  width selector and treats Azimuth short names as future aliases. The domain
  selector is canonical ASCII; the prototype implements experimental v2.
  Historical v1 fixtures remain compatibility evidence. See
  [names and domains](08-names-and-domains.md).
  Upstream also needs Mesa-only rekey announcements.
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
  semantics: immutable `ugn/dat` name binding, live-key signature, domain
  dispatch and point invariants), PKI-domain verdict handling, and peer
  trust status (verified, provisional, or explicit life-1 fallback).
- *RIB / namespace:* path → page bindings; the `/flow`, `/publ`, `/chum`,
  `/shut`, `/pawn/proof`, `/muth` regions; host-facing publish/bind API.
- *Flow allocation:* bone/side allocation, per-flow policy selection.
- *Routing:* `SponsorResolver` (fief-based; ranks are a legacy detail, not a
  routing input), lane cache, relay/forwarding role.

**Data transfer control (loss path — policy selected from complete-path guarantees)**
- Retransmission control, congestion gauge (port of the C driver's
  cwnd/rtt machinery), PIT/interest state, the delta-t timer set.

**Data transfer (fast path)**
- Experimental v2 pact codec; explicit v1 reference for historical
  `pact.c`/`lull.hoon` conformance. Delimiting policy follows path bounds;
  LSS blake3 Merkle build/verify and SDU
  protection (spaces; E2E-by-default per `04-crypto.md`).

## 4. Module sketch

Target decomposition, not a list of completed modules. The current implementation
contains noun, wire, crypto, identity primitives, and wire-only FFI. See
[the implementation review](10-implementation-review.md) for the dependency
boundaries. The [peer-engine handoff](11-peer-engine-handoff.md) now sets the
implementation order; authority integration is deferred.

| Module | Contents | Depends on |
|---|---|---|
| `mesa-noun` | jam/cue, mug (murmur3), `+mat`/`+rub` (with the bounded-scan hardening from kernel commit `382243cd7c`), `@p`/`@q`/`@uv` rendering | — |
| `mesa-crypto` | Kernel-compatible Edwards signing/name tweaks, Montgomery agreement, blake3 (KDF / MAC / LSS), XChaCha8, constant-time compares | — |
| `mesa-wire` | pact codec: header/name/data/auth etch+sift; golden-vector driven | noun |
| `mesa-identity` | Suite-C pass/ring codec, bounded domain-tag parsing, point and trust-status models, attestation/rotation state machine, domain interface, mnemonyms | noun, crypto; currently wire for shared name types |
| `mesa-core` | namespace, flow engine (state vector + policy modules), peer/enrollment state machine, `Transport` (N-1 DIF) + `SponsorResolver` + storage traits, forwarding/relay role | all above |
| `mesa-udp` / `mesa-tcp` / `mesa-ws` | N-1 adapters; UDP gets STUN + hole-punch + forwarding parity with `mesa.c` | core |
| `mesa-dom-gwbtc` | Groundwire `dat/xtr` codec, canonicality, Bitcoin/secp256k1 custody verification, chain-currency policy over a light-client backend | identity |
| Future domain adapters | Additional authorities, including a possible Azimuth adapter; no mandatory resolver or gateway | identity |
| `mesa-ffi` | C ABI over core + identity | all |

**Integrator requirements** (relayed from a prospective embedder,
2026-10-13): *C bindings, nix flake, reasonably simple API.* All three are
commitments: the C ABI ships from day one (language decision), the repo
carries a flake (`packages.default` exports the staticlib and checked-in
header alongside the dev shell), and "reasonably simple" is the
design bar for the FFI surface — the embedder-facing API is the mini-ship
model of §2 (make an identity, bind paths, peek paths, send/receive
messages, pump the transport), not the engine internals of §3.

## 5. Identity through registered domains

[Spec chapter 5](../spec/05-identity.md) is the identity contract.
[The baseline](00-kernel-baseline.md) pins the composed kernel stack and
separates its implemented mechanics from companion gaps.

The current suite-C profile commits names to immutable `ugn/dat`. Other
domains may bind fixed 128-bit names through their own identity ledger. The
live key `cry` signs and derives channel keys, and rotates without renaming
the peer. Attestation establishes possession and name binding; the committed
domain authorizes the current key and point. First contact and PKI updates
use the same verifier interface. Generic point feeds cannot bypass it.

The core owns bounded parsing, domain-authorized authentication, the registry,
point invariants, admission, and public/private activation. A domain owns the
meaning of its evidence and its currency policy. The suite-C parser extracts a leading domain
term from `dat`; the target wire design makes domain selection explicit. `%gw-btc` owns kelvin 9, spawn satpoints, custody logs,
and Bitcoin validation. A later Azimuth adapter uses the same authority
boundary without becoming a prerequisite for boot or routing.

The proposed domain interface is asynchronous and host-authenticated:
verification requests carry a candidate pass; results distinguish accepted
point, rejected candidate, and unavailable/unevaluable work. Withdrawal is a
separate event for a previously vouched peer; own-evidence refresh is another
operation. Registration binds an adapter to its domain. The interface must
preserve these distinctions before a concrete Rust trait or C ABI is frozen.

A rejection drops a candidate without damaging an accepted peer. Withdrawal
soft-blocks traffic while retaining point and flows, then solicits a new
attestation. An accepted point advances keys and fief, releases the soft gate,
and preserves any independent hard block. Life rotation preserves continuity;
a higher remote rift breaches it. The core activates a private ring only when
its exact derived pass matches current public authorization.

The host may opt into life-1 unregistered-domain fallback or sponsor-assisted
provisional bootstrap. The API exposes each trust status and its source;
neither becomes domain-verified without the committed verifier's acceptance.
Provisional expiry and revalidation are explicit embedding policies.

Mesa-only operation remains a requirement. The kernel currently announces
rekeys using legacy control packets even for Mesa peers. A compatible Mesa
announcement/recovery path must land upstream before full rekey interop.
Verifier readiness, causal freshness after withdrawal, own-rift quiescence,
and bounded evidence remain separately tracked release gates.

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

The milestone numbers identify workstreams, not a strict dependency order.
Current priority is the [peer engine with preconfigured peers](11-peer-engine-handoff.md):
namespace/interest machinery and flows can progress before generalized identity.
Jael and userspace verifier responsibilities stay behind host-supplied services.

| Milestone | Deliverable | Gate |
|---|---|---|
| 0 | Spec skeleton + this doc set + WG review | today |
| 1a | Bounded wire codec, atom/mug, reconstruction, minimal C ABI | Full packet vectors, adversarial corpus, compiled C smoke test |
| 1b | Remaining noun primitives, crypto, LSS verification | Authenticated fragment and seal/open vectors |
| 2 | Domain-first identity: pass/ring, attestations, point transitions, trust modes, host verifier interface | Kernel-derived positive/negative vectors and real activation-path tests |
| 3 | core: namespace + peek/page with preconfigured peers; enrollment integrated later | Deterministic lossy harness, then protected libmesa UDP reads; upstream interop separately |
| 4 | Flow engine: sequencing, acknowledgment, recovery, backpressure and policy | Loss/reordering and durable delivery tests; upstream announcements and simultaneous-rekey interop follow identity integration |
| 5 | TCP/WSS N-1s + relay role | phone-class client through a relay |
| 6 | Groundwire adapter: bounded evidence and authority-backed verification | Verdict/currency parity and multilateral rotation tests; Azimuth deferred |
| 7 | Extend the C ABI to core/identity + first embedding (Nostr client) | demo |
