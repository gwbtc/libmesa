# libmesa

A standalone Rust implementation (with C FFI) of Urbit's **Mesa** ("directed
messaging") network protocol and **Groundwire** identity, lifted out of the
split Arvo-vane + Vere-runtime implementation into one self-contained,
transport-agnostic engine — usable by non-Arvo peers: Nostr clients, LND
nodes, Shrubbery ships, and ChatControl-threatened phones.

> **Status: spec-first, pre-implementation.** This repository currently holds
> design documents and a spec skeleton, prepared as a starting point for the
> working group to argue over. No Rust yet. Nothing here is final except the
> four decisions marked *settled* in `doc/05-open-questions.md`.

## Why

Today the Mesa protocol lives in three places that don't know they're one
system: the `|mesa` core of `ames.hoon` (flows, acks-as-scries, crypto, the
scry namespace), the Vere driver `mesa.c`/`pact.c` (packet codec,
retransmission, congestion, LSS verification, forwarding, caching), and the
ambient UDP/IP beneath them. A peer that isn't an Urbit ship has to be all
three at once. libmesa unifies them — and takes the chance to demote Azimuth
from a privileged assumption to one identity domain among others, on top of
Groundwire's Bitcoin-anchored comets as ground truth.

The unification is done **RINA-shaped**: one IPC engine, recursed, with
mechanism separated from policy, so a transport is not a UDP emulator but an
N-1 layer with declared properties. That framing is the subject of the lead
design doc.

## Read in this order

**Design (`doc/`) — the argument:**
1. [`doc/01-architecture.md`](doc/01-architecture.md) — what libmesa is, the
   engine decomposition, crate layout, the kernel contract it mirrors, roadmap.
2. [`doc/02-rina.md`](doc/02-rina.md) — **the RINA report.** Why a
   recursive-IPC shape, how Mesa already half-is one, the two-level
   packetization problem as policy, and the flow-engine/transport options
   re-posed through this lens. Start here for the architecture debate.
3. [`doc/03-azimuth.md`](doc/03-azimuth.md) — Azimuth as a second-class
   domain: native gateway resolution vs cash-out to suite-%c comets, with the
   complexity/running-cost/usability tradeoffs.
4. [`doc/04-crypto.md`](doc/04-crypto.md) — **E2E-encrypted by default: what it
   actually requires.** An audit corrected our priors — flows are *already*
   encrypted; the real gaps are metadata, `%publ`-defaulting scry/attestation,
   and forward secrecy. Prioritized gap list + upstream bug findings.
5. [`doc/06-forward-secrecy.md`](doc/06-forward-secrecy.md) — the forward-
   secrecy design space: why static ECDH + on-chain-priced rotation fails the
   threat model, the four tensions (byte-identity, soft state, relay caching,
   Arvo-never-forgets), and the FS0–FS3 option ladder with FS2
   (namespace-published signed epoch prekeys) as the proposed lane.
6. [`doc/05-open-questions.md`](doc/05-open-questions.md) — **the WG agenda.**
   Every open decision, tiered, each with a proposed default.

Also: [`doc/00-kernel-baseline.md`](doc/00-kernel-baseline.md) — the tracked
fork snapshot, the **pending snob doctrine** (deletes `%stale`; defines
key-currency — attestations are bearer tokens), and the upstream-fix program
with per-item dispositions.

**Spec (`spec/`) — the skeleton that implementations conform to:**
`00-scope` · `01-wire` · `02-packets` · `03-namespace` · `04-flows` ·
`05-identity` · `06-routing` · `07-transports`. Chapter outlines only;
normative text lands per-milestone.

## Grounding

Tracks the gwbtc forks: kernel `urbit@hd/cc-kernel` (spec
`pkg/arvo/doc/spec/pluggable-comet-pki.md`, status: implemented — "a base
kernel that names no vendor and no domain"), runtime `vere@gw/next/kelvin/408`,
verifier agent `groundwire@hd/cc-snob` (`%gw-btc`), naming `mnemonyms`,
protocol kelvin **9**. Where prose docs and code disagree, code
(`gw-btc/lib/gw-btc-pass.hoon`) wins.

## Not in scope for v1

Legacy ames / Fine / `%ahoy` interop · Nock evaluation · wire-format redesign ·
CDAP/RIB formalism · onion routing · forward-secrecy ratchet (design-tracked,
not shipped). See `doc/05-open-questions.md`.
