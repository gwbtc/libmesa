# Working-group agenda: open questions

Ordered by how much they change the shape of libmesa. Each has a proposed
default so the meeting argues about a concrete position, not a blank page.

## Settled going in (not for debate, listed for the record)
- Mesa-only, no legacy ames / Fine / `%ahoy`. **Settled.**
- Fixed 128-bit names; no target wire width selector; Azimuth short names are
  future aliases. This supersedes preserving v1 name encoding.
  **Settled direction 2026-10-21.**
- Globally unique 128-bit names with an explicit domain selector.
  Experimental v2 uses canonical ASCII selectors and exact-byte checksums.
  **Approved and implemented at the codec layer.** Authority association and
  Mesa-only announcements remain identity/upstream work.
- Groundwire's comet/domain model is the native identity convention; Azimuth
  is a possible later domain adapter. **Settled 2026-10-21.**
- Life-1 unregistered-domain fallback is opt-in. Sponsor-assisted provisional
  bootstrap is explicit and distinguishable from domain verification.
  **Settled 2026-10-21.**
- Everything E2E-encrypted by default; fix upstream over compromise. **Settled.**
- Implementation language: **Rust primary**, C ABI exported from day one;
  a C wire-codec stays available as a post-phase-1 conformance exercise.
  **Settled 2026-10-13** (decision record: `07-language.md`).

## Tier 1 — decisions that set the architecture

1. **RINA-shaped or monolithic engine?** Proposed: RINA-shaped (three-task
   IPCP decomposition = the deliberate Arvo/Vere unification), with an explicit
   v2 wire profile and no CDAP/RIB formalism beyond vocabulary. `02-rina.md` §8.
1a. **Implementation language.** **Settled 2026-10-13: Rust primary** with
   the C ABI committed from day one, so Vere can link libmesa and C hosts
   need no binding layer. The dual-wire-codec option stays open as a
   post-phase-1 conformance exercise. Rationale and the road not taken:
   `07-language.md`.

2. **Flow engine: peek-only, monolithic port, or state-vector + policies?**
   Proposed: state-vector + policy modules (EFCP option C); peek-only is
   milestone 3, full flows milestone 4. `02-rina.md` §6.1.
3. **Transport mapping: pacts-verbatim, per-N-1-policy, or native framing?**
   Proposed: same pact everywhere, per-N-1 policy (delimiting/retransmit/
   congestion), with endpoint recovery across lossy relay legs and explicit
   path-size bounds. Relays retain PIT state (spec chapter 7). `02-rina.md` §6.2.
4. **Forward secrecy — which lane?** The marquee crypto question, now mapped
   in `06-forward-secrecy.md`. Static ECDH means one key compromise reads all
   history, and rotation is priced in on-chain sats (a rekey is a sat move).
   Proposed: adopt **FS2** (namespace-published signed epoch prekeys —
   asynchronous prekey discovery, with authenticated capability selection
   and explicit compatibility policy for any static-ECDH fallback); reserve
   the `/epok` region and KDF labels in v1;
   don't block v1 messaging; drive upstream. FS3 (double ratchet) declared an
   application-layer concern. Also note the asymmetry worth an upstream
   conversation: Arvo's event log retains secrets, so libmesa peers can honor
   FS deletion guarantees Arvo ships structurally can't (yet).

## Tier 2 — decisions that shape the spec

4a. **Identity contract.** **Settled direction 2026-10-21:** use the composed
   key-rotation/snob kernel contract, with rotating signer/agreement key,
   registered-domain point authority, non-terminal candidate rejection, and
   withdrawal followed by re-attestation. The earlier terminal moved/strike
   ladder is not the core contract. `../spec/05-identity.md` defines the model;
   `00-kernel-baseline.md` pins its sources and implementation status.
4b. **Identity release gates.** Resolve verifier readiness, delayed pre-withdrawal
   completions, overlapping policy ownership, and live own-rift quiescence.
   Define provisional expiry/persistence and transition from fallback after
   verifier installation. A process restart or stale verdict must not silently
   restore authority. These remain design and implementation work.
4c. **Mesa-only rekey interoperability.** **Selected:** change upstream to
   announce through Mesa; do not add legacy identity-control packets to
   libmesa. Specify receiver-life handling, lost announcements, simultaneous
   rotations, and recovery. Existing proof messages provide a starting point,
   not a completed convergence protocol.
4d. **Evidence bounds.** A complete first-contact proof must fit one 1,024-byte
   fragment under the current kernel. Growing custody logs eventually violate
   that constraint. Choose bounded/compact evidence or specify proof transfer;
   pin the complete encoded-size boundary in interoperability tests.

5. **E2E default definition.** Adopt the three-tier definition (payload /
   metadata / relationship)? Proposed: yes; implement Tier 1 from day one,
   Tier 2 mandatory-to-implement, Tier 3 first-class open design. `04-crypto.md`.
6. **Which E2E fixes go upstream vs live only in libmesa?** Several are
   bug-class (default-flip to `%chum`, ECIES attestation, `peek-shut` gang
   `[~ ~]`, constant-time compare, unauth'd `%peek`). Proposed: file all
   bug-class items upstream; libmesa implements the hardened behavior
   where they preserve the chosen protocol. Revalidate the source findings in
   `04-crypto.md` D against the pinned stack before implementation; the identity
   baseline does not establish that those separate crypto fixes have landed.
7. **Onion routing for who-talks-to-whom?** Destination ship is unhideable
   from a relay without it — a hard floor. Proposed: scope as a separate
   stacked DIF, out of v1, acknowledged in the threat model. `04-crypto.md`.
8. **Azimuth aliases.** Selected direction: short names resolve to underlying
   128-bit identities. Authority, reassignment, and expiry remain to be specified.
   `03-azimuth.md` and `08-names-and-domains.md`.
8a. **Name/domain association.** The globally unique-name model and v2 selector
   bytes are settled. The next milestone must authenticate initial authority
   association and reject conflicting claims. Domain migration requires an
   explicit rule; packet arrival order is not authority.
8b. **Checksum and fragment compatibility.** V2 uses exact body bytes, with no
   alternate checksum mode. The explicit v1 reference retains the historical
   Hoon/Vere disagreement. Fragment normalization and LSS checks remain separate;
   receivers reconstruct omitted data zeros before verification.

9. **Delta-t timer algebra.** Adopt the audit (map every ames/mesa timer to
   MPL/A/R or policy; prove exactly-once closes over reliable N-1s)? Proposed:
   yes — it's spec work we owe anyway, and it settles the cork question.
   `02-rina.md` §7.3.
10. **Corks: necessary or optimization?** Falls out of #9. Proposed: treat as
    reclaimable-by-timer with corks as an optimization, pending the audit.

## Tier 3 — decisions we can make later but should flag

11. **Policy derivation vs negotiation.** Does the responder simply serve
    whatever `boq` the name requests, dissolving negotiation? Proposed: yes,
    confirm and write it down. `02-rina.md` §7.2.
12. **Recursion in v1.** Engine scope-parametric (groups-as-DIFs, LN-embedded
    DIF possible) but one instance shipped? Proposed: yes; recursion latent.
13. **Multihoming.** UDP + WSS attachments under one node address — what does
    the fief advertise, how do senders choose? Proposed: defer, note the door.
14. **Relay congestion role.** Stateless relays, or room for relay-assisted
    backpressure? Proposed: stateless bias, note the door. `02-rina.md` §7.4.
15. **Noun-layer sourcing** (contingent on #1a). If Rust: vendor from
    Nockchain/Sword vs write a small clean jam/cue+mug+mat/rub. If C: reuse
    Vere's `ur` library (as tcp-sidecar does) vs write clean. Proposed either
    way: write small and clean — we need `mat`/`rub` with the bounded-scan
    hardening anyway, and the surface is tiny.

## Cross-repo follow-up

The current baseline supersedes the older Jael-migration and Mesa-not-tested
claims. Consult the pinned lifecycle/rebase evidence rather than carrying
those historical findings forward as current defects.

- **Kernel:** `+pass-pki-dom` (ames) and the `%dome` scry (jael) are
  hand-duplicated with the `mat`-bound logic copied verbatim, sync enforced
  only by a comment. Drift hazard; libmesa's single implementation is the
  chance to define the one true version.
- **Groundwire docs are stale** relative to code: `confidential-comets.md`
  still describes `dat` as a 32-byte hiding commitment (reverted 2026-08-18 to
  plaintext satpoint). libmesa's identity chapter should cite
  `gw-btc/lib/gw-btc-pass.hoon` as ground truth, not the prose docs.
- **Shared golden vectors** (`vectors/gw-kelvin-9.json` pin exists; the
  cross-repo positive/negative set does not). libmesa's `vectors/` is the
  natural home; this unblocks cross-implementation (kernel / runtime /
  libmesa) conformance.
