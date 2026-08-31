# Working-group agenda: open questions

Ordered by how much they change the shape of libmesa. Each has a proposed
default so the meeting argues about a concrete position, not a blank page.

## Settled going in (not for debate, listed for the record)
- Mesa-only, no legacy ames / Fine / `%ahoy`. **Settled.**
- Wire-compatible with `hd/cc-kernel`; no wire-format redesign in v1. **Settled.**
- Groundwire suite-%c comets are ground truth; Azimuth second-class. **Settled (soft).**
- Everything E2E-encrypted by default; fix upstream over compromise. **Settled.**

## Tier 1 — decisions that set the architecture

1. **RINA-shaped or monolithic engine?** Proposed: RINA-shaped (three-task
   IPCP decomposition = the deliberate Arvo/Vere unification), wire-compatible,
   no CDAP/RIB formalism beyond vocabulary. `02-rina.md` §8.
2. **Flow engine: peek-only, monolithic port, or state-vector + policies?**
   Proposed: state-vector + policy modules (EFCP option C); peek-only is
   milestone 3, full flows milestone 4. `02-rina.md` §6.1.
3. **Transport mapping: pacts-verbatim, per-N-1-policy, or native framing?**
   Proposed: same pact everywhere, per-N-1 policy (delimiting/retransmit/
   congestion), so relays bridge transports statelessly. `02-rina.md` §6.2.
4. **Forward secrecy — in v1 or deferred?** The marquee crypto question. Static
   ECDH means one key compromise reads all history — squarely against the
   device-seizure threat model. A ratchet is per-pair mutable state, in tension
   with soft-state. Proposed: specify as Tier 3, design-doc it now, don't block
   v1 messaging on it but commit to driving it upstream. `04-crypto.md` gap 8.

## Tier 2 — decisions that shape the spec

5. **E2E default definition.** Adopt the three-tier definition (payload /
   metadata / relationship)? Proposed: yes; implement Tier 1 from day one,
   Tier 2 mandatory-to-implement, Tier 3 first-class open design. `04-crypto.md`.
6. **Which E2E fixes go upstream vs live only in libmesa?** Several are
   bug-class (default-flip to `%chum`, ECIES attestation, `peek-shut` gang
   `[~ ~]`, constant-time compare, unauth'd `%peek`). Proposed: file all
   bug-class items upstream; libmesa implements the hardened behavior
   regardless. `04-crypto.md` D.
7. **Onion routing for who-talks-to-whom?** Destination ship is unhideable
   from a relay without it — a hard floor. Proposed: scope as a separate
   stacked DIF, out of v1, acknowledged in the threat model. `04-crypto.md`.
8. **Azimuth: native gateway resolver, cash-out, or both?** Proposed: ship N1
   gateway resolver as reference-optional; specify the cash-out linkage
   attestation; defer C-hard snapshot pinning. `03-azimuth.md`.
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
15. **Noun crate sourcing.** Vendor from Nockchain/Sword vs write a small
    clean jam/cue+mug+mat/rub. Proposed: write small and clean — we need
    `mat`/`rub` with the bounded-scan hardening anyway, and the surface is tiny.

## Cross-repo hygiene items surfaced during exploration (not libmesa design,
but the WG should know)

- **Kernel:** `dek` was added to `dom-state` inside Jael `state-5` without a
  version bump — a ship already running the earlier `%5` with a populated
  `dos` hits a mold mismatch. This is exactly the class of bug the
  confidential-comets todo warned against. Worth a `%5`→`%6` migration
  alongside the deferred `%bane` tombstone.
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
  natural home; this unblocks three-way (Hoon/C/Rust) conformance.
