# Working-group agenda: open questions

Ordered by how much they change the shape of libmesa. Each has a proposed
default so the meeting argues about a concrete position, not a blank page.

## Settled going in (not for debate, listed for the record)
- Mesa-only, no legacy ames / Fine / `%ahoy`. **Settled.**
- Wire-compatible with `hd/cc-kernel`; no wire-format redesign in v1. **Settled.**
- Groundwire suite-%c comets are ground truth; Azimuth second-class. **Settled (soft).**
- Everything E2E-encrypted by default; fix upstream over compromise. **Settled.**
- Implementation language: **Rust primary**, C ABI exported from day one;
  a C wire-codec stays available as a post-phase-1 conformance exercise.
  **Settled 2026-10-13** (decision record: `07-language.md`).

## Tier 1 — decisions that set the architecture

1. **RINA-shaped or monolithic engine?** Proposed: RINA-shaped (three-task
   IPCP decomposition = the deliberate Arvo/Vere unification), wire-compatible,
   no CDAP/RIB formalism beyond vocabulary. `02-rina.md` §8.
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
   congestion), so relays bridge transports statelessly. `02-rina.md` §6.2.
4. **Forward secrecy — which lane?** The marquee crypto question, now mapped
   in `06-forward-secrecy.md`. Static ECDH means one key compromise reads all
   history, and rotation is priced in on-chain sats (a rekey is a sat move).
   Proposed: adopt **FS2** (namespace-published signed epoch prekeys —
   handshake-free, soft-state compatible, degrades gracefully to static ECDH
   when no prekey is bound); reserve the `/epok` region and KDF labels in v1;
   don't block v1 messaging; drive upstream. FS3 (double ratchet) declared an
   application-layer concern. Also note the asymmetry worth an upstream
   conversation: Arvo's event log retains secrets, so libmesa peers can honor
   FS deletion guarantees Arvo ships structurally can't (yet).

## Tier 2 — decisions that shape the spec

4a. **Adopt the snob doctrine as libmesa's baseline?** The in-process kernel
   change (groundwire#129 / urbit#67, `ops/doc/snob-doctrine.md`) deletes
   `%stale`, adds `%snob`/`%poof`/`snob-notice`, retains points while
   snobbed, and defines **key-currency** (attestations are bearer tokens;
   currency is chain-established, not signature-established). Proposed:
   **yes** — libmesa implements post-snob semantics from day one (its
   attestation state machine needs key-currency regardless), and the spec's
   identity chapter tracks the snob ladder rather than the doomed `%stale`.
   The doctrine's own three open decisions (accept the key-current
   definition; unknown-class silence evaluated before attribution; the two
   sharp rows — post-strike plain rekey = permanent snub, clean re-send with
   sat unmoved = ignored) are WG items this repo inherits verbatim.
   `00-kernel-baseline.md` § "Pending".

5. **E2E default definition.** Adopt the three-tier definition (payload /
   metadata / relationship)? Proposed: yes; implement Tier 1 from day one,
   Tier 2 mandatory-to-implement, Tier 3 first-class open design. `04-crypto.md`.
6. **Which E2E fixes go upstream vs live only in libmesa?** Several are
   bug-class (default-flip to `%chum`, ECIES attestation, `peek-shut` gang
   `[~ ~]`, constant-time compare, unauth'd `%peek`). Proposed: file all
   bug-class items upstream; libmesa implements the hardened behavior
   regardless. Per-item dispositions (*file* / *snob-PR vehicle* / *spec-led*)
   are now in `00-kernel-baseline.md` § "Upstream program" — ratify or amend
   them. `04-crypto.md` D.
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
15. **Noun-layer sourcing** (contingent on #1a). If Rust: vendor from
    Nockchain/Sword vs write a small clean jam/cue+mug+mat/rub. If C: reuse
    Vere's `ur` library (as tcp-sidecar does) vs write clean. Proposed either
    way: write small and clean — we need `mat`/`rub` with the bounded-scan
    hardening anyway, and the surface is tiny.

## Cross-repo hygiene items surfaced during exploration (not libmesa design,
but the WG should know)

- **Kernel:** `dek` was added to `dom-state` inside Jael `state-5` without a
  version bump — a ship already running the earlier `%5` with a populated
  `dos` hits a mold mismatch. This is exactly the class of bug the
  confidential-comets todo warned against. Worth a `%5`→`%6` migration
  alongside the deferred `%bane` tombstone — the snob PR (which already bumps
  Ames state `%31`→`%32`) is a natural landing.
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
