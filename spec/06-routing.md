# libmesa spec — 6: Routing, relays, discovery

> **Skeleton.** Rank-free: routing inputs are points (fiefs) and lanes,
> never `@p` width. Galaxy semantics survive only as one relay deployment.

## Outline

1. **Lanes.** `%if`/`%is` (+ port); the bare-`@p` galaxy lane as a legacy
   resolution rule; multihoming (multiple attachments per peer — open,
   doc/02-rina.md §7.5).
2. **Sponsors as relays.** Any enrolled peer with a fief may serve the relay
   role (per the comet-attestation UIP); sponsor chains terminate at any
   fief-holder; cycle detection.
3. **Forwarding mechanism.** PIT (interest → lanes), hop rewriting, origin
   lane stamping, hop-count saturation; statelessness requirements; PIT
   expiry as a delta-t bound.
4. **Route liveness.** direct vs sponsor-indirect; demotion timers;
   hole-punch dual-send over UDP (policy); STUN against sponsor (policy);
   `%dear`-class LAN discovery (optional).
5. **Discovery & bootstrap.** fief-at-mint; gateway `=lamp=`-class seed
   lists; sponsor-mediated attestation push (gevulot) as the discovery
   channel for NAT'd clients.
6. **Interaction with encryption.** what a relay must be able to read
   (routing-visible name prefix) — normative boundary set in ch. 2 / doc
   04-crypto.md.
