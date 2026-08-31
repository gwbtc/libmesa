# libmesa spec — 3: Namespace

> **Skeleton.** The namespace is the protocol's data plane *and* management
> plane: every mesa peer serves `/ax/~self//1/...`; acks, attestations, and
> flow state are bindings like any other.

## Outline

1. **Binding model.** path → immutable authenticated page; referential
   transparency; growth (`%pine`-class latest-value queries) deferred to a
   later kelvin.
2. **Region map.** `/mess/<rift>/...` (fragment server) · `/publ/<life>/...`
   · `/chum/<life>/<her>/<hyf>/<cyf>` · `/shut/<kid>/<cyf>` ·
   `/flow/<bone>/{poke,ack,naxp,cork}/...` · `/pawn/proof/...` (attestation)
   · `/muth/...` · `/meta`, `/whey` (probes).
3. **Authorization.** Public vs gang-gated regions; how flow regions are
   scoped to their counterparty.
4. **Host API surface.** bind/unbind, serve-callback, peek-out; the RIB
   reading of all this (doc/02-rina.md §2).
5. **Vectors.** name↔beam, region dispatch tables.
