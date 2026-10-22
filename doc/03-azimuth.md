# Azimuth as a PKI domain and alias source

**Direction, 2026-10-21:** libmesa uses a common Groundwire-style 128-bit
identity representation. Azimuth can be modeled as a PKI domain alongside
others, with its allocation and key-authorization rules supplied by its adapter.
This keeps the core simple and neutral about the source of identity authority.

Azimuth short names may resolve to underlying 128-bit identities. A single
wire-name representation then serves all domains, while an alias layer
preserves human-facing names. Alias resolution and identity verification have
separate responsibilities.

The intended lookup is `short alias -> canonical identity -> point -> lanes`.
The alias authority establishes the first mapping; the identity domain
establishes the current key and point. An Azimuth adapter may provide both
services, but each binding still needs an explicit verification rule.

Alias validity, expiry, reassignment, and cross-domain binding need a later
protocol. An alias change must not silently retarget an existing authenticated
session. A gateway trusted for alias or key resolution can substitute mappings
unless they are independently authenticated; possession of its supplied key
alone cannot prove an Azimuth allocation.

[Fixed names and domains](08-names-and-domains.md) describes the RINA-related
naming separation and the explicit-domain proposal. The current codec still
implements experimental Mesa v2, with v1 retained explicitly for comparison.
The Groundwire suite-C profile supplies the first concrete identity reference;
identity authorization, alias resolution, and an Azimuth adapter remain
implementation work.
