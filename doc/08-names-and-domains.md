# Fixed names and explicit identity domains

**Wire direction superseded, 2026-11-25.** The
[Mesa-v1 default decision](23-mesa-default-and-flow-durability.md) replaces this
document's separate-default wire plan. Fixed internal identities, explicit
accepted authority bindings, and separable verifier policy remain. The text
below records why libmesa-exp-v2 was introduced; it does not set the new target.

**Direction, 2026-10-21:** libmesa standardizes on 128-bit comet names.
Azimuth short names may later alias those underlying names. The target wire
format has no name-width selector. This supersedes the earlier requirement to
preserve Mesa v1's variable-width names.

## Architectural rationale

Azimuth can be represented as a PKI domain alongside other identity systems.
Standardizing on Groundwire's 128-bit identity representation gives libmesa
a simple common base: one name layout and one domain-authority interface.
Each domain retains its own allocation, key-binding, and verification rules.

This is the simplest, cleanest, and least opinionated architectural choice
for the core: the representation is uniform while the PKI source remains a
domain choice. Azimuth short names can remain available through aliases to
underlying 128-bit identities. Alias authorization and lifecycle rules still
need specification.

The existing Mesa v1 codec and Vere comparison document interoperability
requirements. Target-format changes need explicit versioning, migration rules,
and conformance tests.

## Names and authority

The canonical name value occupies exactly 16 bytes, including leading zero
bytes. Its width does not express a rank, issuer, relay role, or cryptographic
algorithm. Allocated numeric values and hash-derived values both fit the type;
the responsible domain defines valid allocation and binding rules.

**Selected:** identity is globally unique `name128`; the domain selector
identifies its claimed authority. Peer identity equality and hashing use
`PeerId(u128)`. Full wire-name equality also includes the domain context for
interest/cache matching. The v2 selector is canonical ASCII, 1–63 bytes, with
no normalization or default (see the wire spec).

Global uniqueness is an authority invariant, not something a 128-bit integer
proves. The identity layer must establish the initial domain association through
a valid name construction or explicitly trusted resolution/bootstrap policy.
A different selector cannot overwrite an accepted association. Conflicting
claims must not create independent peers for the same name or use a
first-arrival-wins rule. Domain migration remains unspecified and fails closed
until an explicit authorization rule exists. The codec only represents claims.

The domain selector identifies an authority namespace, not a signature
algorithm. A domain may change its authorized key algorithm over time. The
core must authenticate the domain/name/key relationship and bind the relevant
context into protected messages; an unauthenticated selector is only a request
for verification, never authority in itself. V2 carries the canonical ASCII
identifier for cross-peer agreement. Hosts bind that identifier to an explicitly
configured authority; a process-local index is insufficient on the wire.

## Two ways to establish a current key

A domain may require carried evidence. The current `%gw-btc` suite-C profile
uses `ugn/dat` name binding and a custody log in `xtr`. Its adapter validates
that evidence and establishes the currently authorized key. Those fields and
the Edwards tweak are properties of this profile, not requirements imposed on
every future identity domain.

A queryable identity-ledger domain may instead resolve the current key and
point directly from `(domain, name)`. Such a peer need not carry a custody log
or a tweak opening. The verifier still needs a specified chain trust root,
validation/finality policy, and currency rules. An arbitrary HTTP response is
not equivalent to validated ledger state. The peer proves possession of the
authorized key separately from the verifier establishing that authorization.

Both modes feed the same accepted-point, rejection, unavailability, withdrawal,
and rotation interface. Direct authority observation may initiate updates;
re-attestation remains a way to prove possession and drive peer convergence.
Neither a signature nor the mere absence of carried evidence selects a weaker
verification mode. Domain policy determines the evidence source.

## Algorithm independence

The core's name type must not require an Edwards public key or a tweak.
The current discrete-log signing/agreement construction is not a post-quantum
scheme; changing a selector alone does not fix it. Signature/key encodings,
algorithm authorization, downgrade protection, and proof-size limits also need
an extensible design. A 128-bit name is an identifier, not a claim of 128-bit
post-quantum authentication security. See
[NIST's migration guidance](https://pages.nist.gov/nccoe-migration-post-quantum-cryptography/).

## Azimuth aliases and RINA

The intended resolution chain is:

```text
Azimuth short alias -> canonical 128-bit identity -> accepted point -> lane(s)
```

The alias binding has its own authority, freshness, and reassignment rules.
Resolving an alias does not authorize the destination's current key; the
underlying identity domain does that. Reassigning a short alias must not
silently transfer an existing authenticated session to another identity.
Alias resolution precedes construction of canonical wire names and cache keys.

This fits RINA's separation of naming/directory resolution from forwarding and
attachment resolution. The proposed mapping is a libmesa design interpretation,
not a claim that a stable 128-bit identity is automatically a RINA node address.
A PKI domain is not automatically a DIF: multiple identity authorities may serve
one communication scope. A separate DIF is justified by a distinct IPC scope
and policy, not merely by another issuer. IRATI's
[directory and DIF allocator description](https://github.com/IRATI/stack#3211-dif-allocator)
provides a concrete reference for the naming/discovery separation.

## Implementation and upstream boundary

The Rust default implements experimental Mesa v2: fixed names, canonical domain
tags, exact-body-byte checksums, and length-prefixed signatures. The low two
name-meta bits are reserved zero. V1 remains an explicit `legacy_v1` module;
neither decoder tries the other version after failure. Version 2 is an
experimental assignment, not an upstream allocation.

The C reference is Vere's existing `pkg/vere/io/mesa/pact.c`, with local parser
and harness hardening in a separate Vere worktree. There is no independent
libmesa C codec. `mesa-ffi` exposes Rust through new v2 functions while retaining
its v1-only functions. Vere's target-layout changes belong to a later upstream
update. The differential comparison continues to check v1 only.

The v2 fixtures are hand-specified body bytes with an independent Python
checksum; they test fixed names, domain tags, signature framing, and version
separation. They establish neither identity authorization nor cryptographic
validity. [The next milestone](09-identity-milestone.md) builds those layers.
