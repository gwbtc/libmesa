# Implementation review: identity, RINA, and the original plan

**Review date: 2026-10-22.** libmesa has the packet and identity primitives for
an enrollment engine. It does not yet implement a communicating IPC process.
The module boundaries largely follow the original plan; authority, namespace,
transfer control, transport policy, and host persistence still need executable
contracts. This review compares the original planning state at `d167f39` with
`codex/identity-primitives`, including the current crypto increment.

## 1. What now runs

| Area | Implemented and checked | Remaining gate |
|---|---|---|
| Wire | Bounded experimental v2 codec; fixed `PeerId`; explicit `DomainTag`; length-prefixed signatures; exact-byte checksum; separate legacy v1 codec | Protected v2 transcript and upstream adoption |
| Nouns | Canonical atoms, byte mug, bounded mat/rub, canonical jam/cue with retained sharing | Domain-specific schemas and bounded traversal by their consumers |
| Crypto | Validated Edwards public keys, signing/strict verification, scalar addition, raw Montgomery agreement, SHA-256 | Channel KDF, seal/open, LSS, authenticated packet processing |
| Suite-C profile | Current pass/ring parsing; immutable claims; `ugn/dat` name derivation; exact ring/pass correspondence | Domain authority, accepted points, proof of possession in a specified protocol, key activation |
| C embedding | Rust wire validation and roundtrip through the C ABI; static library/header packaged by Nix | Identity/core ABI, secret ownership, event and persistence contracts |
| Peer engine | Design contract only | Enrollment, namespaces, interests/PIT, timers, flows, transports, relay service |

The crypto fixtures execute pinned Lull and Zuse in Vere's standalone evaluator.
They check public keys, exported pass/ring bytes, names, atom/octet signatures,
and both agreement directions. Rotation changes live signing and agreement
while preserving identity; old/new signatures fail under the opposite key.
These tests do not execute Jael activation or a domain verifier. The fixture
[provenance and reproduction instructions](../vectors/crypto/README.md) state
which source and runtime supplied each result.

`BoundPass` proves a narrow fact: its immutable parsed fields contain acceptable
curve points and derive the reported name. Its live key remains a claim. A domain
must establish currency, a protected exchange must establish possession, and
scope policy must authorize service. Exact private/public correspondence is
necessary for local activation; it is not sufficient authorization to activate.

## 2. The RINA mapping

The three-part decomposition remains useful: layer management owns admission,
authority updates, routing policy, and namespace management; transfer control
owns sequencing, recovery, flow control, and timers; data transfer owns encoding,
fragment handling, and protection. RINA also separates enrollment, allocation,
and data transfer. These are distinct phases in the
[primary architecture paper](https://csr.bu.edu/rina/papers/BUCS-TR-2013-014.pdf),
§§2.2 and 5.1. libmesa currently implements supporting primitives for those
parts, rather than the three operating services.

A `DomainTag` identifies the authority responsible for an identity. A DIF
identifies a communication scope whose members provide IPC service. The mapping
proposed for libmesa permits several PKI domains in one scope and one identity
to participate in several scopes. A successful PKI verdict should establish the
current point; scope enrollment policy should decide which services that peer
may use. A scope boundary must not silently become part of identity equality.
This separation matters when recursion is introduced.

The 128-bit name is a stable identity, not a topological address. The proposed
resolution path is `alias → PeerId → accepted point → attachment(s)`. Resource
paths select data/services under that identity. Future Azimuth short aliases
fit the directory step; their reassignment must not redirect an established
identity-bound flow. None of this yet implements RINA addressing or a recursive
DIF allocator. [Names and domains](08-names-and-domains.md) records the mapping.

Delta-t concerns transport synchronization and bounded state lifetime. It does
not eliminate authentication, admission, or allocation exchanges. The original
report overstated the absence of handshakes and treated persistence as stronger
packet-lifetime evidence. Those passages now distinguish timer bounds from host
transactions. Exactly-once application effects still require the durable
[delivery and acknowledgment contract](../spec/04-flows.md).

The transport plan remains option C + ii: a shared state-vector engine with
separate policies, using the same pact format over different attachments. Policy
must use complete-path guarantees. A reliable WSS leg to a relay does not repair
loss on the following UDP leg. No adapter, path guarantee model, or relay has
been implemented, so this remains a design commitment rather than a result.

## 3. Changes from the original plan

| Original plan | Current direction | Assessment |
|---|---|---|
| Preserve the existing wire layout | Experimental v2 uses fixed 128-bit identities and explicit domains | Deliberate approved change. Unmodified upstream interoperability is no longer the first loopback gate. |
| Name described as a hash of the pass; suite-C mixed with secp256k1 custody primitives | Suite-C name commits to immutable `ugn/dat`; the live Edwards key rotates; Bitcoin custody belongs to the domain adapter | Correction to match the key-rotation kernel. |
| Fixed Azimuth integration/gateway in the module plan | Uniform authority interface; future Azimuth adapter and aliases | Approved simplification of the core. |
| Rust primary with C ABI | Rust workspace and wire ABI exist | Preserved. The C reference is Vere's codec, not an independent libmesa C implementation. |
| Noun/crypto/wire milestone, then identity | Parsing and identity crypto progressed together | Partial milestones 1b and 2. LSS and seal/open are still missing; neither milestone is complete. |
| One engine with policy at its boundaries | Only libraries exist so far | Consistent preparation; the first stateful implementation will test the architecture. |
| Peek/page, then poke flows, then more transports | Same sequence after identity and protection gates | Preserved. No timer or durability proof can be inferred from codec tests. |

The actual dependency graph has one mismatch with the intended layering:
`mesa-identity` depends on `mesa-wire` for `PeerId` and `DomainTag`. Move those
neutral types and their validation into a small shared module/crate before
adding the authority engine, with wire re-exports to preserve callers. Identity
policy should not acquire packet-codec dependencies. Keep suite-C construction
inside its profile and Bitcoin schemas inside their adapter.

The original broad crypto module remains only partly implemented. Raw agreement
must feed a specified KDF; it must not become a channel key by convenience.
The new strict point/signature checks intentionally narrow hostile-input
acceptance. Valid-input Hoon vectors support compatibility, but do not prove
an identical acceptance set or a complete protocol security argument.

## 4. Identity integration sequence (deferred)

**Priority update, 2026-10-22:** the sequence below is retained for identity
integration. It no longer gates peer-engine development. Follow the
[peer-engine handoff](11-peer-engine-handoff.md) for current work with
preconfigured peers and a deterministic test harness.

Build the authority and activation engine with deterministic test authorities
before attaching sockets. Use an event/action interface so the host owns its
runtime, verifier I/O, clock, and durable storage. This is a proposed concrete
shape for the existing asynchronous authority contract, not a frozen public ABI.

1. Extract the shared identity types. Define candidate, point, authority handle,
   request identifier, and authority generation types. Only host registration
   may create a verifier handle. Incoming domain strings select requests, not
   trusted results.
2. Implement accepted-point invariants and event ordering. Cover first domain
   association, conflicts, candidate rejection without poisoning accepted state,
   unavailability, withdrawal, same-life evidence refresh, life rotation, and
   rift changes. Fence stale completions after withdrawal or verifier restart.
3. Implement the selected trust policies: explicit life-1 fallback and explicit
   sponsor-assisted provisional bootstrap, with source, expiry, and revalidation.
   Domain verification alone upgrades a peer to verified status. Admission and
   independent administrative exclusions remain separate.
4. Stage local rings separately from authorization and active keys. Exercise both
   arrival orders, exact pass matching including evidence, stale refreshes, and
   failed activation. Assert the active signer's public key changes and opposite
   life signatures fail. Model persistence completion before advertising durable
   activation; test crash/recovery around that boundary.
5. Specify the protected v2 messages, KDF, replay context, and recovery exchange.
   Then add LSS/seal-open evidence and a two-peer UDP read in both directions,
   followed by rotation, withdrawal, loss, and recovery. Programmatic verifier
   tests are not network authentication. Upstream v2/Mesa-only announcements
   remain a separate interoperability gate.

This order makes identity authority the ground truth before flows depend on it.
It also exercises the management boundary without coupling it to UDP or an async
runtime. Reliable flow machinery then needs the timer audit and host durability
contract; TCP/WSS and recursive scopes follow their own acceptance gates.

## 5. Remaining design risks

- **Domain association:** globally unique names need authenticated allocation
  or construction. Conflict and migration rules cannot be inferred from the
  integer representation. Migration remains unsupported.
- **Protected context:** v2 framing specifies neither a complete handshake nor
  replay protection. Recipient, purpose, version, name/domain, life/rift, and
  content commitments must be assigned to concrete messages before exposure.
- **Persistence:** the host contract for own-rift quiescence and activation is
  still open. In-memory transitions cannot establish crash-safe continuity.
- **Scope:** the initial implementation can use one scope, but authority currency
  and permission to use that scope must remain distinct. Literal recursion and
  RINA wire interoperability are not current deliverables.
- **Authority backend:** no live Bitcoin verifier or query-backed domain has
  been implemented. Test-authority acceptance must remain labeled as such.
