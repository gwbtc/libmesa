# Peer-engine milestone and fresh-task handoff

**Priority reset, 2026-10-22:** build `mesa-core` with explicitly preconfigured
peers. Completing generalized identity, Jael replacement, or a live Groundwire
verifier is not a prerequisite. This supersedes the next-work ordering in
`09-identity-milestone.md` and §4 of `10-implementation-review.md`; their eventual
identity acceptance requirements remain intact.

## Objective and starting point

Deliver a deterministic peer engine that binds data, reads it through Mesa
interests/pages, and supports message flows under loss, duplication, reordering,
and backpressure. Start with two fixture peers and a virtual clock; add the UDP
adapter after the in-memory engine works. Keep a single communication scope.

At baseline `810c114`, the workspace contains `mesa-noun`, `mesa-wire`,
`mesa-crypto`, `mesa-identity`, and wire-only `mesa-ffi`. The v2 codec, bounded
noun parsing, and suite-C crypto are implemented. There is no peer engine,
namespace store, PIT, LSS verifier, flow state machine, or transport adapter.
The baseline has 59 passing tests and five executed Hoon crypto fixtures.

Keep these settled choices: globally unique 128-bit `PeerId`; canonical explicit
ASCII `DomainTag`; experimental v2; separate legacy-v1 reference; Rust with C ABI;
Mesa-only operation. A domain is authority context, not a second identity key.
Do not reopen name representation or generalize crypto algorithms in this phase.

## Translation boundary

Translate the networking behavior of Ames/Mesa and Vere into one engine. Keep
Arvo's external-service boundaries explicit instead of translating every service
on the other side of them.

| Source responsibility | Initial libmesa treatment |
|---|---|
| Mesa namespace, interests/pages, fragmentation, message/flow sequencing and acknowledgments | Implement in the core |
| Vere packet handling, PIT, recovery, congestion, forwarding and cache behavior | Implement incrementally as core mechanisms and policies |
| Ames reactions to current peer keys, blocking, route changes and remote breach | Small trusted host-input boundary; test their effects on engine state |
| Jael key/point authority, domain registration, verdict orchestration and local key activation | External host/provider responsibility; defer implementation |
| Userspace domain evidence decoding, custody checks, Bitcoin synchronization and currency policy | External adapter; use a static fixture provider |
| Arvo event scheduling, I/O and persistence environment | Explicit events/actions, virtual time and host completion callbacks |

The pinned source already separates these concerns: `sy-init` in
`pkg/arvo/sys/vane/ames.hoon` subscribes to Jael; `sy-publ` consumes point/key,
route and breach updates; `sy-sybl` consumes authority outcomes. Port the effects
needed by networking, not Jael's internals or Gall's agent execution model.
Reference: `gwbtc/urbit@734ac17cfb88e571081b84406319a17d3d5e79dd`.

## Minimal identity and protection boundary

The host installs an explicit fixture table containing peer ID, domain, current
life/rift, fixed current key material or handles, and permitted service access.
Routes are separate configuration. The host supplies the local key at startup;
freeze local activation for this milestone. Existing suite-C helpers may check
fixture consistency without introducing a domain registry or verifier service.
Call this source **preconfigured**, not domain-verified, provisional, or life-1
fallback. Those previously selected modes remain deferred features.

Expose only the peer-control operations the engine needs: install/update a
trusted peer view, block/unblock service, update an attachment, and reset a peer
on remote breach. Reject conflicting domain associations and regressing
coordinates. Preserve flow state across a same-rift key change, gate traffic
when blocked, and invalidate old-epoch work on breach. Start with injected host
events; do not build re-attestation solicitation or autonomous rotation recovery.

Separate authority provisioning from packet/data authentication. A preconfigured
key removes the discovery/verifier dependency; it does not authenticate a packet.
A source UDP address or a packet's named data owner is not proof of sender
identity. Keep wire claims distinct from checked data/protection results.

For the first deterministic harness, a test-only protection adapter can supply
controlled successful/failed verification outcomes. This proves engine behavior,
not cryptographic packet compatibility. Do not put an accept-all verifier or a
packet-controlled trust switch in the production receive path. Implement real
LSS and the selected packet protection before calling network reads authenticated.
The protected v2 context still needs a bounded specification for that step;
generalized enrollment handshakes do not.

## Build sequence and acceptance gates

1. **Core and deterministic harness.** Implement `Engine::step(event) -> actions`
   or an equivalent synchronous API. The host owns time and I/O; no runtime or
   sockets inside the core. Introduce owned types only where state requires them.
   Move shared identity types below wire/identity only as needed, preserving
   existing re-exports; avoid a broad trait or module redesign.
2. **Named reads.** Implement bounded bind/unbind, peek/page handling, pending
   interests, fragment scheduling/reassembly, timeout/cancellation and resource
   accounting. Gate: exact bytes returned between two preconfigured peers under
   dropped, duplicate, delayed, reordered and malformed traffic; failed requests
   terminate and release state. Test small pages first, then multi-fragment data.
3. **Data integrity and UDP.** Add real LSS build/verify and a fixed supported
   protection profile using configured keys. Specify the exact protected context.
   Gate: corrupted/wrong-context data never reaches the host; two peers read in
   both directions over loopback UDP. This is libmesa-to-libmesa bring-up, not
   unchanged-Urbit interoperability or permissionless enrollment.
4. **Message flows.** Add sequencing, windows, ack/nack bindings, bounded recovery
   and backpressure, with injected congestion/timer policies. Use a fake durable
   host that acknowledges storage completion explicitly. Gate: ordered delivery,
   deduplication, loss recovery and crash/restart tests around delivery/ack
   boundaries. A production storage backend can wait; the durability contract
   cannot be replaced by acknowledging an ordinary callback.
5. **Transport and relay separation.** Exercise another attachment model and a
   relay path in the harness. Keep retries across an unproven/lossy downstream
   leg. Add TCP/WSS, multihoming and relay policies incrementally. Literal
   recursive DIF allocation can wait until one engine instance works.

The initial loss tests use fixed, documented retry budgets and window
policies. The engine also supports [injected transfer policies](../spec/09-transfer-policies.md):
capped exponential retries, aggregate peer windows, bounded AIMD feedback,
and fair scheduling across reads. This implements the policy prerequisite for
step 4. The [bounded durable flow profile](../spec/10-durable-flows.md) now
implements its transaction, sequencing, and crash/restart acceptance gate
with a fake atomic host. The tests establish bounded behavior under their schedules. A delta-t proof, production congestion
control, and complete-path policy selection remain engine work.

Steps 1 and 2 now have a deterministic implementation and in-memory acceptance
tests. See [the engine contract and test profile](12-peer-engine.md) for the
implemented behavior and replay command. Step 3 now has a
[fixed signed-public v2 profile](../spec/08-signed-public.md), C-checked LSS,
and bidirectional UDP tests between independent libmesa processes. Step 4 now
adds preconfigured finite flows, signed ACK/NACK receipts, explicit commit
completion, and deterministic crash/fault tests.

Step 5 connects the durable node to UDP and framed TCP host I/O and
exercises a bounded two-leg relay. The deterministic stream-to-lossy-datagram
harness preserves endpoint retries through disconnect and receiver restart.
See [the transport contract](../spec/11-flow-transports.md). A
[reference persistent host](../spec/12-persistent-host.md) now stores the inbox
and checkpoint atomically in SQLite, fences old writers, and passes subprocess
crash tests across both transports. Continuous log reclamation, arbitrary
application transactions, multihoming, and general relay service remain
unimplemented. Private-space encryption remains unimplemented. The RINA engine
sequence remains the priority; the later comet-demo deadline is superseded.

## Deferred work

Freeze the existing identity primitives and conformance tests. Defer the general
domain interface, verifier readiness/generations, custody schemas, chain queries,
provisional bootstrap, unregistered-domain fallback, domain migration, aliases,
algorithm negotiation, private-ring staging/persistence, and enrollment/rekey
wire exchanges. Implement neither a Jael clone nor a userspace verifier runtime.
The full identity contract returns as an integration track after engine progress.

LSS, namespace authorization, bounded memory, recovery, congestion policy and
host acknowledgment semantics remain networking work. Keep them in scope even
while the authority provider is a fixture.

## Fresh-task prompt

> Continue with safe continuous flow-log reclamation. Specify the authenticated
> and durably committed evidence that permits each endpoint to retire history.
> Keep message names monotonic and duplicate rejection valid across restart.
> Implement bounded protocol state and test delayed/replayed packets, lost
> acknowledgments, reconnects, and crashes around every watermark transition.
> Separate protocol-history reclamation from application inbox retention; do
> not delete application records without an explicit host retention decision.
> Reuse the persistent host and UDP/TCP paths. Keep preconfigured peers and the
> fixed signed-public v2 profile. Do not add generalized PKI, Jael, userspace
> verifiers, enrollment, or comet compatibility.

Read this file, current crate APIs, and spec chapters 7 through 12. Consult
Ames/Mesa and Vere source only for the mechanism being implemented. The prior
identity discussion and all planning documents are not required opening context.
