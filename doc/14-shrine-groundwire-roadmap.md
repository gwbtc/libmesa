# Shrine integration, modular PKI, and native Groundwire interoperability

**Roadmap, 2026-11-19.** The `codex/raw-udp-embedding` phase PR implements the
raw-host work in phases 1–3. See the [phase-0 contract](17-raw-udp-phase0.md),
[API extension](../spec/15-raw-udp-host.md) and
[validation record](18-raw-udp-validation.md). Native live-capture evidence
in phase 0 remains open. PKI implementation has not started.

Build the modules an operating system needs to use Mesa and Groundwire ID.
Shrine is the first integrator. Existing Urbit ships are network peers; they
will continue to run their own Ames, Jael, and Vere. Replacing Ames inside
Vere is a separate future project.

The primary identity scope is suite-C comets / Groundwire IDs on both Shrine
and Urbit nodes. Azimuth-ID interoperability is a later track. Shrine's current
networking work predates libmesa PR #11; its authors own migration to the new
API. The older bridge is a requirements reference, not a migration task for
this repository.

This plan supersedes the scheduling and external-Jael assumption in
[the original engine handoff](11-peer-engine-handoff.md) and
[the deferred identity milestone](09-identity-milestone.md). It also revises
the proposed interoperability strategy in
[identity spec §8](../spec/05-identity.md#8-transport-compatibility): do not make
an upstream rekey-announcement change the default prerequisite for a working
peer. The native compatibility investigation below must determine the required
control packets. This document does not claim those packets are implemented.

Read [the source snapshot](15-shrine-groundwire-reference.md) for evidence and
[the continuation handoff](16-shrine-groundwire-handoff.md) before resuming in
a fresh context. Phase numbers below belong to this revised plan.

## 1. Destination and priorities

The first complete integration runs a Shrine world through libmesa's raw
interfaces, uses Groundwire identity with a host-supplied verifier, and exchanges
data with a pinned Groundwire-enabled Urbit ship through its native network
stack. Both directions must survive restart, key rotation, withdrawal and
readmission. No `%mesa-v2` agent or protocol translation service stands in for
the ship's native Ames/Mesa implementation.

Shrine uses the UDP adapter. Its historical TCP bridge is not the target.
Live Shrine-to-Shrine communication is a required acceptance gate before
Shrine-to-Urbit communication; a libmesa host harness does not satisfy it.
These refinements keep the phase boundaries below unchanged.

The priorities are:

1. Make the raw Rust and C interfaces usable by Shrine's runtime and scheduler.
2. Supply reusable kernel-side PKI mechanisms, including an optional Jael module.
3. Establish native network compatibility with Groundwire-enabled Urbit nodes.
4. Package standalone verifiers and a composed library for smaller integrators.

The full library supplies the machinery that Urbit places in its kernel.
Verifiers remain outside that machinery: Bitcoin synchronization, custody-chain
validation, confirmation and reorganization policy belong to a provider.
Shrine does not need to implement Jael before integrating Mesa. It may initially
select the Mesa Jael module, then replace its orchestration without replacing
the packet engine or cryptography.

“Host” means the integrating operating system or runtime, such as Shrine.
It does not mean a Gall application or a Shrine namespace application. Those
applications receive the services their operating system exposes. Their
transactions and privileges are not part of the C ABI by default.

Full PKI support means complete authority and key lifecycle mechanisms for
Groundwire suite C, not just verifying a pass once. An inventory must account
for kernel PKI responsibilities and distinguish reusable mechanisms from
domain-specific profiles. Urbit login presentation, Azimuth-ID ships, moons,
and related bootstrap paths are outside this primary milestone. Preserve module
boundaries that can support those later without making them prerequisites.

## 2. Starting point and integration gaps

Main at `041f2148379bf9232063a9f7d6f6e4e45e4c6b0c` includes PR #11:
immutable refcounted `[dat wid]` buffers, noun-free Rust core/flow/wire data,
the raw C engine, separate POSIX transport adapters, and a SQLite inbox.
The engine has deterministic reads, fragmentation, integrity checking, bounded
retries and windows. The flow layer has its own durable experimental protocol.
These are foundations, not a native Urbit networking implementation.

| Current capability | Required delta |
|---|---|
| Experimental v2 signed public reads with preconfigured keys | Native Groundwire wire/protection profile, discovery, authorization, private spaces and key lifecycle |
| C options with fixed capacity and credential tables | Validated resource profiles and generation-aware credential updates |
| Immutable engine description | Stable configuration description plus explicit versioned mutable-state views |
| Fixed/exponential retry and fixed/AIMD windows | Verify host scheduling and overload behavior; add measured RTT/pacing policies only where needed |
| Separate UDP/TCP adapters | Host-supplied attachments, readiness and route updates that fit Shrine; native Urbit UDP path |
| `mesa-flow` profile 2, `flow/2/...` | Separate native Ames/Mesa message and receipt semantics where required; profile 2 is not native `%plea`/`%boon` |
| Suite-C primitives and bounded noun codecs | Typed PKI state machines and an isolated Urbit serialization boundary |
| SQLite managed inbox | Optional packaging; Shrine keeps its own durable world and application semantics |

Shrine's inspected `ic-net` branch already has publication, landing, custody
logs, TCP framing, timers, and an Enki Mesa bridge. It uses raw named reads and
rebuilds transient engines from durable world data. Its current custody-derived
names are not Groundwire suite-C names. Its `gw-btc` engine selector is not
evidence of Groundwire authorization. Its peer-specific encryption is not
evidence of native Urbit private-space compatibility.

The new C ABI differs from that older bridge. It caps objects
at 64 KiB, reads at 32, bindings at 1,024, and bound/reassembly bytes at 8 MiB.
The inspected Shrine configuration uses 1 MiB pages, 1,024 reads, 65,536
bindings and 64 MiB bound/reassembly limits. These are requested limits, not
measured working-set requirements. Confirm which limits remain requirements
after Shrine's migration. Extend libmesa's public configuration only for agreed
requirements; do not duplicate the Shrine-side migration in this repository.

## 3. Module boundaries

Module names below are proposed responsibilities, not promises of one crate
per row. Keep the dependency direction and independently selectable behavior.

| Module | Owns | Receives from the host or another module |
|---|---|---|
| `mesa-bytes`, `mesa-core` | Immutable buffers, named reads, reassembly, integrity, bounded recovery and transfer scheduling | Time, installed peer/credential views, bindings, transport outcomes |
| `mesa-flow` | Experimental reliable flow state and explicit commit proposals | Host delivery decisions and durable commit completion |
| `mesa-identity` / PKI types | Names, domains, profiles, typed candidates, accepted points, generations and transition validation | Authenticated authority decisions; never packet-supplied trust |
| `mesa-jael` | Domain registry, verifier request orchestration, point/key history, subscriptions, source provenance, local activation coordination | Provider availability/readiness, verified results, host persistence completion |
| Key/crypto module | Key import, scoped signing/agreement, historical-key selection and retirement | Authorized activation, secret custody supplied by the host or selected backend |
| `mesa-urbit` compatibility module | Native packet/profile mapping, proof paths, required identity-control and messaging semantics, bounded Urbit serialization | Typed identities, crypto services and core transfer mechanisms |
| `mesa-transport` | Optional socket adapters, framing, bounded queues and readiness | Host-owned descriptors/attachments, routes, declared lower-layer properties |
| Verifier provider | Domain evidence meaning, ledger view, custody validation, currency and withdrawal decisions | Requests and opaque evidence from Jael; ledger data from its own environment |
| Managed wrapper/inbox | Optional composition, storage, event loop and application inbox | The same modules and provider interface used by an OS |

Jael and an alternative host authority manager must emit the same typed
credential and policy transitions. The raw engine must not call Jael internally
or depend on SQLite, Gall, a chain client, or a verifier plugin loader. The
host chooses whether to connect those components.

Groundwire domain formatting and cryptographic pass/name checks are profile
code. Interpreting custody evidence against Bitcoin is verifier code. Urbit
`jam`/`cue` and suite-C atom encodings belong in bounded compatibility codecs;
they may reuse `mesa-noun` internally. No noun, borrowed noun, noun arena, or
noun lifetime enters the core, public Rust state-machine API, or C API. Add
dependency checks to preserve that boundary as PKI grows.

The RINA relationship stays constant: Mesa provides an IPC service over an
N-1 attachment. Shrine schedules events and selects drivers; a driver carries
bytes over UDP, TCP, or another IPC service. An attachment's reliability does
not establish peer identity or end-to-end application acceptance. Native Urbit
compatibility fixes a particular network mapping; it does not force all Mesa
attachments to emulate UDP.

## 4. Contracts to preserve and extend

### Ownership, mutation and batching

All public byte values remain immutable, refcounted `[dat wid]` buffers.
Preserve trailing zero bytes through logical width. Inputs remain owned by the
caller; outputs retain their buffers independently of engine lifetime. Imported
Shrine bars must strip the sentinel and retain the byte width exactly. Secret
material needs explicit access and destruction rules; it must never appear in
descriptions, diagnostics, or ordinary checkpoints by accident.

Each mutable handle has one serialized caller. Mutation occurs only through
documented input events and commit completions. Completed result batches and
immutable descriptors may cross threads. Retain the existing per-event batch
semantics; a batch is not an implicit all-or-nothing application transaction.
Specify partial progress, result limits, resume/drain behavior, and failure
before adding new event kinds.

Split immutable configuration from changing identity state. A host may import
configuration into PLAN once. Accepted point, key generation, readiness,
route, policy and counters are versioned views or explicit events, not silent
edits to a supposedly immutable description. An old view remains readable but
cannot authorize work against a newer generation.

Batch engine inputs, verifier completions and output records. Report the next
deadline and I/O readiness needs so the host can run one scheduler. Avoid
mandatory periodic polling, per-packet callbacks and synchronous verifier I/O.
Measure calls, copies and syscalls; batching an ABI alone does not reduce socket
syscalls. Keep optional batched OS I/O in the transport adapter.

### Durability without a mandatory inbox

Raw CORE reads may be retried after restart. Shrine can rebuild publication
bindings from its world, provided it preserves immutable naming and epoch
rules. A successful read is not a durable application-delivery acknowledgment.
Do not impose a flow checkpoint transaction on every named read or Shrine epic.

Raw FLOW and future native messaging require an explicit delivery contract.
If a host promises durable acceptance, it commits the protocol proposal and
the corresponding delivery/outbox effect together, or records a durable
deduplicated handoff before acknowledging. One latest committed snapshot is
sufficient; the host may use a log to implement that transaction. A callback
return alone does not prove persistence.

PKI adds durable authority and activation state even when the host uses only
CORE. Prepare a transition with an id, expected generation and resulting
state; activate it only after the host confirms durable commit. Persist the
matching key reference, point, evidence version and epoch fence together or
through a recoverable staged protocol. Do not require every unrelated
application mutation to join this transaction. Recovery must distinguish
committed, aborted and unresolved proposals and reject stale completions.

Restoring an older world is different from restarting the latest world.
Shrine currently keeps an external mark for this distinction. Agree which host
epoch prevents old identity or publication state from resuming after restore;
libmesa cannot infer rollback from an old checkpoint alone.

## 5. Implementation phases and exit gates

Work on provider contracts and native-profile discovery begins in phase 0.
Finish the three bounded embedding phases, then make PKI the main implementation
track. Do not wait for managed-inbox productization or a general transport stack.

### Phase 0 — Freeze the integration contract and native target

Refresh Shrine's successor to `ic-net` with its authors when available. Record
its commit, Enki revision, actual Mesa dependency, bridge API and required bounds.
Until then, use PR #11 as the API contract and the old snapshot as context. Decide
whether Enki uses the public Rust API directly or the C ABI; the current bridge
does not prove it uses the new C interface. Keep both public APIs coherent.
Shrine-side adaptation remains owned by that team; an unpublished successor
branch does not block independent libmesa work against the agreed API.

Pin an Urbit source, Groundwire desk, Vere executable and pill built from the
chosen source. Distinguish `gw/final` from deployed `gw/release` behavior.
Inventory suite-C native wire versions, checksums, paths, signatures, spaces, KDFs,
sealing, legacy control packets and application message framing. Capture
first contact, successful reads, rekey and attestation refresh from that stack.
Use those captures to choose a native profile; do not relabel v2 packets as v1.
Use direct configured routes for initial connectivity if necessary, while
obtaining identity authority through the real provider. Defer Azimuth-ID
discovery and sponsor services; record any native dependency on them explicitly.

Agree how a Shrine world presents a Groundwire identity. The proposed default
keeps Shrine's existing world identity and introduces an explicitly bound
Groundwire network persona. If the team instead adopts a Groundwire name as
the world identity, specify migration and custody before changing it. Neither
an arbitrary 128-bit Shrine name nor a domain string can impersonate a
suite-C-derived Groundwire name. Any binding between the identities needs an
explicit trust and authorization rule.

**Deliverables:** compatibility matrix with source references; host event and
buffer mapping; profile/limits agreement; kernel PKI coverage inventory;
native wire fixtures; named owners for external verifier and integration work.
**Gate:** no unresolved question about which network protocol, identity, ABI or
source revision the first integration will use. Unknown deployment facts are
recorded as blockers, not guessed defaults.

### Phase 1 — Complete raw-engine embedding for Shrine

Expose versioned validated resource options, stable configuration descriptions,
and owned state views as required by the post-migration host contract. Cover
retain/release and exact-width byte conversion in compiled C and Rust hosts.
Publish the bar conversion contract for Shrine's authors to implement.
Let the host batch binding,
read, receive, cancellation and timer events without extracting one action per
runtime crossing. Preserve bounded result production and exact error locations.

Resolve long-lived publication behavior: binding release, immutable-name
retirement, repeated publication, retention and capacity recovery. An eviction
policy must not allow one name to mean different bytes. Avoid requiring an
engine rebuild whenever a publication cache fills. Give the host explicit
pressure and retirement outcomes.

Define the credential-update seam needed by PKI without implementing a
verifier. Credentials carry peer, domain, life, rift and generation; late work
cannot cross a retirement fence. Keep raw preconfigured operation available.

**Gate:** a libmesa-side host harness models Shrine's publication/read/restart
cycle within the agreed bounds; buffers outlive handles; cancellation and
partial batches release resources; no noun dependency enters the engine.
Actual Shrine landing remains a joint test, not something this harness proves.

### Phase 2 — Complete attachment and multi-peer lifecycle

Let the host connect raw engine outputs to its own drivers or optional Mesa
adapters. Define readiness, partial writes, queue saturation, send failure,
detach, replacement and route changes. Fence delayed input and output by
attachment generation. A source address or claimed sender header is a routing
hint, not authentication.

Use the UDP adapter for Shrine, including multiple peers on one socket.
Exercise source-route lookup, bounded receive batches, route replacement,
local datagram loss and stale attachment generations. Keep framed TCP as an
optional adapter with regression coverage; Shrine TCP migration is not work
for this phase.

**Gate:** several peers make progress under loss and a saturated peer; a closed
or replaced connection cannot leak partial frames into its successor; driver
failures remain bounded and observable; the host has no hidden Mesa I/O loop.

### Phase 3 — Establish scheduling, pressure and recovery bounds

Exercise the existing retry and AIMD policies before adding another controller.
Expose deadlines, retry state and pressure counters sufficient for host
scheduling. Specify monotonic clock advancement, overdue timers, coalescing,
large time jumps, cancellation, pending output and zero-work polls. Bound work
per call so a network burst cannot monopolize Shrine's actor scheduler.

Measure fairness and retry load over UDP loss and bounded driver pressure.
Retain TCP backpressure regression tests for the optional adapter. Add
RTT estimation or pacing where those results show a need; freeze the selected
policy and its limits. Transfer control stays in the engine; the host owns
time and I/O. Lower-layer reliability informs policy but cannot replace
end-to-end deadlines or durable message receipts.

**Gate:** deterministic tests show bounded memory and work, eventual completion
or explicit timeout, and no retransmission after cancellation/retirement.
Publish a small reproducible load report with calls, bytes, copies, syscalls and
completion latency. Stop transport expansion here and move to PKI.

### Phase 4 — Implement separable Jael and authority lifecycle

Introduce deterministic PKI events/actions and the optional Jael orchestrator.
Implement domain registration, suspension, revival and removal; accepted-point
and key history; queries/subscriptions; provider request correlation; and
policy provenance. Make registry presence, process availability, verification
readiness and a current vouch distinct states.

Carry provider instance/generation, request id, domain, peer, evidence digest
and candidate coordinates through asynchronous verification. Authenticate
provider results through host capabilities. Bound pending candidates and
solicitation; cancel or invalidate work on withdrawal, replacement and removal.
Apply direct resolution and peer-carried evidence through one validation path.

Implement these outcomes as separate transitions:

| Outcome | Required effect |
|---|---|
| Accepted current point (`%full`) | Install validated authority state; clear only the applicable authority block |
| Candidate rejected (`%fail`) | Reject that candidate; retain unrelated accepted state |
| Provider unavailable (`%lost`) | Report unavailable; never manufacture authorization or withdrawal |
| Vouch withdrawn (`%snob`) | Gate ordinary traffic, preserve same-rift continuity, solicit fresh evidence |
| Domain suspended/revived (`%gost`/`%ghul`) | Retain registry/history; apply explicit readiness and resumption policy |
| Domain removed (`%bane`) | Remove registration and fence its outstanding work; apply defined peer consequences |
| Local evidence refreshed (`%anew`) | Update only matching active identity/key evidence after durable validation |

Separate operator hard blocks from domain suspension and per-peer withdrawal.
Verify life/rift monotonicity, same-life key consistency, domain association,
sponsor/fief validity, and source provenance before changing engine state.
An authority module must not clear an independent administrator's block.

**Gate:** deterministic provider fixtures exercise every transition and stale
completion race, including rejection without poisoning an accepted peer.
Run the same engine tests with Jael selected and with a host authority manager.
A fake provider proves orchestration only, not Groundwire verification.

### Phase 5 — Implement local keys, activation and durable recovery

Separate staged secret material, authorized point, active credentials and
retained historical keys. Support point-first and ring-first arrival. Activate
only the exact authorized pass/ring pair, including evidence. Supply signing
and agreement through scoped operations or selected key backends; never expose
unrestricted packet-chosen signing.

Preserve flows on a same-rift life change while fencing old credential work.
On remote rift advancement, retire prior-epoch reads, messages and timers with
explicit host outcomes. On local rift advancement, quiesce first, commit the
new epoch and credentials, then resume. A delayed `%anew` cannot reinstall an
old signer. Define historical-key retention and retirement against outstanding
protocol work and bounded storage.

**Gate:** kill/restart tests at each prepare/persist/confirm/send boundary;
point-first/ring-first permutations; stale evidence and stale key rejection;
restore of an older world; lost commit response; concurrent life rotation;
and own-rift transition without old-key traffic. No mandatory SQLite inbox is
used in the OS integration harness.

### Phase 6 — Implement native Groundwire network compatibility

Build the native profile identified in phase 0 as a selectable module. Cover
wire encoding, protected name/root context, fragmentation/LSS, public and
private spaces, agreement/KDF/seal/open, proof construction/intake, solicitation,
and identity update control. Maintain explicit separation from experimental
v2 and its custom flow protocol.

The inspected kernel bootstraps proof reads at public life 1, while the signed
proof carries the actual sender life and must address the receiver's current
life. Its proof intake expects one 1,024-byte fragment. Specify oversized
evidence behavior; a larger generic read limit does not fix that peer limit.
Test current and narrowly supported legacy life-1 attestation signers without
extending that exception to ordinary page signatures.

The inspected kernel also announces key changes through legacy open packets.
The proposed strategy is an isolated compatibility implementation of the
control subset needed by native peers. Determine `%keys`, open-packet and
migration/`%ahoy` requirements from traces and source. If convergence requires
more than that subset, expose the dependency and extend the profile explicitly.
Do not hide a required Urbit patch or whole legacy data stack inside a fixture.

Only implement legacy control required by suite-C peers in the primary track.
Legacy packet format does not imply support for Azimuth-ID peers. If a native
bootstrap route assumes such a peer, identify an explicit suite-C/direct route
or record a separate dependency instead of broadening identity scope silently.

Implement native application messaging and receipts if they are needed for
the agreed Shrine-to-Urbit service. Define its `%plea`/`%boon`, acknowledgment,
ordering, retry and durability semantics independently of `mesa-flow` profile
2. A minimal ordinary Gall application may consume test data; it must not
implement an alternate network protocol or bypass native PKI.

**Gate:** a Rust process reads and serves through the chosen ship's native
Ames/Mesa path in both directions, then exchanges the agreed application
messages. Capture proof admission, authorization, encrypted traffic, receipts
and rekey recovery. There is no `%mesa-v2` endpoint in this acceptance path.

### Phase 7 — Connect real verification and complete joint Shrine integration

Connect a host-provided Groundwire verifier through the phase-4 interface.
The provider validates real Groundwire custody evidence against an identified
ledger view, reports readiness, and issues currency/withdrawal updates. Test
vectors and fixed positive verdicts are insufficient. A regtest setup is useful
only if the selected Groundwire stack supports it; otherwise use a supported
controlled chain environment and record its parameters.

Coordinate with Shrine's authors on identity/persona mapping, secrets, durable
PKI transactions, epoch recovery, publication paths, private data and the
application payload codec. Shrine publications and Urbit applications have
different semantics; specify the mapping instead of assuming that byte exchange
creates namespace interoperability. Let Shrine own that mapping and landing.

First require two Groundwire-identified Shrine worlds to exchange data over
the UDP adapter, with publication/landing, retained buffers, restart, and
identity lifecycle outcomes checked by the host. Record this as a separate
passing gate. A preconfigured Shrine-to-Shrine run may happen as soon as the
Shrine migration is ready; the full gate also requires phase-4/5 PKI behavior.
Only after the Shrine-to-Shrine gate passes, run a Groundwire-identified Shrine
world and an existing suite-C Urbit ship over UDP/network attachments. Verify first contact in both directions, private and
public operations, application acceptance, same-rift rotation, evidence-only
refresh, withdrawal/readmission, remote breach and restart. Cover simultaneous
rotation and lost announcements. Exercise provider outage, restart, stale
results and a chain reorganization/withdrawal case with the real provider.
Include suite-C Shrine-to-Shrine cases through the same modules; use
Urbit-to-Urbit behavior as a pinned reference where it helps isolate a mismatch.

**Gate:** a repeatable joint run records exact source/runtime/pill hashes,
provider and chain view, identity provenance, network capture, host commit
evidence and application-visible outcomes. No private seeds appear in the
report. Report unsupported historical profiles and deployment constraints.
Call this full Groundwire integration only after lifecycle tests pass, not
after the first successful packet.

### Phase 8 — Package verifiers and the composed library

Provide standalone verifier plugins behind the same interface, with explicit
authentication, lifecycle and resource bounds. Start with a versioned process
protocol or another specified boundary; do not assume a stable Rust dynamic
library ABI. Keep in-process linking available where appropriate.

Compose engine, Jael, key backend, native compatibility, transport, verifier
and persistence into a drop-in library. Expose simple durable send/receive
operations and diagnostics. The wrapper must use the modules already exercised
by Shrine, not fork their state machines. Finish inbox retention, consume-marker
compaction, store migration, packaging and operator tooling here.

**Gate:** the same PKI and network acceptance suite runs through the composed
wrapper, plus process-crash, storage-upgrade and plugin-restart tests.

## 6. Kernel responsibility coverage checklist

Phase 0 must turn this checklist into a source-to-test inventory. Inventorying
does not require copying Arvo's scheduler or Gall's execution model.

| Kernel responsibility | Planned home and evidence |
|---|---|
| Pass/ring formats, name derivation, signature/agreement and key selection | Profile/key modules; kernel-derived valid and hostile vectors |
| Domain registry and provider lifecycle | Jael; registration/suspension/revival/removal replay tests |
| Public points, key history, life/rift, sponsor/fief and subscriptions | PKI/Jael; monotonicity, source, query and notification tests |
| Evidence solicitation, verification dispatch and verdict routing | Jael plus native control; correlated and bounded async tests |
| Local key installation, activation, evidence refresh and breach | Key/Jael modules; durable transition and restart matrix |
| Traffic consequences of authority and epoch changes | Core/native messaging; gate, resume, cancellation and continuity tests |
| Public/private spaces and wire protection | Crypto/native profile; differential KDF and seal/open vectors |
| Native proof and identity announcements | Urbit compatibility; unchanged-peer capture and rekey tests |
| Bootstrap from sponsor/provisional sources and optional life-1 fallback | Explicit policy modules; provenance, expiry and promotion tests, default off |
| Azimuth-ID/moon/turf/login-related kernel facilities | Deferred profiles or host presentation; inventory reusable mechanisms without putting Azimuth peers on the critical path |
| Gall verifier execution and Bitcoin ledger/custody checking | Host provider, later plugin; not a dependency of the engine or Jael implementation |
| Files, entropy, scheduling, sockets and application transactions | Host interfaces and optional adapters; deterministic replay and crash tests |

## 7. Test architecture and evidence levels

Use four harnesses with explicit claims:

1. **Deterministic state machines:** virtual time, controlled providers,
   loss/reordering/duplication, resource limits, generation races and replay.
2. **Embedding and crash harness:** compiled C and Rust hosts, retained-buffer
   tests, partial batches, host transaction proposals and process termination.
3. **Native profile conformance:** pinned Hoon/Vere vectors and captured packets,
   positive and hostile cases, exact paths and protected byte contexts.
4. **Joint live integration:** real host verifier, Shrine runtime and native
   Urbit peer, network transport and application-visible durable effects.

Keep existing experimental v2 fixtures as regressions. They prove their own
profile and cannot substitute for levels 3 and 4. Every phase records what was
read, what was executed, which hashes ran, and which guarantees remain untested.

Cross-cutting negative tests include wrong domain, wrong peer, rollback,
same-life key substitution, stale provider generations, invalid evidence,
unauthenticated routing hints, malformed/oversized proofs, jam expansion limits,
provider outage, conflicting policy sources, and stale commit completions.
Private-service tests must prove unauthorized access fails: public read service
policy is not requester authentication.

## 8. Work that can wait and dependencies that cannot

Move managed-inbox consumer ergonomics, archival/compaction policy, database
backends, wrapper deployment, generic plugin discovery, standalone verifier
packaging, Azimuth-ID interoperability, general routing/relay expansion,
forward secrecy and replacing Vere
behind the Shrine/native-PKI track. Keep existing supported paths working.

Keep bounded protocol history, immutable-name retirement, raw host transaction
correctness, PKI crash recovery and key/epoch fencing in the main track. These
are engine and operating-system obligations, not inbox-only features.

The critical path is phases 0–3 → 4–5 → 6–7. Native profile research and provider
contract work start at phase 0; the external verifier and Shrine-side work can
advance alongside libmesa. Phase 7 depends on their delivery. Phase 8 does not
block a full OS integration.

The unresolved decisions are concrete: the successor Shrine branch and bridge;
Groundwire/world identity binding; native target deployment; proof-size limits;
legacy identity-control requirements; supported private/application service;
provider readiness/reorg semantics; and the host's durable activation/restore
protocol. Resolve each with a source reference, contract and acceptance test.
Do not resolve them by adding a mandatory inbox or assuming Shrine already has
Jael.
