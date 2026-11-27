# Mesa default, terminology, and flow durability

Phase 6 implements this accepted design. Read [the implementation contract](../spec/18-mesa-profile.md) and [validation record](25-mesa-profile-validation.md) for the final API and execution boundary.

**Accepted design, implemented 2026-11-27.** Mesa-v1 is the default protocol. This decision
narrows `mesa-urbit` to Urbit serialization, naming, service conventions, and
required compatibility controls. The flow mapping below records the accepted design;
[specification 18](../spec/18-mesa-profile.md) describes its implementation. It supplements
[the roadmap](14-shrine-groundwire-roadmap.md) and supersedes the separate-default
wire direction in [the 2026-10-21 decision](08-names-and-domains.md).

The [retention design and Urbit crash investigation](24-retention-and-urbit-crash-semantics.md)
now supplies the exact rejection/closure rules and process-crash evidence.
Its evidence package separates executed Urbit tests from the libmesa tests
added in phase 6.

## Strict terminology

Use these names in conversation, specifications, test reports, and new design
documents. Version numbers always name the layer they version.

| Term | Exact meaning |
|---|---|
| **Mesa-v1** | Mesa packet format with header version 1, implemented by the pinned Urbit/Vere stack. This is the target for libmesa too; it is not an Urbit release number or old-Ames packet format. |
| **libmesa-exp-v2** | Libmesa's experimental packet format with header version 2. The assignment is local to the experiment, not an upstream Mesa version allocation. |
| **libmesa-flow/1**, **libmesa-flow/2** | Libmesa's experimental message/receipt protocols. The number versions the flow namespace and associated profile, independently of the outer packet version. Both were built over libmesa-exp-v2. |
| **Urbit-Mesa profile** | The pinned Urbit conventions over Mesa-v1: beam/path encoding, gages, proof endpoints, private-space conventions, and plea/boon messaging. It is a service/profile name, not a new packet version. |
| **old-Ames messaging** | Urbit's pre-Mesa application-message transport and its peer/flow state. This does not mean Mesa-v1. |
| **old-Ames identity controls** | Historical-format `%keys` and open packets still used by suite-C peers for identity recovery. Supporting these controls does not imply supporting old-Ames messaging or Azimuth IDs. |
| **Ames vane** | Urbit's kernel networking component, which contains both old-Ames and Mesa paths. Naming the vane does not select a transport. |
| **Groundwire suite C** | The identity/cryptographic profile. Independent of packet version, host runtime, and experimental flow version. |
| **Pinned Urbit stack** | The exact kernel, companion, runtime, and pill recorded in the investigation. Use these pins for compatibility claims; `gw/final` alone is a moving branch name. |

Do not use bare “v1,” “v2,” “legacy,” “native,” or “new Ames” to select a
protocol. Say “Mesa-v1 wire,” “libmesa-flow/2 checkpoint,” “old-Ames-to-Mesa
relationship migration,” or “Urbit-Mesa profile.” Reserve “native” for qualified
historical quotations or implementation-platform descriptions. “Urbit-compatible”
means compatibility with the recorded profile and pins, not every Urbit release.
Say “historical suite-C life-1 signer” for the narrow attestation exception;
that exception is neither old-Ames migration nor Azimuth support.

Existing symbols and paths such as `legacy_v1`, `%mesa-v2`, `flow/2`, and
`urbit_v2` keep their literal spelling when cited. The Rust module `legacy_v1`
contains the Mesa-v1 codec; its name does not make that codec old-Ames. No symbol,
ABI, checkpoint, or file rename is authorized by this terminology update.
Historical evidence retains its original labels with this interpretation.

“Default” must specify time and layer. Today's implemented engine default is
libmesa-exp-v2. The intended protocol default is Mesa-v1 after the phase-6 gates.
The Urbit-Mesa service mapping remains explicit; selecting Mesa-v1 alone does
not silently select Gall application semantics. Checkpoint schema, C ABI,
identity life/rift, and software release versions remain independent counters.

## Module ownership and transition

Reusable protocol mechanisms belong in the general Mesa modules. `mesa-wire`
encodes Mesa-v1 packets; `mesa-lss` implements the target root/proof rules;
`mesa-crypto` and `mesa-keys` supply protected operations and activation fences.
`mesa-core` owns reads, reassembly, authentication gates, congestion/retry policy,
deadlines, and cancellation. These modules remain noun-free.

`mesa-flow` owns typed ordering, stable delivery identities, outboxes, receive
progress, commit proposals, replay suppression, and recovery. A selected profile
provides message/receipt/control interpretation. Do not make this reusable
mechanism depend on Gall, nouns, or `mesa-urbit`; compose typed profile events and
actions at the boundary. Avoid a general plugin framework until the two actual
profiles require it.

`mesa-urbit` owns bounded jam/cue, marked gages, textual beam/path construction,
proof endpoints, plea/boon envelopes, bone/direction conventions, nack explanation
and cork mappings, and old-Ames identity-control encoding/exchange conventions.
It translates those conventions into typed CORE/FLOW/PKI/key operations. It does
not own generic packet parsing, cryptographic primitives, authority decisions,
host persistence, or a second transfer engine. Shared cryptographic operations
consume the exact profile-produced context bytes and retain the security checks.

Keep fixed internal `PeerId(u128)`, explicit accepted domain bindings, immutable
refcounted `[dat wid]` buffers, batched inputs/results, serialized handle mutation,
caller-owned time/readiness, and optional Jael/inbox modules. Mesa-v1 width tags
do not import Azimuth rank semantics. Domain authority comes from verified
bindings rather than a new domain field in each packet.

Freeze libmesa-exp-v2 and libmesa-flow/2 as explicit experimental compatibility
profiles while implementing the replacement. Preserve their fixtures and
existing supported restores. Change the default only after Mesa-v1 transfers,
Urbit-Mesa messaging, and recovery pass phase 6. A checkpoint must unambiguously
identify its protocol/profile, schema, endpoints, and epochs; ambiguous or
mismatched state must fail closed. Never reinterpret an experimental checkpoint
as Urbit-Mesa state or reuse its sequence namespace under another profile.
Any later conversion needs its own lossless migration design. Retirement of
the experimental profiles is a later decision, not part of this document.

## Flow mapping: what is observed and what is proposed

The source baseline is Urbit commit
`9f437ff097a0e3836fea7875a568b6192eef6a27`. Its
[`fo-call`, `fo-take`, and `fo-peek`](https://github.com/gwbtc/urbit/blob/9f437ff097a0e3836fea7875a568b6192eef6a27/pkg/arvo/sys/vane/ames.hoon#L11529)
and
[`fo-sink-boon` through `fo-take-nax`](https://github.com/gwbtc/urbit/blob/9f437ff097a0e3836fea7875a568b6192eef6a27/pkg/arvo/sys/vane/ames.hoon#L11748)
show the message and receipt transitions. This is source evidence, not a new
execution or proof of the runtime's disk/effect ordering. The earlier live
investigation establishes packet exchange; it does not establish process-crash
durability of the proposed Rust implementation.

| Operation | Pinned Urbit behavior | Proposed libmesa contract |
|---|---|---|
| Raw named read | Authenticated value transfer; no flow application-completion promise | Return owned bytes. Rebuild reads after restart; no flow checkpoint on every read. |
| Outgoing plea or boon | Bone/direction and sequence identify an ordered message; an outbox serves the payload | Commit stable identity, payload and sequence allocation before any message-bearing send. |
| Incoming plea | Deliver to the addressed vane; `%done` advances acknowledgment state and selects ACK or NACK | Offer the next ordered delivery. Publish the corresponding receipt only after the host commits its acceptance/rejection and deduplication state. |
| Incoming boon | Emit the result to the local vane and ACK without a separate application `%done`; a failed delivery can become `%lost` | Commit the received result or durable host handoff plus receive progress before ACK. Do not advertise this ACK as successful higher-level business execution. |
| Positive receipt | Releases the pending message; plea completion is reported to its client | Authenticate receipt, then commit sender outcome and outbox removal before advancing the durable send frontier. |
| Negative receipt | NACK initiates a separate read of its explanation (`%naxp`) | Preserve rejection and explanation state through recovery. Finish the mapped rejection after obtaining the required explanation; loss reports stalled recovery, never success. |
| Close | `%cork` and `%gone` exchanges close flows and preserve closed-flow knowledge | Commit closing/closed state and replay fences before publishing corresponding control results or reclaiming state. |

Pleas and boons are not interchangeable send/receive messages. A plea is a
request with an explicit completion outcome. A boon is a result/event in the
associated reverse direction; its transport acknowledgment does not provide a
general application rejection interface. For a byte service that needs explicit
accept/reject in both directions, use independently initiated plea flows in both
directions. Keep boons for the defined result/subscription behavior. The service
mapping must say which contract applies to each operation.

For a libmesa receiver, durable handoff means its embedding host has recorded
responsibility for the result. It may record a landing entry in its own world;
the managed SQLite inbox is not required. A boon ACK from an Urbit receiver
provides that profile's delivery semantics, not evidence that an arbitrary Gall
business operation succeeded. Stronger business completion needs an explicit
application response. The [runtime audit](24-retention-and-urbit-crash-semantics.md#urbits-commit-before-output-boundary)
establishes commit-before-output and process-crash recovery, with explicit
limits for business effects, storage failure, and rollback.

## Three durable boundaries for a plea

1. **Sender enqueue.** Persist the exact payload or a durable immutable reference,
   peer/epoch/profile identity, bone/direction/sequence mapping, and outbox entry
   with the host's originating effect. Confirm the commit, then publish/send.
   Keep the stable ID on retries and across same-rift key rotation.
2. **Receiver decision.** Authenticate and reassemble before offering the next
   ordered delivery. Commit its effect (or durable deduplicated handoff), outcome,
   receive frontier, and receipt/explanation reconstruction state together.
   Confirm the commit, then expose the ACK/NACK. Duplicates do not reapply the
   effect; pending duplicates cannot manufacture a completion.
3. **Sender settlement.** Authenticate the receipt and, for a rejection, obtain
   the mapped explanation. Commit the outcome and outbox removal together.
   Confirm settlement before sending subsequent work whose recovery assumes
   the prior outcome is durable. A lost local notification is recoverable from
   the host's state; it is not permission to reuse a sequence.

Use a stable delivery ID containing the selected flow profile, endpoint
identities/epoch fences, bone/direction, and sequence. A signing-key life is not
a new application-delivery identity. Same-rift rotation rederives protected
names without resetting committed ordering. A rift change fences old work;
never automatically relabel an uncertain old message as a fresh delivery.

One latest committed snapshot per transaction domain is sufficient; a host may
implement it with a log. The sender and receiver commit independently. There
is no distributed transaction and no requirement to commit every unrelated
host mutation with Mesa. A returned callback or an uncommitted proposal does
not authorize a receipt. Preserve revision guards, process-incarnation tokens,
writer fencing, and recovery from a commit whose callback was lost.

Durable flow state includes sequence allocation, outbox references, receive
frontiers, unresolved dispositions, and replay/closure fences. Read interests,
fragment caches, congestion estimates, and retry scheduling are disposable
and can be rebuilt from that state. Authority/key activation has its own durable
contract, including for hosts using only raw reads; preserve its generation and
epoch fences without combining every transaction into one global checkpoint.

Exactly-once effects require the host to commit the effect and deduplication
record together, or use an idempotent external effect. Persisting a handoff
acknowledges responsibility for later execution, not completion of that execution.
An old snapshot restore requires an epoch/fencing policy; it is not an ordinary
restart from the latest committed state.

| Crash or uncertainty | Required recovery |
|---|---|
| Before sender enqueue commit | No authorized send; retry creation against durable state. |
| After enqueue commit, before send | Rebuild the outbox and send the same delivery ID. |
| Before receiver decision commit | No receipt; retry the delivery without an unrecorded external effect. |
| After receiver commit, before ACK or commit callback | Restore its decision and regenerate the receipt; suppress duplicate effects. |
| After receipt arrives, before sender settlement commit | Restore the outbox and recover the same remote outcome. |
| After settlement commit, before notification | Recover the outcome from host state without resending as a new message. |
| During nack explanation or close recovery | Retain durable unresolved state and retry within limits; report a stall on exhaustion. |

## Bounded history, timeout, and closure

Libmesa-flow/2 uses `release/released` batch handshakes. Urbit-Mesa does not
implement them. Preserve bounded-history requirements, not those packet names
or their checkpoint arithmetic. Generic publication fences remain useful local
mechanisms, but cannot invent remote retirement evidence.

The pinned source uses a one-message send window per direction, a receive
frontier, bounded duplicate re-ack behavior, rejection explanations, and corked
flow state. Start with that window; it does not limit a large message to one
fragment in flight. In particular, `fo-peek` refuses old plea ACKs outside a
ten-sequence window unless a retained rejection explains the result, while
boon ACK queries use the receive frontier. Do not assume all old receipts
remain queryable or that a later ACK proves every earlier outcome was success.

The settlement fence prevents a restarted sender from falling behind the
peer's recoverable receipt window by advancing on uncommitted outcomes. The
[completed retention design](24-retention-and-urbit-crash-semantics.md) keeps ten
sequence outcomes, bounds explanation bodies, and compacts confirmed closed
identities into non-reused intervals with reserved quota. Sparse allocation
exhaustion backpressures new flows; timeout never evicts a replay fence.
The pinned Urbit's sparse NACK map and explicit corked set are not themselves
strictly bounded by those rules. Phase-6 bounded-history acceptance applies to
libmesa; changing Urbit's storage requires separate scope.

A read timeout ends that read attempt. A message timeout after possible
transmission reports uncertain/stalled completion; it does not prove rejection
or erase the outbox. Canceling a wait or retry cannot undo a remote effect.
Removing an unsent committed item must preserve sequence obligations; dropping
an item from the middle of a flow is not a cancellation protocol. Specify close
and abort behavior without inventing a remote rollback guarantee. Wall-clock
expiry alone is insufficient evidence for replay-safe state reclamation.

## Implementation gates after design review

Keep phases 0–5 complete and phase 7's live Shrine-to-Shrine-before-Shrine-to-Urbit
order unchanged. Phase 6 now has an explicit default-switch gate:

1. Review this service/receipt mapping, stable IDs, checkpoint/profile boundary,
   and the completed rejection/closure design. Use its source audit and recorded
   process-crash evidence; carry remaining fault cases into implementation tests.
2. Implement shared Mesa-v1 transfers and protection, plus the narrow Urbit-Mesa
   serialization/service boundary. Test Rust-to-Rust first and Rust-to-pinned-Urbit
   public/private operations, admission, and identity recovery next.
3. Implement typed flow/host commit transitions and Urbit-Mesa message/control
   mappings. Test ordered pleas, boons, acceptance, rejection explanations,
   duplicate replay, closing, and quota backpressure.
4. Exercise loss, duplication, reordering, fragmentation, timeout, cancellation,
   held/rejected verification, rotation and process termination around every
   durable boundary. Retain C/Rust ownership, batching, and stale-callback gates.
   Check actual storage and application records, not only emitted callbacks.
5. Switch the protocol default only after these gates pass. Test default-created
   peers as Mesa-v1 and explicit experimental restore as libmesa-exp-v2. Reject
   cross-profile restores and fallback/downgrade attempts. Do not require the
   experimental Hoon endpoint for any Urbit-Mesa acceptance test.

Remaining decisions concern the host service's acceptance contract and stronger
requirements for pending boons or storage bounds in the unchanged Urbit peer.
The retention design and pinned runtime audit are recorded in the follow-up;
implementation still needs its own fault and quota tests.
Shrine-side migration, real verifier integration, old-Ames relationship conversion,
and Azimuth-ID support remain outside this phase-6 implementation scope.
