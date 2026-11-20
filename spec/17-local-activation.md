# Local key custody and durable activation

Phase 5 adds `mesa-keys` and `mesa_keys.h`. It separates staged secret material,
accepted public authority, committed activation, active engine credentials, and
retained historical material. It uses the experimental signed-public CORE and
FLOW profiles. Native Groundwire packets, Shrine changes, verifier
implementations, and managed-inbox policy remain separate work.

## Components and ownership

| Component | Owns |
|---|---|
| `mesa-identity::owned::suite_c_material` | Bounded current-ring decoding, public-pass reconstruction, name/domain/key/evidence binding |
| `mesa-keys::SoftwareStore` | Bounded private key objects and versioned references; zeroization on final secret-owner release |
| `mesa-keys::Activation` | Durable activation proposals, current authorization checks, history, retirement intents, scoped work and send-gate revocation |
| `mesa-pki::Authority` | Public point authority, provider lifecycle, withdrawal, policy and revision provenance |
| `mesa-jael` | Optional orchestration feeding the same authority interface |
| CORE / FLOW | Transfer state, active signer, publications, read cancellation and flow epoch consequences |
| Mesa UDP adapter | Final route and credential-generation checks at the send syscall |
| Embedding host | Key-object persistence, manifest transactions, external restore fence, verifier, time and scheduling |

The embedding host means the runtime calling Mesa. A host application receives
that runtime's services. The underlying OS supplies sockets and storage.
Incoming admission ownership remains as specified in
[the authority contract](16-authority-admission.md); this phase adds no incoming
packet format or application-driven first-contact path.

Public bytes use immutable refcounted `[dat wid]` buffers. Imported material
retains its public pass, including evidence and logical byte width. Private
keys use `Arc<KeyPair>` with final-owner zeroization. Dropping a store entry
cannot erase an input ring or seed buffer retained by the caller. Descriptions,
snapshots and manifests contain public points and key references, never seeds,
expanded private keys or agreement results. Agreement results have separately
retained opaque C handles.

The default Rust/C graph contains no `mesa-identity` or `mesa-noun` dependency.
The optional C `suite-c` feature uses the bounded identity codec internally.
Neither feature exposes nouns. The current ring layout must be selected from
trusted provenance: the historical incompatible layout shares its tag.

## Custody and activation state

`KeyRef` contains nonzero backend ID, object ID and version. The software store
rejects reuse of a deleted or superseded version within its lifetime and bounds
both live keys and object-version tombstones. Activation retains 1–64 historical
slots; explicit retirement frees a slot before another rotation needs it. The embedding host protects the
same version rules when reopening its durable backend. These references are
identifiers, not file paths, callbacks or proof of authority.

The software implementation derives a key from a 32-byte seed and checks its
public key against a profile-produced candidate. The optional suite-C import
reconstructs the full pass from the ring and checks the derived name and domain.
Activation requires equality with the committed authority candidate, including
life, rift, public key and exact evidence. A seed import through the raw typed
boundary assumes the selected profile has already checked name and domain
binding; it is a trusted component entry point.

Point-first and ring-first arrival produce the same result. Missing material,
wrong evidence, a suspended provider, withdrawal, operator blocking or an
uncommitted point leaves the activation closed. Installing material alone
changes no authority or engine. Evidence refresh requires a new exact material
binding; a matching curve key with stale evidence is insufficient.

For an activation-managed composition, close a newly constructed engine before
admitting protocol work: call `SYNC_CORE` while activation is quiescent, or
`QUIESCE_FLOW` for FLOW. The legacy engine constructor remains runnable for
preconfigured callers. Selecting the key module requires this explicit wiring.

The state transition is:

```
stage public binding + private material
          + committed, current, permitted authority
                       |
                     prepare  -> close old sends and cancel scoped work
                       |
                  host durable write
                       |
                     commit   -> committed, engine still closed
                       |
                  sync CORE/FLOW -> active generation
```

A manifest holds the active reference/point, authority revisions, retained
history, deletion intents, generation, host epoch, and optional FLOW cutover
checkpoint with remote authority dependencies and retired message IDs. Activation
revision and generation increase together. Proposal tokens also carry a fresh
runtime incarnation. Prepare reserves a new revision even if that proposal is
later canceled. Confirm only the latest live token before its deadline.

Reconcile after each relevant authority mutation and before further engine work.
Loss of local permission or a changed FLOW dependency closes attached send gates
and discards pending activation and scoped work. Provider availability alone
follows the existing PKI policy; it is not an invented revocation condition.
A remote change between FLOW prepare and confirm rejects the proposal.

Cancellation, timeout and retirement leave the module quiescent. They do not
silently reinstall an older signer. A retirement-only proposal may commit after
public authority advances, allowing bounded history to be reclaimed before the
next activation. Retirement does not grant readiness.

## Persistence and recovery

The embedding host follows this order:

1. Persist the new key object and its version metadata in the selected custody
   backend. Confirm that it can be reopened with the expected public binding.
2. Prepare activation. Commit the proposed manifest with the host epoch fence
   and any FLOW cutover checkpoint and retired-message outcomes. Compare the
   proposal's base revision with the latest durable manifest.
3. Confirm the exact token, then synchronize the engine. Resume protocol work
   only after successful application.
4. To delete history, commit a retirement intent first. Perform replay-safe
   backend deletion of that exact version, then acknowledge deletion to Mesa.

One latest committed manifest suffices. The host may use a transaction log to
implement the write. Private material can live in a separate backend because
it is staged before the manifest references it. A crash before manifest commit
leaves an unused object; a crash after commit requires reopening that object.
Deletion intents make crashes between durable retirement and deletion safe.
This does not require unrelated application state to join every key transaction.

After a lost write/commit response, read durable storage. Restore using a fresh
runtime incarnation, reopen material, revalidate public authority, and prepare
a new activation. Never infer readiness from a restored manifest. Missing or
mismatched material leaves the engine closed. Do not let delayed writes overwrite
a newer manifest; use the host's transaction/CAS mechanism.

An old-world restore requires an external host epoch or minimum manifest
revision that cannot roll back with the restored world. `restore` checks both
inputs. Mesa cannot detect rollback if the host also restores those protections
and all identity state to matching older values.

FLOW continues to persist its normal latest ledger after activation. The
manifest's FLOW field is the checkpoint at cutover, not a replacement for later
FLOW commits. Restore the latest host ledger, quiesce it, drain outstanding
storage/delivery decisions, and prepare a new cutover against that ledger.
Include any resulting retired outbox outcomes in the same host transaction.

## CORE and FLOW consequences

CORE cutover cancels transient reads with `PeerReset` and clears their timer.
A same-rift life change retains immutable publications and namespace retirement
state. Cached signatures from another life/key are discarded or regenerated
under the new signer when the root is served. A local rift advance clears the
publication namespace before reopening it. Remote credential installation still
uses the phase-4 bridge and its generation checks.

FLOW quiescence is explicit and emits transient `Stalled` outcomes before
planning. `QUIESCE_FLOW` precedes `PLAN_FLOW`; a busy or rejected plan cannot
swallow cancellation results. Complete an outstanding delivery decision and its
storage proposal while closed. Quiescent completion preserves durable effects
and suppresses new sends and deliveries. FLOW stays closed until a new activation.

A same-rift life change preserves sequence numbers, message IDs, outboxes,
receipts and settled outcomes. Applying activation rebuilds transient work from
the committed checkpoint with the new signer and remote public keys. An advanced
remote rift resets only affected flows; an advanced local rift resets every flow.
The plan lists abandoned outbox message IDs explicitly. Reset sequence counters
belong to the new epoch, not the old message identity.

Every rebuilt FLOW node needs a fresh nonzero incarnation. Reusing the previous
node's incarnation is rejected; the host must also prevent reuse across older
nodes and restarts. This fences old storage completions even when a new epoch
resets ledger counters. Time remains monotonic across an in-process rebuild.
After synchronization, submit `AdvanceTo(current_tick)` to restart transient
work. For C, use the new engine incarnation in subsequent submissions.

## Retained output and send fencing

New C CORE/FLOW send records retain a `mesa_packet` capability in their batch.
`mesa_batch_packet` returns an owned reference; it survives batch and engine
lifetime changes. Cutover or engine destruction permanently revokes old records.
`mesa_udp_endpoint_send_packets` batches final submissions. Each packet checks
both its credential generation and its route/attachment generation. CORE remote
credential/policy/attachment changes conservatively revoke the whole retained
engine send batch; unaffected peers recover through their normal retries.

The Rust `SendGate::packet` composition seam stamps newly generated actions at
output time. A custom adapter calls `FencedPacket::submit` around the final
nonblocking driver submission. The gate holds its lock through that operation,
so cutover waits for a send already in progress and rejects later old sends.
Never restamp retained bytes. Never enqueue raw bytes inside `submit` for an
unchecked later send. Already submitted OS datagrams cannot be recalled.

Legacy raw-byte transport APIs remain available for preconfigured compositions;
they cannot revoke bytes copied by a caller. Activation-managed integrations
must use fenced packets through the final submission. The new packet handles
and getters preserve the existing `mesa_result` ABI layout.

## Scoped operations, mutation and batching

A public-root request contains an owned path, total size and root hash. Mesa
constructs the existing v2 signed-public transcript from the active identity,
life and rift. Agreement requests select an authorized peer, capture its public
key and revision, and return a secret outside ordinary result buffers. Requests
are immutable; callers cannot replace their transcript through the Rust API.

Operations have bounded IDs, deadlines and activation generations. Completion
checks the current authority and exact ticket. Signatures are verified against
the captured key/transcript. Agreement completions trust the selected backend
for its secret calculation and still check current peer authority. Rotation,
timeout and cancellation invalidate old completions. Retaining a completed
secret does not itself grant authority to use it under a newer identity state.

This phase implements software custody and protocol-scoped asynchronous request
and signature-completion seams. The current CORE/FLOW signer uses software keys.
Hardware-only signer activation, native session KDFs/sealing, and plugin loading
are separate integrations; this API does not claim to implement them. Historical
keys cannot sign ordinary new traffic. Reopen retained versions of one software
object in increasing version order; rebuilding a store does not import its
historical slots automatically. Explicit bounded pins protect retained
protocol material until the owning protocol releases it. A pending retirement
rejects new pins for its deletion set; cancellation or expiry releases that
reservation. Reconstruct those pins from durable protocol state before allowing
retirement after restart. There is no implicit old-key grace period.

Mutable handles require one serialized caller. Completed batches, descriptors,
packets and buffers are immutable and may cross threads. C `mesa_keys_submit`
consumes a prefix, emits a status for each consumed input, stops after a rejected
input, and reports its next deadline. Capacity reservation precedes mutation.
Rejected security-sensitive inputs may quiesce state; batches do not roll back
prior inputs. Snapshots expose changing state separately from immutable config.
All 128-bit identity, incarnation and backend fields retain their full width.
JSON consumers must preserve integer precision.

The host supplies monotonic ticks in one chosen unit. Activation and operation
timeouts share the configured duration. `deadline()` / `MESA_KEYS_TIMER` lets the
host arm one scheduler; it must advance time before delivering a completion at
that deadline. No key API reads the clock or performs filesystem, verifier or
socket I/O. Software signatures and agreement consume bounded CPU work.

Fenced UDP batching reduces ABI calls. This implementation still makes at most
one socket syscall per packet. It claims neither `sendmmsg` support nor a syscall
reduction from key batching alone.

## Validation entry points

- `cargo test -p mesa-keys`: authority/material ordering, mismatch, retirement,
  operation and engine bridges, currentness and restore fences.
- `cargo test -p mesa-core --test protected`: real signed publication rotation.
- `cargo test -p mesa-flow --test credentials`: signed flow continuity and epochs.
- `cargo test -p mesa-identity --test crypto`: pinned suite-C ring/pass binding.
- `cargo test -p mesa-transport`: retained-send syscall fencing and route checks.
- `bash tools/test-ffi.sh`: C ownership, batching, CORE/FLOW bridges, UDP fencing
  and bootstrap/rotation process-kill recovery without a managed inbox.
- `MESA_SUITE_C=1 bash tools/test-ffi.sh`: optional C ring-import boundary.
- `python3 tools/check-embedding-deps.py`: default noun-free dependency graph.

See [the phase-5 validation record](../doc/20-local-activation-validation.md)
for executed checks and limits.
