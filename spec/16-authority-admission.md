# Authority and admission components

Phase 4 adds `mesa-pki`, optional `mesa-jael`, an owned suite-C codec boundary,
and `mesa_pki.h`. It implements deterministic authority mechanisms. It does
not implement a Groundwire verifier, native first-contact packets, private
spaces, local secret activation, or Shrine migration.

## Ownership and terminology

The embedding host is the client calling Mesa. Shrine is an embedding host;
Linux/macOS is its underlying OS. Shrine applications are host applications.
The host scheduler drives readiness, time, batches and durable commits. It
neither parses incoming peer messages nor initiates incoming admission.

The Mesa transport adapter feeds the selected Mesa protocol profile. That
profile screens packet structure, name/key binding and any protocol-required
proof before calling Mesa admission. Admission emits bounded verification
requests. Shrine dispatches those requests to its verifier provider. A future
composed wrapper handles provider dispatch internally and exposes admitted
messages to its application.

The current UDP endpoint still discards unknown-source packets. Phase 4
provides `AdmissionProfile::screen` and `Jael::receive` as the component seam;
phase 6 connects native Groundwire decoding. Test profiles are explicitly
fixtures. Neither `ProfileCandidate` nor the C event of that name is a public
network packet format or a request for Shrine to parse incoming traffic.

`mesa-identity::owned::suite_c_candidate` checks bounded canonical pass framing,
curve validity and the derived name, then retains the full pass in an immutable
buffer. The verifier receives the exact pass, including genesis, dat and xtr.
Life and rift remain claimed coordinates until verified. The codec contains
noun machinery; PKI, Jael, core, flow and the normal C embedding dependency
graph contain none. No borrowed noun leaves the owned codec boundary.

## Modules and trust

`Authority` owns domain registration, point/history validation, policy provenance
and durable proposals. An alternative embedding-host authority manager can
use it directly. `Jael` owns optional request orchestration, subscriptions,
admission budgets and retries; it contains one Authority, not a second ledger.
Both paths use the same engine bridge and successor validation.

A Provider value identifies a registered domain generation and a live handle
incarnation. It is a capability of the embedding integration, not a secret
network authenticator. The embedding host must ensure only the registered
provider can submit that domain's results. Never construct a provider result
from packet-supplied fields. Standalone provider execution and chain-view
interpretation remain outside these crates.

A positive verdict attests the candidate's name/domain association, current
life/rift/key and any sponsor/fief relationships. PKI rejects coordinate
regression, domain reassociation, same-life key substitution and self sponsorship
or fief. The provider checks domain-specific relationship semantics; the generic
mechanism does not invent a sponsor hierarchy or a Bitcoin ordering rule.
Provider chain-view/reorg state belongs in its verifier; a withdrawal carries
the current peer revision. Refresh requests bind the full evidence digest.

## State and mutation

Every mutable handle has one serialized caller. Immutable options and owned
snapshots may be retained independently. No mutation occurs through a view.
All evidence, checkpoint and result bytes use immutable refcounted `[dat wid]`
buffers. The candidate digest includes exact logical width and trailing zeros.
No private key occurs in authority state, descriptions or checkpoints.

Peer names form one global namespace. A domain association cannot be replaced
by submitting the same name under another domain. Accepted points carry
provider generation, evidence and scope provenance. Retained history has a
configured bound; pruning oldest history never lowers the current life/rift
floor. Removed-domain tombstones and withdrawal fences consume configured
capacity and are not silently evicted.

Registration, availability, readiness and endorsement are separate states:

| Operation | Effect |
|---|---|
| Register/replace/revive | Require expected generation and a strictly larger generation; quarantine affected peers |
| Set unavailable, retain ready | Stop new dispatch; preserve existing permission |
| Set not ready | Quarantine domain peers and invalidate Jael jobs |
| Accept | Validate the candidate and propose state; permission waits for commit |
| Reject | Finish that candidate; leave accepted state intact |
| Unavailable result | Schedule a bounded retry; manufacture no acceptance or withdrawal |
| Withdraw | Fence jobs, gate ordinary traffic, retain history and emit one bounded evidence-solicitation action |
| Suspend | Retain registration/history; close readiness and ordinary traffic |
| Remove | Retain generation/history fences; remove the domain's authority |
| Evidence refresh | Require the exact accepted name/domain/key/life/rift before verifying new evidence |
| Operator block | Preserve a separate restriction that provider acceptance cannot clear |

Revival uses registration with a new generation, followed by readiness and
fresh peer vouches. Removing a suspended domain is supported. Withdrawal of
an as-yet-unaccepted peer records a bounded fence, invalidating first-contact
work that began before the withdrawal.

`Policy::ordinary` requires committed, revalidated authority, domain readiness
and no withdrawal or operator block. `Policy::recovery` permits only the future
profile's bounded proof recovery path; it is not application authorization.
The native profile must also authenticate packets and apply space/access rules.
Public named-read requests remain anonymous; a peer block cannot identify or
exclude an anonymous requester at a different route.

## Verification jobs, clocks and budgets

A ticket binds incarnation, provider registration generation, request ID, peer,
expected peer revision and candidate digest. The completion additionally names
the domain and must match the pending entry. `resolve_peer(domain, peer)` emits a correlated provider lookup without requiring
the embedding host to possess a pass. `resolved` validates the returned point
against the requested name/domain and the same acceptance path as incoming
profile candidates. Candidate revalidation remains available separately. Stale results,
duplicate completions and results after cancellation cannot authorize peers.

Mesa charges a global budget before profile screening. New candidates,
malformed inputs and duplicates consume it; a completed/rejected request does
not refund the interval. This bound does not rely on spoofable addresses or
claimed names. Pending count, retained evidence bytes, packet size, subscribers
and retry work have separate bounds. Unverified application messages are never
queued by these components. Jael retains candidate evidence only.

The embedding host supplies monotonic ticks. Jael emits the earliest deadline;
it owns no timer thread, polling loop or socket. A caller may select milliseconds
but must use one unit. Request timeout/unavailability triggers bounded attempts;
each dispatched retry gets a new request ID and retires the old one. A provider
that remains unavailable exhausts the attempt budget. Deadlines still overdue
after the per-tick retry-work limit remain due for the next scheduler slice.
Clock regression is rejected. Overflow finishes pending work or rejects a new
request instead of wrapping a deadline.

Withdrawal emits one `Solicit` action for an eligible known peer, destined for
the Mesa protocol profile. This phase does not encode or retransmit native
solicitations. There is no periodic Bitcoin polling, assumed attestation lease,
or automatic expiry. Provider-directed evidence refresh uses `RefreshEvidence`;
local pass/ring activation remains phase 5.

Rust `Authority::step_batch`, `Jael::step_batch` and C `mesa_pki_step` accept
bounded prefixes. Each reserves its documented worst-case output before
mutation. An error consumes its event and stops the batch; capacity preserves
the unprocessed suffix. Empty batches do no work. Completed batches retain
all buffers without an internal pending-output queue.

## Durable authority proposals

Each mutation prepares a full state snapshot with an incarnation/revision token
and the last confirmed base revision. A newer proposal includes preceding
uncommitted mutations and supersedes their tokens. Only the latest token can
be confirmed. Dirty peers remain gated until confirmation; unaffected peers
retain their committed policy. The host can persist only the newest snapshot
when coalescing a batch.

The embedding host serializes checkpoint writes. Once a newer snapshot is
written, an older asynchronous write must never overwrite it. Confirm only
after the write is durable. The base revision identifies the last confirmation;
it is not an instruction to overwrite an intervening durable snapshot. Lost
confirmation is recovered by loading the durable snapshot into a fresh handle.
The API does not roll back a staged restriction or offer an implicit abort.
Reconcile an unresolved proposal or restart from committed storage.

One latest snapshot suffices; the embedding host may implement storage with a
log. This transaction covers authority state, not every named read or unrelated
application mutation. There is no SQLite/inbox dependency. Checkpoints contain
public evidence and require trusted storage with host-defined integrity and
rollback protection; they are not network inputs or authenticated storage blobs.

Restore requires a fresh, nonzero incarnation. It discards jobs, readiness,
subscriptions and timers, and quarantines every restored peer. Reasserting
provider readiness alone cannot restore permission: a fresh vouch and durable
commit are required. Thus a crash after persisting acceptance but before
confirmation, or before persisting withdrawal, cannot automatically reopen
traffic. Old-world restore still requires the embedding host's external epoch
and the verifier's current authority view; Mesa cannot infer rollback from an
old snapshot alone.

Restrictions take effect before their durability confirmation. A valid domain
restriction that hits checkpoint capacity closes readiness; the embedding host
must reconcile errors and synchronize engine gates before running more traffic.

## Engine bridge

`Authority::sync_peer` and `mesa_pki_sync_core` read current policy rather than
replaying a queued permission. Call them for affected peers after authority or
status changes and before further CORE work. Domain-wide changes affect all
peers in that domain. Unsubscribed peers still require synchronization; a
subscription is notification, not permission to skip gates.

The bridge closes existing service gates while proposals/revalidation are
pending. After commitment it provisions a remote public key and credential
atomically. `Engine<SignedPublic>::install_public_credential` checks generation,
coordinates, handle ownership and key validity before accepting the update;
failure restores the original key table. A handle cannot alias another peer or
the local signer. Rotation reuses a peer's dedicated slot and retires an unused
previous slot, so repeated rotations do not exhaust a lifetime key table.

CORE credential changes retire cached roots, reads, reassembly and timers with
explicit outcomes. The bridge returns those engine actions; the embedding
host must process them. This does not reset a FLOW sequence ledger, implement
native same-rift message continuation, or change local secret material. Those
modules remain separate. Route installation also remains separate and confers
no authority. Stop engine service on bridge failure until the states reconcile.

## C ownership and observation

`mesa_pki_create` selects raw Authority or Jael and optionally restores a
checkpoint. `mesa_pki_describe` returns immutable options suitable for importing
once into a native plan. `mesa_pki_snapshot` returns desired authority state
plus explicit policy flags; it is an observation, not a checkpoint. Persist
only proposal checkpoints. C checkpoint size is capped at the shared 8 MiB
buffer-construction limit.

`mesa_pki_batch_get` acquires an owned buffer reference in its record. Call
`mesa_pki_record_release` for every retrieved record; independently retained
buffers survive record, batch and handle destruction. Input buffers stay owned
by the caller. No buffer lifetime depends on a noun arena or mutable view.

## Validation boundary

Deterministic provider fixtures prove lifecycle and correlation, not Groundwire
authority. Tests use real signatures for engine reads with Jael and an alternate
authority manager, including rejection of a retired signer. Compiled C tests
cover both modes, prefix budgets, retained buffers, engine synchronization and
five SIGKILL persistence boundaries. Native network first contact, real chain
verification and live Shrine acceptance remain unclaimed.
