# Rejection retention, closure, and Urbit crash semantics

**Design and investigation, 2026-11-25.** This completes the retention rules
proposed in [the flow mapping](23-mesa-default-and-flow-durability.md). It changes
no libmesa protocol implementation, Urbit kernel, or Shrine code. Investigation
fixtures exercise the pinned Urbit-Mesa profile. Implement these rules only
after review; the default-switch gate remains in phase 6.

## Rejection outcomes and bounded receipt history

Use one unsettled outgoing message per flow direction. A receiver offers only
the next sequence after its committed receive frontier `h`. A successful host
transaction records the outcome, deduplication/effect or durable handoff, and
the information needed to reconstruct its receipt. Publishing a NACK requires
the rejection explanation to be committed as well.

Keep the last **10 committed sequence outcomes** per incoming plea direction:
`max(1, h - 9)..h`. A positive outcome needs a disposition bit; a negative
outcome also retains its exact encoded explanation or a durable immutable
reference. Prune every entry below that floor in the same transaction that
advances it. Never replace a forgotten rejection with a positive ACK.

Requests within the retained window reproduce the exact committed outcome.
Older plea ACK/explanation requests receive no invented outcome. Future
sequences receive no ACK. A duplicate at or below `h` never reaches the host
as a new effect, even when its receipt body has been reclaimed. Boon ACKs can
be reconstructed as positive receipt from their committed frontier; boons do
not acquire a rejection channel through this design.

The sender treats an authenticated NACK as evidence of rejection and retrieves
its separate `%naxp` explanation. It retains the outbox identity and unresolved
settlement until the required explanation is available and settlement commits.
It can report “rejected; explanation pending” to the host. Timeout, an oversized
explanation, or unavailable storage reports a stalled recovery and preserves
that fact; none becomes success or a fabricated explanation. The next outgoing
message remains blocked until settlement commits.

The explanation bound `E` is an explicit encoded-object limit, no larger than
the selected CORE object limit. Both local rejection construction and incoming
explanation reads enforce it. The host must provide a representable error before
committing a local rejection; a library error-size failure is not a network
NACK. Do not silently truncate an Urbit explanation. Bound both per-flow and
aggregate retained explanation bytes. Reserve the resources for the pending
decision before offering it, or apply backpressure before accepting the work.
The receipt-history bound is at most `10 * E` explanation bytes per direction,
plus fixed disposition/frontier metadata; application retention is separate.

This window is safe for the supported fresh, single-message-window profile.
Sending sequence `s+1` requires the sender to have settled `s`, including its
explanation. Its durable settlement precedes output. Thus a restarted conforming
sender cannot legitimately need an outcome that the receiver retired after
ten later committed messages. The proof excludes old-Ames queue migration,
snapshot rollback, sequence reuse, and pipelining across uncommitted outcomes.
Those cases do not silently inherit this guarantee.

The pinned kernel does **not** establish a strict ten-entry NACK bound.
[`fo-take-done`](https://github.com/gwbtc/urbit/blob/9f437ff097a0e3836fea7875a568b6192eef6a27/pkg/arvo/sys/vane/ames.hoon#L11862)
deletes only `seq - 10`, and only when the new outcome is a rejection. Rejections
at sequences 1, 12, 23, ... can therefore leave older entries behind. Its
`fo-peek` checks that map before refusing old plea ACK queries. Our bounded
implementation preserves required recovery for the supported profile without
copying this accidental extra retention or promising historical query service.

## Close is a durable protocol transition

Use three persistent states: **Open**, **Closing**, and **Closed**. Stop new
ordinary submissions when Closing begins. Commit sequence allocation and the
close request exactly as an ordinary outgoing message. Local graceful close
waits for preceding outgoing pleas and their explanations to settle; it does
not bypass a stalled predecessor. Reject new submissions rather than silently
enqueueing them behind a completed close.

The forward endpoint sends `%cork` as the next plea. The backward endpoint
commits acceptance of that cork and its Closing state before ACKing it. It
retains the final cork sequence and receipt, and requests the forward endpoint's
`%gone` closure record. A repeated cork while Closing reproduces the committed
close receipt without reopening or redelivering the flow.

The forward endpoint commits Closed after authenticating the cork ACK. The
pinned profile also permits a matching `%gone` response when only the cork
remains outstanding; it cannot settle arbitrary preceding application work.
Only after that commit may it serve `%gone` and release its detailed close
state. The backward endpoint commits Closed after authenticating the matching
`%gone`, then releases its detailed close state. If either side crashes before
commit it restores Closing; after commit it reconstructs the closure response.
Loss of the final ACK or `%gone` triggers retries, not timeout-based deletion.

The two sides need no new acknowledgment-of-acknowledgment packet. A Closed
forward endpoint keeps serving `%gone`; a Closing backward endpoint retains
the cork receipt until it observes that evidence. Once both are Closed, only
the replay fence and ability to answer closure queries remain necessary.
The source transitions are `fo-take-ack`, `fo-take-cor`, and
[`fo-abel`](https://github.com/gwbtc/urbit/blob/9f437ff097a0e3836fea7875a568b6192eef6a27/pkg/arvo/sys/vane/ames.hoon#L11377).

Closed-flow `%gone` is a statement about the flow, not proof that every earlier
message succeeded. The pinned `fo-peek` can synthesize positive ACKs for a
closed backward side without retaining individual sequence outcomes. Libmesa
must never use that behavior to settle an old application message from stale
state. Its Closed responder serves `%gone` for closure recovery; it need not
invent application ACKs for reclaimed sequences. While Closing, it still serves
the exact retained cork receipt. Validate this narrower responder against the
pinned peer during implementation, including repeated close traffic.

Closing a subscription can abandon reverse-direction boons. Urbit's `fo-abel`
removes remaining payload/read state when the flow closes; a cork is not a
promise that every result reached its consumer. Record any locally outstanding
boon as closed with delivery unconfirmed, rather than accepted or rejected.
A durable received boon remains in the host's records after protocol close.
Services requiring business completion for every result need explicit
application responses or independently acknowledged plea flows.

## Closed-flow storage and identifier reuse

Never reuse a bone/direction identity within its endpoint epoch scope. Persist
the local next-bone allocation with flow creation; the pinned allocator advances
by four. Same-rift key rotation does not reset it. Preserve allocator exhaustion
as an explicit resource error; do not wrap or silently advance the host's rift.

Store Closed membership as sorted, disjoint intervals of actual closed bone
indices, partitioned by peer, endpoint epochs, allocation class and direction.
Normalize by the allocator's stride before coalescing adjacent indices. A
contiguous closed prefix is one interval. Keep live/Closing state separately.
Never infer that an unseen gap is closed merely because a larger bone arrived.
Ordinary traffic for a Closed member cannot recreate a flow; closure queries
can reconstruct `%gone` from membership without per-message history.

Bound active flows and closed intervals independently. Reserve one worst-case
closed-interval slot for each admitted active or Closing flow. Maintain
`stored_closed_intervals + reserved_close_slots <= T`, for a configured quota
`T`. Final close consumes at most its reservation; coalescing returns spare
slots. Commit membership and release of detailed state together. Thus closure
cannot fail because a new flow consumed the storage needed for its tombstone.

Long runs of consecutive closures compact into intervals. Sparse or adversarial
allocation can exhaust `T`; then refuse new flows with resource backpressure.
Do not evict replay fences to make room. Existing admitted flows can still
finish closing. This is a bounded-storage guarantee with explicit availability
limits, not unlimited progress under arbitrary sparse identifiers. Long-lived
flows are the initial byte service's normal use, not one new bone per message.

Route loss, verifier outage, idle time, and same-rift rotation cannot erase these
fences. An authorized epoch transition may retire a scope only when the existing
PKI/key/packet fences reject its old traffic. Forgetting a peer and restoring an
older world are separate lifecycle operations, not ordinary crash recovery.

Urbit currently retains an explicit `corked` set. This design bounds libmesa's
history; it does not bound the unchanged peer's memory under unlimited flow
churn. Requiring that stronger two-endpoint guarantee would add an Urbit change
to scope. No such change is assumed here.

## Urbit's commit-before-output boundary

The source pin is Vere `828244e7751ffc2c7a91c34907c49a9d51f2cc8f`. The
executed binary matches the earlier investigation's SHA-256. The audit follows
the active worker path, not an obsolete daemon-side persistence design:

1. `_mars_fact` schedules the processed event for the log and queues its effects
   with the event number.
2. `_disk_commit_cb` calls `u3_lmdb_save`; that function returns success only
   after `mdb_txn_commit`. The selected initialization uses ordinary LMDB sync
   behavior, without `MDB_NOSYNC` or `MDB_NOMETASYNC`.
3. `_disk_commit_done` advances the durable event frontier only on success.
4. [`_mars_flush`](https://github.com/gwbtc/vere/blob/828244e7751ffc2c7a91c34907c49a9d51f2cc8f/pkg/vere/mars.c#L834)
   releases an event's effects only when its number is at or below that frontier.
   Commit failure exits instead of releasing them.
5. The daemon's `_pier_on_lord_work_done` dispatches the released effects through
   `u3_auto_kick`. Mesa page scries also use the worker reply queue: `_mars_gift`
   appends behind pending event gifts, so a later scry cannot bypass an earlier
   uncommitted event at the queue head.

On restart,
[`_mars_poke_play`](https://github.com/gwbtc/vere/blob/828244e7751ffc2c7a91c34907c49a9d51f2cc8f/pkg/vere/mars.c#L974)
replays the committed log to reconstruct kernel state and checks its hash. It
discards replay effects. The snapshot is a recovery acceleration, not the
commit boundary: a crash before the next snapshot still recovers committed
events. Mesa outboxes, receive decisions, explanations, and closed-flow state
then drive protocol retries and reproduce replies.

A plea completion receipt therefore follows a committed kernel transition
containing its application/kernel outcome. It does not certify an arbitrary
external side effect or future application action. Boon acknowledgment follows
the kernel's delivery handling, including its `%lost` failure behavior; it does
not certify business success. A crash after commit but before output can lose
the output, which is why durable protocol retry state remains necessary.

This is a process-crash guarantee under successful storage commits. Source
inspection supports the configured sync ordering; the experiment does not
simulate power loss, broken storage, log corruption, or snapshot rollback.

## Executed verification and limits

The [evidence package](../investigation/native/retention/README.md) records
commands, UDP bytes, selected runtime traces, lifecycle signals, source hashes,
and an offline checker. The two suite-C piers were isolated copies of stopped
fixtures from the earlier investigation. Their mounted kernel files matched
all 15 entries in its recorded hash inventory. Their original piers were not
modified. The provider remains a deterministic test provider, not a real
Groundwire ledger verifier.

| Case | Observation |
|---|---|
| Receiver killed after emitting a withheld ACK | The accepted-delivery count survived restart; retry recovered the receipt without a second application effect. |
| Sender killed after emitting a withheld message | The receiver had not received that message. Restart recovered the sender outbox, and the receiver applied it once. |
| Receiver killed after emitting a withheld NACK | Restart recovered rejection and its explanation. The sender recorded a negative result; the rejected operation did not increment application state. |
| Both peers killed after closing flows | Both reconstructed the same closed bones. Replaying a captured request from a closed flow did not deliver it again; a new-flow positive control remained usable. |

The proxy observed UDP before applying SIGKILL to the emitting fixture's process
group. These tests kill processes after output eligibility, not at a debugger
breakpoint inside `mdb_txn_commit`. The source ordering proves that gate; the
experiments test its externally visible recovery consequences. Explicit `%prod`
was used in some recovery steps, so this is not an autonomous retry-deadline test.
Direct route learning can bypass the proxy; the record distinguishes an early
sender case that completed normally from the later captured-and-dropped kill.

Normal boons and their retained Gall state were exercised during subscription
and closure tests. A kill precisely at boon receipt, lost final cork ACK/%gone,
quota exhaustion, interval compaction, and libmesa host-transaction fault
injection remain implementation acceptance tests. The retention mechanism is
designed here, not implemented or benchmarked.

## Decisions before implementation

The protocol choices are settled by this design: ten sequence outcomes,
commit-gated advancement, explicit explanation recovery, two-sided durable
closure, non-reused IDs, interval replay fences, and quota backpressure.
Do not add a retirement handshake that an unchanged Urbit peer cannot speak.

The remaining service choice is what acceptance means to the embedding host:
an applied namespace effect or a durable landing/handoff. Label that contract
explicitly. Use independent plea flows where both directions require rejectable
business operations; use boons for the agreed result/subscription semantics.
Shrine's authors own the application mapping, not this repository.

Two stronger requirements would change scope: guaranteed delivery of every
pending boon despite subscription close, and bounded historical storage in the
unchanged Urbit peer under arbitrary churn. The recommendation is to promise
neither in phase 6. Report unconfirmed delivery at close and keep flows
long-lived; keep any stronger service or Urbit change separate.

Resource values such as `E`, active-flow slots, and `T` are host-configurable
limits rather than new wire negotiation. Implementation must expose their
accounting, reject unsupported bounds, and test saturation. No user-specific
default is inferred from the older Shrine networking branch.
