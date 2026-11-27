# Mesa-v1 engine and Urbit-Mesa service profile

Mesa-v1 is the protocol for new integrations. `libmesa-exp-v2` and
`libmesa-flow/2` remain explicit experimental compatibility profiles. A wire
version, C ABI, checkpoint schema and service profile are separate identifiers.
No decoder retries another profile, and no checkpoint converts implicitly.

## Ownership

`mesa-core` owns framing selection, authenticated ROOT reads, LSS reconstruction,
fragment scheduling, retry budgets, deadlines and per-peer congestion windows.
`mesa-crypto` owns exact-byte path protection and encryption. `mesa-flow::ordered`
owns sequence frontiers, outboxes, retained outcomes and closure. These crates
have no noun dependency.

`mesa-urbit` owns bounded jam/cue, marked gages, textual paths, Gall byte-service
conventions, proof screening and the required old-Ames identity controls. Its
UDP listener composes `mesa-transport`; the host owns the socket lifetime,
clock input, verifier and local transactions. Optional Jael consumes screened
candidates through the same authority API. Neither admission nor a route hint
establishes application delivery.

An unknown peer's ordinary payload stays below the host interface. The listener
solicits a proof and emits a screened `Verify` request. `promote` requires the
exact candidate in committed, currently usable PKI authority. A route is a
hint, not authenticated address ownership. Provider failure cannot promote it.

## Raw C engine

```c
mesa_options options;
mesa_options_default(&options); /* ABI 2, MESA_CORE */
/* Fill local identity, incarnation, custody seed and transfer policy. */
mesa_namespace namespaces[] = {
  /* { peer ID, immutable profile prefix buffer } */
};
mesa_engine *engine = NULL;
mesa_engine_create_mesa(&options, NULL, keys, key_count,
                        namespaces, namespace_count, &engine);
```

The optional resource argument selects the existing CORE limits. Namespace
prefixes are copied and fixed at creation. The immutable descriptor includes
them, the selected profile and resource bounds. Constructors and submissions
retain ordinary `[dat wid]` buffers; callers release their input references.
Results own references independently of the batch and engine.

`MESA_RELEASE_PROTOCOL_OBJECT` releases a transient binding only after the
service owns a durable sequence/closure fence. It refuses an object referenced
by an active payload-bearing read. Ordinary publication retirement keeps its
existing `UNBIND`/prefix-fence semantics.

The existing submit budget, prefix processing, event cookies, incarnation
checks and final timer replacement apply to Mesa-v1. Private operations add:

| Event | Inputs | Meaning |
|---|---|---|
| `MESA_BIND_PRIVATE` | `peer.id`, `data=path`, `aux=ciphertext` | Publish only to that configured peer |
| `MESA_READ_PRIVATE` | `peer.id`, `id`, `data=path` | Authenticate MAC and every leaf before completion |
| `MESA_READ_POKE` | `peer.id`, `id`, `data=remote ACK path`, `aux=local payload path` | Retry a payload-bearing request with CORE's scheduler |
| `MESA_POKE` | `peer.id`, `data=payload path`, `aux=ACK path` | Send one payload-bearing packet |
| `MESA_SEND_PAGE` | `peer.id`, `data=path` | Send a bound initial page |
| `MESA_SEAL_PATH` / `MESA_OPEN_PATH` | `peer.id`, `data=path` | Protect or authenticate profile path bytes |
| `MESA_ENCRYPT_OBJECT` / `MESA_DECRYPT_OBJECT` | `peer.id`, `data=sealed-path IV`, `aux=object` | Transform exact bytes; return `MESA_PROTECTED_BUFFER` |

Byte-protection events change no engine state and perform no I/O. They require
current installed credentials and an open key gate. The caller decrypts only
a completed authenticated private read. Generic CORE does not interpret a
service path or a payload noun. `MESA_KEYS_MESA_ROOT` supplies a scoped signature
operation for a trusted profile namespace; the older `MESA_KEYS_ROOT` keeps its
experimental transcript.

Use `mesa_batch_packet` and the fenced UDP submission API for retained sends.
Never restamp an old packet after activation. The final transport syscall
checks the capability under the same gate used by key cutover. Retaining a
buffer preserves its bytes, not permission to send them with retired keys.

ABI 1 constructors retain experimental behavior. Explicit experimental option
initialization and restore remain available. An ABI 2 options object passed to
an ABI 1 constructor fails; the library does not infer a profile from traffic.
The existing managed inbox remains `libmesa-flow/2`; this phase adds no mandatory
persistence wrapper to the raw engine.

## Ordered host transactions

A transaction domain contains one peer pair, both authority domains and both
rifts. Message IDs also contain bone, direction and sequence. A same-rift life
change preserves these IDs. A new epoch requires a new transaction domain.
The Urbit service wrapper fences its sends and refuses an in-place epoch
replacement; the host records the old outboxes as unconfirmed before starting
the new domain. It must not restore the old domain under new coordinates.

Every mutation returns a proposal with base revision, new state, change and
incarnation-bound token. The host persists that state and the associated local
effect in one transaction, then calls `Committed`. Enqueue releases traffic
only after commit; receive acceptance releases the receipt only after commit;
settlement removes the outbox only after commit. A lost callback recovers from
the latest committed state. No distributed transaction or checkpoint log is
required.

A plea permits accept or reject. A boon permits durable handoff only; its ACK
does not claim business success. Rejection-known state blocks the next send
until a bounded authenticated explanation and settlement are committed.
Timeout, excessive explanation size and unsupported payloads never imply
acceptance. The profile preserves the exact encoded negative explanation.

Each admitted flow reserves ten worst-case negative outcomes and one closure
interval. Every receive advance removes outcomes older than its last ten
sequence numbers. The receive frontier remains permanent: older replay gets
no invented positive receipt. Closed intervals coalesce only adjacent,
actually closed bones of the same allocator class and direction. Holes remain
unknown. There is no tombstone TTL or bone reuse.

Close drains outgoing application work, commits a cork as the next sequence,
and waits for its ACK or a matching gone while that cork is outstanding. The
receiver commits its cork receipt and Closing state before ACK and fetching
gone. Closed state answers gone requests and never fabricates old application
ACKs. Closing a receiver with remaining outgoing work includes `unconfirmed`
in its durable `Closed` change. Recovery and simultaneous corks use the same
rules. Closed-flow reads and retransmission timers are cancelled.

Final closure waits for any outstanding delivery decision on that flow,
including an offer made after Close. Until its effect/receipt transaction
commits, the raw ordered node returns `Busy` for the cork ACK or matching gone
without consuming it or changing state. The raw caller retains and retries that
event after `Decide` and `Committed`; the Urbit session queues it automatically.
Closing another flow preserves the outstanding offer.

## Urbit binding and recovery

The protected prefix is `/<publisher>//1/`. The pinned Hoon beam uses case 1;
it does not serialize the wire rift into that prefix. Authority supplies the
expected epoch. A packet cannot advance it. Domain bindings also come from
authority rather than an unauthenticated wire selector.

Proofs use the public-life-1 bootstrap path and contain the actual sender life.
The encoded marked gage must fit one 1,024-byte fragment. It addresses the
receiver's current life. The optional historical life-1 signer applies only to
attestations under the selected provider policy, never ordinary object roots.

Old-Ames `%keys` and signed open controls support identity recovery only.
Four-bit ticks never select a key. Recovery opens address receiver life 1;
proactive announcements address its exact known life. The listener screens a
known peer's open before verification and promotes only committed authority.
Local activation cancels old proof correlations and recovery replies.

The pinned Urbit kernel skips a private poke naming an unknown key life; that
packet alone does not trigger key discovery. After activation, use bounded
`Announcement` retries of the current signed open. They reuse CORE retry
policies, carry a revocable packet capability, and stop on cancellation,
timeout or budget exhaustion. Only authenticated subsequent traffic proves
that the peer used the new key. There is no inferred success on timer expiry.

The Mesa-v1 decoder ignores Vere's unused two-bit next-hop field on peeks,
which carry no route trailer. Captures include `HOP_SHORT` and `HOP_LONG`;
the pinned C peek codec ignores all four values. These bits grant no route
authority. The historical strict codec retains
its canonical round-trip rule. Pages with unsupported route forms remain
unsupported.

The initial service maps byte pleas to a configured ordinary Gall agent and
uses `[noun octs wid dat]` payloads. It does not implement Gall's general control
protocol, Azimuth identity, old-Ames messaging, relay discovery or `%ahoy`
takeover. Fresh or already-Mesa relationships and direct UDP are required.
