# C embedding: engine, transport, and persistent inbox

ABI 1 in this document is the explicit experimental compatibility API. New Mesa-v1 engines use ABI 2 and [specification 18](18-mesa-profile.md); select `mesa_options_exp_v2` when running these older examples.
The additive [raw UDP host extension](15-raw-udp-host.md) supplies configurable
CORE limits, mutable-state snapshots, generation-checked host updates and a
shared-socket UDP endpoint. The original ABI-1 layouts and constructors below
retain their defaults. Configured handles advertise their own event envelope.

ABI 1 exposes three independently owned components. `mesa_embed.h` contains
immutable buffers, owned result batches, and the raw deterministic engine.
`mesa_transport.h` contains POSIX UDP and framed TCP adapters. `mesa_inbox.h`
contains a flow engine with a SQLite inbox and checkpoint store. The existing
`mesa.h` wire-codec functions retain their ABI.

The profile uses preconfigured peers and v2 signed public objects. It does not
add requester authentication, private spaces, enrollment, generalized PKI, or
native Ames compatibility. Applications, operating systems, and test harnesses
use the same contracts.

## Ownership and immutable descriptions

Every public buffer is immutable and atomically reference-counted. It represents
`[dat wid]`: canonical little-endian data plus a logical byte width. Canonical
storage omits the zero suffix; the width preserves those bytes. For example,
`dat={1}, wid=3` represents `{1,0,0}`. `mesa_buffer_dat` returns the canonical
storage length, not a promise that `wid` bytes can be read from its pointer.
`mesa_buffer_copy` reconstructs a bounded logical range into caller storage.
Neither accessor allocates. The constructor copies its input; retain shares it.

Input references are never consumed. Each component retains or copies the state
it needs before returning. A result obtained with `mesa_batch_get` owns all its
buffer references, including nested commit buffers. Release it with
`mesa_result_release`; release the batch separately. Results and retained buffers
survive component destruction. Retain/release accept NULL. Do not overwrite an
owned result without releasing it. Do not release a reference twice.

Buffer views remain valid while their reference remains alive. There is no noun
arena, borrowed noun, or mutable public buffer. Each mutable handle has one
serialized caller, including inspection and release. Buffers and completed
batches may be read and retained on other threads. Callers supply valid aligned
pointers and declared lengths; input/output regions must not overlap. Invalid
pointers are C undefined behavior, not recoverable status errors.

Each component's `describe` returns an owned, immutable version-1 JSON buffer.
The engine description includes identity scope, installed public keys, flow
identities, resource limits, policy parameters, and incarnation. It excludes the
seed. Transport descriptions include attachment identity, framing, bounds, and
local reliability/ordering. Inbox descriptions add acceptance semantics and store
limits. Import this configuration once into a host-native representation; the
description never changes after route, service, timer, or queue operations.
Mutable state remains behind its handle and changes through explicit operations.

A buffer surviving handle release is a memory-ownership guarantee. Surviving a
process crash requires the storage contract below.

## Mutation and failure contracts

| Component | Mutable state | Mutating operations | External I/O |
|---|---|---|---|
| Engine | Reads, routes, current peers, timers, congestion, flow state | Event submission, close, release | None |
| Transport | Frame parser, send queue, readiness, failed-lane state | Commands, release | Socket reads/writes and descriptor setup |
| Inbox service | Internal engine, pending transaction, durable state, consumption markers | Submission, mark-consumed, create/open, release | SQLite and filesystem |
| Buffer/batch | Reference count only | Retain/release | None |

No component creates a worker thread or calls the host back. The host supplies
monotonic time, owns its scheduler, and services readiness. Socket constructors
duplicate caller-owned descriptors. Nonblocking status is shared with the
original descriptor; TCP construction also enables TCP_NODELAY. Release closes
only the duplicate. The fd in transport capabilities is borrowed for readiness
registration and must never be closed by the caller.

Every export catches Rust unwinding. A panic during submission poisons that
handle; only describe/release remain valid. Allocation failure may abort the
process. Argument, capacity, stale-incarnation, and closed-handle rejections
before submission do not process inputs. A raw engine semantic rejection is a
result at its input index; it stops the batch, preserving earlier successful
steps. Diagnostic strings explain Rust errors but are not a stable parsing API.
A halted flow requires recovery/reconciliation, not blind event retry.

## Bounded batching

`mesa_budget` bounds returned records, logical result-buffer bytes, and steps.
Maximums are 16,385 records, 64 MiB, and 64 steps. Engine/inbox input arrays have
at most the configured number of events (1 through 16); transport arrays have
at most 64 commands. A step is one external event or one internal inbox action.

Before each engine or inbox step, reserve capacity for 1,024 records and 4 MiB
of result bytes. This is a conservative allowance, not an allocation request.
Only actual records and bytes are retained. Reserve one additional final timer
record for the engine, or two records for the inbox timer/pending indication.
If the first required step cannot fit, return CAPACITY and NULL, with no mutation.
Otherwise return a batch describing the processed prefix. The caller must retain
and resubmit unprocessed inputs. An event error counts as processed and stops
further input processing. Batches are not atomic transactions.

The fixed engine envelope admits 32 reads of at most 64 KiB, a four-interest
per-read cap, and at most 128 active interest slots in aggregate. Finishing every
read produces at most 2 MiB of payload; sends add less than 256 KiB. A flow keeps
at most 256 KiB of outbox payload, four flows, 64 messages per reclamation batch,
and one pending proposal. Its bounded checkpoint encoding and packet output fit
the 4 MiB allowance. Runtime assertions poison the handle if these assumptions
are violated. Changing the profile limits requires revisiting this proof.

Returned TIMER is a replacement deadline, not an additional timer. Its flag
clears or arms the host timer. Advance time before packets arriving at the same
deadline. Final timer and internal-service results use event_index=SIZE_MAX and
cookie=0; external event results echo the event index and cookie. Cookies indicate
which submitted step caused a result. Read/message IDs correlate asynchronous
completion with the original operation.

The inbox drains pending work before accepting new inputs. A successful batch
may consume zero external events. `SERVICE_PENDING` requests another submission,
possibly with count=0. An enqueue event can be processed before persistence;
ENQUEUED reports confirmed persistence. Neither result counts nor input batching
imply grouped storage commits.

## Raw engine and explicit transactions

CORE exposes bindings, named reads, cancellation, and peer control. FLOW adds
ordered messages, delivery decisions, settlement, retirement, and checkpoint
recovery. Both emit complete packets and use the same lower transport boundary.
A caller may use the supplied transport or its own packet bridge.

FLOW emits a named `mesa_commit_proposal`: base/new revisions, incarnation token,
change kind, stable message ID, disposition, opaque checkpoint, and optional
payload. There is at most one pending commit per engine. The transaction owner:

1. Checks its writer fence and the expected stored revision.
2. Atomically persists the proposed checkpoint and associated disposition/effect.
3. Submits COMMITTED with the exact token after durable success.

The effect can be an OS mailbox insertion, an application-state transition, or a
record in a shared event log. The transaction owner need not be the final message
consumer. External irreversible actions need idempotence or a separate durable
outbox; this interface cannot make arbitrary external actions atomic.

On uncertain storage success, withhold confirmation and resolve the authoritative
store or restart. The live engine checkpoint is only its last confirmed state;
the store may be newer. Never overwrite newer persisted state with that export.
The host supplies a fresh nonzero incarnation on each raw-engine lifetime and
fences older storage writers. Tokens reject stale confirmations; they do not
fence the database themselves. Closing/releasing a raw handle cannot establish
that a pending transaction aborted.

Checkpoints are opaque versioned bytes, currently the existing flow-format-2
JSON encoding. Refcounted storage preserves that byte-array encoding. One latest
snapshot per node is sufficient; no checkpoint history log is required by Mesa.

## Standard persistent inbox

The inbox service wraps the same FLOW engine and `mesa-store`. Create refuses an
existing path. Open requires an existing compatible database, claims its writer
generation, and restores the latest durable checkpoint. The database supplies
the incarnation; the options field is ignored. Invalid engine configuration is
rejected before creating or claiming a store.

The service accepts messages into its durable inbox. It handles delivery
decisions, persistence, and engine confirmation internally. Each consumes one
step, so max_steps=1 can stop between persistence and confirmation. The storage
transaction records both the delivery and protocol progress before a receipt can
be published. Storage failure produces STORAGE_ERROR alongside earlier results,
stops service mutation, and never confirms the proposal. Release and reopen the
authoritative store after resolving the failure. Temporary storage exhaustion is
not a terminal rejection of the message.

Flow-progress queries expose the durable next-send sequence and outstanding
outbox count. Outcome scans recover sender settlements by revision, including
notifications lost before restart. Neither requires parsing the opaque checkpoint.

INBOX_READY is a lossy notification. Scan by durable revision to recover accepted,
unconsumed entries; restart scanning from zero after losing a volatile cursor.
Consumption markers are atomic and idempotent, but marking consumption does not
atomically apply an effect in another store. Use the explicit transaction
interface for a shared application/OS transaction boundary. Accepted network
receipts mean inbox insertion, not completion of arbitrary application work.

Consumed delivery history remains retained for existing store validation and
deduplication. A supplemental `consumed` table is created with new stores and
added transactionally when older format-2 stores are opened. Checkpoint format
and original delivery/settlement tables remain unchanged. Retention limits are
16,384 rows per application table and 64 MiB of delivery bytes; this phase does
not add application-history pruning. Fenced writers cannot consume or scan the
current inbox. A single database has one current checkpoint and serialized
commit proposals across its flows.

## Transport, congestion, and syscall boundaries

The transport adapter never decides protocol success or commits storage. It
maps one complete packet to a UDP datagram or a four-byte big-endian length and
TCP body. A packet result becomes RECEIVE with the configured peer claim and
attachment. Authentication remains in the engine. Capabilities describe the
local attachment; a reliable TCP hop does not establish whole-path reliability.
The host must compare max_packet_bytes with the engine's advertised bound before
installing a route. POSIX convenience adapters cover one fixed next hop; route
replacement uses a new adapter and explicit engine attachment updates.

Queue pressure reports CAPACITY for that send command. It counts as local packet
loss under the core's existing send/attempt contract. A hard I/O error returns
DISCONNECTED without hiding earlier results, then closes the lane logically.
The host removes its engine attachment and may install a replacement. Release
physically closes the duplicate descriptor. No partial frame crosses replacement.

Each transport command reserves two records plus max(max_packet_bytes,256) bytes,
with one final readiness record. Receive makes one bounded PacketIo attempt
(one UDP read or at most two TCP reads). TCP flush makes at most 64 vectored write
attempts, gathering up to 64 queued frames per attempt. UDP currently makes one
send syscall per command. READINESS requests reading and, when a TCP queue is
nonempty, writing. A zero-command batch inspects readiness without socket I/O.

Core controls interest admission, per-peer windows, verified-response credit,
retry budgets, and deadlines. The host chooses fixed/AIMD and fixed/exponential
retry policies. There is no RTT estimator or pacing; flow availability hints
remain outside the interest congestion window. TCP also has kernel congestion
control. See chapter 9 for the prototype's limits.

Batched FFI calls reduce crossings and scheduling work. Vectored TCP writes can
reduce write calls. Buffer access/retain/release and raw-engine calls make no I/O
syscalls. SQLite persistence still needs durable commits; this phase does not
claim reduced fsync counts or a measured throughput improvement. Buffer sharing
avoids retained payload clones, but hashing, framing, and checkpoint encoding can
still materialize/copy logical bytes.

## Noun boundary and verification

The engine, flow, wire, LSS, and embedding normal dependency graphs contain no
`mesa-noun` or `mesa-identity`. `mesa-bytes` owns shared byte buffers and the
exact-byte checksum helper. Separate compatibility/identity codecs keep their
noun/atom encoding support outside this graph. Host-specific noun serialization
belongs at that host's boundary, not in Mesa's payload representation.

Run `bash tools/test-ffi.sh` for the compiled C host. It covers refcount ownership,
zero extension, multithreaded retention, output lifetime after teardown, deterministic two-peer reads
under fragmentation/loss/duplication/reordering, cancellation, timeout, stale
incarnations, partial batches, immutable descriptions, raw commit recovery,
actual UDP/TCP adapters, queue pressure, and four SIGKILL recovery boundaries:
enqueue before/after persistence and receive before/after persistence. The latter
includes persistence before engine confirmation. Inbox consumption survives
restart, durable sender outcomes remain queryable, and newer owners fence old handles.

Run `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`,
and `python3 tools/check-embedding-deps.py`. Rust tests additionally cover atomic
consumption rollback, retained history, sparse LSS equivalence, and vectored
cross-frame partial writes. The vectored-write test accepts 16 queued frames in
one Write call; it measures adapter calls, not network latency or disk throughput.
Existing process-crash and UDP/TCP flow suites remain required. These are
process-crash tests, not simulated power-loss or storage-device fault tests.
