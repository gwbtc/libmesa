# Raw host API: configuration, generations and shared UDP

These additive interfaces implement the raw-host work in roadmap phases 1–3.
The [ABI 1 ownership and batching contract](14-c-embedding.md) remains in force.
Existing constructors, structures and event tags retain their layouts. The
new configured constructor and snapshots apply to CORE; FLOW and the managed
inbox retain their existing resource and durability contracts.

## Configuration and owned state

`mesa_engine_create_configured` accepts version-1 `mesa_resources` and up to
256 public keys. Its default resource profile matches the original constructor.
Callers may request these validated bounds:

| Resource | Allowed range |
|---|---|
| Peers | 1–256 |
| Reads | 1–1,024 |
| Namespace slots, including retired names/fences | 1–65,536 |
| Object bytes | 1–1 MiB |
| Bound bytes and reassembly bytes | Object limit–64 MiB each |
| Unverified bytes | 1 KiB–8 MiB |
| Per-read window | 1–16, with reads × window ≤ 4,096 |

Wire limits remain 1,472-byte packets, 256-byte paths, bloq 13, and at most
1,024 fragments. Configuration also validates the chosen transfer policy.
Invalid configuration returns before publishing a handle. No allocation is
reserved for every configured object or read at construction.

`mesa_engine_describe` returns the original immutable configuration. It now
reports the configured output reservation. `mesa_engine_snapshot` returns an
independently owned JSON view of mutable state: handle incarnation, revision,
clock, deadline, resource use, counters and peer generations. Snapshots do not
mutate the engine. Retained views remain valid after later events or destruction.
Neither interface exports seeds. The host can import configuration once into
its native representation and update changing state from events or snapshots.

Rust has the same distinction: `Config` and policy select fixed behavior;
`Engine::snapshot()` returns an owned `host::Snapshot`. `step_batch` returns
`host::Record` values with immutable shared `Buffer` payloads. The original
single-event `step` remains available with its existing vector-based actions.
Use `BindBuffer` for shared input storage instead of copying legacy `Bind`
vectors into batches.

## Batching and scheduling

The configured CORE envelope reserves at most:

```text
interests = max_reads × window
Rust records = interests + max_reads + 4
Rust bytes = (interests + 1) × max_packet + max_object_bytes
C records = Rust records + 1
C bytes = max(Rust bytes, 256)
```

The C reservation includes an event-status record; the batch also needs one
final TIMER slot. Use the descriptor's `step_records` and `step_bytes` for
configured engines, not the original `MESA_STEP_*` constants. A receive can
complete one object and schedule other reads. Timeout, cancellation, service
changes and close can finish multiple reads without returning their payloads.

Both APIs reserve before mutation, accept a prefix, count a rejected final
event as processed, and leave later events untouched. Rust's batch contains
per-event results; C carries `event_index` and `cookie`. C coalesces timers to
one final replacement. An empty submit observes the current timer without
advancing time or performing I/O. Resume only the unprocessed input suffix.
There is no hidden result queue.

Time is an unsigned monotonic tick supplied by the host. Use one consistent
unit for all deadlines and retry parameters; the host may select milliseconds.
Advance time before processing packets at that deadline. Same-tick advances
do not resend active interests. A large jump processes expired work once;
it does not replay every missed timer tick. Cancelled, reset and completed
reads have no remaining retry timer. Detached reads retain their absolute
deadline and consume no new send attempts until attached.

Retry and congestion remain host-selected fixed/exponential and fixed/AIMD
policies. Counters expose emitted packets/bytes, retransmissions, received
packets/bytes, drops, completions, cancellations and timeouts. A snapshot also
reports per-peer window, in-flight and queued interests. These counters describe
mechanism behavior; they do not certify Internet congestion safety.

## Trusted credential and attachment updates

`InstallCredential` / `MESA_INSTALL_CREDENTIAL` installs a trusted host view
through a compare-and-swap on its generation. An absent or legacy peer begins
at generation zero. The new generation must exceed the expected generation,
which must equal the current value. Domain, life/rift, key availability,
same-life consistency and explicit breach checks still apply.

The update invalidates old raw reads, including their cached authentication
root, reassembly and timers. It reports `PeerReset` / `MESA_READ_RESET` for
those reads. It does not replace keys in the immutable key table, activate a
local signer, verify authority, or implement PKI. Once a peer uses the fenced
interface, its legacy install/breach events return `StaleGeneration` /
`MESA_STALE`; an unversioned update cannot bypass the fence. FLOW continues
through its existing update API; durable flow continuity is not redefined here.

`ReplaceAttachment` / `MESA_REPLACE_ATTACHMENT` has an independent monotonic
generation. When attached, that generation is also the attachment ID in
SEND/RECEIVE records. Detaching advances and retains the fence. Pending reads
keep their retry/deadline state; delayed receive records from an older
attachment fail the attachment check. Once fenced, legacy `SetAttachment`
cannot overwrite that peer's route.

Generations are scoped to a live handle and its incarnation. A host that queues
work across handle replacement must fence it by incarnation as well. Never
retag an old result with the current generation or incarnation.

## One UDP receive owner

`mesa_transport::UdpEndpoint` and `mesa_udp_endpoint_*` multiplex a bounded
route table on one nonblocking UDP socket. The C constructor duplicates a
caller-owned descriptor. The endpoint must be the socket's exclusive receiver;
neither the original descriptor nor another per-peer adapter may compete for
its datagrams. Release closes only the duplicate. Capabilities expose that
duplicate for host readiness registration.

Each route maps a peer and generation to one next-hop address. Each address
maps to one peer. Route replacement uses the same expected/new generation
rule as the engine. Removal retains a bounded fence slot. Route-table capacity
is a lifetime bound; general identity eviction remains future work. Multiple
identities behind one indistinguishable source address need a separate
demultiplexing protocol and are outside this direct-UDP profile.

Use this host sequence to replace a route:

1. Serialize access to the endpoint and engine; stop submitting old output.
2. Install the new endpoint route with a fresh generation and expected old
   generation. Check its result before changing the engine.
3. Replace the engine attachment with that same new generation. If either
   component rejects the update, reconcile their snapshots before resuming.
4. Submit only SEND records matching the active endpoint generation. Older
   records return STALE without a send syscall.

This is coordinated host work, not an atomic transaction across two handles.
An intermediate mismatch fails closed. There is no UDP connection to migrate.
A datagram still in the kernel after reusing the same source address cannot
carry an out-of-band local route generation; its data must pass the current
engine's protection and interest checks. Address lookup establishes no identity.

Every SEND/RECEIVE command performs at most one socket syscall. Batches contain
at most 64 commands. RECEIVE stops on idle, counting that attempt as processed.
Unknown-source, short and oversized packets consume one bounded receive attempt
and produce a discard status. A capacity stop preserves the unprocessed suffix.
An I/O error preserves earlier results and stops the batch; one destination's
error does not erase all routes. There is no UDP send queue: local pressure
reports CAPACITY, and endpoint recovery remains the engine's responsibility.

READINESS requests read readiness while the endpoint is live. No timer,
connect, accept, thread or persistence loop runs inside the adapter. The host
waits for readiness or the engine deadline instead of polling periodically.
Endpoint counters report send/receive syscall attempts, transferred bytes,
discarded input and local pressure. Batched calls reduce host crossings; this
portable implementation does not claim `sendmmsg`/`recvmmsg` syscall batching.

The old one-next-hop UDP and framed TCP adapters remain supported. Use the
shared UDP endpoint for the Shrine integration target.

## Publication lifecycle and host reconstruction

An immutable name cannot be rebound to different bytes. Unbind releases its
payload but retains a bounded tombstone. `RetireBefore` replaces older names
under a prefix with one monotonic lexicographic fence and reclaims their slots.
Use a sortable fixed-width suffix, such as a big-endian sequence number. The
host chooses retention and persists/restores the fence before publishing again.

CORE does not impose a checkpoint or application inbox transaction. Reconstruct
bindings and retirement fences from the host's durable publication history and
use a fresh incarnation. Retained buffers and snapshots survive the old handle.
This restart contract does not detect rollback of the durable world; the host
must still enforce its publication epoch/restore policy.

Shrine bars encode bytes plus a `0x01` sentinel. Remove the sentinel to obtain
`dat` and preserve the original byte count as `wid`; do not derive width from
the canonical atom after stripping zeros. Conversion and runtime handles remain
Shrine-side work. No noun arena or borrowed noun enters these interfaces.
