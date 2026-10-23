# Deterministic named-read engine

`mesa-core` implements steps 1 and 2 of the
[peer-engine handoff](11-peer-engine-handoff.md). A synchronous engine binds
immutable bytes and reads them through experimental v2 peek/page packets.
Tests connect two preconfigured peers with a virtual clock and controlled
protection outcomes. They establish engine behavior, not cryptographic packet
compatibility or network interoperability.

This document describes the original fixture profile. The engine now also
implements [signed-public v2 reads](../spec/08-signed-public.md) with real LSS
and signatures, plus a separate UDP host. That profile changes proof discovery,
verification, and unverified-buffer accounting as specified there.

## Run

```sh
cargo run -p mesa-core --example two-peer
cargo test -p mesa-core
```

The example returns `hello from the preconfigured Mesa peer`, exactly 38 bytes.
The integration tests extend that slice to empty data, terminal zeros, exact
fragment boundaries, 1024-fragment reads, and the default 1024-byte fragment
profile. Thirty-two seeded schedules each run twice and compare the complete
action trace while transferring exact bytes in both directions. Their fault
period drops, duplicates, corrupts, delays, and reorders packets; subsequent
delivery permits bounded recovery. These schedules test the fixed policy below,
not a complete-path congestion policy or delta-t proof.

## Host contract

`Engine::new(config, local, protection)` freezes the local identity, domain,
life/rift, and key handle. `Engine::step(event)` returns `Result<Vec<Action>,
Error>`. Invalid host operations return an error without modifying engine state.
Network rejection returns a `Dropped` action. The core has no runtime, sockets,
wall clock, randomness, or persistence backend.

The host installs each `PreconfiguredPeer` and configures its `Attachment`
separately. Peer identity remains `mesa_wire::PeerId(u128)`; domain strings pass
the existing canonical `DomainTag` validator. The core uses those existing types
without moving or changing their re-exports. Key and attachment handles are
opaque integers whose interpretation belongs to the host.

| Event | Effect |
|---|---|
| `InstallPeer` | Install a trusted view or advance its life within the same rift |
| `RemoteBreach` | Advance a known peer's rift and fail all its active reads |
| `SetService` | Gate both directions; blocking fails active reads immediately |
| `SetAttachment` | Change or remove a route while preserving active reads |
| `Bind`, `Unbind` | Install immutable bytes and explicit access; withdraw bytes |
| `Read`, `Cancel` | Start a bounded read or terminate it immediately |
| `Receive` | Supply a claimed peer, attachment, and borrowed packet bytes |
| `AdvanceTo` | Advance monotonic virtual time and process due work |

Every successful step ends with `SetTimer(Option<Tick>)`. The host replaces its
previous timer with this deadline; `None` disarms it. Time advances only through
`AdvanceTo`. The host must advance time before delivering traffic at that time,
so a response arriving exactly at the absolute deadline loses to expiration.
Repeated timestamps are allowed; regressing time fails. An overflowing read
deadline fails admission. A large clock jump performs at most one retry per
live interest, and expired reads emit no retries.

`Send` transfers a complete encoded packet to the host. The host owns the output
queue and delivery order. `ReadFinished` transfers the result bytes or reports
one terminal failure. Completion, cancellation, blocking, breach, timeout,
retry exhaustion, and reassembly-budget failure remove all associated read
state before returning. A duplicate or late page cannot complete that read
again. Read IDs may be reused after termination; the wire matches immutable
names, so an old page may satisfy a new read of the same name in the same rift.

## Namespace and packet profile

Paths are bounded, nonempty opaque bytes. Bindings belong to the local peer and
rift. `Access::Peer(id)` permits that preconfigured peer; `Access::Public`
permits all installed, service-enabled peers that pass the protection boundary.
This is a closed fixture profile: anonymous public peeks and encrypted namespace
spaces remain unimplemented. A denied or absent binding sends no response.

A bound path cannot be replaced. Unbind releases its data but retains a bounded
retired-name slot, preventing rebind with different bytes while old fragments
may remain in flight. `max_bindings` includes these slots; unbind does not reclaim
them. Local activation is frozen, so recycling slots requires a future epoch
and persistence design. The host must preserve name immutability across restart;
this engine has no persisted tombstones.

A read first requests `Data(0)`. Its verified test response supplies the bounded
total length and first fragment. The reader then fills a fixed window with
successive data interests. Each peek produces at most one page. Every page
must match a live interest's publisher, domain, rift, bloq, path, and fragment
index. The v2 codec requires canonical fields, so this field comparison also
preserves encoded-name equality. Unsolicited and consumed fragment indices drop.

All fragments in a read must declare the same total length. The core checks
fragment and aggregate limits before reserving the bounded reassembly buffer.
The existing wire helper restores omitted terminal zeros. The core treats an
empty value as one empty `Data(0)` response. Small `Init` peeks can be served,
but the reader does not issue them. Proof fragments, pokes, next-hop trailers,
and non-absent page authentication fields are unsupported by this test profile.

Starting with `Data(0)` avoids inventing the LSS proof/root discovery exchange
for this milestone. Pages carry `Auth::None`; the harness supplies controlled
verification separately. This profile must gain real LSS and a specified
protection context before any network read is described as authenticated.

## Protection and peer updates

The fixture profile requires a supplied `Protection::verify` implementation.
After structural decode and peer/route/service gates,
the core calls `verify(local, current_peer, exact_packet_bytes)`. Failure prevents
namespace service and fragment storage. The claimed transport peer, source
attachment, packet publisher, and checksum provide no authentication by
themselves. A future real adapter must check keys and the protected context;
the fixture trait alone is not a security implementation. The current
`SignedPublic` implementation uses root signatures and LSS instead of this
fixture hook, and the UDP host accepts only that concrete profile.

`tests/support/mod.rs` provides the example's test-only adapter. The harness
issues one-shot out-of-band tickets bound to exact packet bytes, the local view,
and the sender view. Tests control success or failure without encoding a trust
switch in the packet. Tests deliberately authorize some structurally valid but
semantically invalid packets to exercise the independent core checks. The
library never exports this adapter.

Trusted updates cannot change a peer's domain, regress life or rift, or change
its key without advancing life. A same-rift key update preserves the read's
buffer, interests, and deadline; subsequent verification uses the new view.
Only `RemoteBreach` advances an existing rift. It terminates old work, and the
new rift gates subsequent interests and pages. Blocking also terminates reads;
unblocking admits new work. These are host-injected reactions, without Jael,
domain verification, autonomous rotation recovery, or enrollment.

## Resource and timer policy

The [transfer-policy contract](../spec/09-transfer-policies.md) now separates
policy from scheduling. The defaults below describe `Engine::new`;
`Engine::with_policy` can inject shared peer windows and adaptive behavior.

The default engine uses these fixed bounds. Hosts can supply smaller profiles;
configuration validation ensures admitted path and fragment sizes fit the wire
packet limit, including worst-case integer and domain framing.

| Resource or policy | Default |
|---|---:|
| Packet / fragment / path bytes | 1472 / 1024 / 256 |
| Installed remote peers | 64 |
| Namespace slots, including retired names | 128 |
| Total bound payload bytes | 8 MiB |
| Concurrent reads | 32 |
| Maximum bytes / fragments per read | 1 MiB / 1024 |
| Aggregate reassembly payload reservation | 8 MiB |
| Outstanding interests per read | 4 after the initial single interest |
| Retry interval | 100 host ticks |
| Absolute read deadline | 2000 host ticks |
| Transmissions per fragment | 4, including the initial send |

Ticks have no intrinsic duration. At each retry deadline, the engine retransmits
only missing fragments. If a fragment has used its transmission budget, the
next retry deadline fails the read. A removed route suppresses sends and spends
no additional transmission attempts; the absolute deadline still applies.
Progress does not extend the read deadline. No response to a missing binding
eventually produces retry exhaustion or timeout; this profile has no negative
page response.

Admission rejects duplicate active read IDs, concurrent reads of the same
peer/path, unknown or blocked peers, missing routes, and exhausted read slots.
`Usage` reports payload reservations plus peer, namespace, read, interest, and
received-fragment counts. Path and metadata storage are bounded by those counts
and configured path lengths. It does not report allocator overhead, protection
adapter storage, host-owned inputs, returned buffers, or the host's output queue.
A successful step can release queued work across reads. Scheduling emits at
most `max_reads * window` interests; an incoming peek can also emit one page.
Queued entries count toward the same per-read interest and metadata bounds.

## Remaining work

Real LSS, signed-public context binding, and UDP now have an implementation and
tests in the separate profile. Private-space encryption, upstream interoperability,
relay/PIT forwarding, production congestion control, and message flows remain
unimplemented. A bounded fixed/AIMD policy prototype is available.
Flow state and durable acknowledgments require the contract in
[spec chapter 4](../spec/04-flows.md). Generalized PKI, Jael, userspace verifiers,
and enrollment remain outside this milestone.
