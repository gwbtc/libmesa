# Raw UDP phase validation

This phase validates libmesa's raw-host interfaces. It does not run Shrine,
implement PKI, or establish native Urbit compatibility. The required live
Shrine-to-Shrine gate still precedes Shrine-to-Urbit acceptance.

## Executed checks

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- `bash tools/test-ffi.sh`
- `python3 tools/check-embedding-deps.py`
- `python3 tools/protection-vector.py --check`
- `python3 tools/test-protected-udp.py`
- `python3 tools/conformance-v2.py`
- `python3 tools/conformance-noun.py`

The compiled C checks retain the existing ownership, batching, fault, optional
TCP and four SIGKILL-boundary recovery cases. The added raw UDP host creates
three engines and three sockets, with multiple peer routes on each endpoint.
It completes six directed 1 MiB reads with loss, duplication and reordering,
then reconstructs one raw host and completes a seventh read. An unavailable
binding shares a peer window with useful reads and ultimately times out.

The C host also checks configured limits, prefix processing, error position,
zero-input observation, immutable descriptions, stale credential updates,
route removal/replacement, no send syscall for a stale generation, and retained
buffers after handle destruction. Trailing zero bytes survive the full network
round trip and restart.

Rust tests add owned batch-buffer retention across threads, generation CAS,
cached-root invalidation, delayed old-page rejection, cancellation, detached
timeouts, large clock jumps, and a 1,024-read expiry batch within its advertised
envelope. One thousand publication/unbind/retirement cycles keep namespace
slots bounded; restoring the retirement fence rejects an older name.

Endpoint tests cover three source routes on one socket, oversized and unknown
sources, bounded/zero receive batches, duplicate-address rejection, stale
output, removed-route fences, capacity exhaustion, and one destination's I/O
failure while another route remains usable. Existing controller/transport tests
cover shared-peer fairness, local queue pressure, retry exhaustion and TCP
replacement. The new primary host path uses UDP.

## Reproducible load sample

Build the C harness with `bash tools/test-ffi.sh`, then run:

```sh
python3 tools/measure-raw-udp.py --output doc/evidence/raw-udp-load.json
```

The [recorded sample](evidence/raw-udp-load.json) contains platform/compiler,
binary and source hashes, and runs with one versus sixteen commands per host
batch. It reports engine/endpoint calls, actual socket-call attempts, received
packet bytes, explicitly instrumented host copies, injected loss/duplication,
retries, virtual completion tick and wall time.

This is a debug-build correctness/load sample, not a throughput benchmark.
Socket scheduling and batching change packet order and fault realization, so
the two runs do not have identical retransmissions. `last_completion_tick`
includes an intentional clock jump to 30,000 before the restart read; it is
not wall-clock latency. Copy counts cover explicit host buffer construction
and verification copies, not every allocator or cryptographic internal copy.
Socket counts omit setup, clock and unrelated process syscalls.

The batch-size-16 sample reduces host crossings. The portable endpoint still
uses one syscall per datagram attempt; it does not implement `sendmmsg` or
`recvmmsg`. The harness jumps to the next engine deadline when the network is
idle rather than advancing through every empty tick. Production hosts should
wait on socket readiness and that deadline.

The existing exponential retry/AIMD policy completes the bounded faulty
workload. This evidence does not justify introducing an RTT estimator or a
new pacing algorithm in this phase. Internet congestion tuning remains separate.

## Boundaries and remaining risks

The trusted credential interface selects keys already installed at creation.
It fences old raw reads; it supplies neither verification nor local key
activation. PKI, private spaces and native Urbit control remain unimplemented.
The current read profile is signed public data with anonymous requesters.

A UDP source address is only a routing hint. Local generation fences reject
stale host records, but a datagram arriving after reuse of the same address
has no local-generation tag on the wire. The engine must still validate its
current context and interest. One address maps to one peer in this direct
profile; proxy multiplexing and general peer eviction are future work.

Endpoint and engine route changes are serialized host operations, not one
cross-handle transaction. Route slots retain generation fences for the
endpoint's lifetime. Resource limits bound per-call work and memory; they are
not preallocated throughput guarantees.

CORE restart reconstructs publication state from the host. It neither detects
restoration of an older world nor promises durable application delivery.
Shrine's migration, identity-persona mapping and live integration remain owned
by the host team. Native proof/rekey captures and deployment hashes remain
open in the [phase-0 inventory](17-raw-udp-phase0.md).
