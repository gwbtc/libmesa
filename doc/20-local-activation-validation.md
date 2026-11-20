# Phase-5 activation validation

Branch `phase5-local-activation` builds on phase 4, merged by PR #13 at
`05c137015836a4bb28b4d35cccfeeb3aaa182df3`. It implements local software-key
custody, durable activation, historical retirement, CORE/FLOW cutover, and
fenced UDP submission through Rust and C interfaces. Read
[the component contract](../spec/17-local-activation.md) for host obligations.

## Executed checks

The local validation ran on macOS ARM64 with the workspace stable Rust toolchain.
The PR CI repeats the workspace and C checks on Linux. Its workflow includes
both default and optional `suite-c` C builds.

| Check | Evidence |
|---|---|
| Formatting and lint | `cargo fmt --all -- --check`; `cargo clippy --workspace --all-targets --all-features -- -D warnings` |
| Rust regression suite | `cargo test --workspace`; 230 tests, including existing transport/process tests |
| Existing runnable slices | `two-peer`, `two-peer-flows`, `flow-loopback` examples |
| Protection and wire regressions | `tools/protection-vector.py --check`, `tools/test-protected-udp.py`, `tools/conformance-v2.py`, `tools/conformance-noun.py` |
| Default C ABI | `bash tools/test-ffi.sh`; existing ownership/inbox/UDP/admission tests and new activation harness |
| Optional ring codec | `MESA_SUITE_C=1 bash tools/test-ffi.sh`; current-ring import and wrong-name rejection |
| C sanitizers | Activation harness compiled with AddressSanitizer and UndefinedBehaviorSanitizer against the ordinary Rust static library; leak detection disabled for intentional child SIGKILLs |
| Default dependency boundary | `tools/check-embedding-deps.py` rejects noun/identity dependencies in keys, PKI, Jael, CORE, FLOW and FFI |

The test fixtures contain public seeds and synthetic evidence. The suite-C
codec test uses the existing pinned Hoon fixtures in
`vectors/crypto/suite-c.json`; its provenance remains in that file. Fixture
provider acceptance tests orchestration and binding, not Groundwire custody
verification.

## New acceptance evidence

`mesa-keys` tests both arrival orders, missing material, wrong seed/public key,
wrong identity, stale evidence, exact evidence refresh, old-world epoch/revision
fences, and restored-authority quarantine. Full-width 128-bit names, runtime
incarnations and backend references survive serialization and restore.

Scoped operation tests verify real signatures against old and new keys, reject
invalid backend signatures, reject stale generation completions, compare both
sides of real key agreement, and invalidate agreement when the remote point
changes. Timeout, cancellation, backward time, bounded operation capacity,
historical pins and retirement/delete replay have separate assertions.

The CORE test publishes and reads a 16,000-byte value, rotates the local signer,
updates the reader's remote credential, and reads the retained publication
under the new key. Advancing the local rift clears the old publication namespace.
Read quiescence emits explicit `PeerReset` results and disarms the timer.

The FLOW test exchanges signed traffic, retains a committed outbox across a
same-rift life change, and completes it under the new credentials. Message IDs,
receipts and settled state survive. Separate local/remote rift tests inspect
retired outbox IDs, reset epoch state and reject old storage completions.
Pending storage can complete while quiescent without producing sends or new
deliveries. The rebuilt node preserves monotonic time. Authority changes during
prepare invalidate activation; repeated rebuilds do not exhaust gate slots.

A UDP test checks the actual send-call counter: submitting a retained old packet
after cutover returns stale without another syscall. A concurrency test holds a
final submission open and confirms that cutover waits for its completion.
Reopening the gate never revives that old packet. Route generations provide an
independent rejection check. CORE remote credential, rift, policy and attachment
changes also revoke retained packets before the adapter can submit them.

The compiled C host checks retained buffers, partial batches, capacity before
mutation, CORE activation, explicit FLOW quiescence/planning/application, fresh
FLOW incarnations, scoped signing, and batched fenced UDP sends. It retains send
handles across activation-handle changes and verifies that cutover rejects them.
Optional ring tests exercise full-width suite-C names through C descriptions
and snapshots as well as the import entry point.

## Process termination matrix

The C harness runs each boundary twice: initial activation and a life-2/rift-1
rotation after an active life-1/rift-0 credential. Each child terminates through
`SIGKILL`; the parent reopens the files and constructs fresh handles.

| Boundary | Persisted activation state |
|---|---|
| Before new key-object persistence | Empty bootstrap state, or prior activation during rotation |
| After key-object persistence/import | New material staged; prior manifest still authoritative |
| After activation prepare | Proposed transition absent from durable manifest |
| After manifest `fsync`, before confirmation | New manifest durable; commit response absent |
| After confirmation, before engine apply | New manifest durable; no inference that a restored engine is active |
| After engine apply, before send | New manifest durable; old output capabilities revoked |
| After fenced UDP submission | New manifest durable; restarted transient traffic may be retried |

Recovery checks quiescence before activation, reopens exact material, supplies
current public authority, and prepares a fresh transition. The rotation case
rejects the retained old packet before every kill point. If only old material
survives, it cannot activate against the newer point. The restored-world tests
reject a checkpoint below an external revision floor or with a different host
epoch. The host harness uses files and explicit `fsync`, without a managed inbox.

## Limits and remaining work

These are process-crash tests, not storage power-loss or torn-write tests. They
assume the host's manifest transaction and externally protected epoch/floor are
correct. Private keys are public test fixtures in temporary files; the harness
does not establish production secret-storage policy, encrypted storage, hardware
custody or secure erasure of caller-retained ring buffers.

The current signer uses software keys. Scoped asynchronous signing requests and
verified completions provide a component seam; hardware-only activation and
native session KDF/sealing still need their selected integrations. Historical
pins are explicit protocol-owner obligations. The phase defines no implicit
old-key compatibility window.

The tests execute experimental signed-public v2 and FLOW profile 2. They do not
establish native Ames/Groundwire packet compatibility, a real verifier, Shrine
integration, private-service authorization, or live Shrine-to-Shrine acceptance.
The native phase-0 captures remain open. Phase 6 connects native profile input,
admission, identity-control traffic and crypto to these modules; phase 7 retains
the live Shrine-to-Shrine gate before Shrine-to-Urbit.
