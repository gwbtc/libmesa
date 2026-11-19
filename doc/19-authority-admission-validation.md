# Phase-4 authority and admission validation

The phase-4 branch starts at PR #12's merge,
`e02a41aff0b46961bb6d77669d7b784189000782`. It updates ownership terminology,
adds deterministic authority/admission components and a C component API, and
keeps Shrine migration and native wire integration outside the change.

## Executed checks

Local checks ran on 2026-11-19. The full workspace run passed 206 tests. Final
capacity-failure, preconfigured-peer bridge, and provider-domain isolation
regressions were then added; the targeted PKI/Jael run passed all 22 tests.
The final branch therefore contains 210 Rust tests; CI reruns the workspace
against the final head.

| Command | Result |
|---|---|
| `cargo fmt --all -- --check` | Passed |
| `cargo clippy --workspace --all-targets -- -D warnings` | Passed |
| `cargo test --workspace` | 206 passed before the final bridge correction |
| `cargo test -p mesa-pki -p mesa-jael` | 22 passed after the final bridge and provider-domain corrections |
| `cargo run -p mesa-core --example two-peer` | Passed |
| `cargo run -p mesa-flow --example two-peer-flows` | Passed |
| `cargo run -p mesa-transport --example flow-loopback` | Passed |
| `python3 tools/protection-vector.py --check` | Passed |
| `python3 tools/test-protected-udp.py` | Passed both policies and all six object sizes |
| `bash tools/test-ffi.sh` | Existing C tests and new PKI test passed |
| `python3 tools/check-embedding-deps.py` | No noun/identity dependency in normal PKI, Jael, core, flow or C embedding graph |
| `python3 tools/conformance-v2.py` | 611 packet cases and six harness-failure checks passed |
| `python3 tools/conformance-noun.py` | 22 canonical cases and six harness-failure checks passed |

The final C PKI harness also passed with `-fsanitize=address,undefined`. This
instruments the C harness; the linked Rust static library was a normal debug
build. The linker reported pre-existing macOS deployment-target warnings for
SQLite and BLAKE3 objects. No sanitizer failure occurred.

## New acceptance evidence

The authority tests cover registration, replacement, suspension, revival,
removal from active and suspended states, retained history, operator blocks,
evidence refresh, rollback, same-life key substitution, cross-domain conflict and equal-generation provider isolation,
unknown-peer withdrawal fences and capacity. A valid restriction closes
readiness even when its checkpoint exceeds capacity.

The admission tests cover screening before verifier notification, unverified
application-packet discard, global dispatch limits, bounded retained evidence,
deduplication, direct provider lookup by name, stale and mismatched completions,
provider readiness, withdrawal races, timeout, cancellation, clock regression,
large time jumps, retry ticket replacement, subscriptions and batch prefixes.
Fixtures supply authority verdicts; they do not verify Groundwire evidence.

The same engine harness runs with Jael and with a direct authority manager.
Both provision previously unknown public keys, perform real signed reads,
rotate keys repeatedly at one-peer capacity, reject the retired signer, and
close the service gate on withdrawal. Failed credential CAS and same-life
substitution preserve the old key table. Synchronizing an engine peer without
an accepted PKI point closes its existing preconfigured service gate. The owned codec test uses the existing
suite-C vectors to check name binding and retain the pass after input release.

The C harness exercises raw Authority and Jael, provider lookup, 128-bit peer
IDs, retained evidence/checkpoints/descriptions, capacity before mutation,
partial batches and error indices, current-policy CORE synchronization, and
stale commit rejection. Its child processes die with SIGKILL at five boundaries:

1. Before persisting an accepted peer.
2. After persisting acceptance, before confirming it.
3. After confirming acceptance, before further service.
4. After withdrawal, before persisting the restriction.
5. After persisting withdrawal, before confirmation.

Each restart uses a fresh incarnation. Even after provider readiness is
restored, no recovered peer has ordinary permission without fresh verification
and commitment. The test uses a temporary file and fsync, not a managed inbox.

## Remaining integration risks

Native Groundwire first contact is not connected to the UDP endpoint. The
current endpoint still discards unknown sources. Phase 6 must implement the
pinned profile's proof validation, bounded provisional handling, recovery
traffic exceptions and application-message admission.

Embedding integrations must authenticate provider completions, serialize
checkpoint writes, synchronize affected engine gates before further traffic,
and reconcile bridge errors. A snapshot cannot detect an older-world restore;
the embedding host and verifier must supply the external epoch/current view.
Local pass/ring activation and secret custody remain phase 5. No live Shrine
world, native Urbit node or real Groundwire verifier participated in these tests.
