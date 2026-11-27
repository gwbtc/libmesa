# Phase 6: Mesa-v1 implementation and validation

Phase 6 moves new engines to Mesa-v1 and implements the Urbit-Mesa byte-service
profile on the shared core. The branch includes the preceding target and crash
investigations. It changes neither Shrine nor Urbit source. The normative
contract is [specification 18](../spec/18-mesa-profile.md).

## Executed boundary

The [live artifacts](../investigation/phase6/README.md) record public reads in
both directions, private byte pleas in both directions, 4,100-byte fragmented
messages, request-driven first contact, rejection with an exact explanation,
cork closure, key rotation and recovery after a lost announcement. The pinned
Urbit kernel and Vere runtime handle the packets. No `%mesa-v2` endpoint appears
in this acceptance path.

The verifier is an ordinary Gall fixture that accepts exact named passes. It
does not verify a Groundwire chain. The byte-service fixture is also an ordinary
Gall agent. Its deliberate rejection exercises Urbit's existing negative receipt
and explanation path. The source pins, binary/pill hashes, capture limitations
and reproduction steps are recorded with the artifacts.

The live investigation established two implementation details. Vere carries an
unused next-hop bits into follow-up peeks, so the Mesa-v1 decoder ignores
those bits without granting route authority. Captures cover both SHORT and
LONG hints; a mutation test also covers MANY. Urbit skips a private packet
whose sender life differs from its accepted point, so activation sends bounded
retries of the signed current-key announcement. The old strict wire codec still
rejects noncanonical hints, and four-bit identity-control ticks never authorize
a point.

## Tests

Local validation on 2026-11-27 passed 271 workspace tests with no failures or
ignored tests, strict Clippy, formatting, both C configurations, the three
examples, dependency isolation, codec conformance and both evidence checks.
The final generic-protection default change also passed the core regression
suite. Follow-up lint checks use Rust 1.100, matching CI; the full all-target,
all-feature Clippy check and the rotation/session tests pass on that toolchain.
GitHub CI runs the workspace and C checks plus both evidence checks.

The check sequence is:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
bash tools/test-ffi.sh
MESA_SUITE_C=1 bash tools/test-ffi.sh
python3 tools/check-embedding-deps.py
python3 tools/protection-vector.py --check
python3 tools/test-protected-udp.py
python3 tools/conformance-v2.py
python3 tools/conformance-noun.py
python3 investigation/phase6/check-evidence.py
python3 investigation/native/retention/check-evidence.py
```

The new mechanism tests cover public/private ROOT authentication, exact Hoon
crypto/gage/control vectors, fragmentation through 1 MiB, loss, duplicate and
reordered packets, timeout, cancellation, and explicit profile selection. The
raw C UDP harness runs both native and experimental constructors and checks
batched private-buffer operations, retained widths, reconstruction and faults.
The dependency check excludes nouns and identity parsing from CORE, FLOW,
keys, PKI, Jael and the normal C dependency graph.

Ordered-flow tests exercise all three host commit boundaries, stale callbacks,
restore with a new incarnation, blocked negative explanation retrieval, sparse
rejection pruning, closure holes, reservation pressure, lost cork ACKs and
simultaneous corks. Session tests exercise 120 messages with bounded transient
bindings and same-rift simultaneous key changes while preserving the outbox ID.
Retained old packets fail the final transport submission fence.

The new process harness performs 13 SIGKILL cases: nine around enqueue,
receive-effect and settlement persistence/confirmation; two for negative
outcomes; two for closure. It combines the latest checkpoint and host records
in an fsync/rename transaction, then verifies one durable effect and settlement
after restart. The existing C harness retains its five PKI and fourteen key
activation crash cases. These are separate from the five Urbit-process kills
in the preceding [crash investigation](24-retention-and-urbit-crash-semantics.md).

Admission tests with real loopback UDP keep unverified ordinary packets below
the host, dispatch only screened candidates, require durable exact-point
acceptance, and reject stale provider completions and local-life correlations.
Retained admission sends are revoked on activation, cancellation, timeout,
promotion and driver destruction. Signed open controls match pinned Hoon bytes. Current-key proofs work at lives
1 and 2 without the historical policy. Pinned Hoon signatures prove that the
historical name-key exception admits only a policy-selected life-1 attestation;
the ordinary current-key object verifier rejects the same signature.
Announcement tests cover loss,
retry bounds, cancellation, clock regression and key-cutover fencing.

## Default switch

The shared native mechanisms and live gates preceded the default switch.
`Profile::default()` and `SignedPublic::new()` now select Mesa-v1.
`mesa_options_default()` selects ABI 2 for `mesa_engine_create_mesa`; namespace
prefixes remain required trusted configuration. Missing prefixes fail closed.

Explicit `SignedPublic::experimental_v2`,
`SignedPublic::experimental_v2_with_key` and `mesa_options_exp_v2` preserve the
older mechanisms. Existing experimental examples and recovery tests use those
constructors. ABI 1 constructors still require ABI 1 options. Native ordered
checkpoints carry their own schema, profile, domains and epoch; incompatible
restores fail instead of translating state.

## Remaining limits

Phase 7 supplies real host-provided Groundwire verification and joint Shrine
UDP acceptance. Shrine-to-Shrine remains the first joint gate. The C raw engine
is usable independently of `mesa-urbit` and the managed inbox. The optional
managed inbox remains on the explicit experimental flow profile.

This phase supports direct UDP and fresh or already-Mesa relationships. It does
not implement general Gall control traffic, Azimuth identity, old-Ames messaging,
automatic `%ahoy` migration, sponsor relay discovery, hardware key backends or
standalone verifier plugins. A 1,024-byte proof limit is a pinned peer constraint;
large evidence requires a later agreed protocol solution.

Most live captures came from intermediate phase-6 builds. The final-build
capture resumes the 4,100-byte outbox that exposed the LONG-hint case and
records acceptance and cork closure. Final tests replay the captured codecs
and shared mechanisms. Production acceptance still requires
matching the pinned stack and replacing the fixture verifier; a successful
fixture exchange does not satisfy that requirement.
