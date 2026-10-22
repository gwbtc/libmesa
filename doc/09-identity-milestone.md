# Deferred integration track: authenticated identity

**Scheduling update, 2026-10-22:** the
[peer-engine milestone](11-peer-engine-handoff.md) takes priority. Preconfigured
peers and test-only protection outcomes allow engine work without this track.
The requirements below apply when implementing domain-authenticated enrollment
and activation; they are not prerequisites for the deterministic core harness.

**Starting point:** experimental v2 encodes globally unique `PeerId` values,
explicit `DomainTag` selectors, and length-delimited signatures. It validates
structure and checksums only. Domain-authenticated enrollment must establish authority and
key possession before treating a received identity claim as an accepted peer.

## 1. Bounded parsing and cryptographic primitives

**First increment implemented:** `mesa_noun::bits::Bits` exposes bounded borrowed
bit spans; `mesa_noun::mat` encodes canonical atoms and decodes length-prefixed
fields without allocation. `rub` reports consumed bits for nested fields;
`decode` requires complete consumption of the supplied bit span. Both bound
the prefix scan and declared payload, reject truncated/nonminimal encodings,
and preserve the exact start of the next field. Byte padding belongs to the
enclosing format and must be excluded explicitly.

The tests include all 65,536 two-byte atoms, bit truncations, unaligned fields,
hostile prefixes, and source-derived suite-C layout fixtures. The fixtures use
synthetic keys and opaque evidence: they validate layout, not cryptography or
domain authority. See [fixture provenance](../vectors/noun/README.md).

**Second increment implemented:** `mesa_noun::serial` decodes canonical jam into
an immutable arena of borrowed atoms and shared cells. It bounds input/output,
literal nodes, atom sizes, backreferences, and expanded depth. Parsing, encoding,
and destruction use no recursion. A bottom-up equality table lets re-encoding
enforce Hoon's canonical reference choices without expanding shared subtrees.
Historical live-Hoon fixtures and a freshly compiled Vere serializer provide
independent checks. Consumers must retain sharing and bound their own traversal.

`mesa_identity::suite_c` parses public passes and explicitly selected current
rings, checks the committed domain against the expected selector, and exposes
the exact domain-data and evidence spans. Private seeds remain borrowed,
bit-span Debug output hides its backing buffer, and the ring type has no Debug
implementation. The parser cannot identify an old
two-secret-seed ring from its unchanged `'C'` tag; the caller must establish
current-layout provenance. All results remain unverified claims, with no peer
registry or key-activation effects.

**Third increment implemented:** `mesa-crypto` supplies canonical prime-subgroup
public-key checks, strict Ed25519 verification, signing, Edwards scalar addition,
and Edwards-to-Montgomery agreement. `suite_c::crypto::BoundPass` derives the
permanent name and checks exact current-ring/pass correspondence, including
mutable evidence. Parsed fields expose read-only accessors. Neither type admits
peers or activates keys.

Five [executed Hoon cases](../vectors/crypto/README.md) reproduce exported
passes/rings, public keys, permanent names, atom/octet signatures, and agreement
in both directions. Rotation changes live signing and agreement while retaining
the name; cross-life signatures fail. These are primitive/profile tests, not
Jael activation, authority, or network tests. LSS, KDFs, seal/open, and domain
schemas remain outstanding. The suite-C Edwards construction stays in its
profile; other authorities need not use it.

The next increment implements the authority and activation state machine below
with deterministic test authorities. Domain-specific evidence decoding remains
adapter work; decode failure must not poison a claimed name. Freeze the protected
v2 context before connecting that state machine to untrusted network messages.

## 2. Protected v2 context

Specify the signature/MAC context before implementing the handshake. Bind the
protocol version and message purpose, canonical domain/name context, relevant
life/rift coordinates, recipient context, and content commitment. Decide which
fields belong in each message type's protected context; mutable relay hop and
lane fields must not accidentally become endpoint-signed state.

An accepted point/profile selects the algorithm and valid signature length.
The received length or domain string cannot independently select a weaker
algorithm. The new framing permits other signature sizes; it does not define
algorithm negotiation, PQ cryptography, or fragmented authentication. First
contact, proof solicitation, and simultaneous rotation need explicit transcript
and replay rules rather than reliance on packet shape alone.

## 3. Domain authority interface

Define an asynchronous host-authenticated interface for verification and direct
resolution. A carried-evidence domain validates a candidate pass/evidence; a
query-backed domain resolves a name against its authenticated ledger view.
Both produce accepted points through one core validation boundary. Signature
possession and authoritative key currency remain separate checks.

Peer state is keyed by `PeerId`, with its accepted domain association recorded
as authority state. Establish the initial association through the profile's
authenticated construction or explicitly trusted resolution/bootstrap policy.
An arbitrary registered domain cannot overwrite another association. Conflicting
claims do not create separate peers or win by arrival order. Until a migration
rule exists, domain reassignment is rejected.

Results distinguish acceptance, candidate rejection, unavailable/unevaluable
work, withdrawal, and own-evidence refresh. Bound work and model verifier
readiness explicitly. Fence stale completions after withdrawal or verifier
restart; life/rift monotonicity alone cannot order same-point policy events.

## 4. Peer lifecycle and local activation

Implement unresolved, explicit life-1 fallback, provisional, and verified
states without conflating their authority. Preserve the approved suite-C
fallback opt-in and sponsor-assisted provisional mode, with observable source,
expiry, and revalidation. A withdrawn vouch cannot implicitly restore either
weaker mode. Successful verification is the only upgrade to verified status.

Candidate rejection preserves accepted state. Withdrawal retains continuity
while gating ordinary traffic and soliciting fresh proof. At unchanged rift,
accepted rotation rederives keys and preserves flows; higher remote rift emits
a breach. Keep policy ownership explicit so verifier success cannot erase an
independent administrative exclusion.

Keep authorized public points, staged private rings, and active private keys
separate. Test both arrival orders and exact pass agreement, including `xtr`.
A delayed refresh must not reinstall an old live key. Define persistence and
the quiescent own-rift transition before claiming crash-safe activation.

## 5. Milestone evidence and subsequent networking

Use real cryptographic primitives and deterministic test authorities to cover
the complete admission and activation path. Tests must observe requests,
verdict delivery, state changes, signer activation, rejection, and recovery;
injecting an already-verified peer skips the boundary being tested. The test
authority is an oracle, not a claim that Bitcoin currency was validated.

After these tests pass, build a minimal two-peer v2 UDP exchange: mutual
authentication, a protected read in both directions, rotation, withdrawal,
loss, and recovery. It must use Mesa-only control exchange. Upstream Urbit
interoperability requires its separate v2 and announcement changes; a libmesa
loopback does not establish that compatibility. Reliable flows and the actual
Groundwire chain verifier follow with their own conformance and lifecycle gates.
