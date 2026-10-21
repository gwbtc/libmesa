# Next milestone: authenticated identity

**Starting point:** experimental v2 encodes globally unique `PeerId` values,
explicit `DomainTag` selectors, and length-delimited signatures. It validates
structure and checksums only. The next milestone must establish authority and
key possession before any claimed identity becomes an accepted peer.

## 1. Bounded parsing and cryptographic primitives

Implement the noun primitives needed by the current suite-C profile, including
bounded `mat` parsing and safe jam/cue handling. Pin complete input consumption,
canonical forms, byte/bit order, depth, and backreference/resource bounds with
positive and hostile fixtures. Decode failure must not poison a claimed name.

Add kernel-derived vectors for suite-C public passes, private rings, permanent
name derivation, live signing, and agreement. Verify that changing the live seed
changes both live keys without changing `ugn/dat` or the name. Old signatures
must fail under the newly accepted key, and new signatures under the old key.
Keep the current suite's Edwards construction in its profile; the generic
identity interface does not require every authority to use it.

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
