# Phase 6 native target investigation

**Historical record, 2026-11-20.** The live admission gate was open at the end
of this run. The [2026-11-22 follow-up](22-suite-c-first-contact.md) closes
the direct-UDP first-contact investigation and fixes the routing, proof-ordering,
and migration requirements. Production phase-6 implementation remains ahead.

The selected target is Groundwire's native Mesa v1 UDP path, with suite-C
identities and the existing Ames control packets needed for key recovery.
The investigation fixes the network checksum and signed-root conventions,
records executable lifecycle behavior, and narrows the implementation scope.
It changes no production Rust/C code, Urbit kernel code, or Shrine code.

## Pinned stack

| Component | Pin | Evidence |
|---|---|---|
| libmesa base | `c3d34bf473f1912a575243783e399b2001f4a658` | Main after PR #14 |
| Urbit kernel | `9f437ff097a0e3836fea7875a568b6192eef6a27` | Fresh fixture; all 16 mounted `sys` Hoon files equal the pinned tree |
| Groundwire companion | `a5cf857e2de90c283aa18087db9d4a3981f3ab55` | Source pin; its real verifier was not exercised |
| Vere source | `828244e7751ffc2c7a91c34907c49a9d51f2cc8f` | Resolved from runtime version `4.6-828244e`, fetched and inspected |
| Vere executable | SHA-256 `f5a45c0e306dcdf657e60da0e79b90a99e56d8dc5f82c5c5962e1c1de8c8506f` | Executed macOS arm64 artifact from `groundwire-alpha-2026.11.4_3` |
| Kernel pill | SHA-256 `58b23808442be2c3f364d52fae5f8d2d254f271f0188d04df3cacc1d79c50805` | Executed local integration pill; mounted kernel matched the pin |

The executable hash is the runtime authority for this run. Resolving its
version string to a source commit does not prove a reproducible source build.
The pill is the previously built integration artifact, not the release's
unmodified `gw-base.pill`. The source pins do not establish what a remote ship
currently runs. Both `gw/final` branch heads still matched these pins when
queried for this investigation.

The [machine-readable reference](../investigation/native/reference.json)
records artifact and source hashes. The
[evidence and replay instructions](../investigation/native/README.md) explain
each capture boundary.

## Executed evidence

| Boundary | Result | Limit |
|---|---|---|
| Pinned Ames, Jael, and Mesa Hoon tests in a fresh fake ship | 164 passed, zero failures | Includes conventional and suite-C fixtures; test roofs/verdicts are not a real Groundwire verifier |
| Ames test copy with packet logging and three capture gates | 109 passed; 86 emitted packets across 47 cases | Kernel calls/effects, not two processes exchanging UDP; no production kernel patch |
| Native UDP publication reads | Seven responses: one small value, one initial LSS proof, five data fragments | Fresh fake `~zod` serving an ordinary Gall publication; not suite-C network admission |
| Independent offline checks | Both Ed25519 signatures verified; changed bindings rejected; five-fragment LSS verified; decoded gages matched | Uses the fixture's recorded public key; does not establish external identity authority |
| Repeated UDP capture | Byte-identical to the first successful capture | Same live fixture and publications, not a restart test |

The large value carries `[%octs 4100 (bex 32768)]`. Its native jam is 4,115
bytes, carried in four 1,024-byte fragments and a 19-byte final fragment.
The decoded explicit width is 4,100 even though the atom needs only 4,097
bytes. This exercises the required `[dat wid]` semantics across the native
serialization boundary.

The packet trace includes proof page/poke construction, legacy key recovery,
simultaneous suite-C rotation, Mesa path rederivation, evidence refresh,
soft-block solicitation, migration, and application-message tests. The
existing Mesa plea/boon tests separately check that application completion
controls the acknowledgment. Test cases that assert the absence of an effect
produce no packet capture; their assertions remain in the pinned tests.

This evidence does **not** close the full native target gate in
[phase 0](17-raw-udp-phase0.md). No two-process suite-C first-contact/rekey
capture, direct-route recovery capture, or real Groundwire verifier run was
completed. Existing operational ships and their credentials were untouched.

Two additional isolated processes booted with deterministic suite-C test
identities. The first attempt failed Jael's domain-list invariant; supplying
a nonempty reserved `.invalid` domain fixed bootstrap. Installing the fixture
provider then hit `clay: cannot run app from two desks: %gw-btc`, because the
pill already reserves that application on its own desk. No verifier verdict
or peer delivery was established by those attempts. A follow-up must isolate
the test domain or install the fixture on its assigned desk; it must not
substitute the production provider silently. The attempt record preserves
these failures separately from passing packet evidence.

## Findings that change the implementation details

### Network checksums preserve exact bytes

Select `legacy_v1::Checksum::VereBytes` at the native UDP boundary. Four
captured data packets end in zero bytes and pass only that convention. The
number of terminal zeros was 1,007, 1,024, 1,024, and 1,024. The Hoon atom
checksum rejects all four. This is measured native-driver behavior, not a
choice inferred from the version field.

Keep Hoon atom normalization confined to explicit kernel-reference fixtures.
Never retry an invalid network packet under a second checksum convention.
The adapter preserves each transmitted fragment's width, including zeros.

The pinned Vere parser supports absent and short IPv4 page trailers and
rejects long/multiple trailers. Direct UDP remains the target. Implementing
IPv6 or relay trailer variants cannot establish compatibility with this
runtime and is outside the first phase-6 profile.

### The native signed root differs from v2

Native `root:lss` is the standard BLAKE3 output hash. Libmesa's existing v2
LSS root is a chaining value without the final ROOT operation. The captured
native spine and scheduled pairs pass the current LSS verifier, but its
returned v2 root does not verify the native signature.

Native Ed25519 signs `spat(en-beam(...))` followed by the 32-byte native root.
For the small live publication, the path bytes are exactly
`/~zod//1/publ/1/g/x/1/native-publish//1/value`, including the initial slash.
Both live signatures verify with the native hash and that binding convention.
The offline checker deliberately verifies after full reassembly. The
production native profile must derive the native root from the initial
proof and authenticate it before accepting subsequent fragments.

Reuse the tree's chunk hashes, spine, pair schedule, and bounded reassembly.
Add explicit native root finalization and authentication semantics. Preserve
v2's existing vectors and signed context. Native init/data handling must also
cover the captured signature on data fragment zero, the pair on fragment one,
and unauthenticated-by-itself continuation fragments validated by LSS.

### Native private spaces require their own crypto operations

The pinned kernel derives the peer secret through its Ed25519 agreement
operation. It then uses BLAKE3 derivation contexts `mesa-aead` and
`mesa-crypt-iv`, XChaCha/ChaCha with eight rounds, a 16-byte keyed path tag,
and a terminal `0x01` marker for encrypted atoms. The page MAC is a 16-byte
keyed BLAKE3 hash of the full path/root binding. It is called `%hmac` in the
wire-facing kernel interface; that name is not a specification of HMAC-SHA256.

The preserved Hoon crypto vector records the shared key, sealed path,
serialized value, ciphertext, native root, and tag. Its gate checks path and
value round trips. Phase 6 must add independent positive and negative vectors
for every operation, including wrong life, wrong recipient, altered path,
altered ciphertext, altered tag, and marker/length failures.

Primary private scope is `%chum`, the two-party namespace. Group `%shut`
distribution is a separate facility and has no acceptance requirement for
the agreed two-peer service. Reject unsupported spaces explicitly.

### First contact stays inside Mesa

An unknown native peer's traffic can lead Ames to request
`/publ/1/a/x/1//pawn/proof/1/<receiver>/<receiver-life>`. The two life-1 path
coordinates are bootstrap coordinates. The signed inner open packet carries
the actual sender life and the receiver's current life. The executable
life-2 proof test reaches one verifier `%writ` through that path.

Both `%page` and `%poke` carry native proofs. The proof payload is a jammed
marked gage containing an open packet. Its complete advertised body must fit
one 1,024-byte fragment at the selected kernel's intake. Generic CORE limits
and Vere's normal reassembly do not remove this check. The admissible
evidence budget is smaller than 1,024 bytes and depends on the encoded pass
and coordinates. Encode the full candidate proof before testing the limit.
Return an explicit local unsupported-proof-size result for an oversized
proof; do not advertise it as an interoperable credential.

The native compatibility module screens and validates these structures,
then passes a typed candidate to PKI/Jael. The embedding host first receives
the correlated verifier request. Ordinary unverified application messages
remain withheld. This needs bounds on provisional routes, parse work,
proof requests, retransmissions, response bytes, and pending verification.

Keep the narrow legacy life-1 attestation signer rule limited to its defined
proof/control context. Ordinary public pages use the current signing key.
Native Urbit's unregistered-domain life-1 fallback is observed behavior, not
permission to silently weaken the embedding host's authority policy.

### Legacy control remains necessary; whole legacy messaging is separate

The executed simultaneous-rotation test loses both proactive life-3
announcements. Each peer still remembers the other's life 2. `%keys` then
elicits a current-key open packet addressed to bootstrap receiver life 1;
both candidates reach verification. The unauthenticated four-bit tick in
`%keys` is not an authoritative life. Proactive announcements retain the
exact known recipient life. These distinct rules belong in the native
control module, with separate replay tests.

The rekey tests retain old accepted peer state until a positive verifier
result. A key change rederives private paths. A same-key evidence refresh
preserves the transport state. A rift change retires the affected work.
Phase-5 activation fences must cover prepared native control packets and
encrypted packets as well as v2 sends.

`%ahoy` is an Ames flow migration protocol, not an additional PKI proof. The
pinned default network core is `%ames`, and its migration code still handles
`/mesa-2` pleas and acknowledgments. The kernel tests exercise that path, but
they do not establish that a fresh direct suite-C Mesa relationship needs
the entire legacy message engine. The initial target must record per-peer
protocol state as well as the default mode. Test native first contact against
both a fresh default-mode ship and a Mesa-mode ship before selecting the
required migration subset. Do not silently force a target to Mesa mode and
report compatibility with its default configuration.

The legacy bootstrap test also primes numerical sponsor routes. Therefore
direct-only recovery is a remaining network experiment, not an established
property of that unit test. Preserve suite-C scope: report a required sponsor
dependency rather than adding Azimuth peers implicitly.

Source inspection narrows that experiment: `sy-dear` updates a route only for
an already-known peer, and Vere's mDNS handler forwards discovery through
`%dear`. Calling it on an unknown peer is therefore not an unauthenticated
direct-route installation API. Test a Rust-style initiator with an explicit
destination and the ship's reply to its observed source, rather than assuming
two fresh native processes can bootstrap each other through `%dear` alone.

### Public reads and application messages use different host contracts

Native public reads return a jammed marked gage. An ordinary Gall `on-peek`
handler is local; the successful remote fixture publishes through `%grow`.
The fixture's remote path includes publication revision 1 and Gall's remote
namespace prefix. The production profile must represent publication names,
marks, and byte widths deliberately.

Use a fixed byte service for the first cross-runtime acceptance:
`%noun [%octs width atom]`, with an agreed Gall application and versioned
publication paths. The compatibility module owns bounded jam/cue and this
wrapper. CORE, keys, PKI, the C API, and host-visible payloads remain noun-free.
Supporting arbitrary Gall nouns is a separate service decision.

Native `%plea`/`%boon` flows have their own bones, sequence numbers, forward
and backward paths, receipts, and negative acknowledgments. The application
completion signal triggers the receipt; receiving a UDP packet does not.
Implement this profile separately from experimental `flow/2`. The raw
embedding host supplies its durable completion decision. A managed inbox is
not a prerequisite.

## Concrete phase-6 scope and order

The implementation adds a selectable native profile to the existing raw
integration. It preserves the accepted ownership and transaction boundaries:

| Component | Required change |
|---|---|
| `mesa-wire` / `mesa-lss` | Explicit native checksum, name/authentication context, native root finalization and init/data semantics |
| Native compatibility module | Bounded jam/cue, marked-gage and proof codecs, legacy control, native private names; the only noun-facing boundary |
| `mesa-crypto` / `mesa-keys` | Native KDF, path/value protection and purpose-scoped signing/MAC operations, bound to credential generations |
| `mesa-core` / `mesa-flow` | Selectable native reads and message flows, typed admission inputs, native receipts and epoch consequences |
| `mesa-pki` / optional `mesa-jael` | Receive decoded candidates and retain phase-4/5 authority, correlation, activation and withdrawal rules |
| `mesa-udp` / `mesa-ffi` | Compose native ingress and batched results, expose explicit profile/limits and preserve final send fences |
| Embedding host | Supply readiness, time, verifier results and durable application completion through the raw contracts |

Rust CORE/FLOW and public C values remain noun-free. Native buffers retain
immutable refcounted `[dat wid]` semantics. Profile descriptions remain
immutable; mutable transfer/authority state stays explicit. Batch processing
adds no hidden polling thread, socket ownership transfer, storage transaction,
or syscall per fragment. Existing deadlines and readiness drive the adapter.
The host's transaction interface still controls application completion;
native receipts must survive that boundary without implying a managed inbox.

1. **Close the target experiment before broad implementation.** Run two
   isolated native suite-C Urbit processes with a clearly labeled test
   provider, direct UDP routes, and recorded per-peer mode. Capture first
   contact, withheld delivery, positive/negative verification, private
   messaging, refresh, lost announcements, and simultaneous rotation.
   Exercise default `%ames` and selected `%mesa` modes. Determine whether
   `%ahoy` and sponsor routing are required for the fresh-link target. This
   remains investigation work; it is not covered by the seven UDP responses.
2. **Implement a selectable native wire/protection profile.** Add v1
   names/fragments and exact-byte checksums at the CORE profile boundary;
   preserve v2. Add native BLAKE3 root finalization, signed beam bindings,
   LSS init/data behavior, and bounded gage codecs. Start with public reads
   in both directions between Rust and the pinned ship.
3. **Implement native `%chum` operations and automatic admission.** Add
   purpose-scoped native signing, agreement-derived crypto, path sealing,
   encryption, and MACs through keys. Compose UDP, the native profile,
   PKI, optional Jael, and the host verifier port. Add provisional-route
   bounds and proof-size rejection. Retain batched input/output and
   caller-owned time/readiness scheduling.
4. **Implement native identity control and lifecycle recovery.** Cover
   `%keys`, proactive/reactive open packets, proof page/poke refresh,
   current and narrowly permitted legacy life-1 signers, withdrawal,
   readmission, activation fencing, and both rifts. Add only the `%ahoy`
   control/receipt subset established by step 1. Migration of arbitrary
   preexisting legacy flows requires a separate scope decision if needed.
5. **Implement the native byte-service flow profile.** Cover ordered
   `%plea`/`%boon`, application completion, receipt/rejection, retries,
   cancellation, and crash/replay boundaries. The Gall fixture consumes
   ordinary native Ames messages and publications; it implements no
   alternative network endpoint.
6. **Run the full native fault and lifecycle gate.** Require bidirectional
   reads and application messages, exact bytes, authorization failures,
   fragmentation, loss, duplication, reordering, timeout, cancellation,
   delayed/stale verifier results, refresh, rotation, and crash recovery.
   Preserve packet and host-transaction receipts. The earlier `%mesa-v2`
   bridge cannot satisfy this gate.

Shrine migration, namespace/landing changes, a real chain verifier, Azimuth
identity support, NAT/relay discovery, IPv6/multiple trailers, group-key
distribution, replacing Vere's Ames implementation, and a managed inbox
wrapper remain outside this implementation scope. Phase 7 still requires
live Shrine-to-Shrine over UDP before Shrine-to-Urbit, with the real provider
and Shrine's durable application behavior.

The immediate next step is the two-process native target experiment in item
1. The rest of phase 6 has not started. These findings refine phase 6 without
moving the phase-7 Shrine or provider acceptance boundary.
