# Suite-C first contact: routing and migration requirements

**Planning update, 2026-11-25:** the
[Mesa-v1 default and flow design](23-mesa-default-and-flow-durability.md)
supersedes the selectable-profile-only implementation direction below.
Its strict glossary disambiguates this report's historical “native,” “v1,”
and “legacy” labels. The measurements and routing/migration findings stand.

**2026-11-22. Live investigation closed for the direct-UDP, fresh-peer profile.**
A pinned Groundwire-enabled Urbit receiver admitted a suite-C peer through its
registered verifier, exchanged encrypted application messages, and returned
application receipts. Its default remained Ames. This path needed neither a
working sponsor relay nor `%ahoy` migration. An ordering counterexample and a
legacy-state experiment define the limits of that result.

This work changes investigation fixtures and documentation. It implements no
production phase-6 code and changes no Shrine, Urbit, or Vere source.

## Target and fixture boundary

The executable, integration pill, and Urbit/Groundwire source pins remain those
in [the preceding investigation](21-native-target-investigation.md). The new
[reference record](../investigation/native/contact/reference.json) records
hashes, fixture identities, outcomes, and limitations. The
[evidence directory](../investigation/native/contact/README.md) includes raw
UDP bytes, packet summaries, public signing keys, peer snapshots, command
sources, verifier fixtures, and application receipts.

All peers used deterministic suite-C keys committing to `%mesa-test`. A Gall
provider registered that domain with Jael and accepted only exact allowlisted
identity/pass pairs. It could hold, reject, or accept a request. This exercised
the registered-domain path, not the unregistered life-1 fallback. It did not
verify a Bitcoin custody chain. The fixture uses a separate domain because the
pill already reserves `%gw-btc` on its own desk.

A is the sender. B is the first receiver. C is a separate receiver identity,
used in two fresh piers for the ordering comparison. Each receiver started
without A in Ames's peer tables. A's target public point was supplied through
the fixture provider so the existing Urbit sender could form encrypted traffic;
A selected Mesa for new outgoing peers and received an explicit UDP route.
This is not a demonstration of two Urbit processes discovering each other
without configuration. A separate public proof read establishes the wire
operation libmesa can use to obtain the target's candidate before verification.

The receivers used the pinned default Ames mode during first contact. The
ordinary `%native-receive` Gall application logged payloads and poke receipts.
It had no alternate network endpoint. A transparent UDP proxy recorded bytes,
replayed four captured datagrams in the rejection case, and applied explicit
packet gates in the ordering cases. It did not decode application data, sign
proofs, answer protocol requests, or produce verifier verdicts.

## Executed cases

| Case | Observed result | Evidence boundary |
|---|---|---|
| Hold, reject, then accept | B held A as `%chum %alien`; rejection removed the candidate. Acceptance followed by retransmission produced `%chum %known`, three A-to-B deliveries, one B-to-A delivery, and four successful application receipts | 36 captured datagrams, all Mesa v1; four explicitly replayed bytestrings; native `%prod` also requested retries |
| Existing legacy state | Converting B's established A relationship to legacy Ames made it ignore private Mesa messages. Changing the global default left that relationship `%peer %known`. Explicit local `%mate` restored delivery and its receipt | Uses the real `%rege` and `%mate` kernel tasks; not a successful automatic wire migration |
| Proactive proof accepted first | With private packets temporarily dropped, C accepted A's proof poke into `%peer %known`. Releasing private packets did not deliver a message | Fresh default-mode receiver; 27 captured datagrams, including six dropped private packets; no delivery |
| Request-driven proof | A fresh C pier received private packets while proactive proof pokes were dropped. C requested A's proof, accepted the returned page into `%chum %known`, and completed one application message and receipt in each direction | 31 recorded datagrams, including nine dropped proof pokes; all forwarded packets were Mesa v1; no `%load`, `%mate`, or `%ahoy` on C |
| Public target proof read | C served its signed proof for A's coordinates; C's peer table was unchanged | Two additional datagrams; independent signature verification; serving a public proof does not admit the requester |

The packet checker validates exact-byte checksums and single-fragment signed
bindings against independently recorded public fixture keys. It also rejects
a changed binding for each checked signature. In the request-driven case it
checks 12 signatures: nine on dropped proactive proofs and three on returned
proof pages. The separate target-proof read adds one signature. Private MACs
were validated by the running Urbit kernels, as demonstrated by application
delivery and receipts; the offline tool does not implement native private
cryptography.

The held-verifier capture is a prefix of the migration capture. These counts
must not be added as independent runs. The request-driven run reuses A and its
still-unacknowledged sequence-one work against a fresh C pier; it does not
claim a crash-recovery or restore-fencing test.

## Routing requirements

**An explicit destination is sufficient for fresh direct contact.** After an
unknown sender's private Mesa poke reached the receiver, the receiver sent
its bootstrap proof request to that packet's observed source endpoint. The
sender answered there. After acceptance, another authenticated private packet
established the return lane used for data and receipts. No receiver-side
`%dear` route was installed for A.

The proof request used the public life-1 bootstrap path:

```text
/publ/1/a/x/1//pawn/proof/1/<receiver>/<receiver-life>
```

The live identities were at life 1. Higher-life bootstrap and simultaneous
rotation remain covered by the earlier kernel fixtures, not by this live run.

**Sponsor fallback is emitted but is not required for completion here.** The
pinned kernel sometimes included a numeric sponsor destination beside the
direct lane, especially before authenticated liveness. In the request-driven
run, the relevant local sponsor ports, 31402 and 31463, were bound by listeners
that only logged and discarded packets. They recorded 21 datagrams and sent
none. Proof admission, encrypted data, and receipts completed through the
direct proxy endpoints. The pill still carries numerical sponsorship metadata
and starts its normal background applications; this experiment establishes
independence from a working relay, not removal of that metadata from Urbit.

**`%dear` is not an unknown-peer bootstrap API.** It updates an already-known
peer. The sender fixture used it after its target point became known. Libmesa
must associate a configured/discovered endpoint with a bounded provisional
exchange before authority exists. Its adapter must keep that provisional
route distinct from an authenticated peer route. Address possession grants
no identity authority.

Endpoint discovery, NAT traversal, relay discovery, and Azimuth-ID peers remain
outside the initial profile. The embedding host can supply endpoints without
processing unverified peer messages. Mesa owns wire intake and proof exchange;
the first incoming identity work exposed to the embedding host is the
correlated verifier request.

## The proof-ordering trap

**A proof poke can select legacy peer state before the private packet selects
Mesa state.** The pinned `%poke` proof branch calls `al-take-proof` directly.
If authority returns while no Mesa relationship exists, peer insertion follows
the default Ames core. A later private poke finds a known legacy peer and is
handled as traffic for a regressed relationship. The counterexample reached
that state with a valid signature and a positive verifier verdict.

The successful control case dropped proactive proof pokes and forwarded the
private poke first. That packet created an alien Mesa relationship and emitted
a proof request. The signed response page then reached the same verifier,
whose positive result promoted the existing relationship to known Mesa state.
It required no migration. The proxy preserved the proof page bytes.

Phase 6 should use this sequence for a fresh Urbit relationship:

1. Obtain the target's candidate through its public proof endpoint when it is
   not already known. Verify it through the configured authority module before
   using its private namespace.
2. Send the private Mesa contact packet to the explicit endpoint. Keep its
   work pending while the receiver verifies the sender.
3. Answer the receiver's bootstrap proof request with a proof page. Avoid an
   unsolicited proof poke as the first identity-bearing packet to an unknown
   default-mode Urbit receiver.
4. Retransmit pending private work after admission. Expect application receipts
   only after the remote application completes its operation.

This order is a compatibility requirement of the pinned receiver. Libmesa
should select its own peer profile from the actual wire/admission context and
must not reproduce the proof-before-profile race. Supporting proof pokes for
refresh or already-established relationships remains in scope. An upstream
fix could permit a less restrictive first-contact order, but no upstream patch
was made or assumed here.

## Migration requirements

**Fresh peer admission and migration of existing legacy state are separate
operations.** A default Ames receiver can accept a new Mesa relationship.
A known legacy relationship has flows, sequence numbers, and receipt state
that cannot be replaced by changing the global default.

The legacy-state experiment preserved real established flow state through
`%rege`, observed ordinary Mesa pleas being ignored, and verified that `%load
%mesa` did not move the peer. Explicit local `%mate` moved it back to Mesa and
the pending application message completed with its receipt.

The ordinary Hood `%ahoy-prob` path did not establish automatic migration:
it scans remote kernel hashes, while this pin's trigger hash is deliberately
disabled. An explicit legacy `/mesa-2 %ahoy` plea also did not complete the
one-sided mismatch experiment before local migration; the sender logged
`ack missing seq=1`. After local `%mate`, the pending ahoy plea traveled as
Mesa and was acknowledged. That final acknowledgment does not prove that the
preceding legacy negotiation succeeded.

The first phase-6 acceptance profile should therefore require a fresh Mesa
relationship, or a relationship already migrated by the Urbit operator. It
should not promise automatic takeover of arbitrary legacy Ames flows. Such a
promise needs a separate investigation of legacy channel establishment,
`%ahoy` negotiation, flow conversion, and retry/recovery on both sides. Remote
silence alone cannot reliably diagnose legacy state, so an automatic
"migration required" result is not established by these tests.

Legacy `%keys` and open packets for suite-C identity recovery remain in phase
6. Their historical wire format does not make whole legacy application
messaging or `%ahoy` migration prerequisites for fresh direct contact.

## Concrete phase-6 scope after this investigation

The investigation closes the routing and migration selection gate. Proceed
with a selectable Urbit-compatible Mesa v1 UDP profile for fresh suite-C peers:

- exact-byte checksums, native roots and signed bindings, bounded gage codecs;
- public reads and two-party private protection through the key module;
- request-driven first contact, bounded provisional routes, correlated
  verification, and withheld application delivery;
- suite-C proof refresh, `%keys`/open recovery, activation fences, rifts,
  withdrawal and readmission;
- native byte-service flows and durable application-completion receipts;
- fragmentation, loss, duplication, reordering, delayed/rejected verification,
  the proof-ordering regression, timeout, cancellation, rotation, and replay.

Preserve the noun-free Rust CORE/FLOW and public C API, immutable refcounted
buffers, batched inputs/results, optional Jael, and caller-owned readiness,
time and transactions. Keep nouns inside the Urbit compatibility codec.

The full phase-6 interoperability gate is still ahead: these are existing
Urbit processes with test providers, not a completed Rust wire implementation.
Real Groundwire verification, Shrine changes, and joint integration stay in
phase 7. Shrine-to-Shrine UDP acceptance still precedes Shrine-to-Urbit.
