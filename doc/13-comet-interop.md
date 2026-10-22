# Comet interoperability target: 2026-10-23

The next acceptance gate is an exact, authenticated named-read exchange between
a libmesa process and a running Groundwire suite-C comet over loopback UDP.
Use explicitly preconfigured current keys and routes on both sides. The target
is the pinned Groundwire kernel, not a stock Urbit release or permissionless
enrollment. Generalized PKI, Jael replacement, userspace verifiers, and enrollment
remain outside libmesa's scope.

## Compatibility boundary

The current engine speaks experimental Mesa v2 and accepts only the fixture
page profile. The pinned Urbit/Vere implementation speaks Mesa v1. Its page
signatures and LSS proof exchange also differ from the test harness's absent
authentication and initial `Data(0)` request. Adding a UDP socket alone cannot
connect these implementations.

Add an explicitly selected v1 interoperability adapter using
`mesa_wire::legacy_v1`. Preserve v2 as the default and keep `PeerId(u128)` and
explicit domain associations in the core. Since v1 has no domain field, bind
the comet's name to its domain through the configured fixture table. Do not
infer a domain from incoming traffic or add automatic version fallback. This
is a scoped compatibility profile for the comet target, not a change to v2.

Pin the checksum behavior to the actual UDP endpoint. Existing vectors expose
Hoon-atom versus Vere-byte checksum differences, including terminal zeros and
trailers. Capture a live request and response first, then select the profile
explicitly and retain those packets as fixtures. Do not resolve a mismatch by
silently trying both checksum modes.

## Work order and gates

1. **Freeze a runnable comet fixture.** Use the composed Groundwire kernel at
   `734ac17cfb88e571081b84406319a17d3d5e79dd`. Record the exact Vere revision,
   built executable hash, pill/kernel provenance, public identity coordinates,
   and loopback ports. Use disposable test key material and an isolated pier.
   Install the libmesa peer through the comet's existing trusted test/host
   provisioning path. Record the setup commands and one published scry path.
   Gate: the real comet boots and serves a captured Mesa request. An existing
   `pact-test` executable establishes codec behavior only.
2. **Read one small public page from the comet.** Implement v1 name-to-beam/path
   encoding, the actual `Init` response, LSS root construction for one leaf,
   and verification of the publisher's signature over the exact Urbit context.
   Use a fixed configured current suite-C signing key. Preserve the returned
   logical byte length and reconstruct omitted zeros before hashing. Gate:
   libmesa returns the exact bytes from the running comet; altered data, wrong
   name/context, and wrong signing key all fail before host delivery.
3. **Serve one small public page to the comet.** Implement the inverse path and
   signed-page construction. Add a thin UDP host that dispatches core actions
   and monotonic timer events. Gate: a comet scry reads the libmesa binding,
   validates its signature, and returns the expected bytes to a small Hoon
   test program. Run both directions in one repeatable script.
4. **Extend to fragmented reads.** Implement the real `Init`/`Auth(0)` discovery,
   initial LSS spine, proof/hash-pair handling, and verified fragment ingestion.
   Reuse the engine's bounded window, retry, timeout, and cancellation machinery.
   Gate: transfer at least 16 KiB in both directions, including an exact
   1024-byte boundary and terminal zeros, then repeat through a deterministic
   loss/duplication/reordering shim. Corrupted proofs and fragments must fail;
   unsuccessful reads must release state.

Public peeks in the Urbit protocol do not authenticate a requester. The current
fixture adapter therefore needs a role-specific replacement: allow bounded
public interests under namespace policy, and require real publisher/data
verification for pages. Keep claimed source addresses separate from checked
publisher identity. Peer-private bindings must remain unavailable to anonymous
peeks. Do not put the harness's verification tickets on the UDP path.

## Schedule and evidence

Finish fixture boot, packet capture, and the small comet-to-libmesa read first
on October 22. Target both authenticated single-page directions on October 23;
use the remaining time for LSS fragmentation and the fault shim. If fixture
boot or exact signature-context parity remains unresolved, report that blocker
before expanding scope. A pair of libmesa processes is useful bring-up evidence
but does not satisfy the comet gate.

Keep a single replay script with bounded timeouts, the exact revisions and
commands, public fixture inputs, expected bytes, received-byte hashes, packet
captures, and the negative-test outcomes. The report must distinguish small
reads, fragmented reads, and loss recovery according to what actually ran.
This target does not include Gall message delivery, message-flow acknowledgments,
durable exactly-once effects, rotation recovery, relays, or public-network reachability.

## Source starting points

- [Existing wire/checksum evidence](../vectors/pact/NOTES.md).
- `mesa_wire::legacy_v1` and the pinned Vere `pact.c` for framing.
- Pinned Vere `io/lss.c` and `io/mesa.c` for proof construction, request startup,
  fragment ingestion, and the verification callback.
- Pinned Groundwire `ames.hoon`: `ma-pact`, `ma-get-page`, `make-space-path`,
  `peek-veri`, and the public-page signing path; `lull.hoon` for name/beam
  encoding; `zuse.hoon` for the crypto primitives.
- [Engine contract](12-peer-engine.md) for state and resource invariants that
  the compatibility adapter must preserve.
