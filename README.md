# libmesa

libmesa is a Rust implementation of Mesa networking with a C embedding API.
**Mesa-v1 is the default for new engines.** The Urbit-Mesa profile exchanges
public reads and encrypted byte messages with the pinned Groundwire Urbit
stack. See the [phase-6 contract](spec/18-mesa-profile.md) and
[executed interoperability evidence](investigation/phase6/README.md).

`mesa-core` owns authenticated reads, fragmentation, retries, deadlines and
per-peer fixed or AIMD windows. `mesa-flow::ordered` adds host-committed delivery,
settlement, bounded rejection history and durable closure. `mesa-urbit` supplies
Urbit serialization, names, byte-service conventions, proof admission and the
required identity controls. The core, flow, keys, PKI and normal C dependency
graph remain noun-free.

The host owns sockets, clock input, verification and transactions. Immutable
refcounted `[dat wid]` buffers cross component boundaries. Batched events and
results preserve explicit mutation and ownership contracts. Optional Jael,
transport drivers and the managed inbox remain separate choices.

`libmesa-exp-v2` and `libmesa-flow/2` are explicit experimental compatibility
profiles. Existing ABI 1 constructors and checkpoints retain their semantics;
new defaults do not convert them. The managed SQLite inbox still uses the
experimental flow profile. Public reads authenticate objects, not requesters.

Suite-C fixtures validate name binding, key rotation and direct UDP admission.
Their exact-pass providers do not verify a Groundwire ledger. The next phase
connects real host-provided verification and joint Shrine testing, with
Shrine-to-Shrine acceptance before Shrine-to-Urbit. Shrine and Urbit repository
changes are outside this phase.

The [C embedding API](spec/14-c-embedding.md) exposes immutable refcounted
`[dat wid]` buffers, a raw deterministic engine, POSIX transport adapters, and a
persistent SQLite inbox as separate components. Build and run its C host with
`bash tools/test-ffi.sh`. The standard inbox acknowledges durable acceptance;
hosts with their own transaction system can handle raw commit proposals.

The [raw UDP host extension](spec/15-raw-udp-host.md) adds configurable CORE
limits, owned state snapshots, generation-checked updates, and one UDP receive
owner for multiple peers. The compiled C harness exchanges 1 MiB objects among
three raw hosts, then reconstructs a host and reads again. It is a libmesa test,
not live Shrine acceptance. See [the phase-0 contract](doc/17-raw-udp-phase0.md)
and [validation evidence](doc/18-raw-udp-validation.md).

The [authority and admission components](spec/16-authority-admission.md) add
noun-free `mesa-pki`, optional `mesa-jael`, owned suite-C candidates, explicit
authority commits, and bounded remote-key updates. Rust and C APIs expose
provider requests, lifecycle changes and retained buffers. Mesa owns incoming
admission; the embedding host supplies verification and transaction services.
The Urbit-Mesa UDP listener now supplies first-contact wiring. Real verifier integration remains phase 7.

The [local activation component](spec/17-local-activation.md) adds `mesa-keys`,
software custody, exact pass/ring matching, host-confirmed activation and
historical-key retirement. CORE retains publications across same-rift rotation;
FLOW preserves its committed ledger. Retained packet capabilities fence old
UDP sends. The C harness tests bootstrap and rotation at 14 SIGKILL boundaries.
Optional suite-C ring import uses `MESA_SUITE_C=1 bash tools/test-ffi.sh`.

The current [integration roadmap](doc/14-shrine-groundwire-roadmap.md) prioritizes
Shrine embedding, separable Jael/PKI modules, and native network interoperability
between suite-C/Groundwire peers. Shrine owns migration of its older bridge to
this API. Azimuth-ID peers, standalone verifier packaging, and the composed inbox
wrapper follow later. Start a new work session with the
[continuation handoff](doc/16-shrine-groundwire-handoff.md); the
[reference snapshot](doc/15-shrine-groundwire-reference.md) pins the inspected
Shrine and Groundwire sources.

## Build and check

```sh
cargo test --workspace
cargo run -p mesa-core --example two-peer
cargo run -p mesa-flow --example two-peer-flows
cargo run -p mesa-transport --example flow-loopback
python3 tools/test-protected-udp.py
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
bash tools/test-ffi.sh
python3 tools/conformance-v2.py
python3 tools/conformance-noun.py
```

The `two-peer` example binds and reads 38 exact bytes over an in-memory v2
peek/page link. Its one-shot protection verdicts live in test support; they
exercise engine behavior without implementing cryptography. See the
[engine contract and test profile](doc/12-peer-engine.md) for limits, timers,
peer updates, and the multi-fragment fault tests.

The explicit experimental [Rust–Urbit runner](interop/README.md) boots an isolated ship and checks
21 bidirectional clean/fault cases through 64 KiB. Hoon parses and authenticates
the packets; native Ames remains unchanged.

The separate experimental UDP runner uses real signatures and LSS with public test seeds.
It checks exact data in both directions from empty values through 1 MiB under
both fixed and adaptive transfer policies. See the [policy contract](spec/09-transfer-policies.md)
for scheduling, feedback, and timer bounds.
See the [signed-public profile](spec/08-signed-public.md) for its exact transcript,
resource bounds, and verification evidence. Selecting this profile requires
explicit public binds; private binds are rejected.

The experimental flow example adds explicit enqueue, delivery, and settlement commits over
the signed-read engine. It restarts both fake stores and peers and checks that
application effects occur once. See the [durable flow profile](spec/10-durable-flows.md)
for the original host transaction contract. The [continuous flow profile](spec/13-continuous-flows.md)
replaces its finite sequence cap with signed batch retirement and bounded protocol history.

The transport example exchanges four messages in each direction over real
loopback UDP and TCP sockets within one process. The relay harness adds
fragmented stream I/O, downstream loss, duplication, reordering, corruption,
disconnects, and a receiver crash after storage succeeds. See the
[flow transport contract](spec/11-flow-transports.md) for framing, queue/PIT
bounds and recovery.

The [persistent host](spec/12-persistent-host.md) commits checkpoints and inbox
records atomically with SQLite. Its subprocess tests kill peers at 48 transaction
boundaries over UDP and TCP, restart from the same stores, and verify exact
ordered delivery and settlement. Continuous runs retain all 128 application
records per direction across 16 protocol batches and restart. Run `cargo test -p mesa-store` for the matrix.
These are process-crash tests; they do not establish power-loss durability on
arbitrary storage.

The C header is `crates/mesa-ffi/include/mesa.h`; `cargo build -p mesa-ffi`
produces `target/debug/libmesa_ffi.a`. The ABI validates and roundtrips
bounded datagrams; it does not authenticate them. Use `mesa_wire_v2_validate`
and `mesa_wire_v2_roundtrip` for v2. Existing unversioned functions remain
v1-only. The Nix package exports this static library and header.

To check historical v1 against the patched Vere driver, build `pact-test` in
the Vere checkout, then supply that binary explicitly. This does not test v2:

```sh
python3 tools/conformance.py --c-binary /path/to/vere/zig-out/bin/pact-test
```

The shared corpus exercises full golden roundtrips, every truncation,
malformed flags, trailing bytes, and checksum divergences. The runner also
requires empty/malformed corpora and false expectations to fail. The patched
C driver is required; the original exploratory driver does not enforce those
expectations. Rust-only tests cover canonical encodings, width boundaries,
configured limits, zero reconstruction, and deterministic hostile bodies.

V2 has one checksum rule: exact transmitted body bytes. Historical v1 exposes
both Hoon-atom and Vere-byte modes, without fallback. V2 vectors are specified
independently of Rust and exercise its CLI in `tools/conformance-v2.py`.
See [the wire spec](spec/01-wire.md) for both API boundaries.

## Why

Today the Mesa protocol lives in three places that don't know they're one
system: the `|mesa` core of `ames.hoon` (flows, acks-as-scries, crypto, the
scry namespace), the Vere driver `mesa.c`/`pact.c` (packet codec,
retransmission, congestion, LSS verification, forwarding, caching), and the
ambient UDP/IP beneath them. A peer that isn't an Urbit ship has to be all
three at once. libmesa unifies them around Groundwire's domain-based comet
identity model. Registered domains authorize current keys through attestations
and re-attestations. `%gw-btc` supplies the first domain; Azimuth can later use
the same interface without becoming a core dependency.

The unification is done **RINA-shaped**: one IPC engine, recursed, with
mechanism separated from policy, so a transport is not a UDP emulator but an
N-1 layer with declared properties. That framing is the subject of the lead
design doc.

## Read in this order

**Design (`doc/`) — the argument:**
1. [`doc/01-architecture.md`](doc/01-architecture.md) — what libmesa is, the
   engine decomposition, module layout, the kernel contract it mirrors, roadmap.
2. [`doc/02-rina.md`](doc/02-rina.md) — **the RINA report.** Why a
   recursive-IPC shape, how Mesa already half-is one, the two-level
   packetization problem as policy, and the flow-engine/transport options
   re-posed through this lens. Start here for the architecture debate.
3. [`doc/03-azimuth.md`](doc/03-azimuth.md) — the boundary for a future
   Azimuth domain adapter; no mandatory gateway or migration protocol.
4. [`doc/04-crypto.md`](doc/04-crypto.md) — **E2E-encrypted by default: what it
   actually requires.** An audit corrected our priors — flows are *already*
   encrypted; the real gaps are metadata, `%publ`-defaulting scry/attestation,
   and forward secrecy. Prioritized gap list + upstream bug findings.
5. [`doc/06-forward-secrecy.md`](doc/06-forward-secrecy.md) — the forward-
   secrecy design space: why static ECDH + on-chain-priced rotation fails the
   threat model, the four tensions (byte-identity, soft state, relay caching,
   Arvo-never-forgets), and the FS0–FS3 option ladder with FS2
   (namespace-published signed epoch prekeys) as the proposed lane.
6. [`doc/07-language.md`](doc/07-language.md) — the Rust-primary decision,
   C ABI commitment, and retained analysis of implementation alternatives.
7. [`doc/05-open-questions.md`](doc/05-open-questions.md) — **the WG agenda.**
   Every open decision, tiered, each with a proposed default.

Also: [`doc/00-kernel-baseline.md`](doc/00-kernel-baseline.md) — pinned branch
revisions, implemented identity mechanics, companion status, and release gates.

**Spec (`spec/`) — the skeleton that implementations conform to:**
`00-scope` · `01-wire` · `02-packets` · `03-namespace` · `04-flows` ·
`05-identity` · `06-routing` · `07-transports` · `08-signed-public` ·
`09-transfer-policies` · `10-durable-flows` · `11-flow-transports` ·
`12-persistent-host` · `13-continuous-flows`. The wire chapter specifies
the implemented codec profile. Chapter 5 defines the domain-first identity
contract, including opt-in life-1 fallback and explicit provisional bootstrap;
it is not yet implemented. Other chapters contain proposals and outlines.

## Naming direction

The target protocol uses fixed 128-bit names and future Azimuth short-name
aliases. Explicit domain selection allows different name/key binding rules,
including directly queryable identity ledgers. This supersedes preserving
Mesa v1's variable-width names. Namespace scope and selector encoding are
settled for the prototype: globally unique names, canonical ASCII domain tags,
and experimental wire version 2. V1 remains an explicit reference. See
[fixed names and domains](doc/08-names-and-domains.md).

Azimuth can be represented as a PKI domain alongside others. Standardizing on
Groundwire's 128-bit identity representation gives libmesa a simple, uniform
base while leaving PKI policy to each domain. One name layout and one authority
interface keep the core small and avoid assumptions about which identity
system an application uses. Azimuth short names can remain available as aliases.

## Grounding

Identity tracks `urbit@hd/cc-key-rotation` plus `hd/cc-snob-only`, stacked on
`hd/cc-kernel`; all three PRs remain open drafts at the 2026-10-21 audit.
See the [pinned baseline](doc/00-kernel-baseline.md) for exact revisions.
The generic core reads a domain tag; `%gw-btc` owns its kelvin-9 custody format.
The current Groundwire companion and the composed kernel are not yet an
end-to-end validated release.

libmesa remains Mesa-only. The pinned kernel still sends proactive rekey
announcements through legacy Ames control packets; an upstream Mesa
announcement/recovery change is required for full identity interoperability.

## Next implementation milestone

The first two peer-engine steps now have an in-memory implementation:
preconfigured peers, bounded namespace reads, fragmentation, and timers.
Step 3 now adds a fixed signed-public v2 context, real LSS verification, and
libmesa-to-libmesa UDP reads. The engine now separates recovery, congestion,
and timer policies with bounded peer scheduling and deterministic tests.
Durable flow transactions run over UDP, framed TCP, and a bounded relay harness.
The SQLite reference host persists inbox records and sender outcomes, fences
writers, and recovers from process crashes. Signed batch retirement bounds
protocol history across continuous operation. The Rust–Urbit prototype now
validates signed-public v2 reads in a Hoon agent.
Next choose native Ames integration or durable application consumption and
retention; the latter lets storage quotas recover without resetting flows.
Private-space confidentiality remains a protection workstream. The earlier comet deadline and proposed v1
adapter are off the critical path; the default remains v2.
Generalized identity and the Groundwire verifier remain separate integration
work. See the
[peer-engine milestone and fresh-task handoff](doc/11-peer-engine-handoff.md).
The [identity milestone](doc/09-identity-milestone.md) retains the eventual
admission and activation requirements.

Noun decoding now preserves sharing in a bounded arena, checks expanded depth,
and enforces canonical jam output. Suite-C parsers bind the committed domain
to the expected selector and preserve exact data/evidence boundaries. These
parsers return unverified claims. Curve checks, name derivation, exact ring/pass correspondence, signing, and
agreement now have [executed Hoon fixtures](vectors/crypto/README.md).
Domain-specific evidence verification remains external. The modular authority
and software-key activation mechanisms are implemented; native wire integration
remains a separate phase.
See [the implementation and RINA review](doc/10-implementation-review.md) for
progress against the original plan and the next acceptance gates.

## Outside the current implementation

Legacy ames / Fine / `%ahoy` interop · Nock evaluation ·
CDAP/RIB formalism · onion routing · forward-secrecy ratchet (design-tracked,
not shipped). See `doc/05-open-questions.md`.
