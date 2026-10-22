# libmesa

A standalone Rust implementation, exposing a C ABI (decision record:
`doc/07-language.md`), of Urbit's **Mesa** ("directed
messaging") network protocol and **Groundwire** identity, lifted out of the
split Arvo-vane + Vere-runtime implementation into one self-contained,
transport-agnostic engine — usable by non-Arvo peers: Nostr clients, LND
nodes, Shrubbery ships, and ChatControl-threatened phones.

> **Status: wire-codec prototype.** Rust parses and encodes all three packet
> bodies in experimental v2: fixed 128-bit names, explicit domain selectors,
> exact-byte checksums, length-prefixed signatures, and none/IPv4 trailers.
> Decoding is bounded and allocation-free. V1 remains an explicit compatibility
> module. Canonical atoms, byte mug, fragment reconstruction, and C APIs for
> both profiles are implemented. Identity, cryptography, LSS verification,
> networking, and flows remain unimplemented. The design beyond the codec is
> still a working-group draft.

## Build and check

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
bash tools/test-ffi.sh
python3 tools/conformance-v2.py
```

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
`05-identity` · `06-routing` · `07-transports`. The wire chapter specifies
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

Build authenticated identity: bounded suite-C parsing and real cryptographic
vectors, asynchronous domain verification/resolution, accepted-point lifecycle,
explicit trust modes, and exact public/private activation. Define v2's protected
context before network identity acceptance. See
[the identity milestone](doc/09-identity-milestone.md).

## Outside the current implementation

Legacy ames / Fine / `%ahoy` interop · Nock evaluation ·
CDAP/RIB formalism · onion routing · forward-secrecy ratchet (design-tracked,
not shipped). See `doc/05-open-questions.md`.
