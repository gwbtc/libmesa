# Rust–Urbit v2 prototype

A Rust `mesa-core` peer and a Hoon Gall agent exchange authenticated public
named reads in both directions. The agent runs inside a fresh fake Urbit.
Hoon owns packet parsing, exact-byte checksums, Ed25519 signatures, LSS trees,
leaf verification, retries, cancellation, and reassembly. Python forwards
complete datagrams between loopback UDP and Vere's local Lick socket. Its fault
mode may drop, duplicate, reorder, or mutate packets; it holds no signing keys
and supplies no authentication verdicts.

This is an **Urbit-hosted experimental v2 endpoint**. It does not change native
Ames or Vere's Mesa driver. Existing ships still use v1; an unchanged ship
cannot consume these v2 packets. The fixture's peer IDs 1 and 2 are configured
protocol identities, not names derived from the fake ship's Azimuth identity.
The fake ship needs no live identity, enrollment, comet, or production keys.

## Run from a fresh ship

Requirements: Rust, Python 3, a Unix host with PTYs and Unix sockets, and a Vere
executable supporting the pinned pill. `reference.json` records the exact pill
commit/hash and the tested local Vere binary's version/hash. The tested binary
was already built; this experiment does not establish a fresh Vere source build.
Hoon cryptographic primitives may use Vere jets.

Retrieve `bin/mesa.pill` from `gwbtc/urbit` at the commit in `reference.json`.
The runner checks its SHA-256 before boot. It records the supplied executable's
hash rather than accepting a moving release name as evidence.

```sh
python3 interop/boot.py \
  --vere /absolute/path/to/urbit \
  --pill /absolute/path/to/mesa.pill
```

The runner boots a fresh `~zod` under `/tmp`, mounts `%base`, copies the two Hoon
files, commits the desk, installs `%mesa-v2`, and runs the acceptance suite.
Boot can take several minutes. It writes `ship.log`, `results.json`,
`receipt.json`, and captured packets beneath `target/urbit-interop/`. The receipt
records the pill, executable, Hoon source, and results hashes. Successful runs
stop the ship and delete only their own temporary pier. `--keep-pier` preserves
it; failed runs retain it for diagnosis. `--output DIR` selects an evidence directory.

For an already running fixture with the agent installed:

```sh
cargo build -p mesa-udp --bin interop-peer
python3 interop/run.py --pier /absolute/path/to/pier --suite --output /tmp/results.json
python3 interop/run.py --pier /absolute/path/to/pier --length 17425 --fault pair
```

Use a dedicated local fixture. The runner changes that agent's binding and read
state for each case. The Lick control socket can start and cancel reads; its
filesystem permissions are the control boundary. The bridge binds only loopback
UDP and accepts only the configured Rust source address. Public deterministic
seeds `[1; 32]` and `[2; 32]` belong exclusively to this test.

## Acceptance cases

The suite runs 21 bidirectional cases:

- Eight clean lengths: 0, 1, 29, 1024, 1025, 3072, 17425, and 65536 bytes.
  The 29-byte value ends in five zero bytes; exact-multiple and partial leaves
  cover both normalization boundaries.
- Loss, duplication, and reordering. Rust's window receives data page 1 before
  page 0. Hoon uses stop-and-wait, so its reorder case delivers an old duplicate
  after a later page; it does not claim a concurrent Hoon receive window.
- Corrupted signature, initial spine, hash pair, leaf data, and path, with a
  recomputed wire checksum; a separate case breaks the checksum itself. Each
  transient mutation replaces a real page, and the test requires repair in
  both directions before successful delivery.
- Malformed frames: short header/name/body/signature, trailing bytes, oversized
  datagrams, and an impossible signature-length declaration. Endpoints reject
  the malformed input and recover on retry.
- Timeout after partial progress, persistent signature corruption, and
  cancellation after partial progress. Both endpoints return no application
  value and release read state. Previously valid late pages cannot revive a
  cancelled read.

Successful results include independent exact-byte comparisons and SHA-256
receipts for each direction. Packet counts and trace hashes depend on scheduling;
this live harness makes no claim of deterministic timing. The core's virtual
harness remains the deterministic fault oracle.

`vectors/urbit-v2/` contains captured Hoon pages for Rust regression tests.
`cargo test -p mesa-core --test urbit_v2` replays them and checks rejection under
a different configured key. Normal GitHub CI runs these captures and the Rust
suite. It does **not** boot Urbit; fresh-ship acceptance is an explicit local gate.

## Prototype bounds

The Hoon endpoint supports one public fixture path, `example/value`, one binding,
and one outstanding read. The two peers use domain `gw-btc`, life 1, rift 0,
bloq 13, zero hops, and at most 64 KiB/64 leaves. It accepts the canonical subset
needed for this fixture and rejects other v2 names or roles. Signature context
and LSS construction follow `spec/08-signed-public.md`, including the separate
Auth(0) page for empty and single-leaf values. The Hoon codec is not a replacement
for the complete Rust codec.

A Hoon read retries its current interest every 250 ms until its 20-second
deadline. Epoch-specific timer wires discard callbacks from older runs. A Rust
read uses its normal core scheduler, a 5-second deadline, and a bounded retry
budget. Cancellation and completion clear reader state. Binding/tree data remain
available for the other peer's reads. Agent reload disables the fixture until a
new local start; no durable Hoon read checkpoint is claimed.

Native Ames integration, `%plea`/`%boon` messaging, private spaces, generalized
PKI, Jael integration, verifier runtimes, enrollment, NAT traversal, and Internet
admission policy remain separate work. This prototype establishes the v2 byte,
signature, and LSS boundary inside a running Urbit.
