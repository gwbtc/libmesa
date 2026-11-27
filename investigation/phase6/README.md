# Phase 6: executed Mesa-v1 interoperability

The captured Rust processes exchanged Mesa-v1 traffic with the unchanged
Groundwire Urbit stack pinned in `reference.json`. Public and private transfers
use the shared CORE/LSS/crypto implementation. Ordinary Gall fixtures consume
byte payloads; they implement no alternate network protocol.

Run the offline artifact check and deterministic mechanisms:

```sh
python3 investigation/phase6/check-evidence.py
cargo test -p mesa-urbit -p mesa-core -p mesa-flow
MESA_SUITE_C=1 bash tools/test-ffi.sh
python3 tools/check-embedding-deps.py
```

The `process_crash` test launches two independent Rust UDP processes. It sends
SIGKILL before persistence, after fsync/rename, and after confirmation at the
enqueue, receive-effect and settlement boundaries. Four additional cases cover
negative outcomes and cork closure: 13 kills in total. Each recovery checks
one durable effect, one settlement and exact payload bytes. The host world
file combines the checkpoint and application records; no SQLite inbox is used.

## Recorded live results

| Artifact | Observation |
|---|---|
| `public-read.json` | Rust authenticates 24-byte and 4,115-byte Urbit publications |
| `public-serve.json`, `public-serve-result.txt` | Urbit authenticates Rust's publication and returns `[noun octs 3 7]` |
| `d-first-contact.json` | A fresh Rust identity starts with a private poke; Urbit solicits its signed proof, the fixture provider accepts, and the message settles |
| `comet-session-4100.json`, `comet-reverse.json` | Byte pleas settle in both directions |
| `fragment2-live.json`, `reverse-fragment.json` | 4,100-byte application payloads transfer in both directions |
| `reject2-live.json` | Gall rejects a designated payload; Rust retrieves and retains the exact 422-byte explanation |
| `comet-network.log` | Urbit receives gone and deletes the closed bone 4,120 |
| `rekey-live.json` | Urbit accepts a signed life-2 announcement, then the new-key message |
| `recovery-live.json` | The first life-3 announcement is deliberately lost; a bounded retry restores communication |
| `peek-long-before-fix.json` | A fresh 4,100-byte transfer exposes an unused LONG next-hop hint on Vere peeks; the old decoder stalls safely |
| `final-build.json`, `final-closure.json` | The corrected build resumes that same outbox, receives acceptance and commits cork closure |

The final run also captures Vere's LONG next-hop hint. Pinned C peek framing
ignores all next-hop bits; pages interpret them separately. The corrected Rust
decoder follows that distinction. The first five-second restart ended before
Urbit retried its stalled read. A 45-second run resumed the same world file and
closed bone 8 after acceptance. This is a recovery test, not a fresh-state reset.
The final binary hash and capture time are recorded in `reference.json`.

The rejection, recovery and final-build reports include unrelated packets from a previous
missing-agent experiment. Those packets address Urbit's general Gall control
bone zero, outside this byte-service profile, and are rejected with a coordinate
diagnostic. They cause no application delivery or settlement. Duplicate and
early gone requests also appear as ordinary dropped-packet diagnostics.

The trace includes a decisive negative control: omitting announcements entirely
leaves life-3 private packets unaccepted at a life-2 receiver. Urbit logs
`weird poke lifes=[2 1]` and skips them. This establishes the need for bounded
sender announcement retries; it does not establish automatic recovery from
private-packet life hints on the Urbit side.

## Live reproduction

Use disposable piers from the [suite-C setup](../native/contact/README.md).
Pin the exact binary and pill hashes in `reference.json`. A default-mode fresh
relationship needs no `%ahoy`. Existing old-Ames relationships require separate
operator migration and are outside this test. Never run the fixture provider
on an operational ship.

Install `fixtures/crash-probe.hoon` as `/app/crash-probe/hoon` and
`fixtures/mesa-test.hoon` as `/app/mesa-test/hoon` with
`investigation/native/control.py --install`. Wait for Gall installation before
traffic. The provider is an exact-pass allowlist. For the rotation runs install
`mesa-test-rotated.hoon` (life 2), then `mesa-test-recovery.hoon` (life 3).
Those files contain public fixture passes. They do not verify a ledger.

`fixtures/make-rust-identities.hoon` generates the A and D fixture rings and
passes. Keep its output in ignored `target/`, mode 0600. A current ring's bytes
1–32 are its seed; a public pass's bytes 33–64 are its live public key. Preserve
all 32 seed/key bytes. The live comet C is
`~hantyl-dochus-dilryl-narmul--tabtyv-tantel-dotmeb-nacnub`, whose public live key
is `1a330411fe6095b2927e105ae74811d778fe4fe52a68a39ddfa22e374f76f6ae`.

Create a mode-0600 JSON configuration in `target/` for the runnable peer:

```json
{
  "session": true,
  "local": "~dinden-lanpen-dissen-habnub--hacwer-libbus-firdyt-bonlec",
  "remote": "~hantyl-dochus-dilryl-narmul--tabtyv-tantel-dotmeb-nacnub",
  "seed": "<32-byte fixture seed in little-endian hex>",
  "pass": "<complete public fixture pass in little-endian hex>",
  "remote_key": "1a330411fe6095b2927e105ae74811d778fe4fe52a68a39ddfa22e374f76f6ae",
  "bind": "127.0.0.1:32031",
  "address": "127.0.0.1:32032",
  "agent": "crash-probe",
  "bone": 4,
  "send": "070000",
  "world": "target/disposable-world.json",
  "report": "target/disposable-report.json",
  "max_attempts": 30,
  "retry_ms": 100,
  "timeout_ms": 6000,
  "duration_ms": 8000
}
```

Run `cargo run -p mesa-urbit --bin mesa-peer -- target/config.json`. Keep the
same world file for restart. A fresh world must use a fresh identity/epoch or
an unused bone; deleting an outbox is not a reset protocol. The implementation
refuses incompatible checkpoint schemas and domains.

For public serving, set `session=false` and supply
`publish=[{"path":"publ/1/g/x/1/mesa-bytes//1/value","hex":"..."}]` with a jammed
marked gage from `vectors/urbit-mesa/gages.json`. `fixtures/public-serve.hoon`
uses ordinary `%keen` and waits for `%sage`; its path omits the `publ/1` prefix
that Urbit adds. `fixtures/reverse-fragment.hoon` sends the larger reverse plea.
Change its destination to the selected Rust identity when reproducing with D.

`local_life` and `remote_life` default to one. A's life-2 and life-3 fixtures use
32 seed bytes of 42 and 43 respectively, keeping its genesis and domain data.
Use the corresponding public allowlisted pass. Set `announce=true` after
activation. `drop_first_announcement=true` injects the recorded announcement
loss. `close=true` corks after settlement. Sending hex `efbe` to `crash-probe`
selects the deliberate rejection.

These captures were produced while the phase-6 branch was under development.
Their codecs, cryptography and flow rules are covered by final regression tests;
the capture is not a claim that every final source file existed at capture time.
The final validation report separates captured evidence, final tests and the
default switch. Shrine migration, real verifier integration and Urbit kernel
changes remain outside this directory's scope.
