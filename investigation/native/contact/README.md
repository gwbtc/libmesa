# Live suite-C first-contact evidence

Read [the routing and migration report](../../../doc/22-suite-c-first-contact.md)
for conclusions. This directory records the 2026-11-22 investigation against
the unchanged pinned stack in [../reference.json](../reference.json).

## Replay without a running ship

From the repository root:

```sh
python3 investigation/native/contact/check-evidence.py
CARGO_TARGET_DIR="$PWD/target/native-check" cargo clippy --locked --manifest-path investigation/native/check/Cargo.toml --all-targets -- -D warnings
```

The replay checks every evidence/fixture hash, reparses the exact captured
bytes with the existing Mesa v1 codec, verifies each captured complete signed
page/poke against the recorded public keys, rejects changed signed bindings,
and compares the result with the saved summaries. It then asserts admission
states, absence of delivery before acceptance, rejection, successful receipts,
the proof-ordering counterexample, and the distinction between default-mode
selection and migration. This is an offline evidence check, not another live
interop run or the repository's full test suite.

To inspect one capture:

```sh
CARGO_TARGET_DIR="$PWD/target/native-check" cargo run --locked --quiet --manifest-path investigation/native/check/Cargo.toml --bin contact-summary -- investigation/native/contact/evidence/request-first/packets.jsonl investigation/native/contact/evidence/public-keys.json
```

The checker validates only complete single-fragment signatures at life 1 in
this fixture. Private MAC acceptance is evidenced by the real kernels and
application receipts. `not-mesa-v1` classifies the migration experiment's
other traffic; it does not validate that traffic as a legacy Ames handshake.
No checksum fallback or replacement signature is generated.

## Files and roles

| Path | Content |
|---|---|
| `evidence/held-verifier/` | A/B first contact, held verdict, rejection, acceptance, bidirectional messages and receipts |
| `evidence/migration/` | Superset of the A/B run, then legacy regression, ignored Mesa data, default-mode change, attempted ahoy, explicit local migration, resumed delivery |
| `evidence/proof-first/` | Fresh C receives and accepts a proactive proof while private packets are dropped; creates legacy state and ignores later private data |
| `evidence/request-first/` | Fresh C pier accepts a requested proof page, completes both message directions, and records the sponsor packets discarded by non-forwarding listeners |
| `evidence/shared-sender.log` | A's runtime log across all cases, including the return message from fresh C |
| `evidence/*/actions.jsonl` | Successful control responses and peer-state snapshots, with host timestamps |
| `evidence/*/commands/` | Exact Hoon strand source corresponding to each successful control operation |
| `evidence/public-keys.json` | Three public fixture signing keys, extracted from their public passes in the pinned Hoon runtime |
| `fixtures/` | Identity generation, exact-pass provider, ordinary Gall application, bootstrap gateway, UDP proxies and non-forwarding sponsor listeners |
| `reference.json` | Pins, artifact hashes, case counts, file hashes and validation limits |

The held-verifier capture is a prefix of the migration capture. Their packet
counts and deliveries overlap. The shared sender log likewise includes prior
cases. The ordering experiment's original C receiver was stopped before the
request-driven test used another fresh pier for the same C identity. The new
receiver started with no Ames relationship for A; A retained its undelivered
sequence-one work. This is not a restore-fencing test.

Runtime logs use LF line endings with trailing line whitespace removed. The
reference records their original and normalized hashes. Captured UDP hex
bytes are unchanged. The logs retain setup failures: A's first galaxy-table
fetch raced gateway startup, and the first provider source had an invalid
hex-literal spelling. A booted, the provider spelling was corrected, and the
provider installed before test traffic. No assertion depends on empty global
PKI tables; the snapshots establish that the receiver did not know A.

All identities and keys are deterministic test material. Private feed files
and piers are excluded. `make-identities-a-b.hoon` and
`make-identity-c.hoon` generate the feeds locally. The provider sources contain
public pass allowlists. A's allowlist was extended to C after the first case;
the saved hold-provider source contains that extension. Only A/B entries were
used during the first case.

## Live setup and control sequence

The following describes the executed setup. It is a reproduction recipe with
saved command sources, not a newly tested one-command launcher. Use disposable
piers and free ports. Never run these fixture commands against an operational
ship.

1. Verify the executable and pill hashes. Run the identity-generation strands
   through the trusted `%fyrd` helper in `../control.py` on a disposable pinned
   runtime. Decode the returned names, feed cords, and public points locally.
   Write each test feed to its own mode-0600 file. Keep only the public identity
   records in the evidence directory.
2. Run a copy of `fixtures/gateway.py` in a scratch directory containing
   `identities.json`. It serves an empty galaxy table and a nonempty reserved
   domain list on loopback port 18229. The selected executable's bootstrap
   fetched those two endpoints; this gateway is not the domain verifier.
3. Boot each real-key test identity with the pinned pill:

   ```sh
   "$NATIVE_VERE" -t -L --loom 31 -B "$NATIVE_PILL" -c "$TEST_PIER" -w "$TEST_NAME" -k "$TEST_FEED" -p "$TEST_UDP_PORT" --http-port "$TEST_HTTP_PORT" -b 127.0.0.1 --no-dock --gateway http://127.0.0.1:18229
   ```

   A/B used UDP 31727/31728 and HTTP 18227/18228. The two fresh C piers
   used UDP 31738/31739 and HTTP 18238/18239. `-L` restricts network lanes to
   loopback; the pill still starts its normal background applications and
   carries sponsorship metadata. Those applications are not the test provider.
4. Install the selected provider as `/app/mesa-test/hoon` and the ordinary
   receiver as `/app/native-receive/hoon` using `../control.py --install`.
   Enable those applications with `%kiln-rein` on `%base`. The provider calls
   `%anex`; its hold/accept/reject state applies only to remote candidates.
5. Select Mesa for new outgoing peers on A. Use the fixture's `%self-verdict`
   control to install the target public point, submit the application message,
   then set its direct route with `%dear` once the target is known. The control
   command files preserve the exact route packing, point and mode operations.
   Receiver-side first contact does not install A's point or route manually.

Each proxy script expects its scratch directory to contain its own logs and
control files. It keeps both UDP source endpoints stable:

| Case | A's target endpoint | Receiver's observed source | Receiver UDP port |
|---|---|---|---|
| A/B | 31840 | 31841 | 31728 |
| Proof first | 31850 | 31851 | 31738 |
| Request first | 31860 | 31861 | 31739 |

`proxy-pass.py` forwards all bytes. Its `inject.jsonl` input replayed four
already-captured datagrams after rejection; each injected record is labeled
`injected_replay`. `%prod` also explicitly requested native retries. No result
claims autonomous retry timing.

`proxy-proof-first.py` drops A-to-C packets containing `chum/` until a scratch
`release` file exists. Let the provider accept the proof, record `%peer
%known`, then release private packets and observe the absence of delivery.

`proxy-request-first.py` drops only proactive A-to-C proof pokes, identified
by the two plaintext proof/muth paths. It forwards private packets, requested
proof pages, and all receiver responses. The saved decoder independently
checks that every dropped packet really was a signed proof poke. Record the
receiver's initially absent A relationship, its proof request, verifier
acceptance, `%chum %known`, delivery, and receipt. Use `%prod` after acceptance
to resend the outstanding private work.

`blackholes.py` binds local sponsor ports 31402 and 31463 and only records
incoming datagrams. These are `31337 + (ship & 255)` for A and C in this
runtime's local mode. It sends no responses. Both ports bound successfully;
21 packets were discarded during the request-driven case. The successful
messages and receipts used the two direct proxy endpoints.

The additional public proof read used C's identity as the native peek publisher
and path `publ/1/a/x/1//pawn/proof/1/<A>/1`. The captured request and response
are in `public-proof.jsonl`; snapshots before and after show that A remained
absent. A's target point in the message experiment was still supplied by the
fixture provider. These are complementary checks, not a completed libmesa
bootstrap implementation.

## Migration experiment and limits

After the A/B exchange, `%rege` on B converted its established A flow state to
legacy Ames. A's ordinary private Mesa packets were ignored. `%load %mesa`
left the existing peer in legacy state. The Hood `%ahoy-prob` request did not
establish automatic migration with this pin's disabled trigger hash. An
explicit legacy `/mesa-2 %ahoy` plea also failed to complete the one-sided
mismatch; A logged `ack missing seq=1`.

An explicit local `%mate` on B restored the Mesa relationship. Pending work,
including the application message and the now-Mesa ahoy plea, completed. This
is evidence that local state conversion restores compatibility. It is not a
successful legacy wire migration test and does not justify an automatic
migration promise in phase 6.

The live tests cover life-1 suite-C identities and exact fixture passes. They
do not cover real ledger verification, higher-life network rekey, lost
simultaneous announcements, production congestion behavior, arbitrary Gall
payloads, or Shrine integration. Those boundaries remain explicit in the
phase-6/7 roadmap.
