# Native target evidence

This directory records the phase-6 investigation of 2026-11-20. It contains
capture tools and an offline checker, not a native libmesa implementation.
Read [the scope report](../../doc/21-native-target-investigation.md) first.
[reference.json](reference.json) pins sources, executed artifacts and evidence.

The [2026-11-22 live follow-up](contact/README.md) closes first-contact routing
and migration selection for fresh suite-C peers. The failed two-process
attempt and remaining-work section below describe the earlier 2026-11-20 run;
the follow-up records its replacement fixture and the proof-ordering trap.

## Evidence boundaries

- `unit-results.json`: 164 pinned Ames/Jael/Mesa kernel tests passed in a fresh
  fake ship. These tests use their own roofs and provider verdicts.
- `kernel-capture.log`: the instrumented Ames test copy passed 109 gates.
  `kernel-packets.json` extracts 86 emitted packets from 47 cases. It preserves
  Hoon output; it does not replace kernel signatures with Rust/Python signatures.
- `crypto-vector.json`: the native crypto gate's shared key, path, sealed path,
  jammed value, ciphertext, root and tag. These are public deterministic test
  values. The gate checked round trips; independent Rust crypto agreement with
  this vector is still phase-6 work.
- `udp-packets.json`: seven actual UDP responses from pinned Vere's Mesa driver.
  An ordinary Gall `%grow` publication supplied the data. The capture client
  sends native peeks; it neither signs nor implements a bridge protocol.
- `wire-check.json`: independent parsing, LSS verification, two successful
  signature checks and exact value checks. The server is a fresh fake `~zod`
  (suite B). This validates native wire behavior, not suite-C admission.
- `suite-c-attempts.*`: two isolated suite-C processes booted after correcting
  the bootstrap domain list. Installing the fixture verifier collided with an
  existing `%gw-btc` desk reservation. No two-process admission, direct recovery,
  rotation, application delivery, or real Groundwire authority was established.

The capture checker verifies signatures after complete offline reassembly.
Production must authenticate the native root from the initial proof before
accepting continuation fragments. Current v2 roots fail these signatures.

## Replay preserved bytes without a ship

Run from the libmesa repository root:

```sh
mkdir -p target/native-replay
python3 investigation/native/extract.py investigation/native/evidence/kernel-capture.log target/native-replay/kernel-packets.json
cmp investigation/native/evidence/kernel-packets.json target/native-replay/kernel-packets.json
CARGO_TARGET_DIR="$PWD/target/native-check" cargo run --locked --quiet --manifest-path investigation/native/check/Cargo.toml -- investigation/native/evidence/udp-packets.json target/native-replay/small.jam target/native-replay/multi.jam investigation/native/evidence/public-key.json > target/native-replay/wire-check.json
cmp investigation/native/evidence/wire-check.json target/native-replay/wire-check.json
python3 investigation/native/check-values.py target/native-replay/small.jam target/native-replay/multi.jam
```

The checker requires seven pages, all five data fragments, valid native
signatures, failure under the v2 signing roots, rejection of altered signed
bindings, and exactly four network packets rejected by the atom-normalized
checksum. The value checker verifies the complete marked gages, including the
4,100-byte logical width of an atom whose representation needs 4,097 bytes.
These tools read existing captures; passing them is not another live run.

## Recreate a live capture

Use a new disposable pier, the pinned executable and the pinned integration
pill. Set `NATIVE_VERE`, `NATIVE_PILL`, `NATIVE_PIER` and `URBIT_SOURCE` to their
paths. Check their hashes and source commit against `reference.json` first.
The exact local binary and pill are not distributed in this repository.
A clean rebuild is not claimed to reproduce their hashes.

```sh
"$NATIVE_VERE" -t --loom 32 -F zod -B "$NATIVE_PILL" -c "$NATIVE_PIER" -p 31626 --http-port 18126 -b 127.0.0.1 --no-dock > native-boot.log 2>&1
```

Run the following in another terminal after `pier (...): live`. The number
printed there need not equal the requested loom size.

```sh
python3 investigation/native/control.py --vere "$NATIVE_VERE" --pier "$NATIVE_PIER" investigation/native/mount.hoon
```

Compare every mounted `base/sys/**/*.hoon` to `$URBIT_SOURCE/pkg/arvo/sys` and
`evidence/kernel-hashes.json`. Copy `$URBIT_SOURCE/pkg/base-dev/` into the fresh
pier's `base/`, then `$URBIT_SOURCE/tests/` into `base/tests/`. Commit with
`commit-base.hoon` through `control.py`, launch `run-tests.hoon`, and collect
all expected test result lines from the runtime log. A successful control
reply means the thread started; it does not mean the tests passed.

Generate the test-only instrumented copy:

```sh
python3 investigation/native/instrument.py --urbit-source "$URBIT_SOURCE" --output target/native-capture-source
```

Copy `native-capture.hoon` into the pier's `base/tests/`, dispatch
`commit-direct.hoon`, then run `run-captures.hoon`. Preserve the resulting
`%native-case`, `%native-packet`, `%native-crypto` and result lines. This adds
logging around test effects and three capture gates; it changes no kernel.
The diagnostic `native-udp-peek` gate captures an early probe path, not the
successful `%grow` publication path used below.

Install and start the ordinary public fixture:

```sh
python3 investigation/native/control.py --vere "$NATIVE_VERE" --pier "$NATIVE_PIER" investigation/native/native-publish.hoon --install /app/native-publish/hoon
python3 investigation/native/control.py --vere "$NATIVE_VERE" --pier "$NATIVE_PIER" investigation/native/start-publish.hoon
python3 investigation/native/control.py --vere "$NATIVE_VERE" --pier "$NATIVE_PIER" investigation/native/public-key.hoon
python3 investigation/native/probe.py --port 31626 --output target/native-replay/udp-new.json
```

Wait for `gall: installing %native-publish` before the UDP probe. Record the
public key returned by `public-key.hoon` as 32 little-endian bytes. Feed the
new capture/key into the offline checker. The probe expects the first `%grow`
revision, so restarting the fixture application in the same pier can change
its publication paths. Use a fresh pier for an independent replay.

The packaged control helper was checked against the running disposable
fixture. Kernel setup and publication installation were performed through the
same `%fyrd`, Clay `%info`, and `%kiln-rein` mechanisms. The whole procedure
above has not been rerun from scratch as one packaged automation.

## Failed attempts and remaining experiment

Initial exploratory `on-peek` requests did not publish remote data. `%grow`
provided the native remote publication. An instrumented test first failed a
key-aura compile check; the preserved generator includes the corrected cast.
A later attempt to import the entire instrumented file through one large
`%fyrd` source stalled and was interrupted. The saved 109-test capture predates
that attempt and passed. Filesystem `%dirk` is the capture installation path.

The two suite-C peers used deterministic test feeds and a loopback bootstrap
gateway with an empty galaxy table. The initial empty domain list failed
Jael's real-key domain invariant. `native-test.invalid` allowed both to boot.
The attempted provider used a fixed pass allowlist from the pinned test
provider; it failed to install because `%gw-btc` was already assigned to
another desk. Bootstrap, provider-installation and routing failures must not
be counted as rejected-attestation tests. No private piers or key feeds are
included here.

The next experiment must isolate a test identity domain, register its provider,
and capture a Rust-style initiator with an explicit UDP destination. In the
pinned source, `%dear` changes routes only for known peers; it cannot configure
a fresh unknown peer. Determine native proof reply routing and per-peer modes
before deciding whether any `%ahoy` migration subset is needed. Then capture
positive/negative verdicts, delayed delivery, private messages, refresh and
lost simultaneous announcements. This remains an open prerequisite to the
full native compatibility claim.
