# Retention and process-crash investigation

This records the 2026-11-25 investigation described in
[the design and source audit](../../../doc/24-retention-and-urbit-crash-semantics.md).
No libmesa protocol implementation, Urbit kernel, or Shrine code changed.

Run the preserved-evidence check from the repository root:

```sh
python3 investigation/native/retention/check-evidence.py
```

The checker verifies file hashes, recorded application counts and outcomes,
SIGKILL/drop ordering, closed-flow state after restart, and the new-flow positive
control. It reparses all captured datagrams through the existing Mesa-v1 codec
and compares the saved summaries. Private MAC acceptance is evidenced by the
real kernels, not independent MAC verification by this checker. Offline replay
does not execute another crash test.

## Executed cases

| Case | Before / after evidence |
|---|---|
| Receiver ACK lost, receiver killed | Receiver count 1 → 2; after restart and retry it remains 2. Sender result count advances 1 → 2. |
| Sender killed before proxy forwarding | Receiver remains at 3 while sender is dead. Sender restart recovers its outbox; receiver reaches 4 and sender result count reaches 4. |
| NACK lost, receiver killed | Receiver accepted-operation count stays 4. Sender result count advances 4 → 5 with a negative poke result after explanation recovery. |
| Closed flows, both peers killed | Bones 12 and 16 remain closed after restart. Receiver count stays 5 after replay of the captured bone-16 request. A new bone-20 flow advances it to 6; three further old-packet replays leave it at 6. |

The sender's result list also contains normal subscription watch responses and
boons. Its final count is 11. The receiver fixture increments its counter on
each accepted poke and, in the later fixture revision, each accepted watch. It
contains no application-level message deduplication. Rejected pokes crash the
handler with a fixed tagged error and do not increment its state.

## Files and boundaries

- `reference.json`: exact pins, source/artifact hashes, fixture provenance,
  attempt notes, and evidence hashes.
- `evidence/actions.jsonl` and `evidence/commands/`: successful control replies
  and exact Hoon sources. Three extra command files preserve failed setup
  attempts; absence of a successful action record is not a passed operation.
- `evidence/packets.jsonl`: 56 datagrams observed by the proxy, including
  drops and four exact replay injections. Direct route learning can bypass
  the proxy, so this is not a complete network trace.
- `evidence/lifecycle.jsonl`: three UDP-triggered SIGKILLs, two SIGKILLs after
  closed-state observation, restarts, and final cleanup signals.
- `evidence/*-trace.log`: selected runtime lines showing replay and protocol
  transitions. These are excerpts, not complete process logs.
- `fixtures/`: control helper, proxy, and final ordinary Gall fixture. The
  staged fixture revisions are preserved in the installation commands.

The test copied the stopped `target/suite-c-contact/a` and
`target/suite-c-request-first/b` piers into a new scratch directory. It used
APFS clones of their `.urb` subdirectories and omitted stale lock/socket files.
Both ran with `-L`, bound to loopback, on UDP ports 31901/31902 and HTTP ports
18301/18302. The proxy bound UDP 31911/31912. The original fixture piers were
not started or modified; operational ships were not touched.

The binary matched SHA-256
`f5a45c0e306dcdf657e60da0e79b90a99e56d8dc5f82c5c5962e1c1de8c8506f`.
All 15 entries in the earlier mounted-kernel hash inventory matched on each
clone. The compatible pill under the earlier `compat/` directory matched the
original pin; the similarly named top-level pill had changed and was not used
as evidence of that pin. These runs resumed existing disposable piers rather
than booting new piers from either pill.

## Reproduction constraints

Recreate the suite-C fixtures with the [earlier recipe](../contact/README.md),
or use stopped copies whose kernel/identity provenance matches that record.
Verify the executable and mounted kernel hashes. Copy these helper scripts
into a fresh scratch directory and adapt paths/ports explicitly. The helpers
expect execution from the repository root. `actions.py` assumes the public test
identity names recorded in the earlier experiment.

Use the installation commands to reproduce the fixture revisions and the
successful action order. The proxy's `kill_a_once`/`kill_b_once` flags apply
SIGKILL to the process groups recorded in that scratch directory. Those groups
must have been created for these disposable piers with `start_new_session=True`;
never supply an operational PID or reuse stale PID files. Record and assert
that the intended datagram was captured and dropped before counting a kill.
Reset direct routes as in the commands; an early sender attempt bypassed the
proxy and completed normally, and is explicitly excluded from the crash case.

The exact staged live sequence has not been packaged or rerun as a one-command
launcher. `check-evidence.py` is the repeatable offline check. New libmesa
implementation tests must add storage-fault injection, receipt-window bounds,
sparse NACK pruning, interval quota/compaction, lost cork ACK/%gone, and precise
boon-receipt crash points. Power loss and external business effects were not
tested. No piers or private key feeds are included here.
