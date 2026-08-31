# libmesa spec — 4: Flows and messages

> **Skeleton.** The flow engine is sequencing/window mechanism + policy
> modules (retransmission, congestion) gated on the N-1 class — option C in
> `../doc/02-rina.md` §6.1.

## Outline

1. **Message layer.** `%plea`/`%boon` over flows; `$spar`; payload encoding
   (noun for Arvo interop; opaque bytes otherwise).
2. **Flow identity.** side = [bone dire]; bone allocation parity rules;
   forward/backward/naxplanation bone bits.
3. **Sender state vector.** ordered send queue, next-seq, sliding window;
   pokes reference `/flow/<bone>/poke/...` bindings.
4. **Receiver state vector.** last-acked, pending-ack, nack map; exactly-once
   delivery rule (+(last-acked) only; bounded re-ack of dupes).
5. **Acks as bindings.** `/flow/.../ack/<seq>` pages; nacks; naxplanations as
   separate flow bindings.
6. **Timers (delta-t).** The MPL/A/R mapping for every timer (PIT expiry,
   resend, dead-flow, recork); the exactly-once argument; whether corks are
   necessary or an optimization (open — doc/02-rina.md §7.3).
7. **Backpressure.** clog/flub/halt semantics toward the host.
8. **Policies.** retransmission (on/off), congestion (gauge port / off),
   delimiting bloq; derivation from N-1 class, no negotiation (open —
   doc/02-rina.md §7.2).
