# libmesa spec — 7: Transports (N-1 mappings)

> **Skeleton.** A transport is an N-1 DIF with declared properties; the same
> pact is the unit everywhere (option ii, `../doc/02-rina.md` §6.2), so
> relays can bridge transports statelessly.

## Outline

1. **N-1 property declaration.** max-SDU, reliable?, ordered?, datagram vs
   stream, lane representation, duplex.
2. **Policy derivation table.** per N-1 class: delimiting bloq, retransmission
   on/off, congestion on/off. Responder serves whatever bloq the request
   names (negotiation-free; confirm — doc/02-rina.md §7.2).
3. **UDP mapping.** 1 pact/datagram; ≤1472 B; bloq 13; retransmit+congestion
   on; STUN/hole-punch/forwarding as in `mesa.c`.
4. **TCP mapping.** length-prefixed pacts; retransmit+congestion off; bloq
   free to grow (jumbo); keepalive policy.
5. **WebSocket mapping.** 1 pact/binary frame; as TCP otherwise; the
   browser/phone profile.
6. **Exotic N-1 sketches (informative).** Lightning onion messages; Nostr
   relays as rendezvous; Lick (local IPC — cf. tcp-sidecar's pattern);
   mesa-over-mesa (groups as DIFs).
