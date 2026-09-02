# Reference 2: Joe Bryan ~master-morzod, "Names, Data, and Networking"

Reassembly 2023, Day 2, Wyoming, August 2023. Roughly 55 minutes with Q&A.
Source: transcript of the recorded talk.

> **Why this is in the references folder.** This is the design talk, given
> before the implementation existed. It contains the derivation of the poke
> packet (spec ch. 2 §4.3) from first principles, the argument for why packets
> must not be signed (ch. 2 §6), the three-layer namespace projection that
> became the region map (ch. 3 §2), and the cost analysis that motivates almost
> every performance-shaped decision in the spec. Where it describes mechanism,
> some of it was superseded before shipping; those places are flagged below.

## 1. Framing: what Ames was supposed to be

Bryan opens on the 2010 Urbit introduction, which describes the Martian network
as "source independent" and says the change from IP is to delete the four-byte
source address. His observation: an Ames packet does not delete a four-byte
source, it adds an Urbit source field of up to sixteen bytes. So the claim was
aspirational. The second Urbit quote points at content-centric networking and
the Jacobson talk, and Bryan's read is that the overlap between CCN and Ames as
built is "technically present but incredibly remote".

He then recaps Jacobson at length. That material is summarised in
`01-jacobson-2006.md` and not repeated here, except where he adds something:

- He is careful that the "network hooks itself together autonomously" claim is
  euphemistic for IP, but accurate relative to punching down copper.
- On content addressing: naming a thing by its own hash gives coordination-free
  naming and trivial binding validation, but has no locality, and in practice
  every content-addressed system grows a naming layer above it and then has to
  authenticate that binding, which puts you back where you started. He treats
  making content addressing the base layer as a mistake many later projects
  made.
- On group cryptography: security protocols are two-party. Even Signal does not
  send one message under one key under one identifier to a group. He does not
  claim that is a mathematical necessity, only that nobody has needed it, so it
  does not exist. He also dismisses deniability as a goal for Urbit, since Urbit
  attests strongly to the association between data and identity, and if you want
  deniability you use another pseudonym out of a 128-bit comet space.

## 2. Why NDN never shipped

His diagnosis, offered as opinion:

- It is stuck in a research trap. Pick any buzzword, search it with "NDN", get
  twenty papers.
- The benefits do not justify switching if everything you run on top is still
  conversation-shaped.
- New application paradigms are required. Everyone becomes a publisher and
  conversations are derived from mutual publication, which means turning
  application design inside out.
- Rumour, offered as conjecture: content-based protocols are already common
  inside big tech (CDN management, internal service meshes) and the reason none
  of it escapes is that the internet's incentive structure prevents shipping any
  new protocol regardless of merit.

What Urbit brings that NDN lacks: a node model, a PKI, and a referentially
transparent namespace where every path begins with a ship. That collapses the
problem. NDN has to do content-based routing, build a FIB by prefix, flood
across every interface on a miss, and then invent BGP-class protocols to
negotiate and authenticate routes. Urbit does not have to, because the publisher
is a first-class routable identity and is the obvious place to start looking.
NDN is also equivocal about referential transparency: it wants a
zero-configuration story (the projector in the room advertising itself by name)
and ends up two-tier, some names locally scoped and some global, some
referentially transparent and some not.

## 3. Fine, as shipped in spring 2023

Fine is NDN on Urbit: a request is a path in the namespace, the response is a
signed binding of path to page. It drove OTA updates from May 2023. Reads do not
hit the event loop, do not log to disk, and can be served from a runtime hash
table after the first request warms a window of packets.

Its incompleteness, in his list:

- It uses Ames framing, so requests carry source and destination, and relays
  must rewrite metadata per destination. Not source-independent.
- Routing is parasitic on Ames. If you cannot reach a peer over Ames you cannot
  reach them over Fine.
- Public data only. The alternative is user-space devs rolling their own crypto
  and putting ciphertext in the namespace, which is not acceptable. There is
  also a real difference between public inside the network and public outside
  it, and few things are genuinely the latter.
- User-space publication patterns are limited, because the kernel's job is to
  guarantee referential transparency, so any pattern must be legible to it.

And it is expensive. His measurement, run on a fakezod on an M2 that morning:
4 ms to sign the atom `0`, 6 ms to sign and verify it. Fine signs every message
and every packet.

## 4. The cost programme

Three moves, in order of aggressiveness:

1. Sign most messages, not all. Content-addressed data needs no signature at
   all, because the binding is trivially checkable.
2. Do not sign packets. What a packet needs to prove is its existence and
   position within a message, and a Merkle hash does that. Blake3 is already a
   tree hash; bao is the existing serialisation for verified streaming; it needs
   tweaking for our case.
3. Reduce event-log writes, which turn out to fall out of the design rather than
   needing separate work (see §6).

## 5. Deriving the poke

The Ames critique first. Every message is a transaction and every packet is a
transaction, which gives very strong invariants and is arguably a good thing,
but the model mismatches both the current and the planned application model, and
he calls it a perfect castle nobody wants to live in. Concretely: every packet
elicits an ack, the last packet's ack is the end-to-end ack meaning the message
was processed, and none of this is legible on the wire. You cannot correlate a
packet to a message or an ack to a packet. You cannot prioritise by flow, route
differently by flow, or say this one is latency-sensitive and that one is
throughput-sensitive. It is theoretically transport-agnostic and in practice
UDP over IPv4 with fixed-size fields. Plus the 25-second NAT ping, which is
performing two unrelated jobs at once.

The naive unification is to run Ames over Fine, and it is absurd: to send you a
message I request that you acknowledge a message I have not sent you; you notice
you cannot answer, so you request the message; I answer with the message; you
then bind the ack. It is completely legible and has every dissemination
property, and it doubles round trips and packet count.

The fix is concatenation. Take the read of the ack and the response carrying the
payload and stick them together. Formally: "can you produce an ack for this
message, and by the way here is the message". Same semantics, same round-trip
count. That produces three packet types, named after Arvo's own interfaces:

- `%peek`, a stateless read request, a path.
- `%page`, the single response type to either request, a binding of path to
  data.
- `%poke`, a stateful write request, carrying an ack name and a payload name.

Correlation between request and response is exact match on the name. No prefix
matching, no funny business. He says this explicitly, and it is the origin of
the byte-equality rule in spec ch. 2 §3.

One further optimisation: if the payload fits a single packet, elide the
signature. Bind it under a slightly different name and send only the
authenticated encryption already in use, because a single-fragment poke is
formally the two-party conversational case of dissemination and there is nobody
else to attest to. Multi-fragment pokes must be signed, because the signature is
what validates every other packet in the message. A poke always carries the
first fragment, which tells the receiver how big the message is and where to go
for the rest.

If the two paths are too long to fit together in one MTU, temporarily bind the
payload under a short content-addressed name, send that, and tombstone the
binding later.

## 6. Wins that fell out

He describes these as surprising, and as consequences of legibility rather than
targets:

- Event-log writes for sending an n-fragment message drop from 2n to n+1. On the
  sender side they drop to one: you write when you initiate, and you write the
  ack when it comes back. The receiver writes the pieces it pulls.
- The receiver's reads do not hit the event log, parallelise once the
  interpreter can, and hit caches if anyone asked first.
- Gall's subscription model has one subscription with a set of ships attached,
  but crossing into Ames turns that into a separate conversation per ship,
  sharing nothing but the bytes. Under named data the identifiers are shared and
  the work is done once.

## 7. Merkle sketch, 2023 version (superseded)

Complete binary tree, leaves are data fragments, node hash is the hash of its
children. Send fragments in leaf order; attach to each the next hash in a
pre-order depth-first left-to-right traversal. Two multiplexed sequences,
fragments and hashes. You must accumulate roughly log2(n) fragments before you
can begin validating, because you need the complete path from root to first
fragment; after that you validate each fragment as it arrives, provided you
process in order.

**This is not what shipped.** The buffering requirement was removed and the
traversal replaced by the Blackman/Lackman ordering. See
`03-bryan-2024-lake-summit.md` §5 and the USTJ paper. Do not cite this section
as the LSS design.

He does note in passing that this is a good incremental step toward
depacketisation: Vere can take the first response, start requesting the rest,
do its own congestion control, and decide how much to inject into Arvo and when.

## 8. The three-layer projection

The private message layer holds the real names and the real data, the names an
application would actually use. The public encrypted layer is a pure
non-materialised computational projection over it. The packet layer is another
projection over that, obtained by extending the path with a fragment index. None
of it needs to be materialised in state; it is recomputed and memoised. This is
where the spec's region map and space table come from.

Two consequences he draws:

- Persistent memoisation makes this affordable. Nock memoisation currently lives
  in one virtualisation context; if it can live across events, you stop
  materialising your pending packet queue in state and instead express it as a
  function over the message that the runtime is free to discard under memory
  pressure.
- If you have a trusted channel, you can punch through the layers by convention
  and pass a pointer to the data as it is persisted on the other ship. Aqua
  (ships inside a ship, with software-defined networking over fake I/O drivers)
  and sophisticated hosting environments both want this.

He is candid that his worry about message-oriented protocols that bypass the
authentication or encryption layer is agglomeration: an Urbit UDP network plus
an Urbit WireGuard network plus an Urbit whatever, paying the full complexity of
the cartesian product. The projection framing is what makes it one thing.

## 9. Relays, caching and poisoning

Any node can cache, but a relay that caches unvalidated data is a poisoning
vector, and validating everything at a relay is not practical. NDN's answer is
digest-based exclusion (next time you ask, name the bad digest you don't want),
which he sets aside. His proposal for now: relays are full nodes, they cache
only responses to requests they issued themselves and only those they processed
successfully, and they pass everything else through. In Q&A he adds that
verification is local because who you trust is your own business, and delegated
verification (your star validating for you) is only sensible over a trusted
channel.

## 10. Practical network items

- Request-response fits the real internet. Stateful firewalls and NATs already
  jerry-rig request-response semantics onto a packet network, with bindings that
  live around 30 seconds. Modelling the overlay as request-response means not
  fighting that. IPv6 is not coming, and would still have stateful firewalls.
- Ping math: at 5 ms per event and one ping per ship per 25 seconds, a galaxy
  that does nothing but process pings tops out around 5,000 ships, so the
  network tops out around 1.2 million. Tlon hit this as a real scaling limit;
  the ping app grew a `no-nat` bypass, which drops you off the network if you
  are wrong about your reachability.
- The fix is to separate the two jobs pinging was doing. Discoverability stays
  with a formal ping; route maintenance moves to actual STUN, not STUN by
  analogy, with the responder masking the address out (NATs will rewrite it in
  the body otherwise). Save the response, compare each time, and if it changes,
  send one formal ping. Falls back to formal pings if STUN goes quiet. Also puts
  us one step from WebRTC.
- mDNS for the local network, to fix moons next to planets that cannot reach
  each other because the NAT does not hairpin. He asks for volunteers.
- Real NAT traversal: a side channel, each side enumerates its own inbound
  candidates, exchange the sets, try them all, keep the best.

## 11. Relevance to libmesa

- **ch. 2 §4.3, poke.** Section 5 above is the derivation. The requirement that
  `her.ack` be the receiver and `her.pok` the sender, that the data be exactly
  the binding at `pok`, and that the remainder is pulled by ordinary peeks, are
  all the original design. The single-fragment signature elision is here too,
  though the spec's version is stated in terms of spaces rather than as an
  optimisation.
- **ch. 2 §3, byte-equality matching.** Explicitly chosen against prefix
  matching, in this talk. Worth citing in the rationale, since it is the thing
  that makes relay matching well-defined and makes deterministic path sealing
  load-bearing.
- **ch. 2 §6, LSS.** The argument for why packets are not signed is here, with
  numbers. The traversal is not.
- **ch. 3, namespace.** The region map is the three-layer projection, made
  concrete. The kernel-guarantees-referential-transparency point is the
  motivation for ch. 3 §3 and §4.
- **ch. 4, flows.** Acks as bindings rather than a packet type, exactly-once
  delivery, and the transactional invariants Ames had and Mesa must keep, all
  trace here. The open questions in ch. 4 §6 (are corks necessary or an
  optimisation) and §8 (policy derivation without negotiation) are downstream of
  his "subscription reform" and "notifications" gaps, which he lists as
  out of scope: frontier discovery, long-lived requests, and change
  notification for a channel that is quiet for months.
- **ch. 6, routing.** PIT and stateless forwarding, relay caching restricted to
  self-validated responses, STUN for route maintenance (ch. 6 §4), mDNS as the
  `%dear`-class LAN discovery (ch. 6 §4), candidate-set exchange as real NAT
  traversal. Note that his relay model assumes galaxies and stars; ch. 6's
  rank-free fief model replaces that, and the spec should say so rather than
  inherit sponsor semantics silently.
- **ch. 7, transports.** "If you have a better way to talk, bypass the packet
  layer" is the N-1 argument, and the projection framing is why bridging
  transports statelessly is coherent rather than an agglomeration.
- **1024-byte leaves and the 1500-byte MTU** are asserted here as facts of the
  world, matching ch. 1 §6's bloq 13 default and ch. 7 §3.
