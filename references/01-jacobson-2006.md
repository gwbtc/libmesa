# Reference 1: Van Jacobson, "A New Way to Look at Networking"

Google Tech Talk, 30 August 2006. Roughly 75 minutes including Q&A.
Source: transcript of the recorded lecture.

> **Why this is in the references folder.** This is the talk Curtis cited in the
> 2010 Urbit introduction, and the direct ancestor of CCN, then NDN, then Fine,
> then Mesa. Most of what the spec treats as given (a name is a request, a
> response is authenticated by itself and not by the channel, data has no
> canonical location) is argued for here and nowhere else in the lineage. What
> the talk does *not* contain is as useful as what it does: the identity,
> key-currency and resource-bound machinery in spec ch. 2, 5 and 6 exists
> because Jacobson left those problems open.

## 1. The historical argument

Jacobson frames networking as three generations, each one taking something
implicit in the layer below and making it explicit in the data.

**Generation 1, wires (circuit switching).** The phone system was never about
calls. Calls were a side effect. The system was about getting wires everywhere,
because in 1870 there were none and the capital cost was enormous and entirely
sunk before any revenue. A phone number is not a name, it is a program for the
switch: the original four-digit numbers were 2D coordinates on a 100x100
switchboard, and a Strowger switch cascades two 10x10 matrices to consume them.
Structural consequences: path building needs global knowledge and central
scheduling, so the operator trends to monopoly; reliability is the product of
per-link failure probabilities, so it degrades exponentially with scale, which
is why Bell Labs became the world's authority on making individual components
that never fail; and setup cost has to be amortised. His number: 100 ms
transcontinental setup at 1 Gbit/s wastes 12 MB, so you would need 12 MB web
pages to run the network at 50% efficiency. ISDN's 64 kbit ceiling was partly a
way to make setup cost irrelevant by making everything else slow.

**Generation 2, endpoints (packet switching).** Baran (RAND, published 1964 in
IEEE Transactions on Communications) and Davies independently proposed taking
the wires as given, chopping data into bounded pieces, and putting the endpoint
addresses into the packet so that any node receiving one that isn't for it can
try to pass it on. Transitivity does the rest: a random graph with a bit more
than one edge per node is connected, so you don't engineer the topology, you
just hook things up. Bell Labs said publicly that this could not work. Licklider
at ARPA liked the paper anyway and tasked BBN; the ARPANET ran in September 1971
over 56 kbit acoustic couplers, on the phone company's own wires. To telco eyes
it was a wasteful overlay on a real network. Being an overlay was the point: it
made the design agnostic to the delivery technology. Cerf saw that since
topology was now irrelevant, a common encapsulation and address structure lets
you concatenate networks (specs 1974, the SRI van demo over packet radio,
ARPANET and satellite in 1977). "Catenet" had too many letters, so it became
TCP/IP. The three known telco problems all invert: reliability improves with
scale because more paths means more ways around a failure, there is no setup so
the system is bandwidth-agnostic, and no hierarchy is needed because nothing is
being scheduled. The freebie was self-configuration: adaptive routing means a
new node is usable from the moment it has an address, with nobody in a manhole.

**Generation 3, data (dissemination).** Same move again. Time, sequence and
integrity are implicit in a conversation; make them explicit in the data.

## 2. The success disaster

TCP/IP is not broken. The problem changed. Jacobson's list of symptoms:

- Connectivity is binary. You are on the internet or you are not, and if you're
  not, you're stuck, so you write ad hoc sync protocols to pre-stage data.
- Connecting is heavyweight, because you need a globally known address that is
  topologically stable on a minutes-to-hours timescale, otherwise traffic loops
  or black-holes. Everything follows from that: the network hates mobility, and
  putting a network on a train or in a car means papering over movement at
  layer 2.
- Broadcast is the best physical medium we have and the transport protocols
  can't use it. 10,000 radios hear a frame, 9,999 discard it, and each of them
  has to ask individually for something they all wanted.
- He saw a router downstream of NBC's Olympic servers carrying 6,000 copies of
  the same content (Bode Miller hitting a gate). Dynamic content, so no proxy
  cache helps; the router sees 6,000 TCP conversations and can do nothing.
- By his measurement, well over 90% of traffic is someone handing over a name
  and expecting a chunk of data back. That is not a conversation. A conversation
  is the degenerate case of dissemination where the multipoints collapse to one.
- You cannot build a security model on a conversational network. You can armour
  the pipe, but an SSL connection to your mail server does not stop spam. The
  network is deliberately blind to content, which is exactly what makes it
  unable to help.

## 3. The dissemination model

Data has a name, not a location. You present the name to the network and hope
something answers; anything holding the data may answer. The request leaves
state along its path and the response follows that state back. Nothing needs to
know where the data lives, because it doesn't live anywhere.

Two bindings need authenticating, not one. His worked example is asking for
today's New York Times: a generic name binds to a specific name (the 2006-08-30
edition), and the specific name binds to the bytes. The bytes self-identify by
hash, but the hash has to be tied to the name by a signature, and the generic to
specific step needs its own signature so Murdoch cannot substitute his edition
for theirs. He is explicit that this is not content addressing and not caching:
content addressing has no locality, no ownership and terrible ergonomics, and
"caching" presupposes one true location, which he denies exists.

What falls out, in his account:

- **QoS becomes the requester's.** Congestion happens on the way down to you,
  where you have no control in a push model. Under request-response the order of
  your requests is the order of your priorities, and it is entirely local.
- **Multicast for free** for anything popular, without global multicast. Local
  scope is enough: misses go unicast, hits go multicast.
- **Bits are bits.** Wire, memory, disk, USB stick, a plane with a drive in it.
  If it moves bits in space or time it is part of the network. This is the
  argument for transport independence, made as a moral point.
- **Immutability and supersession.** Once data is out you have lost control of
  it, so you never mutate, you publish a new version that references the old.
  Version and sequence information goes explicitly into the name. He points at
  ATM as the failure mode: identifiers with only local meaning, rewritten every
  hop, buying nothing.
- **Segmentation.** Never send large things. Small named pieces travel over
  multiple paths, let a user interleave a VoIP packet with a large download, and
  are individually verifiable. RTP is his own prior art: every packet carries a
  timestamp and sequence number so anyone can reconstruct the stream from any
  source.

## 4. What he left open

Explicitly flagged as unsolved, in his own words as hard problems:

- The incentive structure, which he treats as the analogue of congestion
  control. Freeloaders, miscreants and injected garbage should be architected
  out at the network level, and he has no design for it.
- Redistribution policy. What should a node carry on behalf of others, and how
  much, and for how long.
- Revocation and liability. Once bad content is distributed you want lazy
  invalidation back up the distribution path, and he gestures at gossip,
  reputation and epidemic algorithms.
- Trust structure. He rejects certificate hierarchies outright (VeriSign selling
  a root cert to an unknown party is his example) on the grounds that you cannot
  place ultimate trust in an economic structure staffed at minimum wage. His
  alternatives are PGP-style web of trust plus repository-issued attestations
  ("instant PKI"): the repository attests that this is the thing that was
  deposited under this name at this time, not that it is any good.
- Finding things at all. His answer is Google, which is to say he has none.
- In Q&A: BitTorrent fails because the only eligible sources are other people
  currently downloading, so it works for large content only, and the protocol is
  topology-unaware with no way to distribute trackers. IP multicast he likes but
  considers unnecessary to globalise.

## 5. Relevance to libmesa

Where the spec inherits directly:

- **ch. 2 §3, the interest model.** Jacobson's request-leaves-breadcrumbs,
  response-follows-them-back is exactly the PIT. What the spec adds is
  byte-equality of the serialised name as the normative matching rule. Jacobson
  had loose two-level matching (generic to specific), which is precisely what
  makes relay-side matching ambiguous. Our stricter rule is why ch. 6 §3 can say
  relays match the same way endpoints do.
- **ch. 2 §4.1, unauthenticated `%peek`.** This is Jacobson's model unmodified,
  and it inherits his unaddressed DoS and amplification surface. He never
  discusses request-side abuse. Everything in ch. 2 §8 is ours.
- **ch. 2 §5, spaces.** Jacobson only ever has `%publ`. Confidentiality is
  outside his model entirely, and the tension the spec records (deterministic
  sealing so interests still match, versus fingerprinting, doc 04-crypto gap 7
  and FS2 epoch salting) is the price of keeping his matching rule while adding
  encryption. Worth stating that way in the normative text.
- **ch. 2 §6, LSS.** He argues for segmentation with per-piece verification and
  supplies no mechanism. LSS is the mechanism. His framing (make the implicit
  explicit, at bounded size) is a good one-paragraph motivation for the chapter.
- **ch. 3, namespace.** Immutability, referential transparency and supersession
  are his. So is the hole: `%pine`-class latest-value queries are his generic
  name layer, deferred to a later kelvin, and he had no answer either.
- **ch. 5, identity.** He rejects CA hierarchies and lands on web of trust plus
  repository attestation. `%gw-btc` is a third answer he did not consider: a
  chain-anchored custody log with positive unspent proof. Key currency, in his
  vocabulary, is the thing the repository model cannot express. Useful contrast
  for the chapter's rationale section.
- **ch. 6, routing.** He has no node model, hence content-based routing and the
  prefix-based FIB that NDN inherited. Our collapse of that (points and lanes,
  never `@p` width) only works because we have identity first. The relay
  poisoning problem in ch. 6 is his unsolved miscreant problem, scoped down.
- **ch. 7, transports.** "Bits are bits" is the argument for N-1 independence,
  and it is a better one than protocol-layering abstraction, because it licences
  the exotic sketches in ch. 7 §6 rather than treating them as curiosities.

Where he is silent and the spec must not be: no verdict contract, no notion of
key currency or of an attestation that verifies forever but proves nothing about
the present, no rate limits, no bounded-parsing discipline, no admission
control. Any claim in the spec that leans on "this is how NDN does it" should be
checked against this talk first, because a lot of what is attributed to NDN is
later accretion.
