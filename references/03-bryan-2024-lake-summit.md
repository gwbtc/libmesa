# Reference 3: Joe Bryan ~master-morzod, "Directed Messaging"

Lake Summit 2024. Roughly 45 minutes, with two live demos.
Source: transcript of the recorded talk.

> **Why this is in the references folder.** This is the implementation talk,
> given about a year after Reassembly with almost everything built except
> routing. It recapitulates the Jacobson history and the poke derivation, both
> covered in `01-jacobson-2006.md` and `02-bryan-2023-reassembly.md` and not
> repeated here. What is new and load-bearing for the spec is in §4 and §5
> below: the crypto replacement, the stateless-publisher architecture, the
> Arvo/runtime trust boundary, and the scale-invariant Merkle traversal that
> makes `boq` a free per-flow parameter. Cross-check anything technical against
> the USTJ paper (Directed Messaging, `urbitsystems.tech/ustj/v03-i01/mss0.html`),
> which is more precise and uses different names for the traversal.

## 1. The demo

At the top of the talk, a 134 MB file is read from Clay over old Ames. It
finishes 26 minutes 36 seconds later, near the end. The same read after
migrating that peer to the new protocol takes 2.8 seconds. The USTJ paper puts
the overall improvement at over 100x, reaching above 1 Gibit/s on commodity
hardware against a previous ceiling in the hundreds of KB/s.

## 2. What was wrong, and the single design principle

Ames failures he lists: routes are flaky and peer discovery is unprincipled in
both directions (how you find peers and how you forget them), so topology moves
for no reason; performance collapses under load, to the point that people run
dedicated moons to distribute apps and host channels; legibility is nil, since
the packet metadata is only enough to bootstrap the authenticated encryption;
and debugging is misery.

He is emphatic that these were not the design criteria. There was no feature
list. The entire design principle was: push everything through the namespace.
He describes the payoff as repeatedly unexpected, and elsewhere in the talk
calls the commitment irrational, which is roughly the tone.

## 3. What was built

- Three packet types (`%peek`, `%poke`, `%page`), codecs in both Hoon and C. He
  singles out a framework that defers serialisation as long as possible, building
  a tree in a small DSL that describes the serialisation to perform, then doing
  it all at once in a jet where the allocation can be amortised.
- New symmetric crypto. Azimuth keys and ed25519 signatures are unchanged. The
  old construction dates to 2016 or 2017, was deterministic AEAD with no nonces
  and elegant, but required two full passes over the data (hash to derive the
  nonce, then encrypt). ~watter-parter did most of the replacement work,
  combining XChaCha and Blake3 into a construction he describes as roughly twice
  as fast, chosen specifically to remove a scalability ceiling rather than to win
  a benchmark.
- Blake3 was picked for speed but more importantly because it is already a
  Merkle tree, so the constructions nest: you sign a hash, and that hash is
  itself a tree root, so you can zoom in and out of the structure and chain the
  provenance of authentication down to a fragment. He believes the application
  of this to networking is novel.
- Stateless publishers, implemented as a hierarchy of recursive overlay
  namespaces. Small pure functions composed naturally, made efficient by
  persistently memoising intermediate results. This kills the packet queues that
  plagued Ames: you store the data you actually care about, and everything else
  is a projection you keep around informally without committing to it under Arvo
  semantics.
- Stateful clients, as a layer of state machines. He argues this is correct
  rather than merely convenient: demand in a P2P network is Pareto-distributed
  and lands in unpredictable places, so the work of retrieving data has to sit
  with clients or you rebuild the incentive structure that produced the current
  internet. He concedes the client side is not as clean as the publisher side,
  because state-machine entry points form a cartesian product rather than
  composing linearly.
- A reimplementation of one of those client state machines in the Vere driver:
  it receives response packets, requests subsequent fragments, runs its own
  congestion control, validates packets incrementally against the Merkle tree,
  assembles the message and delivers it. Packets do not churn Arvo's event loop.
  This is where the speedups live.
- A new vein, publisher namespaces, client state machines, route storage, and
  live per-peer migration between old and new Ames, made bidirectional (a first
  for the project). Credited to Jose.

## 4. The protocol jet argument

He has wanted this for years and states it carefully. You cannot jet a protocol:
you either speak it or you do not, and the semantics live on one side of the
formal boundary or the other. Nock jets work because the jet is formally absent,
the acceleration must produce the same result, and mechanism is separated from
policy at arbitrary granularity.

The nearest analogue for I/O: Arvo must control policy and should implement the
default mechanism. It is legitimate not to, and Urbit's HTTP client does not:
the vein is a scheduler that says "make this request" and Urbit never implements
HTTP semantics at all. That is fine for HTTP. It would not be acceptable for the
network.

The concrete boundary: he does not want the keys in the driver, which is C code
next to a socket on the public internet. Keys stay in Arvo, the trust base stays
in Arvo, and informal external code takes load without taking semantics. The
Merkle construction is what lets the runtime do more work than it ever has while
that boundary holds. The USTJ paper adds detail: Vere is two processes, the
Arvo process holds the private key and the I/O process cannot encrypt, decrypt
or verify, and Arvo re-validates packets itself as defence in depth, which stays
cheap because each validated unit can be a jumbo frame.

## 5. Lockstep streaming and scale invariance

The technical core of the talk, and the newest material.

**Starting point.** Bao serialises a Merkle tree depth-first with hashes
preceding the data they validate, which gives verified streaming over a byte
stream. Mesa is datagram-oriented and wants explicitly sized units, not
arbitrary chunk boundaries, so the traversal is run over packets instead: each
data packet carries a pair of hashes, and the pair does not authenticate that
packet, it authenticates data that arrives later. There is a deliberate layer of
indirection there.

**The problem.** That first version worked and shipped, but it was scale
variant. Roll four 1 KiB packets up into one 4 KiB packet and the traversal
shifts around; the data dependencies needed to perform the transformation
amount to most of the tree. He looked for a shortcut and never found one.

**Why it matters.** The public-internet MTU is a fiction with a de facto answer:
the standards floor is around 576 bytes, everything actually runs over Ethernet
at 1500, minus IP and UDP headers leaves 1472. Path MTU discovery is a bad fit
for this protocol, because if data has a name and not a location, there is no
path to probe. NDN's answer is hop-by-hop fragmentation and reassembly, which he
rejects: loss between two relays that had reassembled a large message destroys
all incremental progress and the loss propagates back to the original requester,
who reissues the same request. He asks openly, and it remains open, whether any
hop-by-hop fragmenting protocol does retransmission and guaranteed delivery at
intermediate nodes.

So the packet format and messages were made effectively arbitrarily sized even
though the wire stays at the standard MTU for now. Loopback wants 64 KiB, a LAN
wants whatever the LAN is, and you cannot claim to be building a long-term
foundation while baking sizes in. But if sizes cannot be switched mid-path you
get an end-to-end agreement problem over a path that is only known very late
(and computing it in advance is intractable), and your caches fragment across
sizes.

**The fix.** Credited to Ted, and he says he still does not know how it was
found. He calls the pattern "adjacent cousins" in the talk and says he cannot
describe the traversal by natural recursion. It works like this:

- The initial proof is the Merkle proof for leaf 0 plus one extra element: the
  rightmost nodes on the spine and both leftmost pairs. That gives you the root,
  so you can start verifying the signature or MAC immediately. Notably you do
  not send the root itself.
- The proof is an authentication packet carrying no data. It always fits one
  MTU, because fragment numbers are 32 bits, so there are at most 32 hashes.
- Each subsequent data packet carries a pair. To find it: take the subtree that
  this packet completes, take that node, skip one sibling, take the two adjacent
  siblings. Equivalently (USTJ) the pair's height above the leaves is the number
  of trailing zeros in the packet number.

**What it buys.** The shape of the traversal is identical at every scale. Chop
the bottom layer off the tree and the sequence of interactions is unchanged.
Isolate an aligned subtree and it is unchanged. To turn four packets into one
jumbo frame you concatenate their payloads and need no data from outside those
four packets, because of the alignment on power-of-two subtrees. To split one
into four you need a pair of siblings to descend, and you have it. Consequences
he lists:

- Cache at a size optimised for the storage medium and deliver at a size
  optimised for the workload. The vein serialises one packet, not four thousand.
- Hop-by-hop refragmentation becomes mechanically possible (whether to do it is
  the open question above), and so does path MTU discovery.
- Mesa over HTTP or WebRTC becomes tractable.
- The client keeps a bounded memory footprint rather than imposing an end-to-end
  constraint that everything touching the message can handle its maximum size.
  He raises the terabyte-message reductio: allocate it, push it over IPC, write
  it to the event log.

**Naming.** The talk says "Blackman traversal". The USTJ paper distinguishes
Blackman ordering (~rovnys-ricfer) from Lackman ordering (~watter-parter's
offset-by-one variant, which simplifies the bit manipulation) and calls the
overall scheme Lockstep Streaming, over binary numeral trees per ~watter-parter's
2021 ePrint paper. **Use Lackman and Lockstep in spec text.** At the time of the
talk the traversal was implemented but not yet integrated into the path the demo
exercised.

## 6. Why NDN did not win, 2024 version

Sharper than the 2023 version and worth keeping:

- The compatibility story is backwards. NDN says you can run TCP or UDP over it
  and underlay the existing protocols. Anyone happy with what exists has no
  reason to accept engineering and operational risk where the best case is that
  things keep working.
- Security protocols are conversation-oriented and secure multi-party flows
  either devolve to n-squared conversations or do not exist. If you must
  republish per recipient, you never get a cache hit, and most of the advantage
  evaporates. He does not think this is intractable, only unworked.
- A referentially transparent namespace is genuinely hard to use, and the onus
  being on the client is conceptually inherent, not an artifact of layering.
  You have to know what you are asking for.

That last point is the one that bit Urbit. Fine shipped, was initially buggy
enough to burn early users, and once that was fixed the universal complaint was
frontier discovery: how do I know what the latest version is, how do I orient
myself. `%pine` (scry-at-latest) is the planned concession, and he is explicit
that it is not and cannot be referentially transparent, so caching it introduces
invalidation and cache control. He judges the network small enough and the model
intuitive enough that standing on ceremony is not worth it. Absent that
primitive, what people actually did was have a conversation to orient
themselves, then route around and fetch the data, which he compares to a 1990s
download manager and calls uninteresting.

His cost verdict on Fine: it takes load off publishers for content requested
multiple times. For everything else it is more expensive than old Ames.

## 7. Relevance to libmesa

- **ch. 1 §6 and ch. 2 §6, `boq` and re-delimiting.** Scale invariance is what
  makes "a server SHOULD serve any bloq it can re-delimit for" a cheap
  requirement rather than an expensive one, and it is the actual justification
  for ch. 7 §2's claim that bloq is a per-flow policy with no negotiation step.
  The spec asserts this; this talk explains why it is true, and the explanation
  (alignment on power-of-two subtrees means a re-delimiting relay needs nothing
  outside the packets it is merging) should be in the normative text or a note,
  because an implementer who does not know it will assume negotiation is needed.
- **ch. 2 §6, incremental verification.** "O(1) pending hashes" and "verify each
  leaf against the root chain as it arrives" is Lockstep. The 2023 buffering
  requirement is gone; do not carry it into the spec.
- **ch. 6 §3, stateless forwarding.** A relay that re-delimits across an MTU
  boundary is only stateless because of this property. Worth an explicit
  sentence, since it is the non-obvious part of the forwarding requirements.
- **ch. 7, transports.** Jumbo frames on loopback and LAN, TCP with bloq free to
  grow, the exotic sketches in §6, all rest on the same property. The open
  question about hop-by-hop fragmentation and intermediate retransmission
  belongs in ch. 6 or ch. 7 as a recorded open item rather than being silently
  resolved either way.
- **ch. 2 §5, spaces.** The XChaCha8 and Blake3-KDF work described here is the
  source of the space table. Check the spec against USTJ §4.1 for details the
  skeleton compresses: the sealed path is the AEAD tag concatenated with the
  encrypted path and used as the IV for the message, the path serves as a
  synthetic IV so encryption is deterministic and replay is prevented by
  construction, and the trailer byte is `0x1` appended before transmission so
  that trailing zero bytes survive atom representation. The spec's "16-byte
  keyed-BLAKE3 tag ‖ XChaCha8 ciphertext ‖ terminator" is right but the reason
  for the terminator is not obvious from the text.
- **ch. 3, namespace.** Overlay namespaces are the mechanism, and Directed
  Messaging was the first kernel module to lean on them. Privacy is separated
  from everything else by construction because an overlay handler is a pure
  function of its inputs. Packet publication is itself an overlay parameterised
  by bloq and fragment number. That is worth saying in ch. 3 §1 or §4, since it
  is why the region map is a design rather than a filing convention.
- **ch. 0, conformance classes.** The Reader / Peer / Relay / Verifier split
  maps onto the architecture here: stateless publisher, stateful client, and a
  relay that needs only routing-visible prefix material. The Arvo/runtime
  boundary is a second axis (who may hold keys) and the spec should not conflate
  them.
- **ch. 2 §2, validation pipeline.** The trust boundary argument is the reason
  the pipeline is ordered the way it is: cheap shape checks belong wherever the
  packet lands, crypto belongs where the keys are, and defence in depth means
  the inner layer revalidates.
- **Where the talk assumes what Groundwire replaces.** Azimuth-derived keys,
  galaxy and star sponsors as the relay population, and rank-shaped routing are
  all assumed here. ch. 5 (suite-%c, PKI domains, key currency) and ch. 6
  (rank-free, fief-holders as relays) replace them. Anything in the spec that
  reads as inherited from Directed Messaging should be checked for a sponsor
  assumption smuggled in with it.
