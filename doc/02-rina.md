# A RINA-shaped libmesa

**Status:** discussion draft for the working group. Nothing here is settled except
where it records decisions already taken (see README).

This report answers three questions:

1. What does RINA actually claim, and how does Mesa already relate to it?
2. What would a RINA-shaped libmesa concretely look like, and why do it?
3. How do the open flow-engine and transport decisions change when viewed
   through this lens?

The motivating observation: today the protocol is implemented at **two levels
that don't know they're the same thing** — the Arvo vane (`|mesa` in
`ames.hoon`: flows, acks-as-scries, crypto, namespace) and the Vere driver
(`mesa.c`/`pact.c`: packet codec, retransmission, congestion windows, LSS
verification, forwarding, caching) — sitting on a *third* level (UDP/IP) that
the first two treat as ambient. A standalone implementation has to collapse
these into one artifact. Doing that naively produces a monolith that hardcodes
UDP-shaped assumptions; doing it RINA-shaped produces one engine whose levels
are explicit, uniform, and swappable.

---

## 1. RINA in one page

RINA (Recursive InterNetwork Architecture, John Day, *Patterns in Network
Architecture*, 2008) makes a small number of sharp claims:

- **Networking is IPC, and there is only one layer, repeated.** A layer is a
  *Distributed IPC Facility* (DIF): a set of cooperating IPC processes (IPCPs)
  providing communication over some scope. Layers don't differ in *function*
  (physical/link/network/transport is a category error); they differ only in
  **scope and policy**. A DIF rides on lower DIFs (its "N-1 DIFs") and can
  carry higher ones, recursively.

- **Mechanism and policy are separated.** Every DIF runs the same mechanisms —
  delimiting/fragmentation, sequencing, retransmission control, flow control,
  SDU protection (encryption), routing, enrollment — but each is parametrized
  by policy chosen per-DIF and per-flow. There is one data-transfer protocol
  (EFCP), not a zoo (TCP/UDP/RTP/QUIC/...).

- **Reliable transport needs no handshake.** EFCP is built on Richard Watson's
  **delta-t** result (1981): reliable, exactly-once transfer requires only that
  three timers be bounded (max packet lifetime; max time before ack; max time
  spent retransmitting). Connection state is *soft* — it exists while timers
  run and evaporates afterward. No SYN, no FIN, no SYN-flood class of attack.

- **Names, not addresses-and-ports.** Following Saltzer: *application names*
  are location-independent; *node addresses* are location-dependent but
  route-independent; *points of attachment* are route-dependent; routes are
  computed late. TCP/IP collapses these (an IP address names an interface, a
  port pretends to name an application), which is where NAT, multihoming, and
  mobility pain come from. In RINA you allocate a flow **to a name** with QoS
  requirements, and each layer late-binds names to lower-layer attachments.

- **Management is uniform.** Each IPCP exposes its state as objects in a RIB
  (Resource Information Base) manipulated by one protocol (CDAP: create /
  delete / read / write / start / stop). Joining a DIF is **enrollment** — an
  authenticated admission procedure — so "being on the network" is itself a
  security boundary: an IPCP that can't enroll can't send you anything.

## 2. Mesa is already half a RINA — and half an NDN

Urbit's own stated lineage for directed messaging is Van Jacobson's **Named
Data Networking**, not RINA: requests are routed toward data by name (scry
path), responses retrace the request path via Pending Interest Tables — and
the Vere driver literally calls its structure the PIT. The USTJ *Ad Fontes*
essay sharpens this into the "solid-state" doctrine: all communication is
signed `[path noun]` bindings ("oaths"); acks are oaths; routing is decided on
registration of interest; Arvo should not do routing at all.

These lineages are not in conflict, because they answer different questions:

- **NDN answers the data-plane question** — how do responses find requesters
  without connections? (By name, through interest tables.)
- **RINA answers the architecture question** — how do levels of the system
  compose, and what is one implementation made of? (One IPC engine, recursed,
  policy-parametrized.)

The striking thing once you look is how much of Mesa is *already* implicitly
delta-t / RINA-shaped:

| RINA concept | Mesa today | Notes |
|---|---|---|
| No connection handshake; soft state | No SYN/FIN. First contact is an attestation *datum*, not a handshake. Runtime PIT entries expire (20 s); dead-flow and route-liveness timers everywhere | Mesa is closer to delta-t than TCP is |
| Acks as data, not control packets | Acks/nacks/naxplanations are namespace pages the sender peeks | The "oath" doctrine, verbatim |
| Exactly-once via persistent endpoints | Urbit's founding claim: two uniformly persistent nodes maintain a permanent session | Stronger than delta-t's premise — both ends have event logs |
| Application name vs node address vs PoA (Saltzer) | scry `path` = application name; `@p` = node address (location-independent!); `lane` (`%if`/`%is`) = point of attachment; sponsor chain = route hint | Urbit already late-binds `@p`→lane. This is RINA-correct in a way TCP/IP never was |
| Enrollment as security boundary | Attestation + PKI-domain verdict (`%writ`/`%sybl`); `%snub` on `%fail` | "Can't enroll ⇒ can't talk" is exactly Jael's verdict gate |
| SDU protection as per-layer policy | Spaces: `%publ` / `%chum` / `%shut` select signing/encryption regime per binding | Policy-selected protection, already |
| RIB + uniform management protocol | **The scry namespace is a RIB.** `%peek` ≈ CDAP read; `%poke` ≈ CDAP write; flow state, peer state, and diagnostics are already served as scries (`/flow/...`, `/chums/...`) | Mesa's namespace unifies data and management planes more aggressively than CDAP does |
| Receiver-driven flow control | Pull model: receiver peeks fragments at its own rate; "the receiver of the command performs congestion control" | Per-DIF congestion is also RINA's position |
| IPCP task split: data transfer / transfer control / layer management | **The Arvo/Vere split.** Vere: data transfer + transfer control (codec, resend, cwnd, LSS verify, forwarding). Arvo: layer management (enrollment/attestation, flow allocation, RIB, routing policy) | See below — this is the key structural insight |

**The key structural insight:** the Arvo/Vere division of labor is an
*accidental approximation of RINA's internal IPCP decomposition*. RINA says an
IPCP does three kinds of work at three frequencies: data transfer (per-packet,
fast), data-transfer control (per-loss-event), and layer management
(per-flow/per-peer, slow). Vere took the first two; Arvo took the third; the
vane/driver protocol (`%heer`/`%push`, the `%veri` scry) is the internal
interface between them, ossified into an event-system boundary.

So "transitioning from the split Arvo+Vere implementation to a single-level
self-contained implementation in a RINA-shaped way" has a precise meaning:
**don't erase the boundary — reify it.** libmesa should be one process
containing the same three-task decomposition as explicit module boundaries
with policies at the joints, instead of two codebases with an event loop
between them. What was a process boundary becomes a trait boundary.

## 3. The two-level packetization problem, resolved as policy

The question as posed: Mesa has flow → message → 1024-byte fragments, and then
the transport has its own packetization (1472-byte UDP pacts today; TCP
segments or WSS frames tomorrow). Two levels of packetization, coordinated by
constants.

RINA's answer: fragment size is not a protocol constant, it's the **delimiting
policy of the mesa DIF, chosen against the N-1 DIF's maximum SDU size and
reliability class**. Concretely:

- Over **UDP** (unreliable datagram, ~1472 B max SDU): delimit at bloq 13
  (1024 B leaves), run retransmission control and congestion control in the
  mesa DIF (the cwnd/rtt machinery now in `mesa.c`), verify LSS per leaf.
- Over **TCP/WSS** (reliable ordered stream): the N-1 DIF already provides
  loss recovery and ordering. The mesa DIF should *disable its retransmission
  and congestion policies* (double congestion control is actively harmful —
  the classic TCP-over-TCP meltdown), keep sequencing/windowing (those are
  flow semantics, not transport semantics), and may choose a much larger
  delimiting bloq ("jumbo" leaves — the C driver already has the concept).
  LSS stays: end-to-end integrity must not depend on the pipe.
- Over **exotic N-1s** (Lightning onion messages, Nostr relays as a broadcast
  medium, Lick to a local process): each declares its properties (max SDU,
  reliable?, ordered?, duplex?, addressed how?) and the same engine
  instantiates appropriate policies.

Crucially, **the pact wire format already supports this**: the name encoding
carries `boq` explicitly, and fragment/total sizes are variable-width. The
format doesn't have to change; what changes is that the spec stops saying
"fragments are 1024 bytes" and starts saying "delimiting is a per-flow policy;
bloq 13 is mandatory-to-implement and is the default over datagram N-1s."

This gives the transport-agnosticism story real teeth: a transport is not an
"adapter" that emulates UDP, it's an N-1 DIF with declared properties, and
policy selection is a total function of those properties.

## 4. What a RINA-shaped libmesa looks like

One engine, three task groups, policies at the joints:

```
┌─────────────────────────────────────────────────────────────┐
│                     libmesa "IPCP" engine                   │
│                                                             │
│  Layer management (slow path)                               │
│    enrollment  = attestation + PkiDomain verdicts (Jael-    │
│                  contract: writ/sybl/anew)                  │
│    RIB         = the namespace: path → authenticated page   │
│    flow alloc  = bone/side allocation, policy selection     │
│    routing     = SponsorResolver (fief-based), lane cache   │
│                                                             │
│  Data transfer control (loss path)        [policy-gated]    │
│    retransmission ctl  (off over reliable N-1)              │
│    congestion ctl      (off over reliable N-1)              │
│    PIT / interest state, timers (delta-t bounds)            │
│                                                             │
│  Data transfer (fast path)                                  │
│    pact codec (fixed wire format)                           │
│    delimiting policy (bloq per N-1 class)                   │
│    LSS integrity (always)                                   │
│    SDU protection (spaces; E2E-by-default — see 04-crypto)  │
└──────────────┬──────────────────────────────────────────────┘
               │  N-1 DIF trait: { max_sdu, reliable, ordered,
               │                   lane repr, send, recv }
     ┌─────────┼──────────┬───────────────┬──────────────┐
   UDP        TCP        WSS         LN onion msgs     Lick
```

Beyond the module shape, RINA buys four concrete things:

**a) Recursion is available when we want it.** A `%shut` group can be modeled
as a *DIF riding on the public mesa DIF*: its enrollment policy is "holds the
group key," its SDU protection is the group cipher, and its scope is the
group. A Lightning deployment can run mesa as a DIF whose N-1 is LN onion
messaging. A future "planetary mesh" can stack mesa-over-mesa for
administrative scoping. None of this needs new protocol machinery if the
engine is written once with scope/policy as parameters.

**b) Relays stop being special.** Galaxies today are transport infrastructure
baked into identity rank. In DIF terms a relay is just an **interior IPCP of
the mesa DIF** — any enrolled peer with a public point of attachment (a
`$fief`, per the comet-attestation UIP) that runs the forwarding policy (PIT +
hop rewriting, as `mesa.c` does now). This is the RINA formulation of the
UIP's "sponsor chains MUST NOT assume galaxy termination," and it's the right
frame for the ChatControl story: a phone enrolls in the DIF over WSS through
any relay; the relay is a policy role, not a privileged name.

**c) Delta-t gives the spec its correctness story.** Mesa's soft state is
currently a pile of independently chosen timers (PIT 20 s, retry ~2 min,
dead-flow consolidation, recork, route liveness 30 s). Delta-t says: identify
the three bounds (packet max-lifetime; ack-wait; retransmit-give-up) and
derive everything else, and you get provable exactly-once delivery with
bounded state. The spec should do this audit and *specify* the timer algebra
rather than inherit the constants. Bonus: Urbit's persistent endpoints mean
the delta-t preconditions hold more strongly than Watson assumed — and this
frames a real design question: **are corks necessary, or is flow state
reclaimable purely by timer** (delta-t-style) with corks as an optimization?

**d) One spec, small.** Mechanism/policy separation is what keeps the spec
from being "the union of everything ames.hoon and mesa.c do." Mechanisms
(pact codec, LSS, state vector, namespace, enrollment) get normative
chapters; policies get a registry with mandatory-to-implement defaults.

## 5. What RINA does *not* license

To keep this from becoming architecture astronautics, explicit non-goals:

- **No wire-format redesign.** The pact format (header cookie, name/data
  encodings, auth variants) is fixed by the existing kernel + runtime; libmesa
  v1 is wire-compatible with ships on this branch. RINA is an *implementation
  and specification* architecture here. Where the wire format resists policy
  parametrization (2-bit rank field; fixed auth kinds; 3-bit hop count), we
  document the tension and move on.
- **No CDAP, no literal RIB objects, no IRATI compatibility.** The namespace
  already is our RIB and peek/poke already is our management protocol. We
  adopt RINA *vocabulary* in the spec where it clarifies (enrollment, N-1 DIF,
  delimiting policy, SDU protection) and nothing else.
- **No flow-allocation handshake — yet.** RINA's flow allocator negotiates
  QoS/policy per flow. Mesa has no negotiation step, and adding one would
  reintroduce the handshake delta-t deletes. Near-term: policy is *derived*
  (from N-1 class + defaults) rather than negotiated. If per-flow negotiation
  is ever needed (e.g. bloq upgrade), it can ride the namespace itself (peek
  `/meta/...`) — negotiation-as-data, consistent with everything else. Open
  question below.

## 6. The flow-engine and transport options, revised

### 6.1 Flow engine: peek-only vs full, re-posed

In RINA terms the question dissolves a little: peek/page **is** the data
transfer mechanism, and a poke is a peek with a payload name attached — the
"flow engine" is not a separate protocol, it's the *retransmission-control +
sequencing policy* applied to a bidirectional pair of namespace regions
(`/flow/<bone>/...`). That reframing yields three options:

| Option | What ships | RINA reading | Verdict |
|---|---|---|---|
| **A. Peek-only v1** | Namespace reads: publ/chum/shut pages, no pokes | A DIF with only unreliable-read flows; no state vector | Cheapest, but excludes messaging — the actual use case (Nostr DMs, LN coordination). Rejected as end state; acceptable as milestone 1 |
| **B. Monolithic flow engine** | Port `++fo` wholesale: windows, acks, nacks, corks, naxplanations as one unit | Ignores the mechanism/policy split; hardcodes datagram assumptions into flow logic | Works but forfeits transport agnosticism — this is how we'd accidentally write a UDP-only library |
| **C. State-vector engine + policy modules** | Sequencing/window mechanism once; retransmission & congestion as policies gated on N-1 class; poke support as the write-flow module on top of the read machinery | The EFCP decomposition | **Recommended.** Slightly more design work up front, and it's exactly the work the spec needs to do anyway |

Concretely for the roadmap: milestone 1 is peek-only *because it's the
mechanism substrate* (codec + LSS + namespace + enrollment), milestone 2 adds
the state vector and poke flows as policy modules. A is a stage of C, not a
rival.

### 6.2 Transport mapping: pacts-verbatim vs native framing, re-posed

| Option | Over TCP/WSS | RINA reading | Verdict |
|---|---|---|---|
| **i. Pacts verbatim, tunneled** | Length-prefix each 1472-byte-class pact on the stream; keep all datagram policies running | Treats TCP as a fake UDP; double congestion control | Fine as a *bring-up* mode (it's what lets a libmesa peer talk through a dumb pipe to a UDP relay), wrong as the spec's answer |
| **ii. Same pacts, per-N-1 policy** | Same pact format, length-prefixed; retransmit/cwnd policies **off**; delimiting bloq free to grow (jumbo leaves); LSS and SDU protection unchanged | Delimiting and transfer-control as policy over a declared N-1 | **Recommended.** Wire-derived, relay-bridgeable, no meltdown |
| **iii. Native stream mapping** | New framing: messages as frames, drop fragment/LSS layer on streams | A second wire format; relays can no longer bridge transports without reassembly; integrity now depends on the pipe | Rejected for v1. Revisit only with measurements showing (ii)'s overhead matters |

The load-bearing property of (ii): **a relay can bridge N-1 DIFs
statelessly** — accept pacts over WSS from a phone, emit the same pacts over
UDP toward a ship — because the unit of relay is the pact everywhere. That's
what makes "diverse non-Arvo peers" one network instead of several gateways.

Interaction with E2E-by-default (see 04-crypto): forwarding needs *some*
name-prefix visibility for PIT matching. The encryption design must partition
the name into a routing-visible prefix and a sealed remainder — which is
precisely RINA's "a DIF hides its internals from N+1 and N-1" discipline
applied to the path. The confidentiality audit determines how far the current
`%chum`/`%shut` path-sealing already achieves this.

## 7. Open issues specific to the RINA framing

1. **How literal is recursion in v1?** Proposal: the engine is written
   scope-parametric (so mesa-over-mesa is *possible*), but v1 ships exactly
   one DIF instance over pluggable N-1s. Groups-as-DIFs and LN-embedded DIFs
   are spec appendices, not code.
2. **Policy derivation vs negotiation.** Derived-from-N-1-class works until
   two peers reach each other over different transports with different bloq
   expectations. Does the responder simply serve whatever bloq the name
   requests (the namespace already permits this — bloq is in the name), making
   negotiation unnecessary by construction? Likely yes — worth confirming and
   writing down, because it's an elegant dissolution of the problem.
3. **Delta-t timer audit.** Someone needs to enumerate every timer in
   `ames.hoon` + `mesa.c`, map each to MPL/A/R or "policy," and check the
   exactly-once argument still closes when N-1 is a reordering-free stream.
   This is spec work with real payoff (it's also where the cork question
   lands).
4. **Congestion policy at relays.** RINA puts congestion control inside each
   DIF, which for us means relays (interior IPCPs) may participate — e.g.
   backpressure signals — rather than being dumb pipes. Current mesa relays
   are stateless-ish (PIT only). Do we want to leave room in the spec for
   relay-assisted congestion, or freeze relays as stateless? (Stateless bias
   suggested; note the door.)
5. **Multihoming.** A peer with UDP + WSS attachments simultaneously is
   natural in RINA (multiple PoAs under one node address) and half-supported
   by mesa (`next` lane lists, `%nail`). The spec should say what a
   multi-attachment peer advertises in its fief and how senders choose.
6. **NDN/RINA vocabulary discipline in the spec.** Suggest: data-plane
   chapters use NDN-derived terms (interest, pending-interest, named data);
   architecture chapters use RINA terms (DIF, N-1, enrollment, policy). Mixing
   them per-sentence will produce working-group fights about words instead of
   designs.

## 8. Recommendation

Adopt **"RINA-shaped, wire-compatible"**:

- One engine with the three-task IPCP decomposition as module boundaries
  (this *is* the Arvo/Vere unification, done on purpose).
- N-1 transports as declared-property DIFs; policy (delimiting, retransmit,
  congestion) derived per N-1 class. Options C + ii above.
- Delta-t timer algebra specified normatively; corks re-examined against it.
- Pact wire format frozen; recursion latent in the engine but unexercised in
  v1; no CDAP/RIB formalism beyond vocabulary.
- Relay = policy role available to any enrolled fief-holder, per the
  comet-attestation UIP.

## References

- John Day, *Patterns in Network Architecture: A Return to Fundamentals*, 2008.
- R. Watson, "Timer-based mechanisms in reliable transport protocol connection management" (delta-t), 1981.
- [Recursive InterNetwork Architecture — Wikipedia](https://en.wikipedia.org/wiki/Recursive_Internetwork_Architecture); IRATI project, *Investigating RINA as an Alternative to TCP/IP*.
- Vergara et al., "Error and Flow Control Protocol (EFCP) Design and Implementation," 2019.
- [Directed Messaging — roadmap.urbit.org](https://roadmap.urbit.org/project/directed-messaging) (NDN lineage).
- [Urbit Networking: Ad Fontes — USTJ v01-i02](https://urbitsystems.tech/ustj/v01-i02/mss5-ad-fontes.html) (solid-state doctrine, oaths, seven-layer decomposition).
- Van Jacobson et al., "Networking Named Content," 2009 (NDN/CCN).
- This repo: `01-architecture.md` (engine/crate decomposition), `04-crypto.md` (E2E-by-default), kernel sources `pkg/arvo/sys/vane/ames.hoon` and `pkg/vere/io/mesa/{mesa,pact}.c` on the gwbtc forks.
