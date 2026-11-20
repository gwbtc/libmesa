# Phase 0: raw UDP host contract and native compatibility inventory

**2026-11-19. Host contract frozen for phases 1–3; native live-capture evidence
remains open.** This record distinguishes those two evidence levels rather than
claiming the entire phase-0 native target gate has passed.

**2026-11-20 follow-up:** the [native-target investigation](21-native-target-investigation.md)
records current executable/pill hashes, 164 native kernel tests, instrumented
proof/lifecycle packets, and seven live native UDP publication responses.
It resolves checksum and signed-root conventions. Live suite-C admission,
direct-route recovery, and default-mode migration remain open. The original
inventory below records the phase-0 starting point.

## Scope and owners

Shrine uses the UDP adapter. Its authors own migration from the pre-PR-11
bridge; libmesa supplies the public Rust/C contracts and a runnable host harness.
No Shrine files change in this PR. `ic-net` remained the advertised networking
reference at `5323e7992134c821c569f3651cb3c3bc18f0e43a` when checked for this work;
no successor networking branch was identified by the `*net*`/`*mesa*` query.

The first raw integration uses experimental v2 signed public reads, explicit
preconfigured peers and direct UDP routes. The eventual native integration
uses suite-C/Groundwire identities on Shrine and Urbit. These profiles remain
distinct. The raw harness does not authenticate its fixture IDs through
Groundwire or exercise a Shrine world.

| Contract | Selected behavior | Owner |
|---|---|---|
| Host API | ABI 1 plus additive configured CORE, state snapshots and generation events; equivalent Rust batch API | libmesa |
| Runtime bridge | Consume those public contracts; preserve bar width and capability ownership | Shrine/Enki authors |
| Network attachment | One shared UDP endpoint per socket, bounded route table, host readiness/deadlines | libmesa adapter; Shrine scheduler |
| Required capacities | Configurable up to the inspected host's 1 MiB objects, 1,024 reads, 65,536 slots and 64 MiB byte limits | libmesa validates; host selects its working profile |
| Publication history | Host owns immutable naming, retirement fences, landing and restored-world epochs | Shrine |
| Groundwire persona mapping | Preserve existing world identity until an explicit Groundwire binding/migration is agreed | Joint host/PKI design, still pending |
| Future authority provider | Host-authenticated requests/results, provider generations and chain readiness | Host verifier implementers; libmesa defines module boundary |

No unpublished Shrine change blocks the independent raw-host implementation.
The new API does not assume the older Enki bridge already uses the C ABI.
Both the C and Rust batched surfaces return owned immutable byte buffers.

## Native target and evidence

The selected source reference remains Urbit `gw/final` at
`9f437ff097a0e3836fea7875a568b6192eef6a27` with Groundwire
`a5cf857e2de90c283aa18087db9d4a3981f3ab55`. See the
[pinned source snapshot](15-shrine-groundwire-reference.md).

An existing local acceptance record at
`output/experimental-live-20261107/compat/provenance.json` in the parent
Groundwire workspace records a fresh native ship run using:

- kernel source `166601d2a129a0e25acc6d1ce4f5b124884817f7`, later integrated at
  the selected merge revision;
- release `groundwire-alpha-2026.11.4_3`, runtime `4.6-828244e`;
- pill SHA-256 `58b23808442be2c3f364d52fae5f8d2d254f271f0188d04df3cacc1d79c50805`;
- recorded running-kernel source matches and native application acknowledgments.

That record was read, not rerun. It is historical provenance, not a new packet
capture or proof of the current deployed node. Do not publish private pier or
key material with a test report. Native activation still needs a current
executable hash, deployment confirmation, and proof/rekey/refresh captures.
The full native part of phase 0 remains open; phases 1–3 below have independent
raw-host validation and do not claim native acceptance.

| Surface | Existing evidence | Remaining native work |
|---|---|---|
| Mesa packets | Explicit [v1 codec](../spec/reference/mesa-v1.md), [Hoon/Vere corpus](../vectors/pact/NOTES.md); v2 has no fallback | Pin checksum behavior at the selected native ingress and every required trailer |
| Public object integrity | Executed suite-C and LSS vectors; experimental v2 has its own signed context | Native protected name/root context and message serialization fixtures |
| First contact | Kernel `al-peek-proof` and `al-take-proof`; public-life-1 bootstrap, actual inner sender life and current recipient life | Native end-to-end proof construction and intake capture; oversized evidence handling |
| Proof size | Selected kernel requires one 1,024-byte fragment at proof intake | Define interoperable behavior for a longer custody log; a 1 MiB raw read limit is not a fix |
| Rekey/solicitation | Selected kernel accepts legacy open / `%keys` control for Mesa peers | Capture the exact suite-C control subset, recipient-life rules and concurrent rotation recovery |
| Private data | Suite-C agreement primitives; native spaces/KDF/seal/open remain separate | Differential vectors and authenticated access tests; public peeks prove no requester identity |
| Application messaging | Experimental `flow/2/...` durability tests | Native `%plea`/`%boon` framing, receipts and host application mapping |
| Authority | Kernel Jael registry/verdict paths and companion `%snob-notice` source | Provider implementation, typed orchestration and real custody/ledger verification |

The native compatibility module must account for suite-C control traffic even
when its packet format is historically called Ames. Azimuth-ID peers, their
discovery and sponsor services remain deferred. Prefer direct suite-C routes
for initial native connectivity; record any unavoidable upstream dependency.

## Kernel responsibility to module/test mapping

| Mechanism | Source boundary | Planned module and acceptance evidence |
|---|---|---|
| Permanent name, current key and pass/ring correspondence | Suite-C crypto and pass fields | Identity/key module; existing primitive vectors plus activation tests |
| Domain registration and lifetime | Jael `%anex`, `%gost`, `%ghul`, `%bane` | Separable Jael; registration, suspension, revival and removal replay |
| Accepted points and history | Jael public/private keys, life/rift, sponsor/fief | Typed PKI state; monotonicity, conflict and subscription tests |
| Verification dispatch | Jael `%writ` / `%sybl`, provider result origin | Jael and provider port; stale-generation, wrong-domain and wrong-evidence rejection |
| Vouch consequences | Ames `%full`, `%fail`, `%lost`, `%snob` | PKI-to-engine transitions; retain accepted state on candidate failure, preserve independent operator blocks |
| Own evidence and activation | `%anew`, local key installation and `sy-priv` | Key/Jael modules; exact evidence/key match, durable commit and recovery |
| Remote/local epoch changes | `sy-publ` breach and local quiescence gap | Core/flow plus PKI; old work retirement and own-rift recovery tests |
| Native proofs and private spaces | Ames proof intake, crypto and namespace context | Native compatibility; exact signed context, bounded decoding, positive/negative network fixtures |
| Ledger evidence meaning and currency | Groundwire verifier / Bitcoin light client | External host provider, later plugin; real chain-view and withdrawal/reorg tests |
| Azimuth/moon/turf/login presentation | Other Jael/OS responsibilities | Deferred profile or host presentation, outside suite-C acceptance |

Future verifier requests must bind a provider capability and generation,
request id, domain, peer, candidate coordinates and evidence digest. Responses
must identify the checked view and distinguish accepted, rejected, unavailable
and withdrawn. Availability, readiness and a current vouch are separate.
This PR adds none of that PKI machinery; its generation events are trusted host
configuration only.

## Acceptance order

Phases 1–3 validate the raw interface with compiled C/Rust hosts and real local
UDP sockets. A preconfigured Shrine-to-Shrine run can follow as soon as the
Shrine migration is ready. That run is a joint integration result, not a label
for the libmesa harness.

Phase 7 requires full Groundwire-identified Shrine-to-Shrine communication over
UDP before Shrine-to-Urbit acceptance. PKI lifecycle, durable host outcomes and
application semantics remain part of that gate. This makes the order explicit
without moving a phase boundary. Stop this implementation before phase 4.
