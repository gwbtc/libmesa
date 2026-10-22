# Forward secrecy: the design space

**Status:** discussion draft — the elaboration of `04-crypto.md` gap 8 /
Tier 3, which called forward secrecy "the marquee open question." This
document maps the option space so the WG can pick a lane rather than debate
in the abstract.

## Where we stand

The `%chum` space (all flow traffic, all default peeks once the Tier-1
default-flip lands) derives its symmetric key by **static X25519 ECDH between
long-term messaging keys**. Compromise of either peer's `cry` secret decrypts
**all recorded traffic** between that pair for the lifetime of that key.

The key-rotation stack separates permanent identity from live keys:

- Immutable public genesis `ugn` and `dat` determine the name. The per-life
  `cry` both signs (`sgn == cry`) and derives channel keys; rotating it leaves
  the name unchanged. The genesis secret is not needed after rotation.
- The `%gw-btc` custody model records a new authorized life through a custody
  snapshot and on-chain transaction. That cost belongs to the domain;
  other domains need not price key rotation the same way. Within each life,
  static agreement still exposes recorded traffic if its secret is compromised.

The pinned construction and remaining signing-design questions are recorded in
[the baseline](00-kernel-baseline.md) and [identity chapter](../spec/05-identity.md).

For the threat model that motivates this project — device seizure, coerced
disclosure, ChatControl-grade recording adversaries who tap first and
decrypt later — per-life epochs priced in on-chain transactions are not a
forward-secrecy story. That's the gap.

## Why this is genuinely hard here (the four tensions)

1. **Byte-identity and interest matching.** A peek and its answering page
   must match by *byte-equality* at relays (PIT `memcmp`), and retransmitted
   pages must be byte-identical for fragment reassembly and caching. Any
   scheme where the encryption key evolves must evolve it in **crisp epochs**
   shared by both endpoints, or interest matching breaks mid-flight.
2. **Soft state vs ratchet state.** Mesa identity uses attestation exchange;
   its current data plane adds no ephemeral session-key handshake. A double
   ratchet introduces ordered, loss-sensitive per-pair state beyond the
   transport timers and domain-authorized life keys. Recovery must account for
   both identity updates and that additional state.
3. **Relay caching.** The runtime caches pages keyed by name. Epoch-rotated
   encryption bounds cache validity to an epoch. Acceptable, but it must be
   said out loud: FS trades away long-lived cacheability of `%chum` traffic
   (public `%publ` data — software updates etc. — is unaffected).
4. **Arvo never forgets — but libmesa can.** FS is ultimately about
   *deleting* key material, and an Arvo ship's event log retains old state
   unless secrets are held off-loop in the runtime or the log is truncated.
   A libmesa peer has no event log: it can genuinely delete. **Until
   vere/arvo grow secret-discarding (runtime-held ratchet state or log
   chop), libmesa peers can honor FS deletion guarantees that Arvo ships
   structurally cannot.** This asymmetry belongs in the spec's security
   considerations, and it is an upstream conversation of its own.

## The option ladder

**FS0 — status quo (per-life epochs, on-chain priced).** Static ECDH;
rotation = custody entry. Zero protocol work. Fails the threat model; is the
documented floor.

**FS1 — cheaper life-rotation.** Drive rekey cost down (batching, timing) so
lives rotate more often. Doesn't change the architecture, still leaves
epoch length coupled to Bitcoin fees and custody ceremony. Not a real answer;
listed for completeness.

**FS2 — namespace-published signed prekeys (the leading candidate).** Each
peer binds, in its own namespace, an **epoch prekey**: an X25519 public key
signed by the domain-authorized current life key `cry`, at a well-known path (e.g. `/publ/<life>/epok/<n>`), rotated
on a timer (hours/days), old secrets deleted after a grace window. The
`%chum` key for epoch *n* becomes a KDF over the ECDH of both peers' epoch
prekeys (with the static keys mixed in for mutual authentication —
Noise-KK / X3DH-flavored, exact construction TBD).

Why it fits Mesa unusually well:

- **Namespace discovery.** A peer can fetch a prekey using `%peek`, after
  establishing the publisher's current domain-authorized signing key.
  Withdrawal and proof solicitation supply an identity-recovery mechanism;
  prekey expiry, loss recovery, and simultaneous updates still need a design.
  The reviewed kernel does not adopt tick-triggered re-attestation.
- **No per-pair mutable state** beyond a cached peer prekey with an epoch
  number — soft state with a timer bound, not a ratchet vector. Desync is
  self-healing: an undecryptable packet triggers a prekey re-peek, exactly
  parallel to snob re-solicitation.
- **Deterministic within an epoch** — byte-identity and PIT matching hold;
  epoch boundaries are the crisp cutover points tension 1 demands. This
  also *solves* `04-crypto.md` gap 7 (permanent deterministic-seal
  fingerprints) as a side effect: the epoch prekey is the epoch salt.
- **Recovery remains to be established.** Fresh DH contributions may restore
  confidentiality after an attacker loses access to endpoint state. That
  depends on the construction, authenticated prekey replacement, and which
  secrets were compromised. A stolen signing key can authorize replacement
  prekeys; epoch rotation alone does not establish post-compromise security.

Costs: a well-known namespace convention + signed-prekey format in the spec;
epoch-skew handling (accept epoch *n−1* during a grace window); the Arvo-side
deletion caveat (tension 4) limits what a ship-peer can promise.

**FS3 — per-flow double ratchet.** Signal-grade: per-message FS and fast
healing. Maximum tension with everything above (ordered per-pair state,
desync, multi-device). Assessment: this belongs in an *application layer*
(a chat protocol running over mesa flows), not in the transport. The
transport should make FS3-above-it easy (it does — flows are ordered and
exactly-once), not absorb it.

## Proposed position for the WG

1. Spec **Tier 3 = FS2**: namespace-published signed epoch prekeys, epoch
   granularity on the order of hours-days, construction to be fixed in a
   crypto design doc (Noise-KK vs X3DH-style mixing is the main open choice,
   plus epoch/grace parameters).
2. **Don't block v1 messaging on it**, but reserve the wire/namespace hooks
   now: the `/epok` region and the KDF's domain-separation labels are cheap
   to reserve, expensive to retrofit.
3. **Drive it upstream** as the flagship of the "fix upstream over
   compromise" decision — FS2 needs the kernel to adopt the same prekey
   convention or ships and libmesa peers can't talk under it. Missing prekeys
   do not prove a peer lacks support: a relay can suppress discovery. Define
   authenticated capabilities and explicit compatibility policy before
   allowing a static-ECDH fallback. A peer previously known to support FS2
   must not silently downgrade after a timeout or missing binding.
4. FS3 explicitly out of transport scope; FS0 documented as the floor with
   its on-chain cost stated plainly.

## Construction requirements

Before implementation, specify both peers' epoch identifiers, signed-key
bindings, expiry and rollback checks, transcript/KDF domain separation,
replay handling, grace-window retention, deletion, and the compromise model.
An epoch pair can be skewed; a single shared epoch number cannot be assumed.
Signed prekey publication is asynchronous protocol exchange, not evidence
that handshake security questions disappear. The current codec implements
none of FS2. See the [X3DH key-compromise analysis](https://signal.org/docs/specifications/x3dh/#46-key-compromise)
for the distinction between identity-key compromise and prekey compromise.

## References

- `04-crypto.md` (gap list; Tier definitions; relay constraint).
- The composed kernel contract and lifecycle pinned in `00-kernel-baseline.md`.
- Historical `ops/doc/snob-doctrine.md` in the groundwire repo (domain policy,
  historical solicitation/punishment proposal, not the current kernel contract).
- Signal X3DH / Double Ratchet specs; Noise Protocol Framework (KK pattern)
  — candidate constructions for the FS2 KDF.
