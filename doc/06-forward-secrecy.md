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

How long is that lifetime? The snob-doctrine work pins it down:

- A suite-%c pass has two halves: `ugn` (signing key) — tweaked, hashed into
  the `@p`, **immutable for the life of the name** — and `cry` (messaging
  key), which rotates per snapshot/life. Only `sgn` is in the tweak; rotating
  `cry` leaves the name unchanged.
- But a rotation is a **custody-log snapshot**, and under the snob doctrine a
  plain rekey *is a sat move* — an on-chain Bitcoin transaction. So today's
  FS granularity is **per-life epochs whose length is set by how often the
  owner pays sats**. Realistically: weeks-to-years, not messages-to-days.

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
2. **Soft state vs ratchet state.** Mesa deliberately has no handshake and
   its per-peer state is timer-bounded (the delta-t story, `02-rina.md`
   §4c). A Signal-style double ratchet is per-pair, *ordered*, loss-sensitive
   mutable state — the classic desync failure mode is exactly what
   handshake-free soft-state design exists to avoid.
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
signed by `ugn`, at a well-known path (e.g. `/publ/<life>/epok/<n>`), rotated
on a timer (hours/days), old secrets deleted after a grace window. The
`%chum` key for epoch *n* becomes a KDF over the ECDH of both peers' epoch
prekeys (with the static keys mixed in for mutual authentication —
Noise-KK / X3DH-flavored, exact construction TBD).

Why it fits Mesa unusually well:

- **No handshake.** Fetching a peer's current prekey is an ordinary `%peek`
  — the same mechanics as fetching their attestation, and the snob
  doctrine's solicitation machinery (`%poof`, re-attestation on tick
  mismatch) is precisely the "my counterparty's key view is stale" recovery
  channel this needs. Nothing new to invent for the failure path.
- **No per-pair mutable state** beyond a cached peer prekey with an epoch
  number — soft state with a timer bound, not a ratchet vector. Desync is
  self-healing: an undecryptable packet triggers a prekey re-peek, exactly
  parallel to snob re-solicitation.
- **Deterministic within an epoch** — byte-identity and PIT matching hold;
  epoch boundaries are the crisp cutover points tension 1 demands. This
  also *solves* `04-crypto.md` gap 7 (permanent deterministic-seal
  fingerprints) as a side effect: the epoch prekey is the epoch salt.
- **Per-epoch healing.** Fresh DH contributions each epoch give
  post-compromise security at epoch granularity, not just forward secrecy.

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
   convention or ships and libmesa peers can't talk under it. The fallback
   negotiation ("peer has no epoch prekey bound → static ECDH") is
   graceful-degradation by construction, since the prekey is just a binding
   that may or may not exist.
4. FS3 explicitly out of transport scope; FS0 documented as the floor with
   its on-chain cost stated plainly.

## References

- `04-crypto.md` (gap list; Tier definitions; relay constraint).
- `ops/doc/snob-doctrine.md` in the groundwire repo (two-key structure §1.1,
  code evidence for the fixed signer; solicitation machinery §2.3).
- Signal X3DH / Double Ratchet specs; Noise Protocol Framework (KK pattern)
  — candidate constructions for the FS2 KDF.
