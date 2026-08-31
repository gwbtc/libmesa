# Confidentiality: what E2E-by-default actually requires

**Status:** discussion draft, and the most important one for the ChatControl /
normie-phone framing. The working decision is: **everything E2E-encrypted by
default, and drive fixes upstream rather than compromise.** This document says
what that costs, because an audit of the current kernel changed the picture.

## The headline: flows are already encrypted

I expected to find flow traffic (pokes/acks) riding plaintext-with-MAC. It
does not. On the `hd/cc-kernel` branch, **all flow traffic — pokes, acks,
naxplanations, corks — rides the `%chum` space: AEAD-sealed path +
XChaCha8-encrypted payload + keyed-BLAKE3 MAC under an X25519 ECDH shared
key.** The sender's `fo-send` hardcodes the `%chum` space; acks and
naxplanations likewise.

The thing that makes this easy to misread: the `/flow/...` namespace endpoint
*does* serve a raw page with no crypto — but `/flow/...` is a **private**
endpoint, reachable only from *inside* `peek-chum`, which performs the inner
read as the requesting ship and then encrypts-then-MACs the result. **No
packet ever leaves the ship with a `/flow/` path or a plaintext flow payload
on it.** The construction is correct: encrypt-then-MAC, MAC computed over the
LSS root of the ciphertext.

So "E2E-by-default" is **not** a demand to encrypt flow contents — that's
done. It is a demand about (1) the traffic classes that still default to
plaintext, (2) metadata the encrypted classes still leak, and (3) forward
secrecy. The good news reframes the whole effort: we are hardening a working
E2E design, not retrofitting one.

## What's on the wire, per traffic class

| Class | Path | Payload | Auth | Key | E2E? |
|---|---|---|---|---|---|
| Flow: poke/ack/naxp/cork | sealed (`/chum/<slife>/<client>/<clife>/<0v…>`) | XChaCha8 | keyed-BLAKE3 MAC (128-bit) | static ECDH | **yes** |
| Remote scry `%chum` | sealed | XChaCha8 | MAC | static ECDH | **yes** |
| Remote scry `%shut` (groups) | sealed | XChaCha8 | ed25519 **sig** | group key | **yes** (to group) |
| Remote scry `%publ` (`%keen` w/o `sec`) | **plaintext** | **plaintext** | ed25519 sig | — | **no** |
| Attestation `/pawn/proof`, `%muth` | **plaintext** (`%publ` life 1) | **plaintext** | ed25519 sig | — | **no** |

Metadata every observer/relay reads even on the encrypted classes: protocol
cookie + version + packet type + hop count + 20-bit mug; **destination ship +
rift** (and on a poke, *both* ships, since the poke carries an ack-name at the
receiver and a poke-name at the sender); `boq`; fragment type/index; the
cleartext `/chum/` prefix with **client ship and both lives**; the sealed
inner path's *exact plaintext length* (stream cipher, no padding); `tob` total
message length; the auth-tag *kind* (64-byte sig vs 16-byte MAC distinguishes
the space); and, injected by relays, the previous hop's IP:port in cleartext
in the `%page` `next` trailer.

## The gap list, prioritized

**A. Traffic classes that default to plaintext (close by default-flip).**

1. **`%publ` scry is plaintext by construction.** Any read where the requester
   passes no `sec` rides `%publ`. For E2E-by-default, the *default* peek space
   for a known peer should be `%chum`, with `%publ` reserved for genuinely
   public data (software updates, published feeds) — an opt-*out*, not the
   fallback.
2. **Attestation and `%muth` are plaintext.** Partly necessary — the comet's
   own key is unknown to the receiver, so nothing can be encrypted *from* the
   comet under a shared secret. But the comet *does* know the recipient's
   pass, so a one-sided ECIES (ephemeral→static to the recipient) would hide
   the attestation contents and the `%muth` metadata `(comet-pass, comet-life,
   target-ship, target-life)` that today broadcast in cleartext. Closable.

**B. Metadata leaks on the already-encrypted classes (close by wire tweaks).**

3. **Client ship in the cleartext `%chum` prefix** — highest-value single
   change. Relays do not need it (they key the PIT on opaque name bytes; see
   below); only the destination ship is required for forwarding. Move it
   inside the seal, or replace with a per-epoch blinded key-id.
4. **Space tag + lives in cleartext** classify every packet at a glance.
5. **No path padding** — `seal-path` is length-preserving; the inner path
   length is an oracle (e.g. `%ack`=3 chars vs `%poke`=4 distinguishes acks;
   bone/seq digit counts leak flow age and message counts). Pad to buckets.
6. **`tob` total length in every data packet** — pad message sizes to buckets.
7. **Deterministic (synthetic-IV) sealing → permanent per-flow fingerprints.**
   `seal-path` derives its nonce from a keyed hash of the plaintext, so the
   same path always seals to the same `@uv`. This is *required* by relay PIT
   matching (byte-equality), so it can't simply be randomized — see the
   constraint below. Mitigation: epoch-salted seal where the salt is a
   function of `(key, epoch)` known to both endpoints, rotating the
   fingerprint periodically without breaking `memcmp`.

**C. Forward secrecy (the biggest cryptographic gap).**

8. **`%chum` uses static ECDH over long-term keys**, rotated only on life
   change. One key compromise decrypts all recorded history with that peer.
   For the threat model that motivates this project (device seizure, coerced
   key disclosure), this is the gap that matters most. A ratchet or ephemeral
   DH exchange is a real protocol addition — the hardest and most valuable
   item here, and the one most in tension with the stateless/soft-state
   design (a ratchet is per-pair mutable state). Needs its own design pass;
   flagged as the marquee open question.

**D. Independent bugs found in passing (fix regardless of E2E).**

9. **`peek-shut` scries with the fully-privileged local gang `[~ ~]`** —
   group-key holders get omniscient local scry rather than scry-as-a-ship.
   Looks like privilege escalation; libmesa must scry group reads as the
   requesting ship, and this should be reported upstream.
10. **`%peek` packets are unauthenticated** — free amplification/DoS
    primitive (the forger can't read a `%chum`/`%shut` reply, but can induce
    work and traffic). Consider a lightweight peek auth or rate limiting.
11. **Reduced-round primitive + non-constant-time compare** — `xchacha:chacha
    8` (8 rounds) and a `const-cmp` still marked "XX jet for constant-time."
    libmesa should use constant-time compares unconditionally and the WG
    should decide whether 8 rounds is intended.
12. **Nonce-reuse hazard (unenforced invariant).** The XChaCha IV is the
    sealed path; any path serving two plaintexts under one key is instant
    keystream reuse. Flow paths are safe only because they're immutable per
    seq and pinned to `case=1`. libmesa **must** either enforce this invariant
    explicitly or switch to a counter/random nonce carried on the wire.

## The relay constraint (the floor on metadata privacy)

A relay reads exactly two things and needs nothing else:

- the **destination ship** in cleartext (to forward vs handle, and to look up
  a lane), and
- a **stable, byte-identical request token** shared between a `%peek` and its
  answering `%page` — the entire serialized name, used as an opaque PIT key
  matched by `memcmp`.

Two consequences for the spec:

- Path secrecy is **already fully compatible** with relaying — which is why
  `%chum` works today. Gaps 3–6 are all closable without touching the relay
  model, as long as whatever we seal still yields a stable token.
- **The destination ship cannot be hidden from a relay without onion
  routing.** That is a hard floor on Mesa's metadata privacy — no
  crypto tweak lifts it. If the threat model requires hiding *who talks to
  whom* from relays (plausibly it does, for ChatControl-grade adversaries),
  onion routing over the mesa DIF is a **separate protocol layer** and should
  be scoped explicitly rather than assumed. In RINA terms it's a distinct DIF
  with its own forwarding policy stacked under mesa; see `02-rina.md` §4a.

## Proposed E2E-by-default definition for the spec

Three tiers, so "E2E-by-default" is a checkable claim rather than a slogan:

- **Tier 1 — payload confidentiality by default (near-term, mostly done):**
  every peer-to-peer read and every flow defaults to `%chum`; `%publ` is
  opt-out for public data; attestation uses one-sided ECIES. Fixes: default
  flip + gaps 1, 2, and the bug fixes 9–12.
- **Tier 2 — metadata minimization (medium-term):** client ship inside the
  seal, padded paths and lengths, epoch-salted fingerprints. Gaps 3–7.
- **Tier 3 — forward secrecy and relationship privacy (design-required):**
  ratchet/ephemeral DH (gap 8) and optional onion routing for
  who-talks-to-whom. The two hardest items; each its own design doc.

libmesa should implement Tier 1 as the actual default from day one (it's
cheap and mostly present), specify Tier 2 as mandatory-to-implement, and treat
Tier 3 as first-class open protocol design that we *want* to drive upstream —
consistent with the decision to fix rather than compromise. The upstream value
is real: several Tier-1/Tier-2 items (default-flip, ECIES attestation,
`peek-shut` gang, constant-time compare) are bug-class and belong in the
kernel regardless of libmesa.

## References

- Confidentiality audit of `pkg/arvo/sys/vane/ames.hoon` @ `hd/cc-kernel` and
  `vere/pkg/vere/io/mesa/` (this session).
- `02-rina.md` (SDU protection as per-DIF policy; onion routing as a stacked
  DIF), `01-architecture.md` §5 (verdict/enrollment contract).
