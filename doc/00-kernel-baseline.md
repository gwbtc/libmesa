# Kernel/runtime baseline libmesa tracks

**Source audit: 2026-10-21.** The identity reference is the composed
`hd/cc-key-rotation` and `hd/cc-snob-only` stack. `hd/cc-kernel` alone still
has the earlier identity behavior. The library currently implements wire
coding only; the domain-first contract is [spec chapter 5](../spec/05-identity.md).

## Pinned sources and status

| Repository / role | Revision | Status observed |
|---|---|---|
| `gwbtc/urbit`, upstream base `hd/cc-kernel` | `7a2658febe9da0d3992ea612dc989d660c6b64e4` | Draft PR #67, open against `gw/next/kelvin/408` |
| `gwbtc/urbit`, `hd/cc-key-rotation` | `48deaca137aa8fd46b99ff4afcdd373d7131daff` | Draft PR #71, open against `hd/cc-kernel` |
| `gwbtc/urbit`, `hd/cc-snob-only` | `734ac17cfb88e571081b84406319a17d3d5e79dd` | Draft PR #72, open against `hd/cc-key-rotation`; composed identity reference |
| `gwbtc/groundwire`, `hd/cc-landing` | `cdd46bb506520f96e7bb4a91b47d46d24badbf42` | Current remote tip inspected; verifier still emits `%stale-notice` |
| `gwbtc/groundwire`, local `hd/cc-snob` | `b393078d726aa15f91d27b3e2b09f968207673d4` | Historical companion prototype; no matching remote head advertised at audit |

The key-rotation stack branches from kernel commit
`6251699f8f9977e4411ffc5d7ad977957c82b0ab`. The current kernel tip's additional
changes leave `zuse.hoon`, `lull.hoon`, `jael.hoon`, and `ames.hoon` unchanged
relative to that common base. Key rotation is the ancestor of snob-only.
The prepared `*-408k2-update` branch names are not newer identity contracts;
their production files are already represented by the reviewed stack.

The old combined `urbit@hd/cc-snob` is not the reference tip. The kernel's
composed contract, actual source, and loose-ends annex supersede the early
libmesa notes that imported that branch's entire punishment doctrine.

Immutable source links:

- [Kernel contract](https://github.com/gwbtc/urbit/blob/734ac17cfb88e571081b84406319a17d3d5e79dd/pkg/arvo/doc/spec/pluggable-comet-pki.md)
- [Rotation lifecycle](https://github.com/gwbtc/urbit/blob/734ac17cfb88e571081b84406319a17d3d5e79dd/pkg/arvo/doc/spec/pluggable-comet-pki-lifecycle.md)
- [Loose ends and companion gates](https://github.com/gwbtc/urbit/blob/734ac17cfb88e571081b84406319a17d3d5e79dd/pkg/arvo/doc/spec/pluggable-comet-pki-loose-ends.md)
- [Zuse key construction](https://github.com/gwbtc/urbit/blob/734ac17cfb88e571081b84406319a17d3d5e79dd/pkg/arvo/sys/zuse.hoon)
- [Jael registry, verdict checks, activation](https://github.com/gwbtc/urbit/blob/734ac17cfb88e571081b84406319a17d3d5e79dd/pkg/arvo/sys/vane/jael.hoon)
- [Ames attestation and soft admission](https://github.com/gwbtc/urbit/blob/734ac17cfb88e571081b84406319a17d3d5e79dd/pkg/arvo/sys/vane/ames.hoon)
- [Groundwire domain codec](https://github.com/gwbtc/groundwire/blob/cdd46bb506520f96e7bb4a91b47d46d24badbf42/gw-btc/lib/gw-btc-pass.hoon)

## Settled mechanics in the composed kernel

Suite-C identity uses immutable `ugn/dat` for the name and a per-life `cry`
for both signing and agreement. The private ring carries `[kes ugn]`, a live
seed and a public genesis key. At life 1 the untweaked genesis key is the live
key. The same `'C'` tag does not make earlier two-seed rings compatible.
The alternative tweaked life-1 signer remains an upstream design question;
libmesa follows the pinned construction pending a deliberate protocol change.

The core reads only `mat(domain)` from `dat`. Groundwire owns the subsequent
kelvin-9 and canonical spawn-satpoint fields and the custody-log `xtr`.
Domain registration, request dispatch, and verdict authority use the same
committed name. Generic local or remote comet point feeds cannot replace
validated domain verdicts after bootstrap.

Jael validates a positive point's suite, name, domain, nonzero life,
monotonic life/rift, same-life key consistency, and sponsor class. It publishes
both point and fief. A ring activates only against the exact authorized pass,
including evidence, in either arrival order. `%anew` may refresh evidence
without replacing the live key or immutable name material.

`%fail` rejects a candidate and removes only pending alien state. It leaves
known peers and both block policies intact. `%snob` retains points and flows,
soft-blocks ordinary inbound peer traffic, and solicits re-attestation.
`%full` validates/installs the point and reverses the soft edit; it never
clears the independent hard policy. `%lost` is non-authoritative and currently
a no-op. `%stale` is absent from the composed stack but remains in the
key-rotation prerequisite alone.

Allow-mode auto-admission applies to successful registered-domain `%full`
verdicts. Suite-B promotion, unregistered suite-C fallback, and Azimuth public
updates do not automatically enter the soft allow set. Anonymous Mesa peeks
have no authenticated requester and remain outside identity-based gating.

The kernel offers life-1 self-authentication when a suite-C domain is explicitly
unregistered; a suspended domain or failed lookup cannot use that exception.
libmesa retains that fallback as an opt-in mode and includes explicitly
provisional sponsor bootstrap. Neither is labeled domain-verified.

Mesa proofs use fixed publisher-discovery life-1 coordinates while requiring
the exact inner recipient life. Proactive kernel rekey announcements still
use legacy open packets through the Mesa control bridge. libmesa stays Mesa-only: an upstream Mesa announcement change and recovery
tests are required before claiming full rekey interoperability.

## Companion status and release gates

The current remote Groundwire landing branch is not a completed companion to
the composed snob kernel. Its verifier still uses `%stale-notice`. The local
snob prototype uses `%snob-notice` but retains moved/strike escalation and
terminal-negative assumptions that the kernel narrowed. Its policy must not
be copied into the generic library as settled semantics.

The kernel annex records the following unresolved cross-layer gates. They
remain design/test obligations; this audit did not repair them:

| Gate | Consequence |
|---|---|
| Verifier readiness | Registration or desk revival can make retained keys usable before authority catch-up. A running process is not a current verifier. |
| Causal freshness | A verification begun before withdrawal may finish afterward and clear the soft block. Life/rift monotonicity does not order same-point policy events. |
| Final ring evidence | Companion tooling must stage the final ring whose exact `xtr` matches the authorized point; a matching live seed alone cannot activate. |
| Live own-rift | The kernel lacks the quiescent transition needed to prevent old continuity from surviving or reappearing before new-key activation. |
| Evidence size | Full custody logs eventually exceed the one-fragment Mesa proof envelope. Choose bounded evidence or a specified proof-transfer extension. |
| Hostile evidence | The companion's raw `cue` of peer `xtr` needs bounded structural validation. A surrounding `mole` does not contain every allocation failure. |
| Policy provenance | Shared hard/soft sets cannot distinguish overlapping operator and domain edits. |
| Refresh persistence | `%anew` does not update the boot keyfile. |

The annex's evidence-size measurements are scenario-specific, not a constant
number of supported rotations. Route fields and encoding change the boundary;
interop vectors must measure complete proof bytes.

## Validation boundary

This audit read the pinned source and checked live branch/PR status. It did
not rerun kernel pills, Aqua, Bitcoin regtest, or identity interoperability.
Prior targeted tests are documented upstream and in the earlier review:
key rotation and snob recovery have targeted passing coverage, while the full
Aqua suite and authority-driven multilateral lifecycle are not established
as green. The source annex also records stale fixtures and inherited failures.

The C and Rust prototypes' existing packet tests establish bounded codec
behavior. They do not establish possession, name binding, current-key
authorization, admission, rotation, or revocation.
