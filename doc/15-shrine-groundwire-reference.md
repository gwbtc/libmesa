# Source snapshot for the Shrine/Groundwire roadmap

**Inspected 2026-11-19. Source reading only; no live integration was executed.**

This snapshot supports [the roadmap](14-shrine-groundwire-roadmap.md). Pins
identify what was read, not what another team has deployed. Refresh active
branches before implementation; retain these pins as the planning baseline.

## 1. Revisions and provenance

| Repository | Reference | Inspected revision | Meaning |
|---|---|---|---|
| `gwbtc/libmesa` | `main`, PR #11 merged | `041f2148379bf9232063a9f7d6f6e4e45e4c6b0c` | Current plan base; separate C engine/transport/inbox and noun-free core |
| `axsys-org/shrine-plan` | `ic-net` | `5323e7992134c821c569f3651cb3c3bc18f0e43a` | Active WIP; built against libmesa before PR #11; migration belongs to Shrine's authors |
| `axsys-org/enki` | Shrine lockfile, original ref `lf/wormholes` | `018605b745659df0c655d6cdaaa0c75706aa3ca6` | Recorded from Shrine's lockfile; Enki implementation and its libmesa pin were not independently inspected |
| `gwbtc/urbit` | `gw/final` | `9f437ff097a0e3836fea7875a568b6192eef6a27` | Inspected kernel integration candidate, including narrow legacy life-1 attestation compatibility |
| `gwbtc/urbit` | `gw/release` | `d59b63d29e6249657635737a4d2f5a1c98a7dfb1` | Separately fetched reference; not interchangeable with `gw/final` |
| `gwbtc/groundwire` | `gw/final` | `a5cf857e2de90c283aa18087db9d4a3981f3ab55` | Companion verifier source; emits `%snob-notice` |

The roadmap's primary peers have suite-C/Groundwire identities, whether they
run Shrine or Urbit. Azimuth-ID peers are deferred. No node is assumed to run
`gw/final` merely because that branch exists.

## 2. libmesa evidence

Read the [C embedding contract](../spec/14-c-embedding.md),
[C engine implementation](../crates/mesa-ffi/src/embed/engine.rs),
[core dependency manifest](../crates/mesa-core/Cargo.toml),
[flow dependency manifest](../crates/mesa-flow/Cargo.toml), and
[wire dependency manifest](../crates/mesa-wire/Cargo.toml).

The C engine uses a fixed initial key table (at most 16 entries) and fixed
creation-time signing material. Its descriptor reports the resource profile:
64 KiB objects, 32 reads, 1,024 bindings, 8 MiB bound bytes, 8 MiB reassembly,
and a four-fragment per-read window. Dynamic authority and key activation
need an explicit update contract rather than mutation of that descriptor.

`mesa-core`, `mesa-flow`, and `mesa-wire` use `mesa-bytes`; their normal
dependencies no longer include `mesa-noun`. `mesa-identity` still depends on
`mesa-noun` for suite-C parsing. This is an isolated codec starting point, not
a reason to put nouns back into the engine or public PKI interface.

The existing [interop reference](../interop/reference.json) pins a different
experiment: Urbit pill source `a872698f59ca8bf8c5bbf4c9c89ed61fefa3b812`,
`bin/mesa.pill`, and a separately identified Vere executable. Its
[`%mesa-v2` endpoint](../interop/README.md) exchanges experimental signed public
reads through a UDP/Lick bridge. It proves neither native Ames messaging nor
Groundwire authority lifecycle. Preserve its fixtures as regressions.

Historical [kernel baseline](00-kernel-baseline.md) and
[identity spec](../spec/05-identity.md) contain useful invariants but older
status and scope decisions. In particular, the old “C ABI is wire-only,”
“Jael is external,” and required upstream Mesa-only announcement policy do
not describe the new roadmap.

## 3. Shrine WIP evidence

All links below pin the inspected revision. The branch is a reference for
host requirements; this task did not modify or execute Shrine.

| Source | Observed behavior | Integration consequence |
|---|---|---|
| [`src/reaver/mesa.rvr`](https://github.com/axsys-org/shrine-plan/blob/5323e7992134c821c569f3651cb3c3bc18f0e43a/src/reaver/mesa.rvr) | Calls Enki Mesa operations; handles are ephemeral capabilities; bytes are sentinel-terminated bars; actions are drained through individual calls | Shrine owns migration from the older API. Preserve exact width and expose batch/deadline contracts for its authors |
| [`src/foil/mesa_foot.foil`](https://github.com/axsys-org/shrine-plan/blob/5323e7992134c821c569f3651cb3c3bc18f0e43a/src/foil/mesa_foot.foil) | Publishes immutable epics/pins/slices; reconstructs engines from world data; uses an engine realm with fixed life/rift while its own identity log advances | CORE is a natural integration level. Agree how authority coordinates map before connecting PKI |
| [`src/foil/mesa_wire.foil`](https://github.com/axsys-org/shrine-plan/blob/5323e7992134c821c569f3651cb3c3bc18f0e43a/src/foil/mesa_wire.foil) | Short TCP connections carry a 16-byte claimed sender and four-byte packet lengths; actor clock ticks each second; failed batches are lost and engine recovery retries | This framing is not native Urbit UDP. Claimed sender is not authentication. Keep transport and identity independent |
| [`src/foil/pass.foil`](https://github.com/axsys-org/shrine-plan/blob/5323e7992134c821c569f3651cb3c3bc18f0e43a/src/foil/pass.foil) | A founding hash names a world; custody signs a chained log of live keys/life/rift; conflicting statements can prove a fork | This is a distinct identity scheme. A Groundwire persona or explicit identity migration needs agreement |
| [`extras/mounts/mesa/README.md`](https://github.com/axsys-org/shrine-plan/blob/5323e7992134c821c569f3651cb3c3bc18f0e43a/extras/mounts/mesa/README.md) | Describes peer cards, publication roots, ring/mark files, invitations and route introductions | Host naming, custody and landing are Shrine-owned work |
| [`CONTEXT.md`, “Between worlds”](https://github.com/axsys-org/shrine-plan/blob/5323e7992134c821c569f3651cb3c3bc18f0e43a/CONTEXT.md#between-worlds) | An epic lands as one event; mounts retain publisher records without running their behaviors | Packet delivery does not define cross-OS application semantics |
| [`flake.nix`](https://github.com/axsys-org/shrine-plan/blob/5323e7992134c821c569f3651cb3c3bc18f0e43a/flake.nix), [`flake.lock`](https://github.com/axsys-org/shrine-plan/blob/5323e7992134c821c569f3651cb3c3bc18f0e43a/flake.lock) | Pins Enki's wormholes work and applies local runtime patches | Refresh the whole runtime dependency chain for a joint run |

The inspected foot asks for 65,536 bindings, 64 MiB bound/reassembly storage,
and 1,024 reads. It describes 1 MiB Mesa pages and slices larger values.
It maintains peer-specific sealing above Mesa and uses `effect/admit` to land
an epic. None of those source observations establishes successful execution
with PR #11, a native Urbit peer, or a Groundwire verifier.

The ring and mark files sit outside the durable world. The mark distinguishes
world restoration from ordinary restart. Preserve that problem in the host
recovery contract; do not assume an old engine checkpoint can detect rollback.

## 4. Kernel and verifier evidence

The inspected
[`ames.hoon`](https://github.com/gwbtc/urbit/blob/9f437ff097a0e3836fea7875a568b6192eef6a27/pkg/arvo/sys/vane/ames.hoon)
contains these relevant paths:

- `al-peek-proof` requests the bootstrap public-life-1 proof path, including
  the local receiver's current life in the requested path.
- `al-take-proof` requires one 1,024-byte fragment, bounds jam before cue,
  checks the inner sender and receiver/current-life context, validates the
  pass/name, and dispatches domain evidence to Jael.
- The legacy tweaked-genesis signer exception is restricted to qualifying
  life-1 attestations. Ordinary page signing remains under the current key.
- `sy-sybl` distinguishes `%full`, `%fail`, `%lost`, `%snob` and `%anew`.
  `%snob` retains continuity while soliciting another proof. `%anew` checks
  identity/domain/key correspondence before replacing mutable evidence.
- `sy-publ` applies point, key, sponsor, fief and breach updates. Its own-rift
  no-op is an explicit gap, not a behavior libmesa should treat as safe recovery.
- The source's final dispatch comments explain that `sy-priv` announces
  rekeys with legacy open packets even for peers in `|mesa`. The exact minimal
  native control implementation remains a phase-0 investigation.

The inspected
[`jael.hoon`](https://github.com/gwbtc/urbit/blob/9f437ff097a0e3836fea7875a568b6192eef6a27/pkg/arvo/sys/vane/jael.hoon)
stores domain registry state, accepted points, private/public key histories and
subscriptions. `%anex`, `%writ`, `%anew`, `%gost`, `%ghul` and `%bane` distinguish
registration, verification, refresh, suspension, revival and removal. Gall
agent names, ducts and desk-liveness watches are Arvo bindings; the portable
module needs authenticated provider handles and explicit lifecycle events.
Process liveness alone must not certify the provider's chain readiness.

The companion
[`gw-btc.hoon`](https://github.com/gwbtc/groundwire/blob/a5cf857e2de90c283aa18087db9d4a3981f3ab55/gw-btc/app/gw-btc.hoon)
registers with Jael, validates custody evidence through its Bitcoin light
client, and returns verdicts. Its own-identity path validates an extended log
before returning `%anew-response`. The header records a boot-keyfile refresh
gap. Its `%snob-notice` emission matches the inspected kernel generation.
This is verifier reference behavior, not code to place in `mesa-core` or Jael.

This review sampled the relevant integration paths. It was not a full kernel
audit, packet capture, independent verifier validation, or execution of the
Shrine branch. Phase 0 must produce a complete scope-specific source-to-test
inventory before claiming kernel PKI coverage.
