# Fresh-context handoff: Shrine, suite-C PKI and Mesa-v1 peers

**Phase-6 implementation, 2026-11-27.** Branch `phase6-mesa-v1` builds on
merged PR #14 and the native-target investigation. The shared engine now
supports Mesa-v1; `mesa-urbit` supplies its bounded Urbit edge. Read
[the validation record](25-mesa-profile-validation.md),
[the normative API](../spec/18-mesa-profile.md), and
[the live evidence](../investigation/phase6/README.md) before starting new work.

Mesa-v1 is the new-engine default. The explicit experimental constructors,
ABI 1 and `libmesa-flow/2` checkpoints remain compatible. No state conversion
or managed-inbox migration is included. The latest implementation authorization
ends with one phase-6 PR; phase 7 still needs its own review and scope agreement.

The next project boundary is real host-provided Groundwire verification and
joint Shrine UDP integration. Preserve Shrine-to-Shrine acceptance before
Shrine-to-Urbit. Host-harness tests do not satisfy that gate. The fixed verifier
used by live tests is an exact-pass fixture, not a production verifier.

## Read first

1. [Roadmap](14-shrine-groundwire-roadmap.md), especially phase 7.
2. [Mesa profile contract](../spec/18-mesa-profile.md) and the new C events.
3. [Retention and Urbit crash semantics](24-retention-and-urbit-crash-semantics.md).
4. [Pinned integration reference](15-shrine-groundwire-reference.md).

## Settled direction

- Put reusable Mesa-v1 framing/protection/transfer/flow mechanisms in the core
  crates. Limit `mesa-urbit` to serialization, naming, service conventions and
  required old-Ames identity controls. Freeze experimental profile development;
  preserve explicit restores and fixtures without reinterpreting old state.
- Shrine uses the UDP adapter. Live Shrine-to-Shrine acceptance precedes
  Shrine-to-Urbit; host-harness tests do not substitute for that joint gate.
- Shrine integration is first. Urbit-Mesa communication with existing Urbit nodes
  is second. Replacing Ames in Vere is a separate future project.
- Primary peers use suite-C/Groundwire identities on either runtime.
  Azimuth-ID interoperability and its associated bootstrap work wait.
- Shrine has no existing Jael. Supply all relevant kernel-side PKI mechanisms
  as Mesa modules, with Jael independently selectable. Verifiers stay external.
- OS hosts choose and orchestrate modules and provide verifiers. Later, a
  composed wrapper and standalone verifier plugins serve non-OS hosts.
- Keep immutable refcounted `[dat wid]` values, no nouns in core/public APIs,
  explicit mutation, stable configuration descriptions and batched processing.
- Raw CORE, raw FLOW, transport adapters and managed inbox stay separate.
  Shrine's named-read publication path does not require the managed inbox.
- Phases 1–5 are merged. Phase 6 implements Mesa-v1 and the Urbit-Mesa profile;
  phase 7 supplies real verification and joint host acceptance. Keep general
  transport and inbox expansion off that path.

## Latest user clarification

Shrine's `ic-net` work was built against libmesa before PR #11. Its authors will
fix the integration from their side. Do not spend this phase migrating Shrine
or treating the old bridge as the required new API. Extract host requirements,
publish libmesa contracts, and refresh the successor branch when available.

The primary scope is suite-C comets / Groundwire IDs, whether Shrine or Urbit.
Old-Ames identity controls remain required by the pinned Urbit peers; that
does not put Azimuth-ID peers back on the critical path.

## Baseline and workspace care

Historical phase-1 plan base: `041f2148379bf9232063a9f7d6f6e4e45e4c6b0c`, merged PR #11.
Historical plan branch: `codex/shrine-pki-roadmap`; implementation branch:
`codex/raw-udp-embedding`.

Local repositories used for source reading:

```text
/Users/armitage/r/gwbtc/libmesa
/Users/armitage/r/axsys-org/gh/shrine-plan
/Users/armitage/r/gwbtc/urbit
/Users/armitage/r/gwbtc/groundwire
```

Shrine had unrelated modified/untracked work on `cyc/cell-experiments` during
inspection. Its branch was read with `git show origin/ic-net:PATH`; no checkout
or edits were made. Preserve that work. Fetching a new reference does not
authorize modifying the host project.

Use the exact revisions in the snapshot before reading entire repositories.
The Enki revision was obtained from Shrine's lockfile; the bridge's underlying
Mesa dependency has not been independently verified. Capture that dependency
when the Shrine migration is ready for joint testing.

## Implemented raw-host scope and next boundary

The raw-host PR adds validated configuration, stable descriptions and owned
state views, batched Rust/C results, trusted credential/attachment generation
checks, and shared UDP routing. Publication retirement uses the existing
monotonic prefix fence, tested through 1,000 cycles and host reconstruction.
The C UDP harness transfers among three peers under faults, then reconstructs
one raw host and verifies another read. These are not actual Shrine worlds.
Shrine's authors still own migration and joint live acceptance.

Use the completed phase-6 implementation and validation for the next phase. The experimental
Hoon endpoint speaks libmesa-exp-v2, and libmesa-flow/2 is not Urbit-Mesa
plea/boon messaging. Proofs, spaces, crypto contexts and identity controls
need their recorded fixtures and implementation acceptance tests.

Do not silently retain the old requirement to patch Urbit's rekey announcements.
The revised target is shared Mesa-v1 mechanisms plus a narrow Urbit-Mesa
boundary. Old-Ames `%keys`/open identity controls remain required; full
old-Ames messaging and relationship migration remain separate work.

## Decisions and external dependencies to resolve

| Decision | Evidence or owner needed |
|---|---|
| Updated Shrine bridge/API and capacity requirements | Shrine/Enki authors; PR #11 is the available public API baseline |
| Shrine world identity versus Groundwire network persona | Joint host design; current `pass.foil` names are a different scheme |
| Urbit-Mesa target | Pinned source, companion, executable and pill in `investigation/native/reference.json`; deployment claims require matching those pins |
| Required control subset and oversized proof handling | Kernel/source traces; current proof intake expects one 1,024-byte fragment |
| Real Groundwire authority provider | Host team; interface must cover readiness, view, generations, verdicts and withdrawals |
| Durable PKI activation and restored-world epochs | Host transaction and secret-storage design; keep independent of the inbox |
| Application service and payload mapping | Joint Shrine/Urbit application contract, after Urbit-Mesa profile mapping |

A configured route may bootstrap connectivity. A configured positive verdict
does not prove Groundwire PKI. Likewise, a successful signed read does not
prove private access control, durable acceptance or rekey recovery.

## Validation status

Phase 6 has shared Rust mechanism tests, a C UDP harness, 13 new Rust-process
SIGKILL boundaries and live exchanges with the pinned Urbit stack. Read
[the phase-6 validation report](25-mesa-profile-validation.md) for exact commands
and remaining limits. Earlier [phase-5](20-local-activation-validation.md) and
[phase-4](19-authority-admission-validation.md) reports remain historical evidence.

The final default is Mesa-v1. Explicit experimental callers preserve their old
behavior. The managed inbox stays on `libmesa-flow/2`; no Shrine changes,
Urbit kernel changes, or real Groundwire verifier are included.
