# Fresh-context handoff: Shrine, suite-C PKI and native Urbit peers

**Implementation checkpoint, 2026-11-19.** PR #12 merged phases 1–3 at
`e02a41aff0b46961bb6d77669d7b784189000782`. Branch
`phase4-authority-admission` implements the authorized phase-4 PR. See
[the authority contract](../spec/16-authority-admission.md). Read the [phase-0 contract](17-raw-udp-phase0.md),
[API extension](../spec/15-raw-udp-host.md), and
[validation record](18-raw-udp-validation.md). Native live captures remain open.

## Read first

1. Read [the roadmap](14-shrine-groundwire-roadmap.md).
2. Read [the pinned reference snapshot](15-shrine-groundwire-reference.md).
3. Read [the current C contract](../spec/14-c-embedding.md) and the source for
   the phase being implemented. Use older identity docs for invariants, not
   their superseded scheduling or external-Jael assumption.

The user authorized one phase-4 PR after reviewing the ownership correction.
Keep Shrine-side migration and native wire integration out of scope. Stop after
opening the phase-4 PR; local activation is phase 5. Native phase-0 captures
and live interoperability remain open.

## Settled direction

- Shrine uses the UDP adapter. Live Shrine-to-Shrine acceptance precedes
  Shrine-to-Urbit; host-harness tests do not substitute for that joint gate.
- Shrine integration is first. Native communication with existing Urbit nodes
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
- Finish three bounded embedding gates, then focus on PKI. Start provider
  contract and native profile research immediately; avoid general transport
  or inbox expansion before the PKI pivot.

## Latest user clarification

Shrine's `ic-net` work was built against libmesa before PR #11. Its authors will
fix the integration from their side. Do not spend this phase migrating Shrine
or treating the old bridge as the required new API. Extract host requirements,
publish libmesa contracts, and refresh the successor branch when available.

The primary scope is suite-C comets / Groundwire IDs, whether Shrine or Urbit.
Native legacy packet handling may still be necessary for those peers; that
does not put Azimuth-ID peers back on the critical path.

## Baseline and workspace care

Plan base: libmesa main `041f2148379bf9232063a9f7d6f6e4e45e4c6b0c`, merged PR #11.
Plan branch: `codex/shrine-pki-roadmap`; implementation branch:
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

Carry forward the native-profile investigation alongside those changes. The
existing v2 Hoon endpoint is not native Ames/Mesa interop, and `flow/2/...` is
not native `%plea`/`%boon`. Kernel-native proof, spaces, crypto contexts and
identity-control behavior need their own fixtures and acceptance tests.

Do not silently retain the old requirement to patch Urbit's rekey announcements.
The revised default is a separate native compatibility module supporting the
control subset required by suite-C peers. Determine that subset from the
pinned kernel and captures before committing to its implementation size.

## Decisions and external dependencies to resolve

| Decision | Evidence or owner needed |
|---|---|
| Updated Shrine bridge/API and capacity requirements | Shrine/Enki authors; PR #11 is the available public API baseline |
| Shrine world identity versus Groundwire network persona | Joint host design; current `pass.foil` names are a different scheme |
| Native Urbit target | Actual deployed source, desk, executable and pill hashes; `gw/final` is an inspected candidate |
| Required control subset and oversized proof handling | Kernel/source traces; current proof intake expects one 1,024-byte fragment |
| Real Groundwire authority provider | Host team; interface must cover readiness, view, generations, verdicts and withdrawals |
| Durable PKI activation and restored-world epochs | Host transaction and secret-storage design; keep independent of the inbox |
| Application service and payload mapping | Joint Shrine/Urbit application contract, after native protocol mapping |

A configured route may bootstrap connectivity. A configured positive verdict
does not prove Groundwire PKI. Likewise, a successful signed read does not
prove private access control, durable acceptance or rekey recovery.

## Validation status

Phase-4 evidence is recorded in [the authority validation report](19-authority-admission-validation.md).

The phase PR ran raw-host, Rust workspace, C ownership/crash and UDP tests;
see the validation record for commands and limits. No live Shrine or native
Urbit integration was executed. Phase-4 provider fixtures prove orchestration,
not Groundwire evidence verification. Earlier native acceptance records are
historical evidence only.

Implementation reports must distinguish deterministic simulation, compiled-host
execution, native codec conformance and live joint integration. Keep exact
source/pill/runtime/provider provenance with the acceptance evidence.

## Phase-4 ownership clarification

“Embedding host” means the Mesa client, such as Shrine, not the underlying
Unix OS. Its scheduler drives Mesa; Mesa owns incoming protocol parsing and
admission. Shrine first receives a bounded attestation-verification request,
then supplies its verifier's verdict and durable commit completion. A composed
client receives admitted messages after its wrapper handles those services.
See roadmap section 3 for the shared terminology and incoming sequence.
Shrine-side migration and native packet integration remain outside phase 4.
