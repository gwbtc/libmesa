# Implementation language: an open question

**Status:** open. Earlier drafts of this repo assumed "Rust with a C FFI."
That was a default, not a decision — the spec is language-agnostic, and the
choice deserves its own argument. This doc frames it: Rust vs C vs both, in
general and in the Urbit context, plus what a dual-implementation program
buys and costs.

## The decision actually being made

Three separable questions, often conflated:

1. **What language is the reference implementation** — the one the spec is
   validated against and embedders reach for first?
2. **What ABI do embedders see?** A C ABI is the answer regardless of
   implementation language (every FFI story — Nostr clients, LND plugins,
   mobile, other languages' bindings — goes through a C-shaped surface).
3. **How many implementations does the project maintain?** The Hoon kernel
   and the C runtime already exist; libmesa is #3, and "C *and* Rust" would
   make four.

## Rust

**For, generally:** memory safety exactly where this library is most
exposed — a parser of hostile, unauthenticated UDP bytes plus a crypto
envelope (the validation pipeline of `spec/02-packets.md` is the CVE zone;
the kernel's own recent fixes — the `+mat` bound, jam-shape-before-cue — are
this bug class). First-class test/fuzz/property tooling for the
vector-driven conformance style this repo commits to. The needed crypto is
native and well-maintained (blake3's reference implementation is Rust;
ed25519/x25519-dalek, chacha20, secp256k1). Strong WASM story — browser
Nostr clients and phone runtimes are declared targets. Exporting a C ABI is
routine (`staticlib`/`cdylib` + cbindgen), so choosing Rust does not cost
the C-shaped embedding surface.

**Against, generally:** a heavier toolchain and binary footprint for
embedded/router-class targets; a learning curve for contributors coming
from the C side; ecosystem churn if async creep is allowed (mitigation:
sans-io core, no async in the engine).

**In the Urbit context:** the existing Urbit-adjacent Rust lives in
Zorp's Sword/NockVM lineage — nouns, jam/cue, mug already exist there, so
`mesa-noun` shrinks to vendoring-plus-glue (our own `hoon-rs` is syntax
tooling only, no noun runtime). Strategically, a Rust libmesa is the natural
networking layer for any future Sword-class runtime — the path where "the
runtime is libmesa + a Nock interpreter" becomes an in-process composition
rather than an FFI seam. Against: none of the gwbtc production surface is
Rust today; Vere, urcrypt, tcp-sidecar, comet-miner are all C (with Zig
builds), so Rust adds a second toolchain to the org's stack.

## C

**For, generally:** the universal FFI — a C libmesa is directly linkable
from literally everything with zero binding layer; minimal footprint;
maximal portability to constrained targets.

**In the Urbit context — the serious argument:** Vere is C. A C libmesa
could *share code with the runtime directly* — `pact.c` could become (or be
replaced by) libmesa's codec, and Vere could eventually link libmesa as its
mesa driver. That would collapse the "three implementations of the wire
format" problem to two (Hoon + libmesa) instead of adding a third C-parallel.
urcrypt links natively. And it's where the team's existing fluency is.

**Against:** memory safety on a hostile-input surface is exactly where C
keeps producing the bug class the kernel just patched; parser and
state-machine development is slower to make safe; fuzzing is remedial
rather than preventive; the WASM/mobile story is clunkier (emscripten). For
a from-scratch protocol engine in 2026 whose first consumers include
phones and browsers, these are heavy costs.

**Worth naming: Zig.** The org already builds Vere, comet-miner, and chorus
with Zig. Zig sits between the options (C ABI native, better safety
ergonomics than C, links C directly, young ecosystem, no borrow checker).
Listed for honesty; the crypto-ecosystem and WASM arguments still favor
Rust, and the code-sharing argument still favors C — Zig splits the
difference without winning either.

## Targeting both C and Rust from the agnostic spec

**Additional benefits of a dual program:**

- **Differential testing is the strongest conformance instrument there is.**
  Two independent implementations fuzzed against each other plus the golden
  vectors will find spec ambiguities that any single implementation silently
  papers over. This is the classic N-version argument, and for a protocol
  spec it is the difference between "the code is the spec" and an actually
  normative document.
- **Each implementation lands in its natural host:** the C one feeds Vere
  and embedded targets; the Rust one feeds WASM, mobile, and Sword-class
  runtimes. No single-language compromise.
- **It keeps the spec honest structurally** — mechanism/policy boundaries
  that survive two implementations are real; ones that don't were
  implementation accidents.

**Additional concerns:**

- **Double maintenance and drift.** Every protocol change lands twice or the
  implementations diverge — and we already flagged divergence (Hoon `plot`
  vs `pact.c`) as a standing hazard of the *existing* two implementations.
  Four codebases of one protocol is a lot of surface for this team size.
  Mitigation is vectors + CI, but that mitigates, not removes.
- **Split attention slows v1.** The near-term goal is a working peer to
  argue with, not a conformance program.
- **Authority ambiguity.** When the two disagree, which is right? Answer
  must be "the spec + vectors," which requires the discipline to fix the
  spec first — worth stating as policy now if the dual path is chosen.
- **Feature skew:** optional policies and extensions will land unevenly,
  fragmenting what "libmesa supports X" means.

**Middle paths** (probably where the answer lives):

- **One primary now, second later as a conformance exercise.** Pick one
  language for milestone 1–7; once the spec stabilizes and vectors are rich,
  a second implementation becomes a well-scoped, high-value project (and a
  good onboarding vehicle for new contributors) rather than a drag on v1.
- **Split by artifact, not by whole:** e.g. the wire codec exists in both
  (tiny, vector-driven, cheap to dual-maintain, and it's where differential
  testing pays most) while the engine exists once.

## Proposed framing for the WG (not a decision)

Treat as two votes:

1. **Primary implementation language.** The safety/WASM/ecosystem case
   leans Rust; the Vere-code-sharing and team-fluency case leans C. If Rust:
   commit to the C ABI from day one and treat "Vere links libmesa" as a
   supported target anyway (Vere's Zig build can link a Rust staticlib). If
   C: commit to preventive fuzzing infrastructure from day one and accept
   the weaker browser/phone story.
2. **Dual-implementation posture.** Proposed: *one primary for v1; dual
   wire-codec early* (small, vector-driven, maximal differential-testing
   value); full second implementation deferred until spec stability, kept on
   the roadmap explicitly so the spec is written as if it will happen —
   because that pressure is most of the benefit.
