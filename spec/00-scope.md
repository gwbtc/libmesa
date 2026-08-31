# libmesa spec — 0: Scope and conventions

> **Skeleton.** Chapter outlines only; normative text lands per-milestone.
> Design rationale lives in `../doc/`; this tree is what implementations
> conform to.

## Outline

1. **Scope.** The Mesa protocol (packet, message, flow, namespace layers) and
   Groundwire identity (suite-%c passes, attestation, PKI-domain verdicts) as
   implemented by the gwbtc kernel (`hd/cc-kernel`) and runtime forks,
   restated transport- and host-independently. Mesa-only: no legacy ames, no
   Fine, no `%ahoy`.
2. **Conformance classes.** *Reader* (peek/page only) · *Peer* (+ flows) ·
   *Relay* (+ forwarding role) · *Verifier* (+ ≥1 PKI domain).
3. **Conventions.** RFC-2119 keywords. Mechanism vs policy: mechanisms are
   normative; policies have registries with mandatory-to-implement defaults
   (see `../doc/02-rina.md`). Vocabulary discipline: NDN terms in data-plane
   chapters, RINA terms in architecture chapters.
4. **Protocol kelvin.** This spec tracks gw protocol kelvin **9** (the kelvin
   is committed inside every suite-%c `dat`). Kelvin-change policy: never
   judge a foreign kelvin — no verdict, no snub.
5. **Golden vectors.** `../vectors/` is normative where present; conflicts
   between prose and vectors are spec bugs.
