//! Noun primitives for libmesa.
//!
//! Scope (spec ch. 5 governs the identity hardening requirements):
//! - `jam`/`cue` noun serialization, with jam-shape validation before cue
//! - `mug` (murmur3-based noun hash; also the packet-header checksum)
//! - `mat`/`rub` length-prefixed atom encoding, with the bounded
//!   zero-run scan (kernel commit 382243cd7c) enforced unconditionally
//! - atom views: `@p`/`@q`/`@uv` rendering
//!
//! Implemented: canonical atoms, byte mug, and strict bounded mat/rub over
//! borrowed bit spans. Wire fixtures exercise mug against Hoon/C checksums.
//! Jam/cue and rendering remain planned.

pub mod atom;
pub mod bits;
pub mod mat;
pub mod mug;
