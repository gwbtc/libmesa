//! Noun primitives for libmesa.
//!
//! Scope (spec ch. 1 §7 governs the hardening requirements):
//! - `jam`/`cue` noun serialization, with jam-shape validation before cue
//! - `mug` (murmur3-based noun hash; also the packet-header checksum)
//! - `mat`/`rub` length-prefixed atom encoding, with the bounded
//!   zero-run scan (kernel commit 382243cd7c) enforced unconditionally
//! - atom views: `@p`/`@q`/`@uv` rendering
//!
//! Implemented: canonical atoms and byte mug. Wire fixtures exercise mug
//! against Hoon/C checksums. Jam/cue, mat/rub, and rendering remain planned.

pub mod atom;
pub mod mug;
