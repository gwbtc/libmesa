//! Noun primitives for libmesa.
//!
//! Scope (spec ch. 1 §7 governs the hardening requirements):
//! - `jam`/`cue` noun serialization, with jam-shape validation before cue
//! - `mug` (murmur3-based noun hash; also the packet-header checksum)
//! - `mat`/`rub` length-prefixed atom encoding, with the bounded
//!   zero-run scan (kernel commit 382243cd7c) enforced unconditionally
//! - atom views: `@p`/`@q`/`@uv` rendering
//!
//! Everything here is vector-driven: see `tests/vectors.rs`, which runs
//! the golden fixtures in `../../vectors/noun/`. No vectors, no merge.

pub mod atom;

/// Placeholder so the workspace builds before milestone-1 code lands.
pub const KELVIN: u32 = 9;
