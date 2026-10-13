//! Atoms as little-endian byte strings.
//!
//! Milestone-1 stub: the representation is decided (`Vec<u8>`, LE,
//! no trailing zero bytes — canonical form), the operations land with
//! the vectors.

/// A natural number as canonical little-endian bytes (no trailing zeros).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Atom(pub Vec<u8>);

impl Atom {
    /// Byte length (`met 3` in Hoon terms).
    pub fn met3(&self) -> usize {
        self.0.len()
    }
}
