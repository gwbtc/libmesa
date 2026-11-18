//! Shared immutable [dat wid] buffers. No noun or integer-arithmetic semantics.
use std::sync::Arc;
pub mod mug;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Buffer {
    dat: Arc<Vec<u8>>,
    wid: usize,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Width,
    Range,
}
impl Buffer {
    /// Normalize little-endian data; width includes any implicit zero suffix.
    /// No allocation proportional to width occurs here.
    pub fn new(mut dat: Vec<u8>, wid: usize) -> Result<Self, Error> {
        if dat.len() > wid {
            return Err(Error::Width);
        }
        while dat.last() == Some(&0) {
            dat.pop();
        }
        // Do not retain a potentially large zero-filled allocation.
        dat.shrink_to_fit();
        Ok(Self {
            dat: Arc::new(dat),
            wid,
        })
    }
    pub fn dat(&self) -> &[u8] {
        &self.dat
    }
    pub fn len(&self) -> usize {
        self.wid
    }
    pub fn is_empty(&self) -> bool {
        self.wid == 0
    }
    pub fn copy_range(&self, offset: usize, out: &mut [u8]) -> Result<(), Error> {
        if offset
            .checked_add(out.len())
            .is_none_or(|end| end > self.wid)
        {
            return Err(Error::Range);
        }
        out.fill(0);
        if offset < self.dat.len() {
            let n = out.len().min(self.dat.len() - offset);
            out[..n].copy_from_slice(&self.dat[offset..offset + n]);
        }
        Ok(())
    }
    pub fn to_vec(&self) -> Vec<u8> {
        let mut bytes = self.dat.to_vec();
        bytes.resize(self.wid, 0);
        bytes
    }
    /// Borrow canonical storage when already full-width; otherwise materialize
    /// a temporary logical byte view. This borrowing never crosses the C ABI.
    pub fn with_bytes<T>(&self, f: impl FnOnce(&[u8]) -> T) -> T {
        if self.dat.len() == self.wid {
            f(&self.dat)
        } else {
            f(&self.to_vec())
        }
    }
    pub fn shares_storage(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.dat, &other.dat)
    }
}
impl From<Vec<u8>> for Buffer {
    fn from(bytes: Vec<u8>) -> Self {
        let wid = bytes.len();
        Self::new(bytes, wid).expect("same width")
    }
}
impl PartialEq<Vec<u8>> for Buffer {
    fn eq(&self, other: &Vec<u8>) -> bool {
        self.wid == other.len()
            && other.starts_with(&self.dat)
            && other[self.dat.len()..].iter().all(|b| *b == 0)
    }
}
impl PartialEq<Buffer> for Vec<u8> {
    fn eq(&self, other: &Buffer) -> bool {
        other == self
    }
}

// Keep the existing checkpoint byte-array encoding: changing memory ownership
// must not silently change persisted flow format 2.
#[cfg(feature = "serde")]
impl serde::Serialize for Buffer {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut seq = serializer.serialize_seq(Some(self.wid))?;
        for i in 0..self.wid {
            seq.serialize_element(self.dat.get(i).unwrap_or(&0))?;
        }
        seq.end()
    }
}
#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Buffer {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(<Vec<u8> as serde::Deserialize>::deserialize(deserializer)?.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn widths_and_sharing_preserve_exact_values() {
        let b = Buffer::new(vec![1, 0], 4).unwrap();
        assert_eq!(b.dat(), &[1]);
        assert_eq!(b.to_vec(), [1, 0, 0, 0]);
        assert_ne!(b, Buffer::from(vec![1]));
        assert!(b.shares_storage(&b.clone()));
        let mut suffix = [9; 3];
        b.copy_range(1, &mut suffix).unwrap();
        assert_eq!(suffix, [0; 3]);
        assert_eq!(b.copy_range(usize::MAX, &mut suffix), Err(Error::Range));
        assert_eq!(suffix, [0; 3]);
        assert_eq!(Buffer::new(vec![1], 0), Err(Error::Width));
        assert_ne!(Buffer::default(), Buffer::new(vec![], 3).unwrap());
        // A sparse logical value never allocates its width at construction.
        assert!(Buffer::new(vec![], usize::MAX).unwrap().dat().is_empty());
    }
}
