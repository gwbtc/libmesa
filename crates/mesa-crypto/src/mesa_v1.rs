//! Mesa-v1 two-party protection. Path serialization and peer authority belong
//! to callers; these operations accept exact bytes and contain no noun codec.
use chacha20::{
    cipher::{KeyIvInit, StreamCipher},
    XChaCha8,
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Limit,
    Authentication,
    Ciphertext,
}
/// Shared agreement key. It is never serialized, cloned, or formatted.
pub struct Secret(Zeroizing<[u8; 32]>);
impl Secret {
    pub fn from_agreement(shared: &crate::SharedSecret) -> Self {
        Self::from_bytes(*shared.as_bytes())
    }
    /// Trusted key backend seam; importing bytes grants no peer authority.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }
    pub fn seal_path(&self, path: &[u8], max: usize) -> Result<Vec<u8>, Error> {
        if path.len().checked_add(17).is_none_or(|n| n > max) {
            return Err(Error::Limit);
        }
        let keys = self.path_keys();
        let tag = tag((&keys[32..]).try_into().unwrap(), path);
        let mut ciphertext = path.to_vec();
        crypt((&keys[..32]).try_into().unwrap(), &tag, &mut ciphertext);
        let mut out = Vec::with_capacity(path.len() + 17);
        out.extend(tag);
        out.extend(ciphertext);
        out.push(1);
        Ok(out)
    }
    pub fn open_path(&self, sealed: &[u8], max: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
        if sealed.len() > max {
            return Err(Error::Limit);
        }
        if sealed.len() < 17 || sealed.last() != Some(&1) {
            return Err(Error::Ciphertext);
        }
        let keys = self.path_keys();
        let mut path = Zeroizing::new(sealed[16..sealed.len() - 1].to_vec());
        crypt((&keys[..32]).try_into().unwrap(), &sealed[..16], &mut path);
        if !bool::from(tag((&keys[32..]).try_into().unwrap(), &path).ct_eq(&sealed[..16])) {
            return Err(Error::Authentication);
        }
        Ok(path)
    }
    /// Encrypt exact plaintext bytes under the sealed-path IV. The caller must
    /// authenticate the ciphertext root before attempting decryption.
    pub fn encrypt(&self, iv: &[u8], bytes: &[u8], max: usize) -> Result<Vec<u8>, Error> {
        if bytes.len().checked_add(1).is_none_or(|n| n > max) {
            return Err(Error::Limit);
        }
        let mut out = bytes.to_vec();
        crypt(&self.0, iv, &mut out);
        out.push(1);
        Ok(out)
    }
    pub fn decrypt(
        &self,
        iv: &[u8],
        bytes: &[u8],
        max: usize,
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        if bytes.len() > max {
            return Err(Error::Limit);
        }
        if bytes.last() != Some(&1) {
            return Err(Error::Ciphertext);
        }
        let mut out = Zeroizing::new(bytes[..bytes.len() - 1].to_vec());
        crypt(&self.0, iv, &mut out);
        Ok(out)
    }
    pub fn mac(&self, path: &[u8], root: &[u8; 32]) -> [u8; 16] {
        let mut h = blake3::Hasher::new_keyed(&self.0);
        h.update(path);
        h.update(root);
        let mut out = [0; 16];
        h.finalize_xof().fill(&mut out);
        out
    }
    pub fn verify_mac(&self, path: &[u8], root: &[u8; 32], mac: &[u8; 16]) -> bool {
        bool::from(self.mac(path, root).ct_eq(mac))
    }
    fn path_keys(&self) -> Zeroizing<[u8; 64]> {
        let mut out = Zeroizing::new([0; 64]);
        blake3::Hasher::new_derive_key("mesa-aead")
            .update(&*self.0)
            .finalize_xof()
            .fill(&mut *out);
        out
    }
}
fn tag(key: &[u8; 32], bytes: &[u8]) -> [u8; 16] {
    let mut out = [0; 16];
    blake3::Hasher::new_keyed(key)
        .update(bytes)
        .finalize_xof()
        .fill(&mut out);
    out
}
fn crypt(key: &[u8; 32], iv: &[u8], bytes: &mut [u8]) {
    let mut nonce = [0; 24];
    blake3::Hasher::new_derive_key("mesa-crypt-iv")
        .update(iv)
        .finalize_xof()
        .fill(&mut nonce);
    XChaCha8::new(key.into(), (&nonce).into()).apply_keystream(bytes);
}
