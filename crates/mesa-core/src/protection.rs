//! Mesa-v1 ROOT protection and explicit experimental signed-public compatibility.
use crate::{KeyHandle, PreconfiguredPeer, Protection};
use mesa_crypto::{KeyPair, PublicKey};
use mesa_wire::Name;
use std::{collections::BTreeMap, sync::Arc};

/// Trusted public-key table. Key handles are local and never transmitted.
/// Engine::install_public_credential supports bounded, atomic remote rotation.
pub struct SignedPublic {
    profile: crate::Profile,
    contexts: BTreeMap<crate::PeerId, Vec<u8>>,
    local_handle: KeyHandle,
    local: Arc<KeyPair>,
    peers: BTreeMap<KeyHandle, PublicKey>,
}
impl SignedPublic {
    /// Select Mesa-v1 with authenticated namespace prefixes supplied by the
    /// profile boundary. Its precise binding is defined by that profile.
    pub fn mesa_v1(mut self, contexts: BTreeMap<crate::PeerId, Vec<u8>>) -> Self {
        self.profile = crate::Profile::MesaV1;
        self.contexts = contexts;
        self
    }
    pub fn secret(&self, peer: &PreconfiguredPeer) -> Option<mesa_crypto::mesa_v1::Secret> {
        let shared = self.local.agree(self.peers.get(&peer.key)?).ok()?;
        Some(mesa_crypto::mesa_v1::Secret::from_agreement(&shared))
    }
    fn context(
        &self,
        peer: &PreconfiguredPeer,
        name: Name<'_>,
        total: u64,
        root: &[u8; 32],
    ) -> Option<Vec<u8>> {
        if self.profile == crate::Profile::LibmesaExpV2 {
            return Some(root_context(peer, name, total, root));
        }
        let mut out = self.contexts.get(&peer.id)?.clone();
        out.extend_from_slice(name.path);
        out.extend_from_slice(root);
        Some(out)
    }

    /// Default Mesa-v1 mechanism. Install immutable namespaces before binding
    /// or reading objects; missing namespaces fail closed.
    pub fn new(
        local_handle: KeyHandle,
        local: KeyPair,
        peers: BTreeMap<KeyHandle, PublicKey>,
    ) -> Self {
        Self::experimental_v2(local_handle, local, peers).mesa_v1(BTreeMap::new())
    }
    /// Explicit libmesa-exp-v2 compatibility; never selected by packet input.
    pub fn experimental_v2(
        local_handle: KeyHandle,
        local: KeyPair,
        peers: BTreeMap<KeyHandle, PublicKey>,
    ) -> Self {
        Self {
            profile: crate::Profile::LibmesaExpV2,
            contexts: BTreeMap::new(),
            local_handle,
            local: Arc::new(local),
            peers,
        }
    }
    pub fn experimental_v2_with_key(
        local_handle: KeyHandle,
        local: Arc<KeyPair>,
        peers: BTreeMap<KeyHandle, PublicKey>,
    ) -> Self {
        Self {
            profile: crate::Profile::LibmesaExpV2,
            contexts: BTreeMap::new(),
            local_handle,
            local,
            peers,
        }
    }
}

/// Canonical, length-delimited context. The root commits to fragment contents
/// and order; this transcript commits to the object's namespace and key life.
/// See spec/08-signed-public.md. Fragment coordinates are deliberately excluded:
/// one authenticated root covers all leaves of this immutable public object.
pub fn root_context(
    peer: &PreconfiguredPeer,
    name: Name<'_>,
    total: u64,
    root: &[u8; 32],
) -> Vec<u8> {
    let mut out = b"libmesa/v2/public-lss/1\0".to_vec();
    out.push(name.domain.as_str().len() as u8);
    out.extend_from_slice(name.domain.as_str().as_bytes());
    out.extend_from_slice(&name.publisher.0.to_le_bytes());
    out.extend_from_slice(&name.rift.to_le_bytes());
    out.extend_from_slice(&peer.life.to_le_bytes());
    out.push(name.bloq);
    out.extend_from_slice(&(name.path.len() as u16).to_le_bytes());
    out.extend_from_slice(name.path);
    out.extend_from_slice(&total.to_le_bytes());
    out.extend_from_slice(root);
    out
}
impl Protection for SignedPublic {
    const SIGNED_PUBLIC: bool = true;
    fn profile(&self) -> crate::Profile {
        self.profile
    }
    fn sign_object(
        &self,
        local: &PreconfiguredPeer,
        recipient: Option<&PreconfiguredPeer>,
        name: Name<'_>,
        total: u64,
        root: &[u8; 32],
    ) -> Option<crate::RootAuth> {
        match recipient {
            None => self
                .sign_root(local, name, total, root)
                .map(crate::RootAuth::Signature),
            Some(peer) if self.profile == crate::Profile::MesaV1 => {
                let context = self.context(local, name, total, root)?;
                let secret = self.secret(peer)?;
                Some(crate::RootAuth::Mac(
                    secret.mac(&context[..context.len() - 32], root),
                ))
            }
            _ => None,
        }
    }
    fn verify_object(
        &self,
        _local: &PreconfiguredPeer,
        peer: &PreconfiguredPeer,
        private: bool,
        name: Name<'_>,
        data: mesa_wire::Data<'_>,
        root: &[u8; 32],
    ) -> bool {
        if !private {
            return matches!(data.auth, mesa_wire::Auth::Signature(s) if s.try_into().is_ok_and(|s|self.verify_root(peer,name,data.total_bytes,root,s)));
        }
        if self.profile != crate::Profile::MesaV1 {
            return false;
        }
        let mesa_wire::Auth::Mac(mac) = data.auth else {
            return false;
        };
        let Some(context) = self.context(peer, name, data.total_bytes, root) else {
            return false;
        };
        self.secret(peer)
            .is_some_and(|secret| secret.verify_mac(&context[..context.len() - 32], root, mac))
    }
    fn local_key_available(&self, local: &PreconfiguredPeer) -> bool {
        local.key == self.local_handle && local.life > 0
    }
    fn peer_key_available(&self, peer: &PreconfiguredPeer) -> bool {
        peer.life > 0 && self.peers.contains_key(&peer.key)
    }
    fn verify(&mut self, _: &PreconfiguredPeer, _: &PreconfiguredPeer, _: &[u8]) -> bool {
        // This hook is reserved for the original controlled-verdict harness.
        // Public peeks confer no requester identity; pages use verify_root + LSS.
        false
    }
    fn sign_root(
        &self,
        local: &PreconfiguredPeer,
        name: Name<'_>,
        total: u64,
        root: &[u8; 32],
    ) -> Option<[u8; 64]> {
        self.local_key_available(local).then_some(())?;
        Some(self.local.sign(&self.context(local, name, total, root)?))
    }
    fn verify_root(
        &self,
        peer: &PreconfiguredPeer,
        name: Name<'_>,
        total: u64,
        root: &[u8; 32],
        signature: &[u8; 64],
    ) -> bool {
        self.peers.get(&peer.key).is_some_and(|key| {
            self.context(peer, name, total, root)
                .is_some_and(|context| key.verify(&context, signature).is_ok())
        })
    }
}

impl crate::Engine<SignedPublic> {
    /// Install a stable profile namespace prefix. It grants no peer authority.
    /// A prefix cannot change within an engine lifetime.
    pub fn install_namespace(
        &mut self,
        peer: crate::PeerId,
        prefix: Vec<u8>,
    ) -> Result<(), crate::Error> {
        if self.protection.profile != crate::Profile::MesaV1
            || prefix.is_empty()
            || prefix.len() > 320
        {
            return Err(crate::Error::InvalidPath);
        }
        if let Some(old) = self.protection.contexts.get(&peer) {
            return if old == &prefix {
                Ok(())
            } else {
                Err(crate::Error::NameInUse)
            };
        }
        if self.protection.contexts.len() > self.config.max_peers {
            return Err(crate::Error::ResourceLimit);
        }
        let revision = self
            .revision
            .checked_add(1)
            .ok_or(crate::Error::GenerationOverflow)?;
        self.protection.contexts.insert(peer, prefix);
        self.revision = revision;
        Ok(())
    }
    /// Derive private-space operations from the currently installed key table.
    /// The service profile owns path serialization; this returns no raw key.
    pub fn private_space(
        &self,
        peer: crate::PeerId,
    ) -> Result<mesa_crypto::mesa_v1::Secret, crate::Error> {
        if self.protection.profile != crate::Profile::MesaV1
            || self.quiescent
            || !self.send_gate.is_open()
        {
            return Err(crate::Error::Blocked);
        }
        let view = &self.peers.get(&peer).ok_or(crate::Error::UnknownPeer)?.view;
        if !view.service_allowed {
            return Err(crate::Error::Blocked);
        }
        self.protection.secret(view).ok_or(crate::Error::MissingKey)
    }
    /// Install a remote public key and its credential as one validated mutation.
    /// Handles cannot alias another peer or the local signer. Replacement at the
    /// same life is forbidden even when the caller reuses a handle. Failed CAS or
    /// coordinate validation leaves the key table and all reads unchanged.
    pub fn install_public_credential(
        &mut self,
        update: crate::host::CredentialUpdate,
        key: PublicKey,
    ) -> Result<Vec<crate::Action>, crate::Error> {
        let id = update.peer.id;
        let handle = update.peer.key;
        if handle == self.protection.local_handle
            || self
                .peers
                .values()
                .any(|p| p.view.id != id && p.view.key == handle)
        {
            return Err(crate::Error::KeyConflict);
        }
        if let Some(old) = self.peers.get(&id) {
            if old.view.life == update.peer.life
                && self
                    .protection
                    .peers
                    .get(&old.view.key)
                    .is_some_and(|k| k.as_bytes() != key.as_bytes())
            {
                return Err(crate::Error::KeyConflict);
            }
        }
        if !self.protection.peers.contains_key(&handle)
            && self.protection.peers.len() >= self.config.max_peers
        {
            return Err(crate::Error::ResourceLimit);
        }
        let old_handle = self.peers.get(&id).map(|p| p.view.key);
        let previous = self.protection.peers.insert(handle, key);
        let result = self.step(crate::Event::InstallCredential(update));
        if result.is_err() {
            if let Some(old) = previous {
                self.protection.peers.insert(handle, old);
            } else {
                self.protection.peers.remove(&handle);
            }
        } else if let Some(old) = old_handle {
            if old != handle
                && old != self.protection.local_handle
                && !self.peers.values().any(|p| p.view.key == old)
            {
                self.protection.peers.remove(&old);
            }
        }
        result
    }

    pub fn remote_public_key(&self, peer: crate::PeerId) -> Option<[u8; 32]> {
        self.peers
            .get(&peer)
            .and_then(|p| self.protection.peers.get(&p.view.key))
            .map(|k| *k.as_bytes())
    }

    /// A free local handle; selection establishes no authority. Existing peers
    /// should reuse their dedicated slot so rotations do not consume capacity.
    pub fn free_public_key_handle(&self) -> Result<KeyHandle, crate::Error> {
        (0..=self.protection.peers.len() as u64 + 1)
            .map(KeyHandle)
            .find(|h| *h != self.protection.local_handle && !self.protection.peers.contains_key(h))
            .ok_or(crate::Error::ResourceLimit)
    }
}

impl crate::Engine<SignedPublic> {
    /// Requires prior quiescence. The trusted activation coordinator validates
    /// durable authority and key custody before calling this low-level seam.
    pub fn activate_local(
        &mut self,
        view: PreconfiguredPeer,
        key: Arc<KeyPair>,
        expected: u64,
        generation: u64,
    ) -> Result<(), crate::Error> {
        use crate::Error;
        if !self.quiescent {
            return Err(Error::Blocked);
        }
        if self.local_generation != expected || generation <= expected {
            return Err(Error::StaleGeneration);
        }
        if view.id != self.local.id || view.domain() != self.local.domain() {
            return Err(Error::DomainConflict);
        }
        if view.life == 0 || view.life < self.local.life || view.rift < self.local.rift {
            return Err(Error::CoordinateRegression);
        }
        if expected > 0
            && view.life == self.local.life
            && key.public_key().as_bytes() != self.protection.local.public_key().as_bytes()
        {
            return Err(Error::KeyConflict);
        }
        if self.protection.peers.contains_key(&view.key) {
            return Err(Error::KeyConflict);
        }
        let revision = self
            .revision
            .checked_add(1)
            .ok_or(Error::GenerationOverflow)?;
        if view.rift > self.local.rift {
            self.bindings.clear();
            self.retired.clear();
        }
        if key.public_key().as_bytes() != self.protection.local.public_key().as_bytes() {
            for binding in self.bindings.values_mut().flatten() {
                binding.signature_life = 0;
                binding.signature = None;
            }
        }
        self.send_gate.change(true)?;
        self.protection.local = key;
        self.protection.local_handle = view.key;
        self.local = view;
        self.local_generation = generation;
        self.revision = revision;
        self.quiescent = false;
        Ok(())
    }
}

pub fn root_context_owned(
    peer: &PreconfiguredPeer,
    path: &[u8],
    total: u64,
    root: &[u8; 32],
) -> Vec<u8> {
    root_context(
        peer,
        Name {
            publisher: peer.id,
            domain: peer.domain(),
            rift: peer.rift,
            bloq: 13,
            fragment: mesa_wire::Fragment::Auth(0),
            path,
        },
        total,
        root,
    )
}
