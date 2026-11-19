//! Drive this bridge before admitting further engine work after each authority
//! mutation/status change. It reads current policy, never a queued permission.
//! CORE cancellation is explicit; native recovery/control traffic uses the
//! separate admission path. This does not authenticate anonymous public peeks.
use crate::{Authority, Peer};
use mesa_core::{
    host::CredentialUpdate, protection::SignedPublic, Action, Engine, Event, PeerId,
    PreconfiguredPeer,
};
use mesa_crypto::PublicKey;

impl Authority {
    pub fn sync_peer(
        &self,
        engine: &mut Engine<SignedPublic>,
        peer: Peer,
    ) -> Result<Vec<Action>, mesa_core::Error> {
        let old = engine
            .snapshot()
            .peers
            .into_iter()
            .find(|p| p.peer.id == PeerId(peer));
        let Some(p) = self.peer(peer) else {
            // A withdrawal fence or unresolved lookup may have no accepted
            // point. Taking authority over a preconfigured engine must close
            // that peer's old service gate, not leave it open on an error.
            return if old.is_some_and(|p| p.peer.service_allowed) {
                engine.step(Event::SetService {
                    peer: PeerId(peer),
                    allowed: false,
                })
            } else {
                Ok(vec![])
            };
        };
        let policy = self.policy(peer).expect("present");
        // Never provision a candidate before durable acceptance. Close an
        // existing gate immediately while a proposal/revalidation is pending.
        if !policy.committed || !policy.revalidated {
            return if old.is_some_and(|p| p.peer.service_allowed) {
                engine.step(Event::SetService {
                    peer: PeerId(peer),
                    allowed: false,
                })
            } else {
                Ok(vec![])
            };
        }
        let c = &p.point.candidate;
        let handle = match &old {
            Some(p) => p.peer.key,
            None => engine.free_public_key_handle()?,
        };
        let mut view = PreconfiguredPeer::new(PeerId(peer), &c.domain, c.life, c.rift, handle)?;
        view.service_allowed = policy.ordinary();
        if let Some(old) = &old {
            if old.peer == view && engine.remote_public_key(PeerId(peer)) == Some(c.public_key) {
                return Ok(vec![]);
            }
            if engine.remote_public_key(PeerId(peer)) == Some(c.public_key)
                && old.peer.life == view.life
                && old.peer.rift == view.rift
                && old.peer.domain() == view.domain()
            {
                return engine.step(Event::SetService {
                    peer: PeerId(peer),
                    allowed: view.service_allowed,
                });
            }
        }
        let generation = old.as_ref().map_or(0, |p| p.credential_generation);
        engine.install_public_credential(
            CredentialUpdate {
                breach: old.as_ref().is_some_and(|p| c.rift > p.peer.rift),
                peer: view,
                expected_generation: generation,
                generation: generation
                    .checked_add(1)
                    .ok_or(mesa_core::Error::GenerationOverflow)?,
            },
            PublicKey::from_bytes(c.public_key).map_err(|_| mesa_core::Error::MissingKey)?,
        )
    }
}
