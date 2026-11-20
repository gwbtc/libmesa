//! Local credential changes rebuild soft work from committed flow state.
use super::*;
use mesa_crypto::{KeyPair, PublicKey};
use std::sync::Arc;
#[derive(Clone, Debug)]
pub struct CredentialPlan {
    pub checkpoint: Checkpoint,
    pub retired: Vec<MessageId>,
}
impl Node {
    pub fn local_view(&self) -> PreconfiguredPeer {
        self.core.local_view()
    }
    pub fn local_generation(&self) -> u64 {
        self.core.local_generation()
    }
    pub fn send_gate(&self) -> mesa_core::credentials::SendGate {
        self.core.send_gate()
    }
    pub fn is_quiescent(&self) -> bool {
        self.credentials_quiescent
    }
    /// Close output immediately. Existing delivery/storage decisions may still
    /// finish, but no new delivery/read/send is produced until activation.
    pub fn quiesce(&mut self) -> Result<Vec<Action>, Error> {
        self.core.quiesce()?;
        self.credentials_quiescent = true;
        self.timer = None;
        self.hints.clear();
        let mut out = vec![];
        for (_, work) in std::mem::take(&mut self.jobs) {
            out.push(Action::Stalled {
                flow: work.flow,
                sequence: work.sequence,
                kind: work.kind,
                failure: Failure::Read(ReadFailure::PeerReset),
            });
        }
        self.stalled.clear();
        out.push(Action::SetTimer(None));
        Ok(out)
    }
    pub fn credential_plan(
        &self,
        local: &PreconfiguredPeer,
        peers: &[PreconfiguredPeer],
    ) -> Result<CredentialPlan, Error> {
        if !self.credentials_quiescent || self.pending.is_some() || self.delivery.is_some() {
            return Err(Error::Busy);
        }
        if local.id.0 != self.checkpoint.local.name
            || local.domain().as_str() != self.checkpoint.local.domain
            || local.rift < self.checkpoint.local.rift
        {
            return Err(Error::EpochMismatch);
        }
        let mut next = self.checkpoint.clone();
        let mut retired = vec![];
        for f in &mut next.flows {
            let remote = peers
                .iter()
                .find(|p| p.id.0 == f.remote.name)
                .ok_or(Error::UnknownFlow)?;
            if remote.domain().as_str() != f.remote.domain || remote.rift < f.remote.rift {
                return Err(Error::EpochMismatch);
            }
            if local.rift != self.checkpoint.local.rift || remote.rift != f.remote.rift {
                for sequence in f.outbox.keys() {
                    retired.push(self.checkpoint.message_id(f.flow, *sequence, false));
                }
                f.remote = remote.into();
                f.next_send = 0;
                f.send_floor = 0;
                f.receive_floor = 0;
                f.outbox.clear();
                f.settled.clear();
                f.received.clear();
            }
        }
        next.local = local.into();
        next.revision = next.expected_revision().ok_or(Error::InvalidCheckpoint)?;
        Ok(CredentialPlan {
            checkpoint: next,
            retired,
        })
    }
    /// The embedding host commits CredentialPlan with its activation manifest.
    /// new_incarnation MUST be fresh for the rebuilt node, even at the same rift.
    pub fn activate_credentials(
        &mut self,
        local: PreconfiguredPeer,
        key: Arc<KeyPair>,
        peers: Vec<(PreconfiguredPeer, PublicKey)>,
        checkpoint: Checkpoint,
        generation: u64,
        new_incarnation: u128,
    ) -> Result<(), Error> {
        if new_incarnation == 0
            || new_incarnation == self.incarnation
            || generation <= self.local_generation()
        {
            return Err(Error::CommitToken);
        }
        let views: Vec<_> = peers.iter().map(|(v, _)| v.clone()).collect();
        if self.credential_plan(&local, &views)?.checkpoint != checkpoint {
            return Err(Error::InvalidCheckpoint);
        }
        let keys = peers.iter().map(|(v, k)| (v.key, k.clone())).collect();
        let mut flows = self.flows.clone();
        for f in &mut flows {
            f.peer = views
                .iter()
                .find(|p| p.id == f.peer.id)
                .ok_or(Error::UnknownFlow)?
                .clone();
        }
        let profile = SignedPublic::with_key(local.key, key.clone(), keys);
        let mut replacement = Self::new(
            self.config.clone(),
            local.clone(),
            profile,
            flows,
            checkpoint,
            new_incarnation,
        )?;
        replacement.core.quiesce()?;
        replacement.now = self.now;
        replacement
            .core
            .step(mesa_core::Event::AdvanceTo(self.now))?;
        replacement.core.activate_local(local, key, 0, generation)?;
        *self = replacement;
        Ok(())
    }
    pub fn configured_peers(&self) -> Vec<PreconfiguredPeer> {
        self.flows.iter().map(|f| f.peer.clone()).collect()
    }
}
