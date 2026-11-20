//! No I/O, nouns or private-key serialization. Embedding hosts persist manifests
//! and key objects, and reconcile authority before allowing engine work.
pub use mesa_bytes::Buffer;
use mesa_core::{credentials::SendGate, KeyHandle, PeerId, PreconfiguredPeer};
use mesa_crypto::{KeyPair, PublicKey};
use mesa_pki::{Authority, Candidate};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::Arc};
pub mod operations;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Stale,
    Capacity,
    Unavailable,
    Conflict,
    Busy,
    Rollback,
    MissingKey,
    Clock,
    Backend,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyRef {
    pub backend: u128,
    pub object: u128,
    pub version: u64,
}
impl KeyRef {
    fn valid(self) -> bool {
        self.backend != 0 && self.object != 0 && self.version != 0
    }
}
/// Public binding produced by the selected profile. Ring/pass reconstruction
/// belongs to the optional codec. Importing a seed alone grants no authority.
pub struct Material {
    pass: Candidate,
    key: Arc<KeyPair>,
}
impl Material {
    pub fn binding(&self) -> Candidate {
        self.pass.clone()
    }
    pub fn from_seed(pass: Candidate, seed: &[u8; 32]) -> Result<Self, Error> {
        pass.validate(&mesa_pki::Limits::default())
            .map_err(|_| Error::Invalid)?;
        let key = Arc::new(KeyPair::from_seed(seed));
        if key.public_key().as_bytes() != &pass.public_key {
            return Err(Error::Conflict);
        }
        Ok(Self { pass, key })
    }
}
pub struct SoftwareStore {
    max_keys: usize,
    max_objects: usize,
    keys: BTreeMap<KeyRef, Material>,
    floors: BTreeMap<(u128, u128), u64>,
}
impl SoftwareStore {
    pub fn new(max_keys: usize, max_objects: usize) -> Result<Self, Error> {
        if !(1..=256).contains(&max_keys) || !(1..=256).contains(&max_objects) {
            return Err(Error::Invalid);
        }
        Ok(Self {
            max_keys,
            max_objects,
            keys: BTreeMap::new(),
            floors: BTreeMap::new(),
        })
    }
    pub fn import(&mut self, reference: KeyRef, material: Material) -> Result<(), Error> {
        if !reference.valid() {
            return Err(Error::Invalid);
        }
        if let Some(old) = self.keys.get(&reference) {
            return if old.pass == material.pass {
                Ok(())
            } else {
                Err(Error::Conflict)
            };
        }
        let object = (reference.backend, reference.object);
        if self
            .floors
            .get(&object)
            .is_some_and(|v| *v >= reference.version)
        {
            return Err(Error::Stale);
        }
        if self.keys.len() >= self.max_keys
            || (!self.floors.contains_key(&object) && self.floors.len() >= self.max_objects)
        {
            return Err(Error::Capacity);
        }
        self.floors.insert(object, reference.version);
        self.keys.insert(reference, material);
        Ok(())
    }
    pub fn contains(&self, reference: KeyRef) -> bool {
        self.keys.contains_key(&reference)
    }
    pub fn len(&self) -> usize {
        self.keys.len()
    }
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
    pub fn binding(&self, reference: KeyRef) -> Result<Candidate, Error> {
        self.keys
            .get(&reference)
            .map(|k| k.pass.clone())
            .ok_or(Error::MissingKey)
    }
    fn key(&self, reference: KeyRef) -> Result<Arc<KeyPair>, Error> {
        self.keys
            .get(&reference)
            .map(|k| k.key.clone())
            .ok_or(Error::MissingKey)
    }
    /// Custody primitive. A coordinator must approve deletion of any committed
    /// reference. Removing the store entry cannot wipe caller-retained inputs.
    pub fn remove(&mut self, reference: KeyRef) {
        self.keys.remove(&reference);
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub peer: u128,
    pub domain: String,
    pub incarnation: u128,
    pub host_epoch: u128,
    pub history: usize,
    pub operations: usize,
    pub timeout: u64,
    pub checkpoint_bytes: usize,
}
impl Config {
    fn validate(&self) -> Result<(), Error> {
        if self.incarnation == 0
            || self.host_epoch == 0
            || !(1..=64).contains(&self.history)
            || self.operations == 0
            || self.operations > 256
            || self.timeout == 0
            || self.checkpoint_bytes == 0
            || self.checkpoint_bytes > 8 * 1024 * 1024
        {
            return Err(Error::Invalid);
        }
        mesa_core::DomainTag::new(&self.domain).map_err(|_| Error::Invalid)?;
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credential {
    pub reference: KeyRef,
    pub point: Candidate,
    pub authority_revision: u64,
    pub provider_generation: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteCredential {
    pub point: Candidate,
    pub revision: u64,
    pub provider_generation: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub version: u32,
    pub host_epoch: u128,
    pub peer: u128,
    pub domain: String,
    pub revision: u64,
    pub generation: u64,
    pub active: Option<Credential>,
    pub history: Vec<Credential>,
    pub delete: Vec<KeyRef>,
    pub flow: Option<mesa_flow::Checkpoint>,
    pub remotes: Vec<RemoteCredential>,
    pub retired: Vec<mesa_flow::MessageId>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Token {
    pub incarnation: u128,
    pub revision: u64,
}
#[derive(Clone, Debug)]
pub struct Proposal {
    pub token: Token,
    pub base_revision: u64,
    pub checkpoint: Buffer,
    pub retired: Vec<mesa_flow::MessageId>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Phase {
    Quiescent,
    Prepared,
    Committed,
    Active,
}
#[derive(Clone, Debug, Serialize)]
pub struct Snapshot {
    pub manifest: Manifest,
    pub phase: Phase,
    pub pending: Option<Token>,
    pub deadline: Option<u64>,
    pub operations: usize,
}
struct Pending {
    proposal: Proposal,
    next: Manifest,
    deadline: u64,
    authority_incarnation: u128,
    activation: bool,
}
pub struct Activation {
    config: Config,
    state: Manifest,
    phase: Phase,
    next_revision: u64,
    now: u64,
    pending: Option<Pending>,
    gates: Vec<SendGate>,
    jobs: BTreeMap<u64, operations::Job>,
    next_job: u64,
    pins: BTreeMap<u64, KeyRef>,
}
impl Activation {
    pub fn new(config: Config) -> Result<Self, Error> {
        config.validate()?;
        let state = Manifest {
            version: 1,
            host_epoch: config.host_epoch,
            peer: config.peer,
            domain: config.domain.clone(),
            revision: 0,
            generation: 0,
            active: None,
            history: vec![],
            delete: vec![],
            flow: None,
            remotes: vec![],
            retired: vec![],
        };
        Ok(Self {
            config,
            state,
            phase: Phase::Quiescent,
            next_revision: 1,
            now: 0,
            pending: None,
            gates: vec![],
            jobs: BTreeMap::new(),
            next_job: 1,
            pins: BTreeMap::new(),
        })
    }
    /// floor is the embedding host's externally protected minimum revision.
    /// A new incarnation and external epoch/floor are not inferred from storage.
    pub fn restore(config: Config, checkpoint: &Buffer, floor: u64) -> Result<Self, Error> {
        let mut a = Self::new(config)?;
        if checkpoint.len() > a.config.checkpoint_bytes {
            return Err(Error::Capacity);
        }
        let s: Manifest = checkpoint
            .with_bytes(|b| serde_json::from_slice(b))
            .map_err(|_| Error::Invalid)?;
        if s.version != 1
            || s.peer != a.config.peer
            || s.domain != a.config.domain
            || s.host_epoch != a.config.host_epoch
            || s.revision < floor
            || s.generation != s.revision
        {
            return Err(Error::Rollback);
        }
        if s.history.len() > a.config.history || s.delete.len() > 256 || s.retired.len() > 16384 {
            return Err(Error::Capacity);
        }
        for c in s.active.iter().chain(s.history.iter()) {
            c.point
                .validate(&mesa_pki::Limits::default())
                .map_err(|_| Error::Invalid)?;
            if c.point.peer != s.peer
                || c.point.domain != s.domain
                || !c.reference.valid()
                || c.authority_revision == 0
                || c.provider_generation == 0
            {
                return Err(Error::Invalid);
            }
        }
        if let Some(active) = &s.active {
            if s.history.iter().any(|h| {
                h.reference == active.reference
                    || h.point.life > active.point.life
                    || h.point.rift > active.point.rift
            }) || s.delete.contains(&active.reference)
            {
                return Err(Error::Invalid);
            }
        }
        if (s.revision > 0 && s.active.is_none())
            || s.history
                .iter()
                .map(|h| h.reference)
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != s.history.len()
            || s.delete
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != s.delete.len()
            || s.history.iter().any(|h| s.delete.contains(&h.reference))
            || s.delete.iter().any(|r| !r.valid())
        {
            return Err(Error::Invalid);
        }
        if s.remotes.len() > 256
            || s.remotes
                .iter()
                .map(|r| r.point.peer)
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != s.remotes.len()
        {
            return Err(Error::Invalid);
        }
        for r in &s.remotes {
            r.point
                .validate(&mesa_pki::Limits::default())
                .map_err(|_| Error::Invalid)?;
            if r.revision == 0 || r.provider_generation == 0 {
                return Err(Error::Invalid);
            }
        }
        if s.flow.is_none() && !s.remotes.is_empty() {
            return Err(Error::Invalid);
        }
        if let Some(f) = &s.flow {
            if f.flows.iter().any(|flow| {
                !s.remotes.iter().any(|r| {
                    r.point.peer == flow.remote.name
                        && r.point.domain == flow.remote.domain
                        && r.point.rift == flow.remote.rift
                })
            }) {
                return Err(Error::Invalid);
            }

            if f.local.name != s.peer
                || f.local.domain != s.domain
                || s.active
                    .as_ref()
                    .is_none_or(|c| f.local.rift != c.point.rift)
                || f.expected_revision() != Some(f.revision)
            {
                return Err(Error::Invalid);
            }
        }
        a.next_revision = s.revision.checked_add(1).ok_or(Error::Capacity)?;
        a.state = s;
        Ok(a)
    }
    pub fn config(&self) -> &Config {
        &self.config
    }
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            manifest: self.state.clone(),
            phase: self.phase,
            pending: self.pending.as_ref().map(|p| p.proposal.token),
            deadline: self.deadline(),
            operations: self.jobs.len(),
        }
    }
    pub fn pending(&self) -> Option<Proposal> {
        self.pending.as_ref().map(|p| p.proposal.clone())
    }
    pub fn deadline(&self) -> Option<u64> {
        self.pending
            .iter()
            .map(|p| p.deadline)
            .chain(self.jobs.values().map(|j| j.deadline))
            .min()
    }
    pub fn quiesce(&mut self) -> Result<(), Error> {
        for gate in &self.gates {
            gate.change(false).map_err(|_| Error::Stale)?;
        }
        self.phase = Phase::Quiescent;
        self.jobs.clear();
        Ok(())
    }
    fn remotes_authorized(a: &Authority, m: &Manifest) -> bool {
        m.remotes.iter().all(|r| {
            a.policy(r.point.peer).is_some_and(|p| p.ordinary())
                && a.peer(r.point.peer).is_some_and(|p| {
                    p.revision == r.revision
                        && p.point.provider_generation == r.provider_generation
                        && p.point.candidate == r.point
                })
        })
    }
    fn authorized(&self, a: &Authority, c: &Credential) -> bool {
        a.policy(self.config.peer).is_some_and(|p| p.ordinary())
            && a.peer(self.config.peer).is_some_and(|p| {
                p.revision == c.authority_revision
                    && p.point.provider_generation == c.provider_generation
                    && p.point.candidate == c.point
            })
    }
    /// Call after PKI mutations before further engine work. A staged secret alone
    /// never changes authority. Any loss of current authority closes every gate.
    pub fn reconcile(&mut self, a: &Authority) -> Result<(), Error> {
        let valid = self.pending.as_ref().map_or_else(
            || {
                self.state
                    .active
                    .as_ref()
                    .is_some_and(|c| self.authorized(a, c))
                    && Self::remotes_authorized(a, &self.state)
            },
            |p| {
                p.authority_incarnation == a.incarnation()
                    && (!p.activation
                        || p.next
                            .active
                            .as_ref()
                            .is_some_and(|c| self.authorized(a, c))
                            && Self::remotes_authorized(a, &p.next))
            },
        );
        if !valid {
            self.pending = None;
            self.quiesce()?;
        }
        Ok(())
    }
    fn propose(
        &mut self,
        a: &Authority,
        mut next: Manifest,
        activation: bool,
    ) -> Result<Proposal, Error> {
        let revision = self.next_revision;
        let next_revision = revision.checked_add(1).ok_or(Error::Capacity)?;
        let deadline = self
            .now
            .checked_add(self.config.timeout)
            .ok_or(Error::Clock)?;
        next.revision = revision;
        next.generation = revision;
        let bytes = serde_json::to_vec(&next).map_err(|_| Error::Invalid)?;
        if bytes.len() > self.config.checkpoint_bytes {
            return Err(Error::Capacity);
        }
        let proposal = Proposal {
            token: Token {
                incarnation: self.config.incarnation,
                revision,
            },
            base_revision: self.state.revision,
            checkpoint: bytes.into(),
            retired: next.retired.clone(),
        };
        self.quiesce()?;
        self.next_revision = next_revision;
        self.phase = Phase::Prepared;
        self.pending = Some(Pending {
            proposal: proposal.clone(),
            next,
            deadline,
            authority_incarnation: a.incarnation(),
            activation,
        });
        Ok(proposal)
    }
    pub fn prepare(
        &mut self,
        a: &Authority,
        store: &SoftwareStore,
        reference: KeyRef,
        flow: Option<mesa_flow::credentials::CredentialPlan>,
    ) -> Result<Proposal, Error> {
        self.reconcile(a)?;
        if self.pending.is_some() {
            return Err(Error::Busy);
        }
        let p = a.peer(self.config.peer).ok_or(Error::Unavailable)?;
        if !a.policy(self.config.peer).is_some_and(|p| p.ordinary())
            || p.point.candidate.domain != self.config.domain
        {
            return Err(Error::Unavailable);
        }
        let material = store.binding(reference)?;
        if material != p.point.candidate {
            return Err(Error::Conflict);
        }
        let credential = Credential {
            reference,
            point: material,
            authority_revision: p.revision,
            provider_generation: p.point.provider_generation,
        };
        let mut next = self.state.clone();
        next.retired.clear();
        if let Some(old) = &self.state.active {
            if credential.point.life < old.point.life || credential.point.rift < old.point.rift {
                return Err(Error::Rollback);
            }
            if credential.point.life == old.point.life
                && credential.point.public_key != old.point.public_key
            {
                return Err(Error::Conflict);
            }
            if credential.reference != old.reference {
                if credential.point == old.point {
                    return Err(Error::Conflict);
                }
                if next.history.len() >= self.config.history {
                    return Err(Error::Capacity);
                }
                next.history.push(old.clone());
            }
        }
        if next.delete.contains(&reference) || next.history.iter().any(|h| h.reference == reference)
        {
            return Err(Error::Stale);
        }
        next.active = Some(credential);
        if let Some(plan) = flow {
            if plan.checkpoint.local.name != self.config.peer
                || plan.checkpoint.local.domain != self.config.domain
                || plan.checkpoint.local.rift != p.point.candidate.rift
            {
                return Err(Error::Conflict);
            }
            next.remotes.clear();
            for flow in &plan.checkpoint.flows {
                let p = a.peer(flow.remote.name).ok_or(Error::Unavailable)?;
                if !a.policy(flow.remote.name).is_some_and(|p| p.ordinary())
                    || p.point.candidate.domain != flow.remote.domain
                    || p.point.candidate.rift != flow.remote.rift
                {
                    return Err(Error::Conflict);
                }
                if !next
                    .remotes
                    .iter()
                    .any(|r| r.point.peer == flow.remote.name)
                {
                    next.remotes.push(RemoteCredential {
                        point: p.point.candidate.clone(),
                        revision: p.revision,
                        provider_generation: p.point.provider_generation,
                    });
                }
            }
            next.flow = Some(plan.checkpoint);
            next.retired = plan.retired;
        } else if next.flow.is_some() {
            return Err(Error::Busy);
        }
        self.propose(a, next, true)
    }
    pub fn commit(
        &mut self,
        a: &Authority,
        store: &SoftwareStore,
        token: Token,
    ) -> Result<(), Error> {
        self.reconcile(a)?;
        let p = self.pending.as_ref().ok_or(Error::Stale)?;
        if p.proposal.token != token || p.deadline <= self.now {
            return Err(Error::Stale);
        }
        if p.activation {
            let c = p.next.active.as_ref().ok_or(Error::Invalid)?;
            if store.binding(c.reference)? != c.point {
                return Err(Error::Conflict);
            }
        }
        let activation = p.activation;
        self.state = self.pending.take().unwrap().next;
        self.phase = if activation {
            Phase::Committed
        } else {
            Phase::Quiescent
        };
        Ok(())
    }
    pub fn cancel(&mut self, token: Token) -> Result<(), Error> {
        if self.pending.as_ref().map(|p| p.proposal.token) != Some(token) {
            return Err(Error::Stale);
        }
        self.pending = None;
        self.quiesce()
    }
    pub fn advance(&mut self, now: u64) -> Result<(), Error> {
        if now < self.now {
            return Err(Error::Clock);
        }
        self.now = now;
        self.jobs.retain(|_, j| j.deadline > now);
        if self.pending.as_ref().is_some_and(|p| p.deadline <= now) {
            self.pending = None;
            self.quiesce()?;
        }
        Ok(())
    }
    pub fn pin(&mut self, id: u64, reference: KeyRef) -> Result<(), Error> {
        if self.pins.contains_key(&id) {
            return Err(Error::Conflict);
        }
        if self.pins.len() >= self.config.operations {
            return Err(Error::Capacity);
        }
        if !self
            .state
            .active
            .iter()
            .chain(self.state.history.iter())
            .any(|c| c.reference == reference)
        {
            return Err(Error::MissingKey);
        }
        self.pins.insert(id, reference);
        Ok(())
    }
    pub fn unpin(&mut self, id: u64) -> Result<(), Error> {
        self.pins.remove(&id).ok_or(Error::Stale)?;
        Ok(())
    }
    pub fn retire(&mut self, a: &Authority, reference: KeyRef) -> Result<Proposal, Error> {
        self.reconcile(a)?;
        if self.pending.is_some() {
            return Err(Error::Busy);
        }
        if self.pins.values().any(|r| *r == reference)
            || self
                .state
                .active
                .as_ref()
                .is_some_and(|c| c.reference == reference)
        {
            return Err(Error::Busy);
        }
        let mut next = self.state.clone();
        let len = next.history.len();
        next.history.retain(|h| h.reference != reference);
        if next.history.len() == len {
            return Err(Error::MissingKey);
        }
        if next.delete.len() >= 256 {
            return Err(Error::Capacity);
        }
        next.delete.push(reference);
        next.retired.clear();
        self.propose(a, next, false)
    }
    /// Run only after committing retirement. Backends make deletion idempotent;
    /// a crash may replay this action. The next manifest coalesces acknowledgments.
    pub fn delete_retired(
        &mut self,
        store: &mut SoftwareStore,
        reference: KeyRef,
    ) -> Result<(), Error> {
        if self.pending.is_some() || !self.state.delete.contains(&reference) {
            return Err(Error::Busy);
        }
        store.remove(reference);
        self.state.delete.retain(|r| *r != reference);
        Ok(())
    }
    fn credential(
        &mut self,
        a: &Authority,
        store: &SoftwareStore,
    ) -> Result<(Credential, Arc<KeyPair>), Error> {
        self.reconcile(a)?;
        if !matches!(self.phase, Phase::Committed | Phase::Active) {
            return Err(Error::Unavailable);
        }
        let c = self.state.active.clone().ok_or(Error::Unavailable)?;
        if store.binding(c.reference)? != c.point {
            return Err(Error::Conflict);
        }
        Ok((c.clone(), store.key(c.reference)?))
    }
    fn attach(&mut self, gate: SendGate) -> Result<(), Error> {
        // Closed gates remain closed in retained packets; rebuilt FLOW nodes need no registry slot.
        self.gates.retain(|g| g.is_open() || g.same(&gate));
        if !self.gates.iter().any(|g| g.same(&gate)) {
            if self.gates.len() >= 16 {
                return Err(Error::Capacity);
            }
            self.gates.push(gate);
        }
        Ok(())
    }
    pub fn sync_core(
        &mut self,
        a: &Authority,
        store: &SoftwareStore,
        engine: &mut mesa_core::Engine<mesa_core::protection::SignedPublic>,
    ) -> Result<Vec<mesa_core::Action>, Error> {
        self.attach(engine.send_gate())?;
        let (c, key) = match self.credential(a, store) {
            Ok(credential) => credential,
            Err(Error::Unavailable) => return engine.quiesce().map_err(|_| Error::Backend),
            Err(e) => {
                // Keep reads intact for a subsequent quiescence call to report.
                self.quiesce()?;
                return Err(e);
            }
        };
        if engine.local_generation() == self.state.generation
            && !engine.is_quiescent()
            && engine.send_gate().is_open()
        {
            self.phase = Phase::Active;
            return Ok(vec![]);
        }
        let out = engine.quiesce().map_err(|_| Error::Backend)?;
        let old = engine.local_view();
        let view = PreconfiguredPeer::new(
            PeerId(c.point.peer),
            &c.point.domain,
            c.point.life,
            c.point.rift,
            old.key,
        )
        .map_err(|_| Error::Invalid)?;
        engine
            .activate_local(view, key, engine.local_generation(), self.state.generation)
            .map_err(|_| Error::Backend)?;
        self.phase = Phase::Active;
        Ok(out)
    }
    pub fn flow_plan(
        &mut self,
        a: &Authority,
        reference: KeyRef,
        store: &SoftwareStore,
        node: &mut mesa_flow::Node,
    ) -> Result<Proposal, Error> {
        self.attach(node.send_gate())?;
        if !node.is_quiescent() {
            return Err(Error::Busy);
        }
        let c = store.binding(reference)?;
        let local = PreconfiguredPeer::new(
            PeerId(c.peer),
            &c.domain,
            c.life,
            c.rift,
            node.local_view().key,
        )
        .map_err(|_| Error::Invalid)?;
        let peers = self.flow_peers(a, node)?;
        let views: Vec<_> = peers.iter().map(|(p, _)| p.clone()).collect();
        let plan = node
            .credential_plan(&local, &views)
            .map_err(|_| Error::Busy)?;
        self.prepare(a, store, reference, Some(plan))
    }
    /// Emit all transient cancellation outcomes before preparing a FLOW transition.
    /// Drain existing delivery/storage decisions while the node stays closed.
    pub fn quiesce_flow(
        &mut self,
        node: &mut mesa_flow::Node,
    ) -> Result<Vec<mesa_flow::Action>, Error> {
        self.attach(node.send_gate())?;
        self.quiesce()?;
        node.quiesce().map_err(|_| Error::Backend)
    }
    fn flow_peers(
        &self,
        a: &Authority,
        node: &mesa_flow::Node,
    ) -> Result<Vec<(PreconfiguredPeer, PublicKey)>, Error> {
        node.configured_peers()
            .into_iter()
            .map(|old| {
                let p = a.peer(old.id.0).ok_or(Error::Unavailable)?;
                if !a.policy(old.id.0).is_some_and(|p| p.ordinary()) {
                    return Err(Error::Unavailable);
                }
                let c = &p.point.candidate;
                let v = PreconfiguredPeer::new(old.id, &c.domain, c.life, c.rift, old.key)
                    .map_err(|_| Error::Invalid)?;
                Ok((
                    v,
                    PublicKey::from_bytes(c.public_key).map_err(|_| Error::Invalid)?,
                ))
            })
            .collect()
    }
    pub fn sync_flow(
        &mut self,
        a: &Authority,
        store: &SoftwareStore,
        node: &mut mesa_flow::Node,
        incarnation: u128,
    ) -> Result<(), Error> {
        self.attach(node.send_gate())?;
        let (c, key) = self.credential(a, store)?;
        let peers = self.flow_peers(a, node)?;
        let local = PreconfiguredPeer::new(
            PeerId(c.point.peer),
            &c.point.domain,
            c.point.life,
            c.point.rift,
            node.local_view().key,
        )
        .map_err(|_| Error::Invalid)?;
        node.activate_credentials(
            local,
            key,
            peers,
            self.state.flow.clone().ok_or(Error::Invalid)?,
            self.state.generation,
            incarnation,
        )
        .map_err(|_| Error::Backend)?;
        self.attach(node.send_gate())?;
        self.phase = Phase::Active;
        Ok(())
    }
}
impl Drop for Activation {
    fn drop(&mut self) {
        let _ = self.quiesce();
    }
}
