//! Noun-free authority mechanisms. No packet parsing, verifier I/O or runtime.
//! Trusted callers supply authenticated provider decisions. Network profiles
//! must screen candidates before requesting verification; a candidate is not trust.
pub use mesa_bytes::Buffer;
use mesa_crypto::{sha256, PublicKey};
use mesa_wire::DomainTag;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
pub mod bridge;
pub type Peer = u128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Capacity,
    Stale,
    Unavailable,
    Conflict,
    Rollback,
    Clock,
    Busy,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub domains: usize,
    pub peers: usize,
    pub history: usize,
    pub evidence_bytes: usize,
    pub checkpoint_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            domains: 16,
            peers: 256,
            history: 16,
            evidence_bytes: 65536,
            checkpoint_bytes: 8 * 1024 * 1024,
        }
    }
}
impl Limits {
    pub fn validate(&self) -> Result<(), Error> {
        if self.domains == 0
            || self.domains > 256
            || self.peers == 0
            || self.peers > 4096
            || self.history == 0
            || self.history > 256
            || self.evidence_bytes == 0
            || self.evidence_bytes > 1024 * 1024
            || self.checkpoint_bytes == 0
            || self.checkpoint_bytes > 64 * 1024 * 1024
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}

/// Owned screened claims. Evidence retains exact byte width; the optional
/// codec may encode bit lengths inside this opaque buffer. No private keys.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Candidate {
    pub peer: Peer,
    pub domain: String,
    pub life: u32,
    pub rift: u32,
    pub public_key: [u8; 32],
    pub evidence: Buffer,
}
impl Candidate {
    pub fn validate(&self, limits: &Limits) -> Result<(), Error> {
        DomainTag::new(&self.domain).map_err(|_| Error::Invalid)?;
        if self.life == 0 || self.evidence.len() > limits.evidence_bytes {
            return Err(Error::Invalid);
        }
        PublicKey::from_bytes(self.public_key).map_err(|_| Error::Invalid)?;
        Ok(())
    }
    pub fn digest(&self) -> [u8; 32] {
        // Explicit lengths and fixed coordinates; no JSON or atom normalization.
        let mut bytes = b"mesa/pki/candidate/1\0".to_vec();
        bytes.extend_from_slice(&self.peer.to_le_bytes());
        bytes.push(self.domain.len() as u8);
        bytes.extend_from_slice(self.domain.as_bytes());
        bytes.extend_from_slice(&self.life.to_le_bytes());
        bytes.extend_from_slice(&self.rift.to_le_bytes());
        bytes.extend_from_slice(&self.public_key);
        bytes.extend_from_slice(&(self.evidence.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&self.evidence.to_vec());
        sha256(&bytes)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Lifecycle {
    Active,
    Suspended,
    Removed,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Domain {
    pub generation: u64,
    pub lifecycle: Lifecycle,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Point {
    pub candidate: Candidate,
    pub provider_generation: u64,
    /// Provider-validated scope relationships. Profiles validate their meaning.
    pub sponsor: Option<Peer>,
    pub fief: Option<Peer>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerState {
    pub point: Point,
    pub history: Vec<Point>,
    pub revision: u64,
    pub withdrawn: bool,
    pub operator_blocked: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fence {
    pub domain: String,
    pub revision: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    version: u32,
    pub revision: u64,
    pub domains: BTreeMap<String, Domain>,
    pub peers: BTreeMap<Peer, PeerState>,
    pub fences: BTreeMap<Peer, Fence>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Token {
    pub incarnation: u128,
    pub revision: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proposal {
    pub token: Token,
    pub base_revision: u64,
    pub checkpoint: Buffer,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Provider {
    pub incarnation: u128,
    pub generation: u64,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProviderStatus {
    pub available: bool,
    pub ready: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policy {
    pub operator_blocked: bool,
    pub withdrawn: bool,
    pub domain_active: bool,
    pub ready: bool,
    pub committed: bool,
    pub revalidated: bool,
}
impl Policy {
    pub fn ordinary(self) -> bool {
        !self.operator_blocked
            && !self.withdrawn
            && self.domain_active
            && self.ready
            && self.committed
            && self.revalidated
    }
    pub fn recovery(self) -> bool {
        !self.operator_blocked && self.domain_active && self.ready
    }
}

/// One serialized caller. Mutations produce full, versioned proposals. New
/// proposals supersede older tokens, never their accumulated state. The host
/// serializes durable writes and confirms only after persistence. Dirty peers
/// remain gated until confirmation. Restore also requires fresh provider vouches.
pub struct Authority {
    limits: Limits,
    incarnation: u128,
    state: State,
    committed_revision: u64,
    pending: Option<Proposal>,
    dirty: BTreeSet<Peer>,
    quarantine: BTreeSet<Peer>,
    status: BTreeMap<String, ProviderStatus>,
}
impl Authority {
    pub fn new(limits: Limits, incarnation: u128) -> Result<Self, Error> {
        limits.validate()?;
        if incarnation == 0 {
            return Err(Error::Invalid);
        }
        Ok(Self {
            limits,
            incarnation,
            state: State {
                version: 1,
                revision: 0,
                domains: BTreeMap::new(),
                peers: BTreeMap::new(),
                fences: BTreeMap::new(),
            },
            committed_revision: 0,
            pending: None,
            dirty: BTreeSet::new(),
            quarantine: BTreeSet::new(),
            status: BTreeMap::new(),
        })
    }
    /// Checkpoints are trusted host storage, not network input. A fresh, unique
    /// incarnation is required after every restart, including old-world restore.
    pub fn restore(limits: Limits, incarnation: u128, checkpoint: &Buffer) -> Result<Self, Error> {
        let mut a = Self::new(limits, incarnation)?;
        if checkpoint.len() > a.limits.checkpoint_bytes {
            return Err(Error::Capacity);
        }
        let state: State = checkpoint
            .with_bytes(|b| serde_json::from_slice(b))
            .map_err(|_| Error::Invalid)?;
        a.validate_state(&state)?;
        a.committed_revision = state.revision;
        a.quarantine.extend(state.peers.keys().copied());
        a.state = state;
        Ok(a)
    }
    fn validate_state(&self, state: &State) -> Result<(), Error> {
        if state.version != 1
            || state.domains.len() > self.limits.domains
            || state.peers.len() + state.fences.len() > self.limits.peers
        {
            return Err(Error::Capacity);
        }
        for (name, d) in &state.domains {
            DomainTag::new(name).map_err(|_| Error::Invalid)?;
            if d.generation == 0 {
                return Err(Error::Invalid);
            }
        }
        for (peer, f) in &state.fences {
            if state.peers.contains_key(peer)
                || !state.domains.contains_key(&f.domain)
                || f.revision == 0
                || f.revision > state.revision
            {
                return Err(Error::Invalid);
            }
        }
        for (peer, p) in &state.peers {
            if *peer != p.point.candidate.peer
                || p.revision > state.revision
                || p.revision == 0
                || p.history.len() > self.limits.history
            {
                return Err(Error::Invalid);
            }
            let c = &p.point.candidate;
            let d = state.domains.get(&c.domain).ok_or(Error::Invalid)?;
            let mut previous: Option<&Candidate> = None;
            for point in p.history.iter().chain(std::iter::once(&p.point)) {
                point.candidate.validate(&self.limits)?;
                if point.candidate.peer != *peer
                    || point.candidate.domain != c.domain
                    || point.provider_generation == 0
                    || point.provider_generation > d.generation
                    || point.sponsor == Some(*peer)
                    || point.fief == Some(*peer)
                {
                    return Err(Error::Invalid);
                }
                if let Some(old) = previous {
                    validate_successor(old, &point.candidate)?;
                }
                previous = Some(&point.candidate);
            }
        }
        Ok(())
    }
    pub fn limits(&self) -> &Limits {
        &self.limits
    }
    pub fn incarnation(&self) -> u128 {
        self.incarnation
    }
    pub fn snapshot(&self) -> State {
        self.state.clone()
    }
    pub fn peer(&self, peer: Peer) -> Option<&PeerState> {
        self.state.peers.get(&peer)
    }
    pub fn revision(&self, peer: Peer) -> u64 {
        self.peer(peer).map_or_else(
            || self.state.fences.get(&peer).map_or(0, |f| f.revision),
            |p| p.revision,
        )
    }
    pub fn pending(&self) -> Option<&Proposal> {
        self.pending.as_ref()
    }
    pub fn provider(&self, domain: &str) -> Result<Provider, Error> {
        let d = self.state.domains.get(domain).ok_or(Error::Unavailable)?;
        if d.lifecycle != Lifecycle::Active {
            return Err(Error::Unavailable);
        }
        Ok(Provider {
            incarnation: self.incarnation,
            generation: d.generation,
        })
    }
    pub fn provider_status(&self, domain: &str) -> ProviderStatus {
        self.status.get(domain).copied().unwrap_or_default()
    }
    pub fn check_provider(&self, domain: &str, provider: Provider) -> Result<(), Error> {
        if self.provider(domain)? != provider {
            return Err(Error::Stale);
        }
        Ok(())
    }
    pub fn set_status(
        &mut self,
        domain: &str,
        provider: Provider,
        status: ProviderStatus,
    ) -> Result<(), Error> {
        self.check_provider(domain, provider)?;
        if !status.ready {
            self.quarantine.extend(
                self.state
                    .peers
                    .iter()
                    .filter(|(_, p)| p.point.candidate.domain == domain)
                    .map(|(id, _)| *id),
            );
        }
        self.status.insert(domain.into(), status);
        Ok(())
    }
    pub fn policy(&self, peer: Peer) -> Option<Policy> {
        let p = self.peer(peer)?;
        let domain = &p.point.candidate.domain;
        Some(Policy {
            operator_blocked: p.operator_blocked,
            withdrawn: p.withdrawn,
            domain_active: self
                .state
                .domains
                .get(domain)
                .is_some_and(|d| d.lifecycle == Lifecycle::Active),
            ready: self.provider_status(domain).ready,
            committed: !self.dirty.contains(&peer),
            revalidated: !self.quarantine.contains(&peer),
        })
    }
    fn propose(&mut self, mut state: State, touched: BTreeSet<Peer>) -> Result<Proposal, Error> {
        state.revision = self.state.revision.checked_add(1).ok_or(Error::Capacity)?;
        for peer in &touched {
            if let Some(f) = state.fences.get_mut(peer) {
                f.revision = state.revision;
            }
            if let Some(p) = state.peers.get_mut(peer) {
                p.revision = state.revision;
            }
        }
        self.validate_state(&state)?;
        let bytes = serde_json::to_vec(&state).map_err(|_| Error::Invalid)?;
        if bytes.len() > self.limits.checkpoint_bytes {
            return Err(Error::Capacity);
        }
        let proposal = Proposal {
            token: Token {
                incarnation: self.incarnation,
                revision: state.revision,
            },
            base_revision: self.committed_revision,
            checkpoint: bytes.into(),
        };
        self.state = state;
        self.dirty.extend(touched);
        self.pending = Some(proposal.clone());
        Ok(proposal)
    }
    pub fn commit(&mut self, token: Token) -> Result<(), Error> {
        if self.pending.as_ref().map(|p| p.token) != Some(token) {
            return Err(Error::Stale);
        }
        self.committed_revision = token.revision;
        self.pending = None;
        self.dirty.clear();
        Ok(())
    }
    /// expected is the last registration generation, including removed tombstones.
    /// Replacement/revival requires a strictly larger generation and fresh vouches.
    pub fn register(
        &mut self,
        domain: &str,
        expected: u64,
        generation: u64,
    ) -> Result<Proposal, Error> {
        DomainTag::new(domain).map_err(|_| Error::Invalid)?;
        let old = self.state.domains.get(domain);
        if old.map_or(0, |d| d.generation) != expected || generation <= expected {
            return Err(Error::Stale);
        }
        if old.is_none() && self.state.domains.len() >= self.limits.domains {
            return Err(Error::Capacity);
        }
        let mut state = self.state.clone();
        state.domains.insert(
            domain.into(),
            Domain {
                generation,
                lifecycle: Lifecycle::Active,
            },
        );
        let peers = self.domain_peers(domain);
        let proposal = self.propose(state, peers.clone())?;
        self.quarantine.extend(peers);
        self.status.remove(domain);
        Ok(proposal)
    }
    pub fn lifecycle(
        &mut self,
        domain: &str,
        provider: Provider,
        lifecycle: Lifecycle,
    ) -> Result<Proposal, Error> {
        let registered = self.state.domains.get(domain).ok_or(Error::Unavailable)?;
        if provider.incarnation != self.incarnation || provider.generation != registered.generation
        {
            return Err(Error::Stale);
        }
        if registered.lifecycle == Lifecycle::Removed {
            return Err(Error::Unavailable);
        }
        if lifecycle == Lifecycle::Active {
            return Err(Error::Invalid);
        }
        let mut state = self.state.clone();
        state.domains.get_mut(domain).unwrap().lifecycle = lifecycle;
        let peers = self.domain_peers(domain);
        self.quarantine.extend(peers.clone());
        self.status.remove(domain);
        self.propose(state, peers)
    }
    fn domain_peers(&self, domain: &str) -> BTreeSet<Peer> {
        self.state
            .peers
            .iter()
            .filter(|(_, p)| p.point.candidate.domain == domain)
            .map(|(id, _)| *id)
            .collect()
    }
    pub fn check_candidate(&self, candidate: &Candidate) -> Result<(), Error> {
        candidate.validate(&self.limits)?;
        if let Some(p) = self.peer(candidate.peer) {
            validate_successor(&p.point.candidate, candidate)?;
        } else if let Some(f) = self.state.fences.get(&candidate.peer) {
            if f.domain != candidate.domain {
                return Err(Error::Conflict);
            }
        } else if self.state.peers.len() + self.state.fences.len() >= self.limits.peers {
            return Err(Error::Capacity);
        }
        Ok(())
    }
    /// Authenticated provider verdict. Both direct resolution and admission use
    /// this transition. The provider attests scope validity as well as key currency.
    pub fn accept(
        &mut self,
        provider: Provider,
        expected_revision: u64,
        candidate: Candidate,
        sponsor: Option<Peer>,
        fief: Option<Peer>,
    ) -> Result<Proposal, Error> {
        self.check_provider(&candidate.domain, provider)?;
        if !self.provider_status(&candidate.domain).ready {
            return Err(Error::Unavailable);
        }
        if self.revision(candidate.peer) != expected_revision {
            return Err(Error::Stale);
        }
        self.check_candidate(&candidate)?;
        if sponsor == Some(candidate.peer) || fief == Some(candidate.peer) {
            return Err(Error::Invalid);
        }
        let id = candidate.peer;
        let mut state = self.state.clone();
        state.fences.remove(&id);
        let point = Point {
            candidate,
            provider_generation: provider.generation,
            sponsor,
            fief,
        };
        if let Some(p) = state.peers.get_mut(&id) {
            if p.point != point {
                if p.history.len() >= self.limits.history {
                    p.history.remove(0);
                }
                p.history.push(p.point.clone());
                p.point = point;
            }
            p.withdrawn = false;
        } else {
            state.peers.insert(
                id,
                PeerState {
                    point,
                    history: vec![],
                    revision: 1,
                    withdrawn: false,
                    operator_blocked: false,
                },
            );
        }
        let proposal = self.propose(state, BTreeSet::from([id]))?;
        self.quarantine.remove(&id);
        Ok(proposal)
    }
    /// Evidence-only refresh: exact accepted name/domain/key/life/rift. This
    /// updates an authorized point; local private activation remains phase 5.
    pub fn refresh_evidence(
        &mut self,
        provider: Provider,
        expected_revision: u64,
        candidate: Candidate,
    ) -> Result<Proposal, Error> {
        self.check_refresh(&candidate)?;
        let p = self.peer(candidate.peer).ok_or(Error::Invalid)?;
        self.accept(
            provider,
            expected_revision,
            candidate,
            p.point.sponsor,
            p.point.fief,
        )
    }
    pub fn check_refresh(&self, candidate: &Candidate) -> Result<(), Error> {
        let old = &self
            .peer(candidate.peer)
            .ok_or(Error::Invalid)?
            .point
            .candidate;
        if old.domain != candidate.domain
            || old.life != candidate.life
            || old.rift != candidate.rift
            || old.public_key != candidate.public_key
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    pub fn withdraw(
        &mut self,
        domain: &str,
        provider: Provider,
        peer: Peer,
        expected_revision: u64,
    ) -> Result<Proposal, Error> {
        self.check_provider(domain, provider)?;
        if self.revision(peer) != expected_revision {
            return Err(Error::Stale);
        }
        let mut state = self.state.clone();
        if let Some(p) = state.peers.get_mut(&peer) {
            if p.point.candidate.domain != domain {
                return Err(Error::Conflict);
            }
            p.withdrawn = true;
        } else {
            if let Some(f) = state.fences.get(&peer) {
                if f.domain != domain {
                    return Err(Error::Conflict);
                }
            } else if state.peers.len() + state.fences.len() >= self.limits.peers {
                return Err(Error::Capacity);
            }
            state.fences.insert(
                peer,
                Fence {
                    domain: domain.into(),
                    revision: expected_revision,
                },
            );
        }
        let result = self.propose(state, BTreeSet::from([peer]));
        if result.is_err() {
            self.quarantine.extend(self.domain_peers(domain));
            self.status.remove(domain);
        }
        result
    }
    pub fn operator_block(&mut self, peer: Peer, blocked: bool) -> Result<Proposal, Error> {
        let mut state = self.state.clone();
        state
            .peers
            .get_mut(&peer)
            .ok_or(Error::Invalid)?
            .operator_blocked = blocked;
        self.propose(state, BTreeSet::from([peer]))
    }
}
fn validate_successor(old: &Candidate, new: &Candidate) -> Result<(), Error> {
    if old.peer != new.peer || old.domain != new.domain {
        return Err(Error::Conflict);
    }
    if new.rift < old.rift || new.life < old.life {
        return Err(Error::Rollback);
    }
    if new.life == old.life && new.public_key != old.public_key {
        return Err(Error::Conflict);
    }
    Ok(())
}

/// Direct authority-manager inputs. Verifier decisions are already authenticated
/// by that manager; a network profile must never construct Accept on its own.
#[derive(Clone, Debug)]
pub enum Command {
    Register {
        domain: String,
        expected: u64,
        generation: u64,
    },
    Status {
        domain: String,
        provider: Provider,
        status: ProviderStatus,
    },
    Lifecycle {
        domain: String,
        provider: Provider,
        lifecycle: Lifecycle,
    },
    Accept {
        provider: Provider,
        expected_revision: u64,
        candidate: Candidate,
        sponsor: Option<Peer>,
        fief: Option<Peer>,
    },
    Refresh {
        provider: Provider,
        expected_revision: u64,
        candidate: Candidate,
    },
    Withdraw {
        domain: String,
        provider: Provider,
        peer: Peer,
        expected_revision: u64,
    },
    OperatorBlock {
        peer: Peer,
        blocked: bool,
    },
    Commit(Token),
}
#[derive(Clone, Copy, Debug)]
pub struct Budget {
    pub events: usize,
    pub proposals: usize,
    pub bytes: usize,
}
#[derive(Clone, Debug)]
pub struct Batch {
    pub results: Vec<Result<Option<Proposal>, Error>>,
}
impl Authority {
    pub fn step(&mut self, command: Command) -> Result<Option<Proposal>, Error> {
        Ok(Some(match command {
            Command::Register {
                domain,
                expected,
                generation,
            } => self.register(&domain, expected, generation)?,
            Command::Status {
                domain,
                provider,
                status,
            } => {
                self.set_status(&domain, provider, status)?;
                return Ok(None);
            }
            Command::Lifecycle {
                domain,
                provider,
                lifecycle,
            } => self.lifecycle(&domain, provider, lifecycle)?,
            Command::Accept {
                provider,
                expected_revision,
                candidate,
                sponsor,
                fief,
            } => self.accept(provider, expected_revision, candidate, sponsor, fief)?,
            Command::Refresh {
                provider,
                expected_revision,
                candidate,
            } => self.refresh_evidence(provider, expected_revision, candidate)?,
            Command::Withdraw {
                domain,
                provider,
                peer,
                expected_revision,
            } => self.withdraw(&domain, provider, peer, expected_revision)?,
            Command::OperatorBlock { peer, blocked } => self.operator_block(peer, blocked)?,
            Command::Commit(token) => {
                self.commit(token)?;
                return Ok(None);
            }
        }))
    }
    /// Reserve one maximum checkpoint before each event, with no output queue.
    /// A rejected event is consumed and ends the batch; capacity preserves the
    /// unprocessed suffix. Superseding proposals accumulate earlier mutations.
    pub fn step_batch(&mut self, commands: &[Command], budget: Budget) -> Result<Batch, Error> {
        if budget.events == 0 || budget.events > 64 {
            return Err(Error::Invalid);
        }
        let mut batch = Batch { results: vec![] };
        let mut proposals = 0;
        let mut bytes = 0;
        for command in commands.iter().take(budget.events) {
            if proposals >= budget.proposals
                || self.limits.checkpoint_bytes > budget.bytes.saturating_sub(bytes)
            {
                if batch.results.is_empty() {
                    return Err(Error::Capacity);
                }
                break;
            }
            let result = self.step(command.clone());
            if let Ok(Some(p)) = &result {
                proposals += 1;
                bytes += p.checkpoint.len();
            }
            let failed = result.is_err();
            batch.results.push(result);
            if failed {
                break;
            }
        }
        Ok(batch)
    }
}
