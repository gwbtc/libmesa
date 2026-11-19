//! Optional deterministic admission and authority-provider orchestration.
//! The profile receives transport input inside Mesa and returns screened owned
//! claims. The embedding host sees bounded Verify actions, never peer messages
//! awaiting admission. No native wire decoder, sockets, threads or verifier I/O.
pub use mesa_bytes::Buffer;
use mesa_pki::{
    Authority, Candidate, Error, Lifecycle, Limits, Peer, Proposal, Provider, ProviderStatus, Token,
};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug)]
pub struct Config {
    pub authority: Limits,
    pub pending: usize,
    pub pending_bytes: usize,
    pub max_packet: usize,
    pub request_timeout: u64,
    pub retry_after: u64,
    pub attempts: u32,
    pub work_per_tick: usize,
    pub subscriptions: usize,
    /// Global dispatch budget per interval; claimed peer/source identities are
    /// not used to bypass it. Rejections/completions do not refund this budget.
    pub dispatches: usize,
    pub dispatch_interval: u64,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            authority: Limits::default(),
            pending: 32,
            pending_bytes: 256 * 1024,
            max_packet: 65536,
            request_timeout: 1000,
            retry_after: 100,
            attempts: 3,
            work_per_tick: 16,
            subscriptions: 64,
            dispatches: 32,
            dispatch_interval: 1000,
        }
    }
}
/// Implemented by a Mesa profile, not by application-message handlers. Must
/// bound parsing and perform available name/key/proof checks before returning.
/// An ordinary unverified application packet returns Err and is never queued.
pub trait AdmissionProfile {
    fn screen(&self, packet: &Buffer) -> Result<Candidate, Error>;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ticket {
    pub provider: Provider,
    pub request: u64,
    pub peer: Peer,
    pub base_revision: u64,
    pub digest: [u8; 32],
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    Accept {
        sponsor: Option<Peer>,
        fief: Option<Peer>,
    },
    Reject,
    Unavailable,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum End {
    Rejected,
    TimedOut,
    Cancelled,
    Stale,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Resolve {
        ticket: Ticket,
        domain: String,
        peer: Peer,
    },
    Verify {
        ticket: Ticket,
        candidate: Candidate,
    },
    /// A profile may solicit evidence; the host must not deliver this as an
    /// application message. Native encoding belongs to the phase-6 profile.
    Solicit {
        peer: Peer,
    },
    Persist(Proposal),
    Changed {
        peer: Peer,
        revision: u64,
    },
    Finished {
        request: u64,
        reason: End,
    },
    Timer(Option<u64>),
}
#[derive(Clone, Debug)]
struct Pending {
    ticket: Ticket,
    domain: String,
    candidate: Option<Candidate>,
    due: u64,
    attempts: u32,
    waiting: bool,
}
/// Monotonic peer revision and provider generation fence every asynchronous job.
/// Provider is a host-side capability: never accept it from packet bytes. The
/// embedding integration controls which verifier may submit each completion.
pub struct Jael {
    config: Config,
    authority: Authority,
    now: u64,
    next_request: u64,
    pending: BTreeMap<u64, Pending>,
    subscribers: BTreeSet<Peer>,
    window_start: u64,
    dispatched: usize,
}
impl Jael {
    pub fn new(config: Config, incarnation: u128) -> Result<Self, Error> {
        let authority = Authority::new(config.authority.clone(), incarnation)?;
        Self::with_authority(config, authority)
    }
    pub fn restore(config: Config, incarnation: u128, checkpoint: &Buffer) -> Result<Self, Error> {
        let authority = Authority::restore(config.authority.clone(), incarnation, checkpoint)?;
        Self::with_authority(config, authority)
    }
    fn with_authority(config: Config, authority: Authority) -> Result<Self, Error> {
        if config.pending == 0
            || config.pending > 4096
            || config.pending_bytes == 0
            || config.pending_bytes > 64 * 1024 * 1024
            || config.max_packet == 0
            || config.max_packet > 1024 * 1024
            || config.request_timeout == 0
            || config.retry_after == 0
            || config.attempts == 0
            || config.attempts > 32
            || config.work_per_tick == 0
            || config.work_per_tick > 4096
            || config.subscriptions > 4096
            || config.dispatches == 0
            || config.dispatches > 4096
            || config.dispatch_interval == 0
        {
            return Err(Error::Invalid);
        }
        Ok(Self {
            config,
            authority,
            now: 0,
            next_request: 1,
            pending: BTreeMap::new(),
            subscribers: BTreeSet::new(),
            window_start: 0,
            dispatched: 0,
        })
    }
    pub fn authority(&self) -> &Authority {
        &self.authority
    }
    pub fn config(&self) -> &Config {
        &self.config
    }
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }
    pub fn pending_bytes(&self) -> usize {
        self.pending
            .values()
            .map(|p| p.candidate.as_ref().map_or(0, |c| c.evidence.len()))
            .sum()
    }
    pub fn subscribe(&mut self, peer: Peer) -> Result<(), Error> {
        if !self.subscribers.contains(&peer) && self.subscribers.len() >= self.config.subscriptions
        {
            return Err(Error::Capacity);
        }
        self.subscribers.insert(peer);
        Ok(())
    }
    pub fn unsubscribe(&mut self, peer: Peer) {
        self.subscribers.remove(&peer);
    }
    fn finish_actions(&self, mut actions: Vec<Action>) -> Vec<Action> {
        actions.push(Action::Timer(self.deadline()));
        actions
    }
    pub fn deadline(&self) -> Option<u64> {
        self.pending.values().map(|p| p.due).min()
    }
    fn invalidate(&mut self) -> Vec<Action> {
        let stale: Vec<_> = self
            .pending
            .iter()
            .filter(|(_, p)| {
                self.authority
                    .check_provider(&p.domain, p.ticket.provider)
                    .is_err()
                    || !self.authority.provider_status(&p.domain).ready
                    || self.authority.revision(p.ticket.peer) != p.ticket.base_revision
            })
            .map(|(id, _)| *id)
            .collect();
        stale
            .into_iter()
            .map(|id| {
                self.pending.remove(&id);
                Action::Finished {
                    request: id,
                    reason: End::Stale,
                }
            })
            .collect()
    }
    fn changed(&self, actions: &mut Vec<Action>) {
        for peer in &self.subscribers {
            actions.push(Action::Changed {
                peer: *peer,
                revision: self.authority.revision(*peer),
            });
        }
    }
    fn mutation(&mut self, proposal: Proposal) -> Vec<Action> {
        let mut actions = self.invalidate();
        actions.push(Action::Persist(proposal));
        self.changed(&mut actions);
        self.finish_actions(actions)
    }
    pub fn register(
        &mut self,
        domain: &str,
        expected: u64,
        generation: u64,
    ) -> Result<Vec<Action>, Error> {
        let p = self.authority.register(domain, expected, generation)?;
        Ok(self.mutation(p))
    }
    pub fn lifecycle(
        &mut self,
        domain: &str,
        provider: Provider,
        lifecycle: Lifecycle,
    ) -> Result<Vec<Action>, Error> {
        let result = self.authority.lifecycle(domain, provider, lifecycle);
        // A valid restriction can close readiness even when its checkpoint hits
        // capacity. Invalidate the jobs before propagating that error.
        if result.is_err() {
            self.invalidate();
        }
        Ok(self.mutation(result?))
    }
    pub fn set_status(
        &mut self,
        domain: &str,
        provider: Provider,
        status: ProviderStatus,
    ) -> Result<Vec<Action>, Error> {
        self.authority.set_status(domain, provider, status)?;
        let mut a = self.invalidate();
        self.changed(&mut a);
        Ok(self.finish_actions(a))
    }
    pub fn commit(&mut self, token: Token) -> Result<Vec<Action>, Error> {
        self.authority.commit(token)?;
        let mut a = vec![];
        self.changed(&mut a);
        Ok(self.finish_actions(a))
    }
    pub fn operator_block(&mut self, peer: Peer, blocked: bool) -> Result<Vec<Action>, Error> {
        let p = self.authority.operator_block(peer, blocked)?;
        Ok(self.mutation(p))
    }
    pub fn withdraw(
        &mut self,
        domain: &str,
        provider: Provider,
        peer: Peer,
        revision: u64,
    ) -> Result<Vec<Action>, Error> {
        let result = self.authority.withdraw(domain, provider, peer, revision);
        if result.is_err() {
            self.invalidate();
        }
        let mut a = self.mutation(result?);
        if self.authority.policy(peer).is_some_and(|p| p.recovery()) {
            a.insert(0, Action::Solicit { peer });
        }
        Ok(a)
    }
    /// Called by the Mesa transport/profile composition. No unverified ordinary
    /// payload leaves this path. Global screening budget precedes expensive work.
    pub fn receive<P: AdmissionProfile>(
        &mut self,
        profile: &P,
        packet: Buffer,
    ) -> Result<Vec<Action>, Error> {
        if packet.len() > self.config.max_packet {
            return Err(Error::Capacity);
        }
        self.charge()?;
        let candidate = profile.screen(&packet)?;
        self.enqueue(candidate)
    }
    /// Administrative/outbound resolution of a screened candidate. Uses exactly
    /// the same acceptance path as incoming evidence; no trusted install shortcut.
    pub fn resolve(&mut self, candidate: Candidate) -> Result<Vec<Action>, Error> {
        self.charge()?;
        self.enqueue(candidate)
    }
    fn charge(&mut self) -> Result<(), Error> {
        if self.dispatched >= self.config.dispatches {
            return Err(Error::Capacity);
        }
        self.dispatched += 1;
        Ok(())
    }
    fn enqueue(&mut self, candidate: Candidate) -> Result<Vec<Action>, Error> {
        self.authority.check_candidate(&candidate)?;
        let provider = self.authority.provider(&candidate.domain)?;
        let status = self.authority.provider_status(&candidate.domain);
        if !status.ready || !status.available {
            return Err(Error::Unavailable);
        }
        if self
            .authority
            .policy(candidate.peer)
            .is_some_and(|p| p.operator_blocked)
        {
            return Err(Error::Unavailable);
        }
        let digest = candidate.digest();
        if self.pending.values().any(|p| p.ticket.digest == digest) {
            return Ok(self.finish_actions(vec![]));
        }
        if self.pending.len() >= self.config.pending
            || candidate.evidence.len()
                > self
                    .config
                    .pending_bytes
                    .saturating_sub(self.pending_bytes())
        {
            return Err(Error::Capacity);
        }
        let request = self.next_request;
        let next = request.checked_add(1).ok_or(Error::Capacity)?;
        let due = self
            .now
            .checked_add(self.config.request_timeout)
            .ok_or(Error::Clock)?;
        let ticket = Ticket {
            provider,
            request,
            peer: candidate.peer,
            base_revision: self.authority.revision(candidate.peer),
            digest,
        };
        self.next_request = next;
        self.pending.insert(
            request,
            Pending {
                ticket,
                domain: candidate.domain.clone(),
                candidate: Some(candidate.clone()),
                due,
                attempts: 1,
                waiting: true,
            },
        );
        Ok(self.finish_actions(vec![Action::Verify { ticket, candidate }]))
    }
    /// Outbound/administrative name lookup. The provider returns the point;
    /// no embedding-host pass construction is required.
    pub fn resolve_peer(&mut self, domain: &str, peer: Peer) -> Result<Vec<Action>, Error> {
        self.charge()?;
        let provider = self.authority.provider(domain)?;
        let status = self.authority.provider_status(domain);
        if !status.ready || !status.available {
            return Err(Error::Unavailable);
        }
        if let Some(p) = self.authority.peer(peer) {
            if p.point.candidate.domain != domain {
                return Err(Error::Conflict);
            }
            if p.operator_blocked {
                return Err(Error::Unavailable);
            }
        }
        let mut transcript = b"mesa/pki/resolve/1\0".to_vec();
        transcript.extend_from_slice(&peer.to_le_bytes());
        transcript.extend_from_slice(domain.as_bytes());
        let digest = mesa_crypto::sha256(&transcript);
        if self.pending.values().any(|p| p.ticket.digest == digest) {
            return Ok(self.finish_actions(vec![]));
        }
        if self.pending.len() >= self.config.pending {
            return Err(Error::Capacity);
        }
        let request = self.next_request;
        let next = request.checked_add(1).ok_or(Error::Capacity)?;
        let due = self
            .now
            .checked_add(self.config.request_timeout)
            .ok_or(Error::Clock)?;
        let ticket = Ticket {
            provider,
            request,
            peer,
            base_revision: self.authority.revision(peer),
            digest,
        };
        self.next_request = next;
        self.pending.insert(
            request,
            Pending {
                ticket,
                domain: domain.into(),
                candidate: None,
                due,
                attempts: 1,
                waiting: true,
            },
        );
        Ok(self.finish_actions(vec![Action::Resolve {
            ticket,
            domain: domain.into(),
            peer,
        }]))
    }
    pub fn resolved(
        &mut self,
        domain: &str,
        ticket: Ticket,
        candidate: Candidate,
        sponsor: Option<Peer>,
        fief: Option<Peer>,
    ) -> Result<Vec<Action>, Error> {
        let p = self.pending.get(&ticket.request).ok_or(Error::Stale)?;
        if p.ticket != ticket
            || p.domain != domain
            || p.candidate.is_some()
            || !p.waiting
            || p.due <= self.now
            || candidate.domain != domain
            || candidate.peer != ticket.peer
        {
            return Err(Error::Stale);
        }
        let proposal = self.authority.accept(
            ticket.provider,
            ticket.base_revision,
            candidate,
            sponsor,
            fief,
        )?;
        self.pending.remove(&ticket.request);
        Ok(self.mutation(proposal))
    }
    pub fn complete(
        &mut self,
        domain: &str,
        ticket: Ticket,
        verdict: Verdict,
    ) -> Result<Vec<Action>, Error> {
        let p = self.pending.get(&ticket.request).ok_or(Error::Stale)?;
        if p.ticket != ticket || p.domain != domain || !p.waiting || p.due <= self.now {
            return Err(Error::Stale);
        }
        self.authority.check_provider(domain, ticket.provider)?;
        if self.authority.revision(ticket.peer) != ticket.base_revision {
            return Err(Error::Stale);
        }
        match verdict {
            Verdict::Accept { sponsor, fief } => {
                let proposal = self.authority.accept(
                    ticket.provider,
                    ticket.base_revision,
                    p.candidate.clone().ok_or(Error::Invalid)?,
                    sponsor,
                    fief,
                )?;
                self.pending.remove(&ticket.request);
                Ok(self.mutation(proposal))
            }
            Verdict::Reject => {
                self.pending.remove(&ticket.request);
                Ok(self.finish_actions(vec![Action::Finished {
                    request: ticket.request,
                    reason: End::Rejected,
                }]))
            }
            Verdict::Unavailable => {
                let due = self
                    .now
                    .checked_add(self.config.retry_after)
                    .ok_or(Error::Clock)?;
                let p = self.pending.get_mut(&ticket.request).unwrap();
                p.waiting = false;
                p.due = due;
                Ok(self.finish_actions(vec![]))
            }
        }
    }
    pub fn cancel(&mut self, request: u64) -> Result<Vec<Action>, Error> {
        self.pending.remove(&request).ok_or(Error::Stale)?;
        Ok(self.finish_actions(vec![Action::Finished {
            request,
            reason: End::Cancelled,
        }]))
    }
    pub fn advance(&mut self, now: u64) -> Result<Vec<Action>, Error> {
        if now < self.now {
            return Err(Error::Clock);
        }
        self.now = now;
        if now.saturating_sub(self.window_start) >= self.config.dispatch_interval {
            self.window_start = now;
            self.dispatched = 0;
        }
        let mut actions = self.invalidate();
        let due: Vec<_> = self
            .pending
            .iter()
            .filter(|(_, p)| p.due <= now)
            .take(self.config.work_per_tick)
            .map(|(id, _)| *id)
            .collect();
        for id in due {
            let mut p = self.pending.remove(&id).unwrap();
            // Each attempt gets a new correlation id, so an old timeout or lost
            // response cannot complete a later retry.
            if p.attempts >= self.config.attempts
                || now.checked_add(self.config.request_timeout).is_none()
            {
                actions.push(Action::Finished {
                    request: id,
                    reason: End::TimedOut,
                });
                continue;
            }
            if !self.authority.provider_status(&p.domain).available
                || self.dispatched >= self.config.dispatches
            {
                p.attempts += 1;
                if let Some(due) = now.checked_add(self.config.retry_after) {
                    p.waiting = false;
                    p.due = due;
                    self.pending.insert(id, p);
                } else {
                    actions.push(Action::Finished {
                        request: id,
                        reason: End::TimedOut,
                    });
                }
                continue;
            }
            let Some(next) = self.next_request.checked_add(1) else {
                actions.push(Action::Finished {
                    request: id,
                    reason: End::TimedOut,
                });
                continue;
            };
            actions.push(Action::Finished {
                request: id,
                reason: End::TimedOut,
            });
            self.dispatched += 1;
            p.attempts += 1;
            p.waiting = true;
            p.due = now + self.config.request_timeout;
            p.ticket.request = self.next_request;
            self.next_request = next;
            actions.push(match &p.candidate {
                Some(candidate) => Action::Verify {
                    ticket: p.ticket,
                    candidate: candidate.clone(),
                },
                None => Action::Resolve {
                    ticket: p.ticket,
                    domain: p.domain.clone(),
                    peer: p.ticket.peer,
                },
            });
            self.pending.insert(p.ticket.request, p);
        }
        Ok(self.finish_actions(actions))
    }
}

/// Typed component inputs. ProfileCandidate is a Mesa-internal composition
/// seam, not an instruction for embedding hosts to decode incoming packets.
#[derive(Clone, Debug)]
pub enum Input {
    ResolvePeer {
        domain: String,
        peer: Peer,
    },
    Resolved {
        domain: String,
        ticket: Ticket,
        candidate: Candidate,
        sponsor: Option<Peer>,
        fief: Option<Peer>,
    },
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
    ProfileCandidate(Candidate),
    Resolve(Candidate),
    RefreshEvidence(Candidate),
    Complete {
        domain: String,
        ticket: Ticket,
        verdict: Verdict,
    },
    Withdraw {
        domain: String,
        provider: Provider,
        peer: Peer,
        revision: u64,
    },
    OperatorBlock {
        peer: Peer,
        blocked: bool,
    },
    Commit(Token),
    Cancel(u64),
    Advance(u64),
    Subscribe(Peer),
    Unsubscribe(Peer),
}
#[derive(Clone, Copy, Debug)]
pub struct Budget {
    pub events: usize,
    pub records: usize,
    pub bytes: usize,
}
#[derive(Clone, Debug)]
pub struct Batch {
    pub results: Vec<Result<Vec<Action>, Error>>,
}
impl Jael {
    /// Conservative reservation bounds each event before any mutation. Output
    /// buffers own their storage. Errors consume their event and stop the batch;
    /// capacity stops leave the suffix untouched. No retained output queue.
    pub fn envelope(&self) -> (usize, usize) {
        (
            self.config.pending + self.config.subscriptions + self.config.work_per_tick + 4,
            self.config.authority.checkpoint_bytes
                + self.config.pending_bytes
                + self.config.authority.evidence_bytes,
        )
    }
    pub fn step(&mut self, input: Input) -> Result<Vec<Action>, Error> {
        match input {
            Input::ResolvePeer { domain, peer } => self.resolve_peer(&domain, peer),
            Input::Resolved {
                domain,
                ticket,
                candidate,
                sponsor,
                fief,
            } => self.resolved(&domain, ticket, candidate, sponsor, fief),
            Input::Register {
                domain,
                expected,
                generation,
            } => self.register(&domain, expected, generation),
            Input::Status {
                domain,
                provider,
                status,
            } => self.set_status(&domain, provider, status),
            Input::Lifecycle {
                domain,
                provider,
                lifecycle,
            } => self.lifecycle(&domain, provider, lifecycle),
            Input::ProfileCandidate(c) | Input::Resolve(c) => self.resolve(c),
            Input::RefreshEvidence(c) => {
                self.authority.check_refresh(&c)?;
                self.resolve(c)
            }
            Input::Complete {
                domain,
                ticket,
                verdict,
            } => self.complete(&domain, ticket, verdict),
            Input::Withdraw {
                domain,
                provider,
                peer,
                revision,
            } => self.withdraw(&domain, provider, peer, revision),
            Input::OperatorBlock { peer, blocked } => self.operator_block(peer, blocked),
            Input::Commit(t) => self.commit(t),
            Input::Cancel(id) => self.cancel(id),
            Input::Advance(now) => self.advance(now),
            Input::Subscribe(peer) => {
                self.subscribe(peer)?;
                Ok(self.finish_actions(vec![]))
            }
            Input::Unsubscribe(peer) => {
                self.unsubscribe(peer);
                Ok(self.finish_actions(vec![]))
            }
        }
    }
    pub fn step_batch(&mut self, inputs: &[Input], budget: Budget) -> Result<Batch, Error> {
        if budget.events == 0 || budget.events > 64 {
            return Err(Error::Invalid);
        }
        let (records, bytes) = self.envelope();
        let mut result = Batch { results: vec![] };
        let mut used_records = 0;
        let mut used_bytes = 0;
        for input in inputs.iter().take(budget.events) {
            if records > budget.records.saturating_sub(used_records)
                || bytes > budget.bytes.saturating_sub(used_bytes)
            {
                if result.results.is_empty() {
                    return Err(Error::Capacity);
                }
                break;
            }
            let step = self.step(input.clone());
            if let Ok(actions) = &step {
                used_records += actions.len();
                used_bytes += actions
                    .iter()
                    .map(|a| match a {
                        Action::Verify { candidate, .. } => candidate.evidence.len(),
                        Action::Persist(p) => p.checkpoint.len(),
                        _ => 0,
                    })
                    .sum::<usize>();
            } else {
                used_records += 1;
            }
            let failed = step.is_err();
            result.results.push(step);
            if failed {
                break;
            }
        }
        Ok(result)
    }
}
