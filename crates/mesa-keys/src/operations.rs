//! Scoped asynchronous key work. Software execution is immediate; the request
//! can also be dispatched to a selected backend. No packet-chosen signing API.
use super::*;
use mesa_crypto::SharedSecret;
#[derive(Clone, Debug)]
pub enum Purpose {
    PublicRoot {
        path: Buffer,
        total: u64,
        root: [u8; 32],
    },
    Agreement {
        peer: u128,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ticket {
    pub incarnation: u128,
    pub id: u64,
    pub generation: u64,
}
#[derive(Clone)]
pub struct Request {
    ticket: Ticket,
    reference: KeyRef,
    public_key: [u8; 32],
    transcript: Buffer,
    agreement: Option<[u8; 32]>,
}
pub enum Reply {
    Signature([u8; 64]),
    Agreement(Arc<SharedSecret>),
}
pub(super) struct Job {
    pub request: Request,
    pub deadline: u64,
    pub peer: Option<(u128, u64)>,
}
impl SoftwareStore {
    pub fn execute(&self, r: &Request) -> Result<Reply, Error> {
        let key = self.key(r.reference)?;
        if key.public_key().as_bytes() != &r.public_key {
            return Err(Error::Conflict);
        }
        match r.agreement {
            Some(p) => Ok(Reply::Agreement(Arc::new(
                key.agree(&PublicKey::from_bytes(p).map_err(|_| Error::Invalid)?)
                    .map_err(|_| Error::Backend)?,
            ))),
            None => Ok(Reply::Signature(r.transcript.with_bytes(|b| key.sign(b)))),
        }
    }
}
impl Activation {
    pub fn operation(
        &mut self,
        a: &Authority,
        store: &SoftwareStore,
        purpose: Purpose,
    ) -> Result<Request, Error> {
        let (c, _) = self.credential(a, store)?;
        if self.jobs.len() >= self.config.operations {
            return Err(Error::Capacity);
        }
        let id = self.next_job;
        let next = id.checked_add(1).ok_or(Error::Capacity)?;
        let deadline = self
            .now
            .checked_add(self.config.timeout)
            .ok_or(Error::Clock)?;
        let (transcript, agreement, peer) = match purpose {
            Purpose::PublicRoot { path, total, root } => {
                if path.len() > 256 || total > 1024 * 1024 {
                    return Err(Error::Invalid);
                }
                let v = PreconfiguredPeer::new(
                    PeerId(c.point.peer),
                    &c.point.domain,
                    c.point.life,
                    c.point.rift,
                    KeyHandle(1),
                )
                .map_err(|_| Error::Invalid)?;
                // Public roots are an explicit trusted protocol-module operation.
                let bytes = path
                    .with_bytes(|p| mesa_core::protection::root_context_owned(&v, p, total, &root));
                (bytes.into(), None, None)
            }
            Purpose::Agreement { peer } => {
                let p = a.peer(peer).ok_or(Error::Unavailable)?;
                if !a.policy(peer).is_some_and(|p| p.ordinary()) {
                    return Err(Error::Unavailable);
                }
                (
                    Buffer::default(),
                    Some(p.point.candidate.public_key),
                    Some((peer, p.revision)),
                )
            }
        };
        let request = Request {
            ticket: Ticket {
                incarnation: self.config.incarnation,
                id,
                generation: self.state.generation,
            },
            reference: c.reference,
            public_key: c.point.public_key,
            transcript,
            agreement,
        };
        self.next_job = next;
        self.jobs.insert(
            id,
            Job {
                request: request.clone(),
                deadline,
                peer,
            },
        );
        Ok(request)
    }
    pub fn complete(
        &mut self,
        a: &Authority,
        ticket: Ticket,
        reply: Reply,
    ) -> Result<Reply, Error> {
        self.reconcile(a)?;
        let job = self.jobs.get(&ticket.id).ok_or(Error::Stale)?;
        if job.request.ticket != ticket
            || job.deadline <= self.now
            || ticket.generation != self.state.generation
        {
            return Err(Error::Stale);
        }
        if let Some((peer, revision)) = job.peer {
            if a.revision(peer) != revision || !a.policy(peer).is_some_and(|p| p.ordinary()) {
                self.jobs.remove(&ticket.id);
                return Err(Error::Stale);
            }
        }
        match (&reply, job.request.agreement) {
            (Reply::Signature(sig), None) => {
                job.request
                    .transcript
                    .with_bytes(|b| {
                        PublicKey::from_bytes(job.request.public_key)
                            .unwrap()
                            .verify(b, sig)
                    })
                    .map_err(|_| Error::Backend)?;
            }
            (Reply::Agreement(_), Some(_)) => {}
            _ => return Err(Error::Conflict),
        }
        self.jobs.remove(&ticket.id);
        Ok(reply)
    }
    pub fn cancel_operation(&mut self, ticket: Ticket) -> Result<(), Error> {
        if self.jobs.get(&ticket.id).map(|j| j.request.ticket) != Some(ticket) {
            return Err(Error::Stale);
        }
        self.jobs.remove(&ticket.id);
        Ok(())
    }
}
impl Activation {
    pub fn has_operation(&self, ticket: Ticket) -> bool {
        self.jobs
            .get(&ticket.id)
            .is_some_and(|j| j.request.ticket == ticket)
    }
}

impl Request {
    pub fn ticket(&self) -> Ticket {
        self.ticket
    }
    pub fn reference(&self) -> KeyRef {
        self.reference
    }
    pub fn public_key(&self) -> [u8; 32] {
        self.public_key
    }
    pub fn transcript(&self) -> Buffer {
        self.transcript.clone()
    }
    pub fn agreement(&self) -> Option<[u8; 32]> {
        self.agreement
    }
}
