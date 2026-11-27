//! UDP admission composition. Ordinary unknown-peer packets never leave this
//! adapter; the first host-visible event is a screened verification request.
use crate::{
    contact::{self, Contact, Token},
    Buffer, Error,
};
use mesa_core::{Attachment, PeerId};
use mesa_pki::{Authority, Candidate};
use mesa_transport::{EndpointError, UdpEndpoint, Unrouted};
use std::{collections::BTreeMap, net::SocketAddr};
#[derive(Debug)]
pub enum Failure {
    Profile(Error),
    Transport(EndpointError),
}
impl From<Error> for Failure {
    fn from(e: Error) -> Self {
        Self::Profile(e)
    }
}
impl From<EndpointError> for Failure {
    fn from(e: EndpointError) -> Self {
        Self::Transport(e)
    }
}
pub enum Action {
    Verify {
        token: Token,
        candidate: Candidate,
    },
    /// Only for an installed, currently authorized peer. Feed this into its
    /// service session; authenticated application delivery remains transactional.
    AdmittedPacket {
        peer: PeerId,
        attachment: Attachment,
        bytes: Buffer,
    },
    Ready {
        peer: PeerId,
        attachment: Attachment,
    },
    Expired(Token),
    Timer(Option<u64>),
}
pub struct Listener {
    endpoint: UdpEndpoint,
    contact: Contact,
    hints: BTreeMap<u64, SocketAddr>,
    next: u64,
    max: usize,
}
impl Listener {
    pub fn new(endpoint: UdpEndpoint, contact: Contact, max_hints: usize) -> Result<Self, Error> {
        if max_hints == 0 || max_hints > 256 {
            return Err(Error::Limit);
        }
        Ok(Self {
            endpoint,
            contact,
            hints: BTreeMap::new(),
            next: 1,
            max: max_hints,
        })
    }
    pub fn set_recovery(&mut self, peer: u128, packet: Buffer) -> Result<(), Failure> {
        Ok(self.contact.set_recovery(peer, packet)?)
    }
    pub fn endpoint(&mut self) -> &mut UdpEndpoint {
        &mut self.endpoint
    }
    pub fn deadline(&self) -> Option<u64> {
        self.contact.deadline()
    }
    pub fn pending(&self) -> usize {
        self.contact.pending()
    }
    pub fn poll(&mut self, authority: &Authority) -> Result<Vec<Action>, Failure> {
        let Unrouted::Packet {
            source,
            installed,
            bytes,
        } = self.endpoint.receive_unrouted()?
        else {
            return Ok(Vec::new());
        };
        let control = crate::identity_control::decode(&Buffer::from(bytes.clone())).ok();
        let recovery = self.contact.needs_recovery(&bytes, authority);
        if control.is_none() && !recovery {
            if let Some((peer, attachment)) = installed {
                if authority.policy(peer.0).is_some_and(|p| p.ordinary()) {
                    return Ok(vec![Action::AdmittedPacket {
                        peer,
                        attachment,
                        bytes: bytes.into(),
                    }]);
                }
            }
        }
        let route = if let Some((&route, _)) = self.hints.iter().find(|(_, s)| **s == source) {
            route
        } else {
            if self.hints.len() >= self.max {
                return Ok(Vec::new());
            }
            let route = self.next;
            self.next = self.next.checked_add(1).ok_or(Error::Limit)?;
            self.hints.insert(route, source);
            route
        };
        let actions = if let Some(control) = control {
            let sender = match control {
                crate::identity_control::Control::Keys { sender, .. }
                | crate::identity_control::Control::Open { sender, .. } => sender,
            };
            if installed.is_some_and(|(peer, _)| peer.0 != sender) {
                self.prune();
                return Ok(Vec::new());
            }
            self.contact
                .receive_control(Attachment(route), &bytes.into(), authority)
        } else if recovery {
            self.contact
                .request_recovery(Attachment(route), &bytes, authority)
        } else {
            self.contact.receive(Attachment(route), &bytes.into())
        };
        let result = match actions {
            Ok(a) => self.actions(a),
            Err(_) => Ok(Vec::new()),
        };
        self.prune();
        result
    }
    pub fn promote(&mut self, token: Token, authority: &Authority) -> Result<Vec<Action>, Failure> {
        // Reserve/install the endpoint route before consuming correlation. A
        // full or conflicting route table leaves the verified request retryable.
        let ready = self.contact.preview(token, authority)?;
        let mut out = self.actions(vec![ready])?;
        self.contact.promote(token, authority)?;
        out.push(Action::Timer(self.contact.deadline()));
        self.prune();
        Ok(out)
    }
    pub fn advance(&mut self, now: u64) -> Result<Vec<Action>, Failure> {
        let a = self.contact.advance(now)?;
        let out = self.actions(a);
        self.prune();
        out
    }
    pub fn cancel(&mut self, token: Token) -> Result<Vec<Action>, Failure> {
        let a = self.contact.cancel(token)?;
        let out = self.actions(a);
        self.prune();
        out
    }
    pub fn activate(&mut self, life: u32) -> Result<Vec<Action>, Failure> {
        let a = self.contact.activate(life)?;
        let out = self.actions(a);
        self.prune();
        out
    }
    fn prune(&mut self) {
        let active = self.contact.routes();
        self.hints.retain(|id, _| active.contains(&Attachment(*id)));
    }
    fn actions(&mut self, actions: Vec<contact::Action>) -> Result<Vec<Action>, Failure> {
        let mut out = Vec::new();
        for a in actions {
            match a {
                contact::Action::Send { packet } => {
                    let source = *self
                        .hints
                        .get(&packet.attachment().0)
                        .ok_or(Error::Coordinate)?;
                    packet
                        .submit(|_, _, bytes| {
                            bytes.with_bytes(|b| self.endpoint.send_to_hint(source, b))
                        })
                        .map_err(|_| Error::Coordinate)??;
                }
                contact::Action::Verify { token, candidate } => {
                    out.push(Action::Verify { token, candidate })
                }
                contact::Action::Ready { peer, route, .. } => {
                    let source = *self.hints.get(&route.0).ok_or(Error::Coordinate)?;
                    let old = self
                        .endpoint
                        .routes()
                        .iter()
                        .find(|r| r.peer == peer)
                        .map_or(0, |r| r.generation);
                    let next = old.checked_add(1).ok_or(Error::Limit)?;
                    self.endpoint.set_route(peer, old, next, Some(source))?;
                    out.push(Action::Ready {
                        peer,
                        attachment: Attachment(next),
                    });
                }
                contact::Action::Expired(t) => out.push(Action::Expired(t)),
                contact::Action::Timer(t) => out.push(Action::Timer(t)),
            }
        }
        Ok(out)
    }
}
