//! Bounded first-contact driver, called by the transport adapter before host
//! application dispatch. It retains route hints and correlation, never payloads.
use crate::{admission::ProofProfile, path, Buffer, Error};
use mesa_core::{
    credentials::{FencedPacket, SendGate},
    Attachment, PeerId,
};
use mesa_pki::{Authority, Candidate};
use mesa_wire::mesa_v1::{self as wire, Body, Fragment, Name};
use std::collections::BTreeMap;

#[derive(Clone, Debug)]
pub struct Config {
    pub pending: usize,
    pub attempts: u32,
    pub retry: u64,
    pub timeout: u64,
    pub dispatches: usize,
    pub interval: u64,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            pending: 32,
            attempts: 3,
            retry: 100,
            timeout: 2000,
            dispatches: 32,
            interval: 1000,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Token {
    pub incarnation: u128,
    pub request: u64,
}
#[derive(Clone, Debug)]
pub enum Action {
    Send {
        packet: FencedPacket,
    },
    /// First OS-host notification: a bounded, cryptographically screened
    /// attestation for its verifier. Optional Jael can consume it internally.
    Verify {
        token: Token,
        candidate: Candidate,
    },
    Ready {
        peer: PeerId,
        route: Attachment,
        revision: u64,
    },
    Expired(Token),
    Timer(Option<u64>),
}
struct Pending {
    token: Token,
    route: Attachment,
    deadline: u64,
    due: u64,
    attempts: u32,
    candidate: Option<Candidate>,
}
pub struct Contact {
    config: Config,
    profile: ProofProfile,
    incarnation: u128,
    next: u64,
    now: u64,
    window: u64,
    charged: usize,
    pending: BTreeMap<u128, Pending>,
    recovery: BTreeMap<u128, Buffer>,
    send_gate: SendGate,
}
impl Contact {
    pub fn new(config: Config, profile: ProofProfile, incarnation: u128) -> Result<Self, Error> {
        if incarnation == 0
            || profile.life == 0
            || config.pending == 0
            || config.pending > 256
            || config.attempts == 0
            || config.attempts > 32
            || config.retry == 0
            || config.timeout == 0
            || config.dispatches == 0
            || config.dispatches > 256
            || config.interval == 0
        {
            return Err(Error::Limit);
        }
        Ok(Self {
            config,
            profile,
            incarnation,
            next: 1,
            now: 0,
            window: 0,
            charged: 0,
            pending: BTreeMap::new(),
            recovery: BTreeMap::new(),
            send_gate: SendGate::default(),
        })
    }
    /// Install a pre-signed current open response after durable local activation.
    /// The host/key module signs the bounded identity control, never arbitrary
    /// packet contents. Recovery always addresses receiver life one.
    pub fn set_recovery(&mut self, peer: u128, packet: Buffer) -> Result<(), Error> {
        if !self.recovery.contains_key(&peer) && self.recovery.len() >= self.config.pending {
            return Err(Error::Limit);
        }
        let c = crate::identity_control::screen(
            &packet,
            peer,
            1,
            self.profile.local_rift,
            &self.profile.domain,
            false,
        )?;
        if c.peer != self.profile.local || c.life != self.profile.life {
            return Err(Error::Coordinate);
        }
        self.recovery.insert(peer, packet);
        Ok(())
    }
    /// Old-Ames identity controls are handled inside the admission adapter.
    /// Known peer authority supplies the epoch; four-bit ticks supply none.
    pub fn receive_control(
        &mut self,
        route: Attachment,
        bytes: &Buffer,
        authority: &Authority,
    ) -> Result<Vec<Action>, Error> {
        use crate::identity_control::{self, Control};
        let control = identity_control::decode(bytes)?;
        let (peer, receiver) = match &control {
            Control::Keys {
                sender, receiver, ..
            }
            | Control::Open {
                sender, receiver, ..
            } => (*sender, *receiver),
        };
        if receiver != self.profile.local {
            return Err(Error::Coordinate);
        }
        let accepted = authority.peer(peer).ok_or(Error::Coordinate)?;
        if accepted.point.candidate.domain != self.profile.domain {
            return Err(Error::Coordinate);
        }
        self.charge()?;
        if matches!(control, Control::Keys { .. }) {
            let bytes = self.recovery.get(&peer).ok_or(Error::Coordinate)?.clone();
            return Ok(vec![self.send(peer, route, bytes)]);
        }
        let candidate = identity_control::screen(
            bytes,
            self.profile.local,
            self.profile.life,
            accepted.point.candidate.rift,
            &self.profile.domain,
            self.profile.historical_life_one,
        )?;
        if candidate.life < accepted.point.candidate.life {
            return Err(Error::Coordinate);
        }
        if self
            .pending
            .get(&peer)
            .is_some_and(|p| p.candidate.as_ref() == Some(&candidate))
        {
            return Ok(vec![]);
        }
        if !self.pending.contains_key(&peer) && self.pending.len() >= self.config.pending {
            return Err(Error::Limit);
        }
        let token = Token {
            incarnation: self.incarnation,
            request: self.next,
        };
        let next = self.next.checked_add(1).ok_or(Error::Limit)?;
        let deadline = self
            .now
            .checked_add(self.config.timeout)
            .ok_or(Error::Limit)?;
        let mut out = Vec::new();
        if let Some(old) = self.pending.insert(
            peer,
            Pending {
                token,
                route,
                deadline,
                due: deadline,
                attempts: self.config.attempts,
                candidate: Some(candidate.clone()),
            },
        ) {
            out.push(Action::Expired(old.token));
        }
        self.next = next;
        out.push(Action::Verify { token, candidate });
        out.push(Action::Timer(self.deadline()));
        Ok(out)
    }
    /// Detect only a reason to solicit current identity. Cleartext life fields
    /// are untrusted hints and never advance authority or release a payload.
    pub fn needs_recovery(&self, bytes: &[u8], authority: &Authority) -> bool {
        let Ok(p) = wire::decode(bytes, wire::Checksum::VereBytes, wire::Limits::DATAGRAM) else {
            return false;
        };
        let Body::Poke { ack, payload, .. } = p.body else {
            return false;
        };
        if ack.ship != self.profile.local {
            return false;
        }
        let Some(accepted) = authority.peer(payload.ship) else {
            return false;
        };
        let Ok(path) = std::str::from_utf8(payload.path) else {
            return false;
        };
        let parts: Vec<_> = path.split('/').collect();
        parts.len() == 5
            && parts[0] == "chum"
            && (crate::path::parse_decimal(parts[1])
                .is_ok_and(|life| life > accepted.point.candidate.life as u64)
                || crate::path::parse_decimal(parts[3])
                    .is_ok_and(|life| life != self.profile.life as u64))
    }
    pub fn request_recovery(
        &mut self,
        route: Attachment,
        bytes: &[u8],
        authority: &Authority,
    ) -> Result<Vec<Action>, Error> {
        if !self.needs_recovery(bytes, authority) {
            return Err(Error::Coordinate);
        }
        let p = wire::decode(bytes, wire::Checksum::VereBytes, wire::Limits::DATAGRAM)
            .map_err(|_| Error::Encoding)?;
        let Body::Poke { payload, .. } = p.body else {
            return Err(Error::Shape);
        };
        self.charge()?;
        let bytes =
            crate::identity_control::keys(self.profile.local, payload.ship, self.profile.life)?;
        Ok(vec![self.send(payload.ship, route, bytes)])
    }
    pub fn routes(&self) -> Vec<Attachment> {
        self.pending.values().map(|p| p.route).collect()
    }
    pub fn pending(&self) -> usize {
        self.pending.len()
    }
    pub fn deadline(&self) -> Option<u64> {
        self.pending
            .values()
            .map(|p| {
                if p.candidate.is_some() || p.attempts >= self.config.attempts {
                    p.deadline
                } else {
                    p.due.min(p.deadline)
                }
            })
            .min()
    }
    fn charge(&mut self) -> Result<(), Error> {
        if self.charged >= self.config.dispatches {
            return Err(Error::Limit);
        }
        self.charged += 1;
        Ok(())
    }
    fn send(&self, peer: u128, route: Attachment, bytes: Buffer) -> Action {
        Action::Send {
            packet: self.send_gate.packet(PeerId(peer), route, bytes),
        }
    }
    // Retained outputs share one admission generation. Ending any request
    // conservatively revokes all queued controls; active requests retry normally.
    fn revoke(&self) -> Result<(), Error> {
        self.send_gate.change(true).map_err(|_| Error::Limit)
    }
    fn solicit(&self, peer: u128, route: Attachment) -> Result<Action, Error> {
        let path = path::proof(self.profile.local, self.profile.life)?;
        let packet = wire::Packet {
            hop: 0,
            body: Body::Peek(Name {
                ship: peer,
                rift: self.profile.rift,
                bloq: 13,
                fragment: Fragment::Init,
                path: &path,
            }),
        };
        let bytes = wire::encode(&packet, wire::Checksum::VereBytes, wire::Limits::DATAGRAM)
            .map_err(|_| Error::Limit)?;
        Ok(self.send(peer, route, bytes.into()))
    }
    pub fn receive(&mut self, route: Attachment, bytes: &Buffer) -> Result<Vec<Action>, Error> {
        if bytes.len() > 1472 {
            return Err(Error::Limit);
        }
        let (peer, proof) = bytes.with_bytes(|bytes| {
            let p = wire::decode(bytes, wire::Checksum::VereBytes, wire::Limits::DATAGRAM)
                .map_err(|_| Error::Encoding)?;
            match p.body {
                Body::Poke { ack, payload, .. }
                    if ack.ship == self.profile.local && payload.ship > u64::MAX as u128 =>
                {
                    if ack.rift != self.profile.local_rift || payload.rift != self.profile.rift {
                        return Err(Error::Coordinate);
                    }
                    if payload.path.starts_with(b"chum/") {
                        Ok((payload.ship, false))
                    } else if payload.path == path::proof(self.profile.local, self.profile.life)? {
                        Ok((payload.ship, true))
                    } else {
                        Err(Error::Shape)
                    }
                }
                Body::Page { name, .. }
                    if name.ship > u64::MAX as u128
                        && name.path == path::proof(self.profile.local, self.profile.life)? =>
                {
                    Ok((name.ship, true))
                }
                _ => Err(Error::Shape),
            }
        })?;
        if proof {
            let Some(p) = self.pending.get(&peer) else {
                return Err(Error::Coordinate);
            };
            if p.route != route || p.candidate.is_some() || self.now >= p.deadline {
                return Err(Error::Coordinate);
            }
            // Bound work independently of claimed identity and checksum validity.
            self.charge()?;
            let candidate = self.profile.screen_proof(bytes)?;
            let p = self.pending.get_mut(&peer).unwrap();
            p.candidate = Some(candidate.clone());
            Ok(vec![
                Action::Verify {
                    token: p.token,
                    candidate,
                },
                Action::Timer(self.deadline()),
            ])
        } else {
            if self.pending.contains_key(&peer) {
                return Ok(vec![Action::Timer(self.deadline())]);
            }
            if self.pending.len() >= self.config.pending {
                return Err(Error::Limit);
            }
            self.charge()?;
            let token = Token {
                incarnation: self.incarnation,
                request: self.next,
            };
            let next = self.next.checked_add(1).ok_or(Error::Limit)?;
            let deadline = self
                .now
                .checked_add(self.config.timeout)
                .ok_or(Error::Limit)?;
            let due = self
                .now
                .checked_add(self.config.retry)
                .ok_or(Error::Limit)?;
            let send = self.solicit(peer, route)?;
            self.pending.insert(
                peer,
                Pending {
                    token,
                    route,
                    deadline,
                    due,
                    attempts: 1,
                    candidate: None,
                },
            );
            self.next = next;
            Ok(vec![send, Action::Timer(self.deadline())])
        }
    }
    /// Promote only after durable PKI acceptance of this exact candidate. A
    /// stale verdict, withdrawn point or unavailable provider cannot grant a route.
    pub fn preview(&self, token: Token, authority: &Authority) -> Result<Action, Error> {
        let (&peer, p) = self
            .pending
            .iter()
            .find(|(_, p)| p.token == token)
            .ok_or(Error::Coordinate)?;
        let candidate = p.candidate.as_ref().ok_or(Error::Coordinate)?;
        let accepted = authority.peer(peer).ok_or(Error::Coordinate)?;
        if self.now >= p.deadline
            || !authority.policy(peer).is_some_and(|p| p.ordinary())
            || accepted.point.candidate != *candidate
        {
            return Err(Error::Coordinate);
        }
        Ok(Action::Ready {
            peer: PeerId(peer),
            route: p.route,
            revision: accepted.revision,
        })
    }
    pub fn promote(&mut self, token: Token, authority: &Authority) -> Result<Vec<Action>, Error> {
        let out = self.preview(token, authority)?;
        self.revoke()?;
        if let Action::Ready { peer, .. } = &out {
            self.pending.remove(&peer.0);
        }
        Ok(vec![out, Action::Timer(self.deadline())])
    }
    pub fn cancel(&mut self, token: Token) -> Result<Vec<Action>, Error> {
        let peer = *self
            .pending
            .iter()
            .find(|(_, p)| p.token == token)
            .map(|(peer, _)| peer)
            .ok_or(Error::Coordinate)?;
        self.revoke()?;
        self.pending.remove(&peer);
        Ok(vec![Action::Expired(token), Action::Timer(self.deadline())])
    }
    /// Local activation fences all old receiver-life proof requests.
    pub fn activate(&mut self, life: u32) -> Result<Vec<Action>, Error> {
        if life <= self.profile.life {
            return Err(Error::Coordinate);
        }
        self.revoke()?;
        self.profile.life = life;
        self.recovery.clear();
        let mut out: Vec<_> = self
            .pending
            .values()
            .map(|p| Action::Expired(p.token))
            .collect();
        self.pending.clear();
        out.push(Action::Timer(None));
        Ok(out)
    }
    pub fn advance(&mut self, now: u64) -> Result<Vec<Action>, Error> {
        if now < self.now {
            return Err(Error::Coordinate);
        }
        self.now = now;
        if now.saturating_sub(self.window) >= self.config.interval {
            self.window = now;
            self.charged = 0;
        }
        if self.pending.values().any(|p| now >= p.deadline) {
            self.revoke()?;
        }
        let peers: Vec<_> = self.pending.keys().copied().collect();
        let mut out = Vec::new();
        for peer in peers {
            let p = &self.pending[&peer];
            if now >= p.deadline {
                out.push(Action::Expired(p.token));
                self.pending.remove(&peer);
                continue;
            }
            if p.candidate.is_some() || p.attempts >= self.config.attempts || now < p.due {
                continue;
            }
            if self.charged >= self.config.dispatches {
                // Exhausted budget must not leave a timer armed in the past.
                let due = self
                    .window
                    .checked_add(self.config.interval)
                    .ok_or(Error::Limit)?;
                self.pending.get_mut(&peer).unwrap().due = due;
                continue;
            }
            let due = now.checked_add(self.config.retry).ok_or(Error::Limit)?;
            out.push(self.solicit(peer, p.route)?);
            self.charge()?;
            let p = self.pending.get_mut(&peer).unwrap();
            p.attempts += 1;
            p.due = due;
        }
        out.push(Action::Timer(self.deadline()));
        Ok(out)
    }
}

impl Drop for Contact {
    fn drop(&mut self) {
        let _ = self.send_gate.change(false);
    }
}
