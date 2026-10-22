//! Synchronous, bounded named reads. The host supplies time, routes, and trusted
//! peer views. No sockets, runtime, authority discovery, LSS, or flow protocol.
//!
//! `Engine` requires a host protection adapter; this crate provides no accepting
//! implementation. The example/tests use a controlled, test-only adapter.
//! Passing those tests proves state-machine behavior, not packet authentication.

use std::collections::BTreeMap;

use mesa_wire::{
    decode, encode, reconstruct_data_fragment, Auth, Body, Data, Fragment, Limits, Name, Packet,
};
pub use mesa_wire::{DomainTag, PeerId};

pub type Tick = u64;
pub type ReadId = u64;

/// Opaque host handles. An attachment is a route, never sender evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attachment(pub u64);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyHandle(pub u64);

/// An explicit host assertion, with no domain-verification or fallback claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreconfiguredPeer {
    pub id: PeerId,
    domain: String,
    pub life: u32,
    pub rift: u32,
    pub key: KeyHandle,
    pub service_allowed: bool,
}

impl PreconfiguredPeer {
    pub fn new(
        id: PeerId,
        domain: &str,
        life: u32,
        rift: u32,
        key: KeyHandle,
    ) -> Result<Self, Error> {
        DomainTag::new(domain).map_err(|_| Error::InvalidDomain)?;
        Ok(Self {
            id,
            domain: domain.into(),
            life,
            rift,
            key,
            service_allowed: true,
        })
    }

    pub fn domain(&self) -> DomainTag<'_> {
        DomainTag::new(&self.domain).expect("validated at construction")
    }
}

/// Host trust boundary, called only after bounded structural decoding and peer
/// gating, and before any page is stored or any namespace data is served.
///
/// `peer` is a claim from the transport event, NOT an authenticated sender. The
/// adapter must check the exact packet against the supplied current peer/local
/// keys and context. It must never infer success from the route, publisher name,
/// checksum, or a packet-controlled flag. There is deliberately no default.
///
/// This milestone emits unprotected v2 packets. A real sending protection
/// profile and LSS verifier are required before attaching a network transport.
pub trait Protection {
    fn verify(
        &mut self,
        local: &PreconfiguredPeer,
        peer: &PreconfiguredPeer,
        packet: &[u8],
    ) -> bool;
}

#[derive(Clone, Debug)]
pub struct Config {
    pub wire: Limits,
    pub bloq: u8,
    pub max_peers: usize,
    /// Includes retired names: unbind frees bytes but prevents name reuse.
    pub max_bindings: usize,
    pub max_binding_bytes: usize,
    pub max_read_bytes: usize,
    pub max_reassembly_bytes: usize,
    pub max_reads: usize,
    pub max_fragments: usize,
    pub window: usize,
    pub retry_after: Tick,
    pub read_timeout: Tick,
    /// Includes the initial transmission, per fragment.
    pub max_attempts: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            wire: Limits {
                max_path: 256,
                ..Limits::DATAGRAM
            },
            bloq: 13,
            max_peers: 64,
            max_bindings: 128,
            max_binding_bytes: 8 * 1024 * 1024,
            max_read_bytes: 1024 * 1024,
            max_reassembly_bytes: 8 * 1024 * 1024,
            max_reads: 32,
            max_fragments: 1024,
            window: 4,
            retry_after: 100,
            read_timeout: 2000,
            max_attempts: 4,
        }
    }
}

impl Config {
    fn capacity(&self) -> Result<usize, Error> {
        let shift = self.bloq.checked_sub(3).ok_or(Error::InvalidConfig)?;
        let cap = 1usize
            .checked_shl(shift.into())
            .ok_or(Error::InvalidConfig)?;
        // Worst case v2 name/data framing, absent auth, full domain and integer
        // widths. Ensures all admitted names/fragments fit the output profile.
        let max_packet = 118usize
            .checked_add(self.wire.max_path)
            .and_then(|n| n.checked_add(cap))
            .ok_or(Error::InvalidConfig)?;
        if cap > self.wire.max_fragment
            || max_packet > self.wire.max_packet
            || self.wire.max_path == 0
            || self.wire.max_path > u16::MAX as usize
            || cap > u32::MAX as usize
            || self.max_peers == 0
            || self.max_bindings == 0
            || self.max_reads == 0
            || self.max_fragments == 0
            || self.window == 0
            || self.window > self.max_fragments
            || self.retry_after == 0
            || self.read_timeout == 0
            || self.max_attempts == 0
        {
            return Err(Error::InvalidConfig);
        }
        Ok(cap)
    }
}

/// Explicit namespace access. Even Public requires an installed, allowed peer
/// and a successful protection result in this closed fixture profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    Public,
    Peer(PeerId),
}

#[derive(Debug)]
pub enum Event<'a> {
    InstallPeer(PreconfiguredPeer),
    /// Only this event may advance an existing peer's rift.
    RemoteBreach(PreconfiguredPeer),
    SetService {
        peer: PeerId,
        allowed: bool,
    },
    SetAttachment {
        peer: PeerId,
        attachment: Option<Attachment>,
    },
    Bind {
        path: Vec<u8>,
        bytes: Vec<u8>,
        access: Access,
    },
    Unbind {
        path: &'a [u8],
    },
    Read {
        id: ReadId,
        peer: PeerId,
        path: Vec<u8>,
    },
    Cancel {
        id: ReadId,
    },
    /// Monotonic virtual time. All other events occur at the last supplied time.
    AdvanceTo(Tick),
    Receive {
        claimed_peer: PeerId,
        attachment: Attachment,
        bytes: &'a [u8],
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Send {
        peer: PeerId,
        attachment: Attachment,
        bytes: Vec<u8>,
    },
    ReadFinished {
        id: ReadId,
        result: Result<Vec<u8>, ReadFailure>,
    },
    Dropped(DropReason),
    /// Replace the host's previous timer; None disarms it. One per successful
    /// step. At a deadline, AdvanceTo must precede delivery at that same time.
    SetTimer(Option<Tick>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadFailure {
    Cancelled,
    Timeout,
    RetriesExhausted,
    Blocked,
    PeerReset,
    ResourceLimit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DropReason {
    UnknownPeer,
    Blocked,
    Attachment,
    Malformed,
    Protection,
    Unsupported,
    Name,
    NoInterest,
    Fragment,
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidConfig,
    InvalidDomain,
    UnknownPeer,
    LocalPeer,
    DomainConflict,
    CoordinateRegression,
    KeyConflict,
    BreachRequired,
    InvalidBreach,
    ResourceLimit,
    InvalidPath,
    NameInUse,
    RetiredName,
    Unbound,
    Blocked,
    NoRoute,
    ReadIdInUse,
    AlreadyPending,
    UnknownRead,
    ClockRegression,
    ClockOverflow,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}

/// Payload reservations and bounded structural counts, not allocator overhead.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Usage {
    pub peers: usize,
    pub namespace_slots: usize,
    pub bindings: usize,
    pub binding_bytes: usize,
    pub reads: usize,
    pub reassembly_bytes: usize,
    pub pending_interests: usize,
    pub received_fragments: usize,
}

struct PeerState {
    view: PreconfiguredPeer,
    attachment: Option<Attachment>,
}
struct Binding {
    bytes: Vec<u8>,
    access: Access,
}
struct Attempt {
    count: u32,
    retry_at: Tick,
}
struct Read {
    peer: PeerId,
    path: Vec<u8>,
    rift: u32,
    deadline: Tick,
    total: Option<usize>,
    bytes: Vec<u8>,
    remaining: usize,
    received: usize,
    next_index: u64,
    interests: BTreeMap<u64, Attempt>,
}

pub struct Engine<P> {
    config: Config,
    capacity: usize,
    local: PreconfiguredPeer,
    protection: P,
    now: Tick,
    peers: BTreeMap<PeerId, PeerState>,
    // None is a bounded tombstone: a path is immutable within the local epoch.
    bindings: BTreeMap<Vec<u8>, Option<Binding>>,
    reads: BTreeMap<ReadId, Read>,
}

impl<P: Protection> Engine<P> {
    pub fn new(config: Config, local: PreconfiguredPeer, protection: P) -> Result<Self, Error> {
        let capacity = config.capacity()?;
        Ok(Self {
            config,
            capacity,
            local,
            protection,
            now: 0,
            peers: BTreeMap::new(),
            bindings: BTreeMap::new(),
            reads: BTreeMap::new(),
        })
    }

    pub fn usage(&self) -> Usage {
        Usage {
            peers: self.peers.len(),
            namespace_slots: self.bindings.len(),
            bindings: self.bindings.values().flatten().count(),
            binding_bytes: self
                .bindings
                .values()
                .flatten()
                .map(|b| b.bytes.len())
                .sum(),
            reads: self.reads.len(),
            reassembly_bytes: self.reads.values().map(|r| r.bytes.len()).sum(),
            pending_interests: self.reads.values().map(|r| r.interests.len()).sum(),
            received_fragments: self.reads.values().map(|r| r.received).sum(),
        }
    }

    pub fn step(&mut self, event: Event<'_>) -> Result<Vec<Action>, Error> {
        let mut actions = Vec::new();
        match event {
            Event::InstallPeer(view) => self.install(view, false, &mut actions)?,
            Event::RemoteBreach(view) => self.install(view, true, &mut actions)?,
            Event::SetService { peer, allowed } => {
                self.peers
                    .get_mut(&peer)
                    .ok_or(Error::UnknownPeer)?
                    .view
                    .service_allowed = allowed;
                if !allowed {
                    self.fail_peer(peer, ReadFailure::Blocked, &mut actions);
                }
            }
            Event::SetAttachment { peer, attachment } => {
                self.peers
                    .get_mut(&peer)
                    .ok_or(Error::UnknownPeer)?
                    .attachment = attachment;
            }
            Event::Bind {
                path,
                bytes,
                access,
            } => {
                self.check_path(&path)?;
                if let Some(old) = self.bindings.get(&path) {
                    return Err(if old.is_some() {
                        Error::NameInUse
                    } else {
                        Error::RetiredName
                    });
                }
                if self.bindings.len() >= self.config.max_bindings
                    || bytes.len() > self.config.max_read_bytes
                    || bytes.len().div_ceil(self.capacity).max(1) > self.config.max_fragments
                    || bytes.len()
                        > self
                            .config
                            .max_binding_bytes
                            .saturating_sub(self.usage().binding_bytes)
                {
                    return Err(Error::ResourceLimit);
                }
                self.bindings.insert(path, Some(Binding { bytes, access }));
            }
            Event::Unbind { path } => {
                self.bindings
                    .get_mut(path)
                    .and_then(Option::take)
                    .ok_or(Error::Unbound)?;
            }
            Event::Read { id, peer, path } => self.start_read(id, peer, path, &mut actions)?,
            Event::Cancel { id } => {
                if !self.reads.contains_key(&id) {
                    return Err(Error::UnknownRead);
                }
                self.finish(id, Err(ReadFailure::Cancelled), &mut actions);
            }
            Event::AdvanceTo(now) => {
                if now < self.now {
                    return Err(Error::ClockRegression);
                }
                self.now = now;
                self.tick(&mut actions);
            }
            Event::Receive {
                claimed_peer,
                attachment,
                bytes,
            } => {
                if let Err(reason) = self.receive(claimed_peer, attachment, bytes, &mut actions) {
                    actions.push(Action::Dropped(reason));
                }
            }
        }
        actions.push(Action::SetTimer(self.next_timer()));
        Ok(actions)
    }

    fn check_path(&self, path: &[u8]) -> Result<(), Error> {
        if path.is_empty() || path.len() > self.config.wire.max_path {
            Err(Error::InvalidPath)
        } else {
            Ok(())
        }
    }

    fn install(
        &mut self,
        view: PreconfiguredPeer,
        breach: bool,
        actions: &mut Vec<Action>,
    ) -> Result<(), Error> {
        if view.id == self.local.id {
            return Err(Error::LocalPeer);
        }
        if let Some(old) = self.peers.get(&view.id) {
            if view.domain != old.view.domain {
                return Err(Error::DomainConflict);
            }
            if view.life < old.view.life || view.rift < old.view.rift {
                return Err(Error::CoordinateRegression);
            }
            if breach {
                if view.rift <= old.view.rift {
                    return Err(Error::InvalidBreach);
                }
            } else if view.rift != old.view.rift {
                return Err(Error::BreachRequired);
            }
            if view.life == old.view.life && view.key != old.view.key {
                return Err(Error::KeyConflict);
            }
        } else {
            if breach {
                return Err(Error::UnknownPeer);
            }
            if self.peers.len() >= self.config.max_peers {
                return Err(Error::ResourceLimit);
            }
        }
        let id = view.id;
        let allowed = view.service_allowed;
        let attachment = self.peers.get(&id).and_then(|p| p.attachment);
        self.peers.insert(id, PeerState { view, attachment });
        if breach {
            self.fail_peer(id, ReadFailure::PeerReset, actions);
        } else if !allowed {
            self.fail_peer(id, ReadFailure::Blocked, actions);
        }
        Ok(())
    }

    fn start_read(
        &mut self,
        id: ReadId,
        peer: PeerId,
        path: Vec<u8>,
        actions: &mut Vec<Action>,
    ) -> Result<(), Error> {
        self.check_path(&path)?;
        if self.reads.contains_key(&id) {
            return Err(Error::ReadIdInUse);
        }
        let remote = self.peers.get(&peer).ok_or(Error::UnknownPeer)?;
        if !remote.view.service_allowed {
            return Err(Error::Blocked);
        }
        if remote.attachment.is_none() {
            return Err(Error::NoRoute);
        }
        if self
            .reads
            .values()
            .any(|r| r.peer == peer && r.path == path)
        {
            return Err(Error::AlreadyPending);
        }
        if self.reads.len() >= self.config.max_reads {
            return Err(Error::ResourceLimit);
        }
        let deadline = self
            .now
            .checked_add(self.config.read_timeout)
            .ok_or(Error::ClockOverflow)?;
        self.reads.insert(
            id,
            Read {
                peer,
                path,
                rift: remote.view.rift,
                deadline,
                total: None,
                bytes: Vec::new(),
                remaining: 0,
                received: 0,
                next_index: 1,
                interests: BTreeMap::from([(
                    0,
                    Attempt {
                        count: 1,
                        retry_at: self.now.saturating_add(self.config.retry_after),
                    },
                )]),
            },
        );
        self.send_interest(id, 0, actions);
        Ok(())
    }

    fn send_interest(&self, id: ReadId, index: u64, actions: &mut Vec<Action>) {
        let read = &self.reads[&id];
        let remote = &self.peers[&read.peer];
        if let Some(attachment) = remote.attachment {
            let name = Name {
                publisher: read.peer,
                domain: remote.view.domain(),
                rift: read.rift,
                bloq: self.config.bloq,
                fragment: Fragment::Data(index),
                path: &read.path,
            };
            let bytes = encode(
                &Packet {
                    hop: 0,
                    body: Body::Peek(name),
                },
                self.config.wire,
            )
            .expect("validated config/path");
            actions.push(Action::Send {
                peer: read.peer,
                attachment,
                bytes,
            });
        }
    }

    fn receive(
        &mut self,
        claimed_peer: PeerId,
        attachment: Attachment,
        bytes: &[u8],
        actions: &mut Vec<Action>,
    ) -> Result<(), DropReason> {
        let peer = self
            .peers
            .get(&claimed_peer)
            .ok_or(DropReason::UnknownPeer)?;
        if !peer.view.service_allowed {
            return Err(DropReason::Blocked);
        }
        if peer.attachment != Some(attachment) {
            return Err(DropReason::Attachment);
        }
        let packet = decode(bytes, self.config.wire).map_err(|_| DropReason::Malformed)?;
        if !self.protection.verify(&self.local, &peer.view, bytes) {
            return Err(DropReason::Protection);
        }
        match packet.body {
            Body::Peek(name) => self.serve(claimed_peer, attachment, name, actions),
            Body::Page {
                name,
                data,
                next: None,
            } => self.page(claimed_peer, name, data, actions),
            _ => Err(DropReason::Unsupported),
        }
    }

    fn serve(
        &self,
        peer: PeerId,
        attachment: Attachment,
        name: Name<'_>,
        actions: &mut Vec<Action>,
    ) -> Result<(), DropReason> {
        if name.publisher != self.local.id
            || name.domain != self.local.domain()
            || name.rift != self.local.rift
            || name.bloq != self.config.bloq
        {
            return Err(DropReason::Name);
        }
        let binding = self
            .bindings
            .get(name.path)
            .and_then(Option::as_ref)
            .ok_or(DropReason::Unavailable)?;
        if binding.access != Access::Public && binding.access != Access::Peer(peer) {
            return Err(DropReason::Unavailable);
        }
        let index = match name.fragment {
            Fragment::Init if binding.bytes.len() <= self.capacity => 0,
            Fragment::Data(i) => usize::try_from(i).map_err(|_| DropReason::Fragment)?,
            _ => return Err(DropReason::Unsupported),
        };
        let offset = index
            .checked_mul(self.capacity)
            .ok_or(DropReason::Fragment)?;
        if (binding.bytes.is_empty() && index != 0)
            || (!binding.bytes.is_empty() && offset >= binding.bytes.len())
        {
            return Err(DropReason::Fragment);
        }
        let end = offset
            .saturating_add(self.capacity)
            .min(binding.bytes.len());
        let data = Data {
            total_bytes: binding.bytes.len() as u64,
            auth: Auth::None,
            fragment: &binding.bytes[offset..end],
        };
        let bytes = encode(
            &Packet {
                hop: 0,
                body: Body::Page {
                    name,
                    data,
                    next: None,
                },
            },
            self.config.wire,
        )
        .expect("validated config/binding");
        actions.push(Action::Send {
            peer,
            attachment,
            bytes,
        });
        Ok(())
    }

    fn page(
        &mut self,
        peer: PeerId,
        name: Name<'_>,
        data: Data<'_>,
        actions: &mut Vec<Action>,
    ) -> Result<(), DropReason> {
        let remote = &self.peers[&peer].view;
        if name.publisher != peer
            || name.domain != remote.domain()
            || name.rift != remote.rift
            || name.bloq != self.config.bloq
        {
            return Err(DropReason::Name);
        }
        let Fragment::Data(index) = name.fragment else {
            return Err(DropReason::NoInterest);
        };
        let id = self
            .reads
            .iter()
            .find(|(_, r)| {
                r.peer == peer
                    && r.rift == name.rift
                    && r.path == name.path
                    && r.interests.contains_key(&index)
            })
            .map(|(&id, _)| id)
            .ok_or(DropReason::NoInterest)?;
        // This fixture profile carries no LSS/proof material. Never treat an
        // arbitrary auth variant as verified merely because decode accepted it.
        if data.auth != Auth::None {
            return Err(DropReason::Unsupported);
        }
        let total = match usize::try_from(data.total_bytes) {
            Ok(n)
                if n <= self.config.max_read_bytes
                    && n.div_ceil(self.capacity).max(1) <= self.config.max_fragments =>
            {
                n
            }
            _ => {
                self.finish(id, Err(ReadFailure::ResourceLimit), actions);
                return Ok(());
            }
        };
        if self.reads[&id].total.is_some_and(|old| old != total) {
            return Err(DropReason::Fragment);
        }
        let fragment = if total == 0 {
            if index != 0 || !data.fragment.is_empty() {
                return Err(DropReason::Fragment);
            }
            Vec::new()
        } else {
            reconstruct_data_fragment(
                data.total_bytes,
                name.bloq,
                index,
                data.fragment,
                self.capacity,
            )
            .map_err(|_| DropReason::Fragment)?
        };
        if self.reads[&id].total.is_none() {
            if total
                > self
                    .config
                    .max_reassembly_bytes
                    .saturating_sub(self.usage().reassembly_bytes)
            {
                self.finish(id, Err(ReadFailure::ResourceLimit), actions);
                return Ok(());
            }
            let read = self.reads.get_mut(&id).unwrap();
            read.total = Some(total);
            read.bytes = vec![0; total];
            read.remaining = total.div_ceil(self.capacity).max(1);
        }
        let read = self.reads.get_mut(&id).unwrap();
        // Range was checked by reconstruct_data_fragment; scheduled indices
        // are bounded by max_fragments and each can be consumed only once.
        let offset = index as usize * self.capacity;
        read.bytes[offset..offset + fragment.len()].copy_from_slice(&fragment);
        read.interests.remove(&index);
        read.remaining -= 1;
        read.received += 1;
        if read.remaining == 0 {
            let bytes = std::mem::take(&mut read.bytes);
            self.finish(id, Ok(bytes), actions);
        } else {
            self.fill_window(id, actions);
        }
        Ok(())
    }

    fn fill_window(&mut self, id: ReadId, actions: &mut Vec<Action>) {
        loop {
            let read = self.reads.get_mut(&id).unwrap();
            let count = read.total.unwrap().div_ceil(self.capacity).max(1) as u64;
            if read.interests.len() >= self.config.window || read.next_index >= count {
                break;
            }
            let index = read.next_index;
            read.next_index += 1;
            read.interests.insert(
                index,
                Attempt {
                    count: 1,
                    retry_at: self.now.saturating_add(self.config.retry_after),
                },
            );
            self.send_interest(id, index, actions);
        }
    }

    fn finish(
        &mut self,
        id: ReadId,
        result: Result<Vec<u8>, ReadFailure>,
        actions: &mut Vec<Action>,
    ) {
        self.reads.remove(&id);
        actions.push(Action::ReadFinished { id, result });
    }

    fn fail_peer(&mut self, peer: PeerId, reason: ReadFailure, actions: &mut Vec<Action>) {
        let ids: Vec<_> = self
            .reads
            .iter()
            .filter(|(_, r)| r.peer == peer)
            .map(|(&id, _)| id)
            .collect();
        for id in ids {
            self.finish(id, Err(reason), actions);
        }
    }

    fn tick(&mut self, actions: &mut Vec<Action>) {
        let ids: Vec<_> = self.reads.keys().copied().collect();
        for id in ids {
            let read = &self.reads[&id];
            if read.deadline <= self.now {
                self.finish(id, Err(ReadFailure::Timeout), actions);
                continue;
            }
            if read
                .interests
                .values()
                .any(|a| a.retry_at <= self.now && a.count >= self.config.max_attempts)
            {
                self.finish(id, Err(ReadFailure::RetriesExhausted), actions);
                continue;
            }
            let due: Vec<_> = read
                .interests
                .iter()
                .filter(|(_, a)| a.retry_at <= self.now)
                .map(|(&i, _)| i)
                .collect();
            for index in due {
                let has_route = self.peers[&self.reads[&id].peer].attachment.is_some();
                let attempt = self
                    .reads
                    .get_mut(&id)
                    .unwrap()
                    .interests
                    .get_mut(&index)
                    .unwrap();
                if has_route {
                    attempt.count += 1;
                }
                attempt.retry_at = self.now.saturating_add(self.config.retry_after);
                self.send_interest(id, index, actions);
            }
        }
    }

    fn next_timer(&self) -> Option<Tick> {
        self.reads
            .values()
            .flat_map(|r| {
                std::iter::once(r.deadline).chain(r.interests.values().map(|a| a.retry_at))
            })
            .min()
    }
}
