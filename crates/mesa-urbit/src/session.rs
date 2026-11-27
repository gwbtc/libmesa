//! Urbit-Mesa service composition for an admitted peer. The host owns UDP,
//! clock input and commits. Shared CORE owns transfers; FLOW owns durable state.
use crate::{
    gage,
    path::{self, FlowPath, Load},
    Buffer, Error,
};
use mesa_core::{self as core, protection::SignedPublic, Engine, PreconfiguredPeer};
use mesa_flow::ordered::{self as flow, Flow, Kind, Outcome};
use mesa_wire::mesa_v1::{self as wire, Body};
use std::collections::{BTreeMap, VecDeque};

#[derive(Debug)]
pub enum Failure {
    Profile(Error),
    Core(core::Error),
    Flow(flow::Error),
}
impl From<Error> for Failure {
    fn from(e: Error) -> Self {
        Self::Profile(e)
    }
}
impl From<core::Error> for Failure {
    fn from(e: core::Error) -> Self {
        Self::Core(e)
    }
}
impl From<flow::Error> for Failure {
    fn from(e: flow::Error) -> Self {
        Self::Flow(e)
    }
}
#[derive(Clone, Debug)]
pub enum Action {
    Send(core::credentials::FencedPacket),
    Core(core::host::Record),
    Flow(flow::Action),
    Stalled {
        path: Vec<u8>,
        reason: core::ReadFailure,
    },
}
#[derive(Clone)]
struct Read {
    path: Vec<u8>,
    iv: Vec<u8>,
    flow: FlowPath,
}
pub struct Session {
    core: Engine<SignedPublic>,
    flow: flow::Node,
    local: PreconfiguredPeer,
    remote: PreconfiguredPeer,
    agent: String,
    max: usize,
    reads: BTreeMap<u64, Read>,
    next_read: u64,
    objects: BTreeMap<Vec<u8>, FlowPath>,
    queue: VecDeque<flow::Event>,
}
impl Session {
    pub fn new(
        mut engine: Engine<SignedPublic>,
        flow: flow::Node,
        agent: String,
    ) -> Result<Self, Failure> {
        let snapshot = engine.snapshot();
        if snapshot.peers.len() != 1 {
            return Err(Error::Coordinate.into());
        }
        let local = snapshot.local;
        let remote = snapshot.peers[0].peer.clone();
        let epoch = &flow.state().epoch;
        if epoch.domain != local.domain().as_str()
            || epoch.remote_domain != remote.domain().as_str()
            || epoch.local != local.id.0
            || epoch.remote != remote.id.0
            || epoch.local_rift != local.rift
            || epoch.remote_rift != remote.rift
        {
            return Err(Error::Coordinate.into());
        }
        engine.install_namespace(local.id, path::beam_prefix(local.id.0, local.rift)?)?;
        engine.install_namespace(remote.id, path::beam_prefix(remote.id.0, remote.rift)?)?;
        Ok(Self {
            core: engine,
            flow,
            local,
            remote,
            agent,
            max: 65536,
            reads: BTreeMap::new(),
            next_read: 1,
            objects: BTreeMap::new(),
            queue: VecDeque::new(),
        })
    }
    pub fn core(&self) -> &Engine<SignedPublic> {
        &self.core
    }
    pub fn state(&self) -> &flow::State {
        self.flow.state()
    }
    pub fn snapshot(&self) -> Result<Buffer, Failure> {
        Ok(self.flow.snapshot()?)
    }
    /// Trusted host seam: call only after committing the exact remote authority
    /// update. Life changes preserve flow IDs. An epoch change needs a new
    /// transaction domain; this session refuses it and fences all old sends.
    pub fn install_remote(
        &mut self,
        update: core::host::CredentialUpdate,
        key: mesa_crypto::PublicKey,
    ) -> Result<Vec<Action>, Failure> {
        if update.peer.id != self.remote.id {
            return Err(Error::Coordinate.into());
        }
        self.core.send_gate().change(false)?;
        if update.peer.rift != self.remote.rift {
            return Err(flow::Error::Epoch.into());
        }
        let actions = self.core.install_public_credential(update, key)?;
        let mut out = self.core_actions(actions)?;
        self.remote = self.core.snapshot().peers[0].peer.clone();
        self.clear_transient()?;
        self.core.send_gate().change(true)?;
        if self.remote.service_allowed {
            out.extend(self.recover()?);
        }
        Ok(out)
    }
    /// Trusted host seam following durable key activation. Quiescence revokes
    /// caller-retained packets before changing either credential or ciphertext.
    pub fn activate_local(
        &mut self,
        view: PreconfiguredPeer,
        key: std::sync::Arc<mesa_crypto::KeyPair>,
        expected: u64,
        generation: u64,
    ) -> Result<Vec<Action>, Failure> {
        let actions = self.core.quiesce()?;
        let mut out = self.core_actions(actions)?;
        if view.rift != self.local.rift {
            return Err(flow::Error::Epoch.into());
        }
        self.clear_transient()?;
        self.core.activate_local(view, key, expected, generation)?;
        self.local = self.core.local_view();
        out.extend(self.recover()?);
        Ok(out)
    }
    fn clear_transient(&mut self) -> Result<(), Failure> {
        self.queue.clear();
        for name in self.objects.keys() {
            self.core.release_protocol_object(name)?;
        }
        self.objects.clear();
        Ok(())
    }
    pub fn replace_attachment(
        &mut self,
        update: core::host::AttachmentUpdate,
    ) -> Result<Vec<Action>, Failure> {
        if update.peer != self.remote.id {
            return Err(Error::Coordinate.into());
        }
        let actions = self.core.step(core::Event::ReplaceAttachment(update))?;
        self.core_actions(actions)
    }
    pub fn recover(&mut self) -> Result<Vec<Action>, Failure> {
        let actions = self.flow.recover();
        self.translate(actions)
    }
    pub fn command(&mut self, event: flow::Event) -> Result<Vec<Action>, Failure> {
        if let flow::Event::Decide {
            outcome: Outcome::Rejected(bytes),
            ..
        } = &event
        {
            gage::validate_rejection(bytes, self.max)?;
        }
        if let flow::Event::Enqueue { kind, bytes, .. } = &event {
            // Encode before proposing a transaction so an unsendable message
            // cannot enter the durable outbox.
            match kind {
                Kind::Plea => {
                    gage::encode_plea(&self.agent, bytes, self.max - 1)?;
                }
                Kind::Boon => {
                    gage::encode_boon(bytes, self.max - 1)?;
                }
                Kind::Cork => return Err(Error::Unsupported.into()),
            };
        }
        let committed = matches!(event, flow::Event::Committed(_));
        let a = self.flow.step(event)?;
        let mut out = self.translate(a)?;
        if committed {
            out.extend(self.prune()?);
            out.extend(self.drain()?);
        }
        Ok(out)
    }
    pub fn advance(&mut self, now: u64) -> Result<Vec<Action>, Failure> {
        let actions = self.core.step(core::Event::AdvanceTo(now))?;
        self.core_actions(actions)
    }
    pub fn receive(
        &mut self,
        attachment: core::Attachment,
        bytes: &[u8],
    ) -> Result<Vec<Action>, Failure> {
        if self.core.snapshot().peers[0].attachment != Some(attachment) || self.core.is_quiescent()
        {
            return Err(Error::Coordinate.into());
        }
        let packet = wire::decode(bytes, wire::Checksum::VereBytes, wire::Limits::DATAGRAM)
            .map_err(|_| Error::Encoding)?;
        let mut out = Vec::new();
        match packet.body {
            Body::Poke { ack, payload, .. } => {
                if ack.ship != self.local.id.0
                    || payload.ship != self.remote.id.0
                    || ack.rift != self.local.rift
                    || payload.rift != self.remote.rift
                {
                    return Err(Error::Coordinate.into());
                }
                let (p, iv) = self.open(payload.path, false)?;
                let (a, _) = self.open(ack.path, true)?;
                if p.load != Load::Poke
                    || a.load != Load::Ack
                    || a.bone != p.bone
                    || a.sequence != p.sequence
                    || a.backward == p.backward
                    || p.receiver != self.local.id.0
                    || a.receiver != self.remote.id.0
                {
                    return Err(Error::Coordinate.into());
                }
                if self.queue.len() >= 64 {
                    return Err(Error::Limit.into());
                }
                out.extend(self.read(
                    Read {
                        path: payload.path.into(),
                        iv,
                        flow: p,
                    },
                    None,
                )?);
            }
            Body::Peek(name) if name.path.starts_with(b"publ/") => {
                let a = self.core.step(core::Event::Receive {
                    claimed_peer: self.remote.id,
                    attachment,
                    bytes,
                })?;
                return self.core_actions(a);
            }
            Body::Peek(name) => {
                if name.ship != self.local.id.0 || name.rift != self.local.rift {
                    return Err(Error::Coordinate.into());
                }
                let (p, _) = self.open(name.path, true)?;
                if p.receiver != self.remote.id.0 {
                    return Err(Error::Coordinate.into());
                }
                if let Some(gage) = self.object(&p)? {
                    self.publish(&p, &gage)?;
                }
            }
            Body::Page { name, .. } => {
                if name.ship != self.remote.id.0 || name.rift != self.remote.rift {
                    return Err(Error::Coordinate.into());
                }
            }
        }
        let actions = self.core.step(core::Event::Receive {
            claimed_peer: self.remote.id,
            attachment,
            bytes,
        })?;
        out.extend(self.core_actions(actions)?);
        out.extend(self.prune()?);
        Ok(out)
    }
    fn open(&self, bytes: &[u8], local: bool) -> Result<(FlowPath, Vec<u8>), Failure> {
        if bytes.len() > 320 {
            return Err(Error::Limit.into());
        }
        let s = std::str::from_utf8(bytes).map_err(|_| Error::Encoding)?;
        let parts: Vec<_> = s.split('/').collect();
        let (server, client) = if local {
            (&self.local, &self.remote)
        } else {
            (&self.remote, &self.local)
        };
        if parts.len() != 5
            || parts[0] != "chum"
            || path::parse_decimal(parts[1])? != server.life as u64
            || path::parse_ship(parts[2])? != client.id.0
            || path::parse_decimal(parts[3])? != client.life as u64
        {
            return Err(Error::Coordinate.into());
        }
        let iv = path::parse_uv(parts[4], 256)?;
        let secret = self.core.private_space(self.remote.id)?;
        let plain = secret.open_path(&iv, 256).map_err(|_| Error::Encoding)?;
        let p = FlowPath::parse(std::str::from_utf8(&plain).map_err(|_| Error::Encoding)?)?;
        Ok((p, iv))
    }
    fn named(&self, p: &FlowPath, local: bool) -> Result<(Vec<u8>, Vec<u8>), Failure> {
        let secret = self.core.private_space(self.remote.id)?;
        let iv = secret
            .seal_path(p.render()?.as_bytes(), 256)
            .map_err(|_| Error::Limit)?;
        let (server, client) = if local {
            (&self.local, &self.remote)
        } else {
            (&self.remote, &self.local)
        };
        let name = path::private(server.life, client.id.0, client.life, &iv)?;
        if name.len() > 320 {
            return Err(Error::Limit.into());
        }
        Ok((name, iv))
    }
    fn publish(&mut self, p: &FlowPath, gage: &Buffer) -> Result<Vec<u8>, Failure> {
        let (name, iv) = self.named(p, true)?;
        if !self.objects.contains_key(&name) {
            let secret = self.core.private_space(self.remote.id)?;
            let bytes = gage
                .with_bytes(|b| secret.encrypt(&iv, b, self.max))
                .map_err(|_| Error::Limit)?;
            self.core.step(core::Event::Bind {
                path: name.clone(),
                bytes,
                access: core::Access::Peer(self.remote.id),
            })?;
            self.objects.insert(name.clone(), p.clone());
        }
        Ok(name)
    }
    fn read(&mut self, read: Read, payload: Option<Vec<u8>>) -> Result<Vec<Action>, Failure> {
        if self.reads.values().any(|r| r.path == read.path) {
            return Ok(Vec::new());
        }
        if self.reads.len() >= 32 {
            return Err(Error::Limit.into());
        }
        let id = self.next_read;
        let next = id.checked_add(1).ok_or(Error::Limit)?;
        let event = match payload {
            Some(payload) => core::Event::ReadPoke {
                id,
                peer: self.remote.id,
                path: read.path.clone(),
                payload,
            },
            None => core::Event::ReadPrivate {
                id,
                peer: self.remote.id,
                path: read.path.clone(),
            },
        };
        let a = self.core.step(event)?;
        self.next_read = next;
        self.reads.insert(id, read);
        self.core_actions(a)
    }
    fn translate(&mut self, actions: Vec<flow::Action>) -> Result<Vec<Action>, Failure> {
        let mut out = Vec::new();
        for action in actions {
            match &action {
                flow::Action::Transmit { id, kind, bytes } => {
                    let p = FlowPath {
                        bone: id.flow.bone,
                        backward: id.flow.backward,
                        receiver: self.remote.id.0,
                        sequence: Some(id.sequence),
                        load: Load::Poke,
                    };
                    let gage = match kind {
                        Kind::Plea => gage::encode_plea(&self.agent, bytes, self.max - 1)?,
                        Kind::Boon => gage::encode_boon(bytes, self.max - 1)?,
                        Kind::Cork => gage::encode_cork(self.max - 1)?,
                    };
                    let payload = self.publish(&p, &gage)?;
                    let ack = FlowPath {
                        backward: !p.backward,
                        receiver: self.local.id.0,
                        load: Load::Ack,
                        ..p
                    };
                    let (path, iv) = self.named(&ack, false)?;
                    out.extend(self.read(
                        Read {
                            path,
                            iv,
                            flow: ack,
                        },
                        Some(payload),
                    )?);
                }
                flow::Action::Receipt { id, outcome } => {
                    let p = FlowPath {
                        bone: id.flow.bone,
                        backward: id.flow.backward,
                        receiver: self.remote.id.0,
                        sequence: Some(id.sequence),
                        load: Load::Ack,
                    };
                    let name = self.publish(
                        &p,
                        &gage::encode_ack(matches!(outcome, Outcome::Rejected(_)), self.max - 1)?,
                    )?;
                    let a = self.core.step(core::Event::SendPage {
                        peer: self.remote.id,
                        path: name,
                    })?;
                    out.extend(self.core_actions(a)?);
                }
                flow::Action::FetchExplanation(id) => {
                    let p = FlowPath {
                        bone: id.flow.bone,
                        backward: !id.flow.backward,
                        receiver: self.local.id.0,
                        sequence: Some(id.sequence),
                        load: Load::Explanation,
                    };
                    let (path, iv) = self.named(&p, false)?;
                    out.extend(self.read(Read { path, iv, flow: p }, None)?);
                }
                flow::Action::FetchGone(f) => {
                    let p = FlowPath {
                        bone: f.bone,
                        backward: !f.backward,
                        receiver: self.local.id.0,
                        sequence: None,
                        load: Load::Cork,
                    };
                    let (path, iv) = self.named(&p, false)?;
                    out.extend(self.read(Read { path, iv, flow: p }, None)?);
                }
                flow::Action::Gone(_) => {}
                _ => out.push(Action::Flow(action)),
            }
        }
        Ok(out)
    }
    fn core_actions(&mut self, actions: Vec<core::Action>) -> Result<Vec<Action>, Failure> {
        let mut out = Vec::new();
        for a in actions {
            match a {
                core::Action::ReadFinished { id, result } => {
                    let Some(read) = self.reads.remove(&id) else {
                        return Err(Error::Coordinate.into());
                    };
                    let bytes = match result {
                        Ok(b) => b,
                        Err(reason) => {
                            out.push(Action::Stalled {
                                path: read.path,
                                reason,
                            });
                            continue;
                        }
                    };
                    let plain = self
                        .core
                        .private_space(self.remote.id)?
                        .decrypt(&read.iv, &bytes, self.max)
                        .map_err(|_| Error::Encoding)?;
                    let plain = Buffer::from(plain.to_vec());
                    let p = read.flow;
                    let f = Flow {
                        bone: p.bone,
                        backward: !p.backward,
                    };
                    let seq = p.sequence.unwrap_or(0);
                    let event = match p.load {
                        Load::Poke => {
                            let (kind, bytes) = if plain == gage::encode_cork(self.max)? {
                                (Kind::Cork, Buffer::default())
                            } else if let Ok((agent, bytes)) = gage::decode_plea(&plain, self.max) {
                                if agent != self.agent {
                                    return Err(Error::Unsupported.into());
                                }
                                (Kind::Plea, bytes)
                            } else {
                                (Kind::Boon, gage::decode_boon(&plain, self.max)?)
                            };
                            if kind == Kind::Plea && !f.backward || kind == Kind::Boon && f.backward
                            {
                                return Err(Error::Coordinate.into());
                            }
                            if self.flow.state().flow(f).is_none()
                                && !self.flow.state().is_closed(f)
                            {
                                if !f.backward {
                                    return Err(Error::Coordinate.into());
                                }
                                if self.queue.len() > 62 {
                                    return Err(Error::Limit.into());
                                }
                                self.queue.push_back(flow::Event::Admit(f));
                            }
                            flow::Event::Receive {
                                flow: f,
                                sequence: seq,
                                kind,
                                bytes,
                            }
                        }
                        Load::Ack => flow::Event::Ack {
                            flow: f,
                            sequence: seq,
                            rejected: gage::decode_ack(&plain, self.max)?,
                        },
                        Load::Explanation => {
                            gage::validate_rejection(&plain, self.max)?;
                            flow::Event::Explanation {
                                flow: f,
                                sequence: seq,
                                bytes: plain,
                            }
                        }
                        Load::Cork => {
                            if plain != gage::encode_gone(self.max)? {
                                return Err(Error::Shape.into());
                            }
                            flow::Event::Gone(f)
                        }
                    };
                    if self.queue.len() >= 64 {
                        return Err(Error::Limit.into());
                    }
                    self.queue.push_back(event);
                    out.extend(self.drain()?);
                }
                core::Action::Send {
                    peer,
                    attachment,
                    bytes,
                } => out.push(Action::Send(self.core.send_gate().packet(
                    peer,
                    attachment,
                    bytes.into(),
                ))),
                _ => out.push(Action::Core(a.into())),
            }
        }
        Ok(out)
    }
    fn drain(&mut self) -> Result<Vec<Action>, Failure> {
        let mut out = Vec::new();
        while self.flow.pending().is_none() {
            let Some(event) = self.queue.pop_front() else {
                break;
            };
            match self.flow.step(event.clone()) {
                Ok(actions) => out.extend(self.translate(actions)?),
                Err(flow::Error::Busy) => {
                    self.queue.push_front(event);
                    break;
                }
                // A duplicate receipt or already admitted flow has no authority
                // to replace the current transaction or reopen a closed flow.
                Err(flow::Error::Sequence | flow::Error::Invalid | flow::Error::Closed) => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(out)
    }
    fn object(&self, p: &FlowPath) -> Result<Option<Buffer>, Failure> {
        let f = Flow {
            bone: p.bone,
            backward: p.backward,
        };
        if p.load == Load::Cork {
            return Ok(self
                .flow
                .state()
                .is_closed(f)
                .then(|| gage::encode_gone(self.max))
                .transpose()?);
        }
        let Some(state) = self.flow.state().flow(f) else {
            return Ok(None);
        };
        let seq = p.sequence.ok_or(Error::Coordinate)?;
        Ok(match p.load {
            Load::Poke => state
                .outbox
                .as_ref()
                .filter(|m| m.sequence == seq)
                .map(|m| match m.kind {
                    Kind::Plea => gage::encode_plea(&self.agent, &m.bytes, self.max - 1),
                    Kind::Boon => gage::encode_boon(&m.bytes, self.max - 1),
                    Kind::Cork => gage::encode_cork(self.max - 1),
                })
                .transpose()?,
            Load::Ack => state
                .outcomes
                .iter()
                .find(|r| r.sequence == seq)
                .map(|r| gage::encode_ack(matches!(r.outcome, Outcome::Rejected(_)), self.max - 1))
                .transpose()?,
            Load::Explanation => state
                .outcomes
                .iter()
                .find(|r| r.sequence == seq)
                .and_then(|r| match &r.outcome {
                    Outcome::Rejected(b) => Some(b.clone()),
                    _ => None,
                }),
            Load::Cork => None,
        })
    }
    fn prune(&mut self) -> Result<Vec<Action>, Failure> {
        let stale_reads: Vec<_> = self
            .reads
            .iter()
            .filter_map(|(id, r)| {
                self.flow
                    .state()
                    .is_closed(Flow {
                        bone: r.flow.bone,
                        backward: !r.flow.backward,
                    })
                    .then_some(*id)
            })
            .collect();
        let mut out = Vec::new();
        for id in stale_reads {
            let actions = self.core.step(core::Event::Cancel { id })?;
            out.extend(self.core_actions(actions)?);
        }

        let stale: Vec<_> = self
            .objects
            .iter()
            .filter_map(|(name, p)| match self.object(p) {
                Ok(None) => Some(name.clone()),
                _ if p.load == Load::Cork => Some(name.clone()),
                _ => None,
            })
            .collect();
        for path in stale {
            self.core.release_protocol_object(&path)?;
            self.objects.remove(&path);
        }
        Ok(out)
    }
}
