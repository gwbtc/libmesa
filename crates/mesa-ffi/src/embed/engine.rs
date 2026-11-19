use super::*;
mod host;
pub(super) enum Backend {
    Core(Box<core::Engine<SignedPublic>>),
    Flow(Box<flow::Node>),
}
pub struct Engine {
    pub(super) backend: Option<Backend>,
    pub(super) descriptor: Buffer,
    pub(super) incarnation: [u8; 16],
    pub(super) timer: Option<u64>,
    pub(super) poisoned: bool,
    pub(super) max_events: usize,
    reads: BTreeSet<u64>,
    step_records: usize,
    step_bytes: usize,
    object_bytes: usize,
}
fn peer(p: Peer) -> Result<PreconfiguredPeer, i32> {
    let end = p.domain.iter().position(|b| *b == 0).ok_or(ARG)?;
    if p.domain[end..].iter().any(|b| *b != 0) || p.allowed > 1 {
        return Err(ARG);
    }
    let domain = std::str::from_utf8(&p.domain[..end]).map_err(|_| ARG)?;
    let mut v = PreconfiguredPeer::new(
        PeerId(u128::from_le_bytes(p.id)),
        domain,
        p.life,
        p.rift,
        KeyHandle(p.key),
    )
    .map_err(|_| INVALID)?;
    v.service_allowed = p.allowed == 1;
    Ok(v)
}
pub(super) fn config(o: &Options) -> Result<(core::Config, TransferPolicy), i32> {
    if o.abi_version != 1
        || !(1..=2).contains(&o.kind)
        || !(1..=16).contains(&o.max_batch_events)
        || o.incarnation == [0; 16]
    {
        return Err(ARG);
    }
    let c = core::Config {
        max_read_bytes: 65536,
        max_bindings: 1024,
        ..Default::default()
    };
    let retry = match o.retry_mode {
        0 => RetryTimer::Fixed {
            after: o.retry_initial,
        },
        1 => RetryTimer::Exponential {
            initial: o.retry_initial,
            maximum: o.retry_maximum,
        },
        _ => return Err(ARG),
    };
    let congestion = match o.congestion_mode {
        0 => CongestionPolicy::Fixed {
            window: o.peer_window_initial as usize,
        },
        1 => CongestionPolicy::Aimd {
            initial: o.peer_window_initial as usize,
            maximum: o.peer_window_maximum as usize,
        },
        _ => return Err(ARG),
    };
    Ok((
        c,
        TransferPolicy {
            recovery: RecoveryPolicy {
                max_attempts: o.max_attempts,
            },
            timers: TimerPolicy {
                read_timeout: o.read_timeout,
                retry,
            },
            congestion,
        },
    ))
}
#[allow(clippy::type_complexity)]
pub(super) fn setup(
    o: &Options,
    keys: &[Key],
    flows: &[Flow],
) -> Result<
    (
        PreconfiguredPeer,
        SignedPublic,
        Vec<flow::FlowConfig>,
        flow::Checkpoint,
        Buffer,
    ),
    i32,
> {
    let _ = config(o)?;
    if keys.len() > 256 || flows.len() > 4 {
        return Err(LIMIT);
    }
    let local = peer(o.local)?;
    let mut table = BTreeMap::new();
    for k in keys {
        if table
            .insert(
                KeyHandle(k.handle),
                mesa_crypto::PublicKey::from_bytes(k.public_key).map_err(|_| INVALID)?,
            )
            .is_some()
        {
            return Err(ARG);
        }
    }
    let local_key = mesa_crypto::KeyPair::from_seed(&o.seed);
    let public = *local_key.public_key().as_bytes();
    let protection = SignedPublic::new(local.key, local_key, table);
    let mut fs = Vec::new();
    for f in flows {
        if f.attached > 1 {
            return Err(ARG);
        }
        fs.push(flow::FlowConfig {
            id: f.flow,
            peer: peer(f.peer)?,
            attachment: (f.attached == 1).then_some(Attachment(f.attachment)),
        });
    }
    let cp = flow::Checkpoint::empty(&local, &fs);
    let descriptor = serde_json::json!({"abi":1,"profile":"v2-signed-public","kind":o.kind,
        "local":{"id":format!("{:032x}",local.id.0),"domain":local.domain().as_str(),"life":local.life,"rift":local.rift,"key":local.key.0,"public_key":public},
        "incarnation":o.incarnation,"keys":keys.iter().map(|k|serde_json::json!({"handle":k.handle,"public_key":k.public_key})).collect::<Vec<_>>(),
        "flows":fs.iter().map(|f|serde_json::json!({"flow":f.id,"peer":format!("{:032x}",f.peer.id.0),"domain":f.peer.domain().as_str(),"rift":f.peer.rift})).collect::<Vec<_>>(),
        "policy":{"retry_mode":o.retry_mode,"retry_initial":o.retry_initial,"retry_maximum":o.retry_maximum,"read_timeout":o.read_timeout,"max_attempts":o.max_attempts,"congestion_mode":o.congestion_mode,"peer_window_initial":o.peer_window_initial,"peer_window_maximum":o.peer_window_maximum},
        "limits":{"buffer_bytes":MAX_BUFFER,"object_bytes":65536,"packet_bytes":1472,"path_bytes":256,"reads":32,"peers":64,"bindings":1024,"binding_bytes":8388608,"reassembly_bytes":8388608,"unverified_bytes":131072,"per_read_window":4,"max_fragments":1024,"bloq":13,"flows":4,"flow_window":4,"messages_per_batch":64,"outbox_bytes":262144,"batch_events":o.max_batch_events,"step_records":STEP_RECORDS,"step_bytes":STEP_BYTES},
        "mutation":"events only; descriptor never changes"});
    Ok((
        local,
        protection,
        fs,
        cp,
        serde_json::to_vec(&descriptor).map_err(|_| INVALID)?.into(),
    ))
}
pub(super) fn build(
    o: &Options,
    keys: &[Key],
    flows: &[Flow],
    checkpoint: Option<flow::Checkpoint>,
) -> Result<Engine, i32> {
    build_inner(o, keys, flows, checkpoint, None)
}
fn build_inner(
    o: &Options,
    keys: &[Key],
    flows: &[Flow],
    checkpoint: Option<flow::Checkpoint>,
    resources: Option<core::Config>,
) -> Result<Engine, i32> {
    let custom = resources.is_some();
    let (c, p) = config(o)?;
    let c = resources.unwrap_or(c);
    let (local, protection, fs, empty, mut descriptor) = setup(o, keys, flows)?;
    let (step_records, step_bytes) = if custom {
        let envelope = c.event_envelope().map_err(|_| INVALID)?;
        (envelope.records + 1, envelope.bytes.max(256))
    } else {
        (STEP_RECORDS, STEP_BYTES)
    };
    let object_bytes = c.max_read_bytes;
    if custom {
        let mut d: serde_json::Value =
            serde_json::from_slice(&descriptor.to_vec()).map_err(|_| INVALID)?;
        d["limits"]["object_bytes"] = c.max_read_bytes.into();
        d["limits"]["reads"] = c.max_reads.into();
        d["limits"]["peers"] = c.max_peers.into();
        d["limits"]["bindings"] = c.max_bindings.into();
        d["limits"]["binding_bytes"] = c.max_binding_bytes.into();
        d["limits"]["reassembly_bytes"] = c.max_reassembly_bytes.into();
        d["limits"]["unverified_bytes"] = c.max_unverified_bytes.into();
        d["limits"]["per_read_window"] = c.window.into();
        d["limits"]["step_records"] = step_records.into();
        d["limits"]["step_bytes"] = step_bytes.into();
        d["limits"]["keys"] = 256.into();
        d["configuration_version"] = 1.into();
        descriptor = serde_json::to_vec(&d).map_err(|_| INVALID)?.into();
    }
    let backend = if o.kind == 1 {
        if !fs.is_empty() || checkpoint.is_some() {
            return Err(ARG);
        }
        Backend::Core(Box::new(
            core::Engine::with_policy(c, local, protection, p).map_err(|_| INVALID)?,
        ))
    } else {
        let cfg = flow::Config {
            core: c,
            transfer: p,
            max_outbox_bytes: 262144,
            ..Default::default()
        };
        Backend::Flow(Box::new(
            flow::Node::new(
                cfg,
                local,
                protection,
                fs,
                checkpoint.unwrap_or(empty),
                u128::from_le_bytes(o.incarnation),
            )
            .map_err(|_| INVALID)?,
        ))
    };
    Ok(Engine {
        backend: Some(backend),
        descriptor,
        incarnation: o.incarnation,
        timer: None,
        poisoned: false,
        max_events: o.max_batch_events as usize,
        reads: BTreeSet::new(),
        step_records,
        step_bytes,
        object_bytes,
    })
}
impl Engine {
    pub(super) fn checkpoint(&self) -> Result<Buffer, i32> {
        match &self.backend {
            Some(Backend::Flow(n)) => serde_json::to_vec(n.checkpoint())
                .map(Buffer::from)
                .map_err(|_| INVALID),
            _ => Err(ARG),
        }
    }
    pub(super) fn flow_step(&mut self, e: flow::Event<'_>) -> Result<Vec<flow::Action>, i32> {
        match &mut self.backend {
            Some(Backend::Flow(n)) => n.step(e).map_err(|_| EVENT_ERROR),
            _ => Err(CLOSED),
        }
    }
    // All input buffer widths are bounded before materialization.
    #[allow(clippy::result_large_err)]
    pub(super) unsafe fn event(&mut self, e: &Event) -> Result<Vec<Record>, Record> {
        if e.tag == 17 {
            let mut records = Vec::new();
            for id in std::mem::take(&mut self.reads) {
                let mut r = Record::new(102);
                r.c.id = id;
                r.c.status = 201;
                records.push(r);
            }
            self.backend = None;
            self.timer = None;
            records.push(Record::new(113));
            return Ok(records);
        }
        let mut diagnostic = None;
        let result = (|| -> Result<Vec<Record>, i32> {
            // SAFETY: input references remain live for submit's duration.
            let data = unsafe {
                if e.data.is_null() {
                    None
                } else {
                    Some(buffer(
                        e.data,
                        match e.tag {
                            5..=8 => 256,
                            11 => 1472,
                            _ => self.object_bytes,
                        },
                    )?)
                }
            };
            let aux = unsafe {
                if e.aux.is_null() {
                    None
                } else {
                    Some(buffer(
                        e.aux,
                        if e.tag == 7 { 256 } else { self.object_bytes },
                    )?)
                }
            };
            let bytes = if matches!(e.tag, 5..=8 | 11) {
                data.as_ref().map(Buffer::to_vec).unwrap_or_default()
            } else {
                Vec::new()
            };
            let id = PeerId(u128::from_le_bytes(e.peer.id));
            let attachment = match e.flag {
                0 => None,
                1 => Some(Attachment(e.value)),
                _ => return Err(ARG),
            };
            let backend = self.backend.as_mut().ok_or(CLOSED)?;
            match backend {
                Backend::Core(n) => {
                    let event = match e.tag {
                        1 => core::Event::InstallPeer(peer(e.peer)?),
                        18 => core::Event::InstallCredential(core::host::CredentialUpdate {
                            peer: peer(e.peer)?,
                            expected_generation: e.sequence,
                            generation: e.id,
                            breach: e.flag == 1,
                        }),
                        19 => core::Event::ReplaceAttachment(core::host::AttachmentUpdate {
                            peer: id,
                            expected_generation: e.sequence,
                            generation: e.id,
                            attached: e.flag == 1,
                        }),
                        2 => core::Event::RemoteBreach(peer(e.peer)?),
                        3 if e.value <= 1 => core::Event::SetService {
                            peer: id,
                            allowed: e.value == 1,
                        },
                        4 => core::Event::SetAttachment {
                            peer: id,
                            attachment,
                        },
                        5 => core::Event::BindBuffer {
                            path: bytes,
                            bytes: aux.ok_or(ARG)?,
                            access: core::Access::Public,
                        },
                        6 => core::Event::Unbind { path: &bytes },
                        7 => core::Event::RetireBefore {
                            prefix: bytes,
                            suffix: aux.ok_or(ARG)?.to_vec(),
                        },
                        8 => core::Event::Read {
                            id: e.id,
                            peer: id,
                            path: bytes,
                        },
                        9 => core::Event::Cancel { id: e.id },
                        10 => core::Event::AdvanceTo(e.value),
                        11 => {
                            data.ok_or(ARG)?;
                            core::Event::Receive {
                                claimed_peer: id,
                                attachment: Attachment(e.value),
                                bytes: &bytes,
                            }
                        }
                        _ => return Err(ARG),
                    };
                    let actions = n.step(event).map_err(|e| {
                        diagnostic = Some(format!("{e:?}"));
                        if e == core::Error::StaleGeneration {
                            STALE
                        } else {
                            EVENT_ERROR
                        }
                    })?;
                    if e.tag == 8 {
                        self.reads.insert(e.id);
                    }
                    Ok(self.core_records(actions))
                }
                Backend::Flow(n) => {
                    let event = match e.tag {
                        1 => flow::Event::UpdatePeer(peer(e.peer)?),
                        3 if e.value <= 1 => flow::Event::SetService {
                            peer: id,
                            allowed: e.value == 1,
                        },
                        4 => flow::Event::SetAttachment {
                            peer: id,
                            attachment,
                        },
                        10 => flow::Event::AdvanceTo(e.value),
                        11 => {
                            data.ok_or(ARG)?;
                            flow::Event::Receive {
                                claimed_peer: id,
                                attachment: Attachment(e.value),
                                bytes: &bytes,
                            }
                        }
                        12 => flow::Event::EnqueueBuffer {
                            flow: e.id,
                            sequence: e.sequence,
                            bytes: data.ok_or(ARG)?,
                        },
                        13 => flow::Event::Decide {
                            id: e.message.into(),
                            outcome: outcome(e.outcome)?,
                        },
                        14 => flow::Event::Committed(flow::CommitToken {
                            incarnation: u128::from_le_bytes(e.token.incarnation),
                            revision: e.token.revision,
                        }),
                        15 => flow::Event::Resume { flow: e.id },
                        16 if e.value <= u32::MAX as u64 => flow::Event::InvalidateEpoch {
                            peer: id,
                            new_rift: e.value as u32,
                        },
                        _ => return Err(ARG),
                    };
                    let actions = n.step(event).map_err(|e| {
                        diagnostic = Some(format!("{e:?}"));
                        EVENT_ERROR
                    })?;
                    Ok(actions
                        .into_iter()
                        .filter_map(|a| flow_record(a, &mut self.timer))
                        .collect())
                }
            }
        })();
        result.map_err(|s| {
            Record::diagnostic(
                100,
                s,
                diagnostic
                    .as_deref()
                    .unwrap_or("invalid event arguments or buffer width"),
            )
        })
    }
    pub(super) fn core_records(&mut self, actions: Vec<core::Action>) -> Vec<Record> {
        let mut out = Vec::new();
        for a in actions {
            match a {
                core::Action::SetTimer(t) => self.timer = t,
                core::Action::Send {
                    peer,
                    attachment,
                    bytes,
                } => out.push(send(peer, attachment, bytes)),
                core::Action::Dropped(d) => out.push(Record::diagnostic(103, 0, d)),
                core::Action::ReadFinished { id, result } => {
                    self.reads.remove(&id);
                    let mut r = Record::new(102);
                    r.c.id = id;
                    match result {
                        Ok(b) => r.data = Some(b.into()),
                        Err(f) => {
                            r.c.status = match f {
                                core::ReadFailure::Cancelled => 201,
                                core::ReadFailure::Timeout => 202,
                                core::ReadFailure::RetriesExhausted => 203,
                                core::ReadFailure::Blocked => 204,
                                core::ReadFailure::PeerReset => 205,
                                core::ReadFailure::ResourceLimit => 206,
                            }
                        }
                    }
                    out.push(r);
                }
            }
        }
        out
    }
    pub(super) fn core_envelope(&self) -> (usize, usize) {
        (self.step_records, self.step_bytes)
    }

    pub(super) fn timer_record(&self) -> Record {
        let mut r = Record::new(104);
        r.c.event_index = usize::MAX;
        r.c.flag = u32::from(self.timer.is_some());
        r.c.value = self.timer.unwrap_or(0);
        r
    }
}
fn send(peer: PeerId, attachment: Attachment, bytes: Vec<u8>) -> Record {
    let mut r = Record::new(101);
    r.c.peer = peer.0.to_le_bytes();
    r.c.attachment = attachment.0;
    r.data = Some(bytes.into());
    r
}
pub(super) fn flow_record(a: flow::Action, timer: &mut Option<u64>) -> Option<Record> {
    let r = match a {
        flow::Action::SetTimer(t) => {
            *timer = t;
            return None;
        }
        flow::Action::Send {
            peer,
            attachment,
            bytes,
        } => send(peer, attachment, bytes),
        flow::Action::Commit(q) => {
            let mut r = Record::new(105);
            r.c.commit.token = q.token.into();
            r.c.commit.base_revision = q.base_revision;
            r.c.commit.revision = q.checkpoint.revision;
            r.checkpoint = Some(
                serde_json::to_vec(&q.checkpoint)
                    .expect("checkpoint serialization")
                    .into(),
            );
            let (id, change, o) = match q.change {
                flow::Change::Enqueue { id } => (id, 1, None),
                flow::Change::Deliver { id, bytes, outcome } => {
                    r.payload = Some(bytes);
                    (id, 2, Some(outcome))
                }
                flow::Change::Settle { id, outcome } => (id, 3, Some(outcome)),
                flow::Change::RetireReceived { id } => (id, 4, None),
                flow::Change::RetireSent { id } => (id, 5, None),
            };
            r.c.commit.message = (&id).into();
            r.c.commit.change = change;
            r.c.commit.outcome = o.map_or(0, outcome_code);
            r
        }
        flow::Action::Deliver { id, bytes } => {
            let mut r = Record::new(106);
            r.c.message = (&id).into();
            r.data = Some(bytes);
            r
        }
        flow::Action::Enqueued { id } => {
            let mut r = Record::new(107);
            r.c.message = (&id).into();
            r
        }
        flow::Action::CommittedDelivery { id, outcome } => completion(108, id, outcome),
        flow::Action::Settled { id, outcome } => completion(109, id, outcome),
        flow::Action::Stalled {
            flow,
            sequence,
            kind,
            failure,
        } => {
            let mut r = Record::diagnostic(110, 0, failure);
            r.c.id = flow;
            r.c.sequence = sequence;
            r.c.detail = kind as u32;
            r
        }
        flow::Action::Dropped(d) => Record::diagnostic(103, 0, d),
        flow::Action::AnnouncementStalled { id, kind } => {
            let mut r = Record::new(111);
            r.c.message = (&id).into();
            r.c.detail = kind as u32;
            r
        }
        flow::Action::EpochInvalidated { peer, new_rift } => {
            let mut r = Record::new(112);
            r.c.peer = peer.0.to_le_bytes();
            r.c.value = new_rift as u64;
            r
        }
    };
    Some(r)
}
fn completion(tag: u32, id: flow::MessageId, outcome: flow::Outcome) -> Record {
    let mut r = Record::new(tag);
    r.c.message = (&id).into();
    r.c.outcome = outcome_code(outcome);
    r
}
/// # Safety
/// Callers must satisfy the pointer, ownership, and serialization contracts in
/// the corresponding include/mesa_*.h header and spec/14-c-embedding.md.
#[no_mangle]
pub unsafe extern "C" fn mesa_options_default(out: *mut Options) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: all foreign pointers follow the exported caller contract.
        unsafe {
            if out.is_null() {
                return ARG;
            }
            *out = Options {
                abi_version: 1,
                kind: 1,
                local: Peer {
                    id: [0; 16],
                    domain: [0; 64],
                    life: 1,
                    rift: 0,
                    key: 0,
                    allowed: 1,
                },
                seed: [0; 32],
                incarnation: [0; 16],
                retry_initial: 100,
                retry_maximum: 800,
                read_timeout: 2000,
                max_attempts: 4,
                retry_mode: 0,
                congestion_mode: 0,
                peer_window_initial: 16,
                peer_window_maximum: 128,
                max_batch_events: 16,
            };
            0
        }
    }))
    .unwrap_or(PANIC)
}
/// # Safety
/// Callers must satisfy the pointer, ownership, and serialization contracts in
/// the corresponding include/mesa_*.h header and spec/14-c-embedding.md.
#[no_mangle]
pub unsafe extern "C" fn mesa_key_from_seed(seed: *const u8, public: *mut u8) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: all foreign pointers follow the exported caller contract.
        unsafe {
            if seed.is_null() || public.is_null() {
                return ARG;
            }
            let seed: &[u8; 32] = &*seed.cast();
            let key = mesa_crypto::KeyPair::from_seed(seed).public_key();
            ptr::copy_nonoverlapping(key.as_bytes().as_ptr(), public, 32);
            0
        }
    }))
    .unwrap_or(PANIC)
}
/// # Safety
/// Callers must satisfy the pointer, ownership, and serialization contracts in
/// the corresponding include/mesa_*.h header and spec/14-c-embedding.md.
#[no_mangle]
pub unsafe extern "C" fn mesa_engine_create(
    o: *const Options,
    keys: *const Key,
    nkeys: usize,
    flows: *const Flow,
    nflows: usize,
    checkpoint: *const Buffer,
    out: *mut *mut Engine,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: all foreign pointers follow the exported caller contract.
        unsafe {
            if out.is_null() {
                return ARG;
            }
            *out = ptr::null_mut();
            if o.is_null() || nkeys > 16 || nflows > 4 {
                return ARG;
            }
            let result = (|| {
                let cp = if checkpoint.is_null() {
                    None
                } else {
                    Some(
                        serde_json::from_slice(&buffer(checkpoint, 2 * 1024 * 1024)?.to_vec())
                            .map_err(|_| INVALID)?,
                    )
                };
                build(&*o, array(keys, nkeys)?, array(flows, nflows)?, cp)
            })();
            match result {
                Ok(h) => {
                    *out = Box::into_raw(Box::new(h));
                    0
                }
                Err(e) => e,
            }
        }
    }))
    .unwrap_or(PANIC)
}
/// # Safety
/// Callers must satisfy the pointer, ownership, and serialization contracts in
/// the corresponding include/mesa_*.h header and spec/14-c-embedding.md.
#[no_mangle]
pub unsafe extern "C" fn mesa_engine_describe(h: *const Engine, out: *mut *const Buffer) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: all foreign pointers follow the exported caller contract.
        unsafe {
            if out.is_null() {
                return ARG;
            }
            *out = ptr::null();
            if h.is_null() {
                return ARG;
            }
            *out = owned((*h).descriptor.clone());
            0
        }
    }))
    .unwrap_or(PANIC)
}
/// # Safety
/// Callers must satisfy the pointer, ownership, and serialization contracts in
/// the corresponding include/mesa_*.h header and spec/14-c-embedding.md.
#[no_mangle]
pub unsafe extern "C" fn mesa_engine_checkpoint(h: *const Engine, out: *mut *const Buffer) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: all foreign pointers follow the exported caller contract.
        unsafe {
            if out.is_null() {
                return ARG;
            }
            *out = ptr::null();
            if h.is_null() {
                return ARG;
            }
            if (*h).poisoned {
                return PANIC;
            }
            match (*h).checkpoint() {
                Ok(b) => {
                    *out = owned(b);
                    0
                }
                Err(e) => e,
            }
        }
    }))
    .unwrap_or(PANIC)
}
/// # Safety
/// Callers must satisfy the pointer, ownership, and serialization contracts in
/// the corresponding include/mesa_*.h header and spec/14-c-embedding.md.
#[no_mangle]
pub unsafe extern "C" fn mesa_engine_submit(
    h: *mut Engine,
    incarnation: *const u8,
    events: *const Event,
    count: usize,
    budget: *const Budget,
    out: *mut *const Batch,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: all foreign pointers follow the exported caller contract.
        unsafe {
            if out.is_null() {
                return ARG;
            }
            *out = ptr::null();
            if h.is_null() || incarnation.is_null() || budget.is_null() {
                return ARG;
            }
            let h = &mut *h;
            let budget = &*budget;
            if h.poisoned {
                return PANIC;
            }
            if h.backend.is_none() {
                return CLOSED;
            }
            if slice::from_raw_parts(incarnation, 16) != h.incarnation {
                return STALE;
            }
            if !budget.valid() || count > h.max_events {
                return ARG;
            }
            let events = match array(events, count) {
                Ok(e) => e,
                Err(e) => return e,
            };
            let mut b = Batch::default();
            if !budget.fits(
                &b,
                if count == 0 { 1 } else { h.step_records + 1 },
                if count == 0 { 0 } else { h.step_bytes },
            ) {
                return CAPACITY;
            }
            h.poisoned = true;
            for (i, e) in events.iter().take(budget.max_steps).enumerate() {
                if !budget.fits(&b, h.step_records + 1, h.step_bytes) {
                    break;
                }
                let start = b.records.len();
                let before = b.bytes;
                let failed = match h.event(e) {
                    Ok(records) => {
                        b.push(Record::new(100));
                        for r in records {
                            b.push(r)
                        }
                        false
                    }
                    Err(r) => {
                        b.push(r);
                        true
                    }
                };
                for r in &mut b.records[start..] {
                    r.c.event_index = i;
                    r.c.cookie = e.cookie;
                }
                assert!(
                    b.records.len() - start <= h.step_records && b.bytes - before <= h.step_bytes,
                    "step envelope"
                );
                b.processed += 1;
                if failed || h.backend.is_none() {
                    break;
                }
            }
            b.push(h.timer_record());
            h.poisoned = false;
            *out = publish(b);
            0
        }
    }))
    .unwrap_or(PANIC)
}
/// # Safety
/// Callers must satisfy the pointer, ownership, and serialization contracts in
/// the corresponding include/mesa_*.h header and spec/14-c-embedding.md.
#[no_mangle]
pub unsafe extern "C" fn mesa_engine_release(h: *mut Engine) {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: all foreign pointers follow the exported caller contract.
        unsafe {
            if !h.is_null() {
                drop(Box::from_raw(h))
            }
        }
    }))
    .unwrap_or(())
}
