//! Phase-4 C component API. See mesa_pki.h. No native wire dispatch here.
use super::*;
use mesa_jael::{self as jael, Action, Input, Jael, Ticket, Verdict};
use mesa_pki::{self as pki, Authority, Candidate, Lifecycle, Provider, ProviderStatus};
#[repr(C)]
#[derive(Clone, Copy, serde::Serialize)]
pub struct PkiOptions {
    version: u32,
    incarnation: [u8; 16],
    max_domains: usize,
    max_peers: usize,
    max_history: usize,
    max_evidence_bytes: usize,
    max_checkpoint_bytes: usize,
    max_pending: usize,
    max_pending_bytes: usize,
    max_packet: usize,
    request_timeout: u64,
    retry_after: u64,
    attempts: u32,
    work_per_tick: usize,
    max_subscriptions: usize,
    dispatches: usize,
    dispatch_interval: u64,
}
impl PkiOptions {
    fn config(&self) -> Result<jael::Config, i32> {
        if self.version != 1 || self.max_checkpoint_bytes > MAX_BUFFER {
            return Err(ARG);
        }
        Ok(jael::Config {
            authority: pki::Limits {
                domains: self.max_domains,
                peers: self.max_peers,
                history: self.max_history,
                evidence_bytes: self.max_evidence_bytes,
                checkpoint_bytes: self.max_checkpoint_bytes,
            },
            pending: self.max_pending,
            pending_bytes: self.max_pending_bytes,
            max_packet: self.max_packet,
            request_timeout: self.request_timeout,
            retry_after: self.retry_after,
            attempts: self.attempts,
            work_per_tick: self.work_per_tick,
            subscriptions: self.max_subscriptions,
            dispatches: self.dispatches,
            dispatch_interval: self.dispatch_interval,
        })
    }
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct PkiTicket {
    domain_hash: [u8; 32],
    incarnation: [u8; 16],
    generation: u64,
    request: u64,
    peer: [u8; 16],
    base_revision: u64,
    digest: [u8; 32],
}
impl From<PkiTicket> for Ticket {
    fn from(t: PkiTicket) -> Self {
        Self {
            provider: Provider {
                domain_hash: t.domain_hash,
                incarnation: u128::from_le_bytes(t.incarnation),
                generation: t.generation,
            },
            request: t.request,
            peer: u128::from_le_bytes(t.peer),
            base_revision: t.base_revision,
            digest: t.digest,
        }
    }
}
impl From<Ticket> for PkiTicket {
    fn from(t: Ticket) -> Self {
        Self {
            domain_hash: t.provider.domain_hash,
            incarnation: t.provider.incarnation.to_le_bytes(),
            generation: t.provider.generation,
            request: t.request,
            peer: t.peer.to_le_bytes(),
            base_revision: t.base_revision,
            digest: t.digest,
        }
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PkiEvent {
    tag: u32,
    flags: u32,
    domain: [u8; 64],
    peer: [u8; 16],
    life: u32,
    rift: u32,
    public_key: [u8; 32],
    evidence: *const Buffer,
    expected: u64,
    value: u64,
    ticket: PkiTicket,
    token: Token,
    sponsor: [u8; 16],
    fief: [u8; 16],
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PkiRecord {
    tag: u32,
    status: i32,
    event_index: usize,
    peer: [u8; 16],
    domain: [u8; 64],
    life: u32,
    rift: u32,
    public_key: [u8; 32],
    ticket: PkiTicket,
    token: Token,
    value: u64,
    flags: u32,
    data: *const Buffer,
}
struct PkiOwned {
    view: PkiRecord,
    data: Option<Buffer>,
}
// SAFETY: stored metadata pointers are null. pki_batch_get fills a C copy.
unsafe impl Send for PkiOwned {}
// SAFETY: published batches and buffers are immutable.
unsafe impl Sync for PkiOwned {}
pub struct PkiBatch {
    processed: usize,
    records: Vec<PkiOwned>,
    bytes: usize,
}
enum PkiBackend {
    Raw(Box<Authority>),
    Jael(Box<Jael>),
}
pub struct PkiHandle {
    descriptor: Buffer,
    backend: PkiBackend,
    config: jael::Config,
    poisoned: bool,
}
impl PkiHandle {
    fn authority(&self) -> &Authority {
        match &self.backend {
            PkiBackend::Raw(a) => a,
            PkiBackend::Jael(j) => j.authority(),
        }
    }
    fn envelope(&self) -> (usize, usize) {
        match &self.backend {
            PkiBackend::Jael(j) => j.envelope(),
            PkiBackend::Raw(_) => (2, self.config.authority.checkpoint_bytes),
        }
    }
    unsafe fn event(&mut self, e: &PkiEvent) -> Result<Vec<Action>, i32> {
        let domain = domain(&e.domain)?;
        let peer = u128::from_le_bytes(e.peer);
        let provider = Provider {
            domain_hash: e.ticket.domain_hash,
            incarnation: u128::from_le_bytes(e.ticket.incarnation),
            generation: e.ticket.generation,
        };
        // SAFETY: event buffer handles follow mesa_pki.h.
        let candidate = || unsafe {
            Ok::<_, i32>(Candidate {
                peer,
                domain: domain.clone(),
                life: e.life,
                rift: e.rift,
                public_key: e.public_key,
                evidence: buffer(e.evidence, self.config.authority.evidence_bytes)?,
            })
        };
        let scope = || -> Result<_, i32> {
            if e.flags & !3 != 0 {
                return Err(ARG);
            }
            Ok((
                (e.flags & 1 != 0).then(|| u128::from_le_bytes(e.sponsor)),
                (e.flags & 2 != 0).then(|| u128::from_le_bytes(e.fief)),
            ))
        };
        let token = pki::Token {
            incarnation: u128::from_le_bytes(e.token.incarnation),
            revision: e.token.revision,
        };
        if let PkiBackend::Raw(a) = &mut self.backend {
            let proposal = match e.tag {
                1 => a.register(&domain, e.expected, e.value),
                2 => {
                    if e.flags & !3 != 0 {
                        return Err(ARG);
                    }
                    a.set_status(
                        &domain,
                        provider,
                        ProviderStatus {
                            available: e.flags & 1 != 0,
                            ready: e.flags & 2 != 0,
                        },
                    )
                    .map_err(code)?;
                    return Ok(vec![]);
                }
                3 => a.lifecycle(&domain, provider, life(e.value)?),
                7 => a.withdraw(&domain, provider, peer, e.expected),
                8 => {
                    if e.flags > 1 {
                        return Err(ARG);
                    }
                    a.operator_block(peer, e.flags != 0)
                }
                9 => {
                    a.commit(token).map_err(code)?;
                    return Ok(vec![]);
                }
                15 => a.refresh_evidence(provider, e.expected, candidate()?),
                14 => {
                    let (sponsor, fief) = scope()?;
                    a.accept(provider, e.expected, candidate()?, sponsor, fief)
                }
                _ => return Err(ARG),
            }
            .map_err(code)?;
            return Ok(vec![Action::Persist(proposal)]);
        }
        let input = match e.tag {
            1 => Input::Register {
                domain,
                expected: e.expected,
                generation: e.value,
            },
            2 => {
                if e.flags & !3 != 0 {
                    return Err(ARG);
                }
                Input::Status {
                    domain,
                    provider,
                    status: ProviderStatus {
                        available: e.flags & 1 != 0,
                        ready: e.flags & 2 != 0,
                    },
                }
            }
            3 => Input::Lifecycle {
                domain,
                provider,
                lifecycle: life(e.value)?,
            },
            4 => Input::ProfileCandidate(candidate()?),
            5 => Input::Resolve(candidate()?),
            16 => Input::ResolvePeer { domain, peer },
            17 => {
                let (sponsor, fief) = scope()?;
                Input::Resolved {
                    candidate: candidate()?,
                    domain,
                    ticket: e.ticket.into(),
                    sponsor,
                    fief,
                }
            }
            15 => Input::RefreshEvidence(candidate()?),
            6 => {
                let verdict = match e.value {
                    0 => {
                        let (sponsor, fief) = scope()?;
                        Verdict::Accept { sponsor, fief }
                    }
                    1 => Verdict::Reject,
                    2 => Verdict::Unavailable,
                    _ => return Err(ARG),
                };
                Input::Complete {
                    domain,
                    ticket: e.ticket.into(),
                    verdict,
                }
            }
            7 => Input::Withdraw {
                domain,
                provider,
                peer,
                revision: e.expected,
            },
            8 => {
                if e.flags > 1 {
                    return Err(ARG);
                }
                Input::OperatorBlock {
                    peer,
                    blocked: e.flags != 0,
                }
            }
            9 => Input::Commit(token),
            10 => Input::Cancel(e.value),
            11 => Input::Advance(e.value),
            12 => Input::Subscribe(peer),
            13 => Input::Unsubscribe(peer),
            _ => return Err(ARG),
        };
        match &mut self.backend {
            PkiBackend::Jael(j) => j.step(input).map_err(code),
            _ => unreachable!(),
        }
    }
}
fn code(e: pki::Error) -> i32 {
    match e {
        pki::Error::Capacity => CAPACITY,
        pki::Error::Stale => STALE,
        _ => INVALID,
    }
}
fn domain(bytes: &[u8; 64]) -> Result<String, i32> {
    let end = bytes.iter().position(|b| *b == 0).ok_or(ARG)?;
    if bytes[end..].iter().any(|b| *b != 0) {
        return Err(ARG);
    }
    Ok(std::str::from_utf8(&bytes[..end]).map_err(|_| ARG)?.into())
}
fn life(value: u64) -> Result<Lifecycle, i32> {
    match value {
        1 => Ok(Lifecycle::Suspended),
        2 => Ok(Lifecycle::Removed),
        _ => Err(ARG),
    }
}
impl PkiOwned {
    fn new(tag: u32, index: usize) -> Self {
        Self {
            view: PkiRecord {
                tag,
                status: 0,
                event_index: index,
                peer: [0; 16],
                domain: [0; 64],
                life: 0,
                rift: 0,
                public_key: [0; 32],
                ticket: PkiTicket::default(),
                token: Token::default(),
                value: 0,
                flags: 0,
                data: ptr::null(),
            },
            data: None,
        }
    }
    fn action(a: Action, index: usize) -> Self {
        let mut r = Self::new(0, index);
        match a {
            Action::Resolve {
                ticket,
                domain,
                peer,
            } => {
                r.view.tag = 108;
                r.view.ticket = ticket.into();
                r.view.peer = peer.to_le_bytes();
                r.view.domain[..domain.len()].copy_from_slice(domain.as_bytes());
            }
            Action::Verify { ticket, candidate } => {
                r.view.tag = 101;
                r.view.ticket = ticket.into();
                r.view.peer = candidate.peer.to_le_bytes();
                r.view.domain[..candidate.domain.len()]
                    .copy_from_slice(candidate.domain.as_bytes());
                r.view.life = candidate.life;
                r.view.rift = candidate.rift;
                r.view.public_key = candidate.public_key;
                r.data = Some(candidate.evidence);
            }
            Action::Persist(p) => {
                r.view.tag = 102;
                r.view.token = Token {
                    incarnation: p.token.incarnation.to_le_bytes(),
                    revision: p.token.revision,
                };
                r.view.value = p.base_revision;
                r.data = Some(p.checkpoint);
            }
            Action::Changed { peer, revision } => {
                r.view.tag = 103;
                r.view.peer = peer.to_le_bytes();
                r.view.value = revision;
            }
            Action::Finished { request, reason } => {
                r.view.tag = 104;
                r.view.value = request;
                r.view.flags = match reason {
                    jael::End::Rejected => 1,
                    jael::End::TimedOut => 2,
                    jael::End::Cancelled => 3,
                    jael::End::Stale => 4,
                };
            }
            Action::Solicit { peer } => {
                r.view.tag = 105;
                r.view.peer = peer.to_le_bytes();
            }
            Action::Timer(t) => {
                r.view.tag = 106;
                r.view.flags = u32::from(t.is_some());
                r.view.value = t.unwrap_or(0);
            }
        }
        r
    }
}
/// # Safety
/// Writable options pointer, as specified in mesa_pki.h.
#[no_mangle]
pub unsafe extern "C" fn mesa_pki_options_default(out: *mut PkiOptions) -> i32 {
    if out.is_null() {
        return ARG;
    }
    let c = jael::Config::default();
    // SAFETY: checked output supplied by caller.
    unsafe {
        *out = PkiOptions {
            version: 1,
            incarnation: [0; 16],
            max_domains: c.authority.domains,
            max_peers: c.authority.peers,
            max_history: c.authority.history,
            max_evidence_bytes: c.authority.evidence_bytes,
            max_checkpoint_bytes: c.authority.checkpoint_bytes,
            max_pending: c.pending,
            max_pending_bytes: c.pending_bytes,
            max_packet: c.max_packet,
            request_timeout: c.request_timeout,
            retry_after: c.retry_after,
            attempts: c.attempts,
            work_per_tick: c.work_per_tick,
            max_subscriptions: c.subscriptions,
            dispatches: c.dispatches,
            dispatch_interval: c.dispatch_interval,
        };
    }
    0
}
/// # Safety
/// Live options/checkpoint and writable output. kind: 1 raw, 2 Jael.
#[no_mangle]
pub unsafe extern "C" fn mesa_pki_create(
    kind: u32,
    o: *const PkiOptions,
    checkpoint: *const Buffer,
    out: *mut *mut PkiHandle,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: all pointers follow the public header contract.
        unsafe {
            if out.is_null() {
                return ARG;
            }
            *out = ptr::null_mut();
            if o.is_null() {
                return ARG;
            }
            let result = (|| {
                let c = (*o).config()?;
                let incarnation = u128::from_le_bytes((*o).incarnation);
                let a = if checkpoint.is_null() {
                    Authority::new(c.authority.clone(), incarnation)
                } else {
                    Authority::restore(
                        c.authority.clone(),
                        incarnation,
                        &buffer(checkpoint, c.authority.checkpoint_bytes)?,
                    )
                }
                .map_err(code)?;
                let backend = match kind {
                    1 => PkiBackend::Raw(Box::new(a)),
                    2 => {
                        let j = if checkpoint.is_null() {
                            Jael::new(c.clone(), incarnation)
                        } else {
                            Jael::restore(c.clone(), incarnation, &*checkpoint)
                        }
                        .map_err(code)?;
                        PkiBackend::Jael(Box::new(j))
                    }
                    _ => return Err(ARG),
                };
                Ok(PkiHandle {
                    descriptor: serde_json::to_vec(&*o).map_err(|_| INVALID)?.into(),
                    backend,
                    config: c,
                    poisoned: false,
                })
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
/// Release once after serialized use; buffers and batches remain valid.
#[no_mangle]
pub unsafe extern "C" fn mesa_pki_release(h: *mut PkiHandle) {
    if !h.is_null() {
        unsafe {
            drop(Box::from_raw(h));
        }
    }
}
/// # Safety
/// Live serialized handle, readable events/budget, writable output.
#[no_mangle]
pub unsafe extern "C" fn mesa_pki_step(
    h: *mut PkiHandle,
    events: *const PkiEvent,
    n: usize,
    budget: *const Budget,
    out: *mut *const PkiBatch,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: foreign inputs follow mesa_pki.h.
        unsafe {
            if out.is_null() {
                return ARG;
            }
            *out = ptr::null();
            if h.is_null() || budget.is_null() || n > 64 {
                return ARG;
            }
            let h = &mut *h;
            if h.poisoned {
                return PANIC;
            }
            let budget = &*budget;
            if !budget.valid() {
                return ARG;
            }
            let events = match array(events, n) {
                Ok(e) => e,
                Err(e) => return e,
            };
            let (envelope, bytes) = h.envelope();
            let mut batch = PkiBatch {
                processed: 0,
                records: vec![],
                bytes: 0,
            };
            for (index, e) in events.iter().take(budget.max_steps).enumerate() {
                if envelope > budget.max_results.saturating_sub(batch.records.len())
                    || bytes > budget.max_result_bytes.saturating_sub(batch.bytes)
                {
                    if batch.processed == 0 {
                        return CAPACITY;
                    }
                    break;
                }
                batch.processed += 1;
                match h.event(e) {
                    Ok(actions) => {
                        for a in actions {
                            let r = PkiOwned::action(a, index);
                            batch.bytes += r.data.as_ref().map_or(0, Buffer::len);
                            batch.records.push(r);
                        }
                    }
                    Err(status) => {
                        let mut r = PkiOwned::new(107, index);
                        r.view.status = status;
                        batch.records.push(r);
                        break;
                    }
                }
            }
            *out = Arc::into_raw(Arc::new(batch));
            0
        }
    }));
    match result {
        Ok(code) => code,
        Err(_) => {
            if !h.is_null() {
                unsafe {
                    (*h).poisoned = true;
                }
            }
            PANIC
        }
    }
}
/// # Safety
/// Live immutable batch; writable count outputs.
#[no_mangle]
pub unsafe extern "C" fn mesa_pki_batch_info(
    b: *const PkiBatch,
    processed: *mut usize,
    count: *mut usize,
) -> i32 {
    if b.is_null() || processed.is_null() || count.is_null() {
        return ARG;
    }
    unsafe {
        *processed = (*b).processed;
        *count = (*b).records.len();
    }
    0
}
/// # Safety
/// Live batch and writable record. data receives an owned reference; release with mesa_pki_record_release.
#[no_mangle]
pub unsafe extern "C" fn mesa_pki_batch_get(
    b: *const PkiBatch,
    index: usize,
    out: *mut PkiRecord,
) -> i32 {
    if b.is_null() || out.is_null() {
        return ARG;
    }
    unsafe {
        let records = &(*b).records;
        let Some(r) = records.get(index) else {
            return ARG;
        };
        *out = r.view;
        (*out).data = r.data.clone().map_or(ptr::null(), owned);
    }
    0
}
/// # Safety
/// Release a live batch reference once.
#[no_mangle]
pub unsafe extern "C" fn mesa_pki_batch_release(b: *const PkiBatch) {
    if !b.is_null() {
        unsafe {
            drop(Arc::from_raw(b));
        }
    }
}
/// # Safety
/// Live serialized handle, writable owned-buffer output. Observation only.
#[no_mangle]
pub unsafe extern "C" fn mesa_pki_snapshot(h: *const PkiHandle, out: *mut *const Buffer) -> i32 {
    catch_unwind(AssertUnwindSafe(||unsafe{
        if out.is_null(){return ARG;}*out=ptr::null();
        if h.is_null(){return ARG;}
        if (*h).poisoned{return PANIC;}
        let a=(*h).authority();let s=a.snapshot();
        let policies:Vec<_>=s.peers.keys().map(|id|{let p=a.policy(*id).unwrap();serde_json::json!({"peer":id.to_string(),
            "ordinary":p.ordinary(),"recovery":p.recovery(),"operator_blocked":p.operator_blocked,"withdrawn":p.withdrawn,
            "domain_active":p.domain_active,"ready":p.ready,"committed":p.committed,"revalidated":p.revalidated})}).collect();
        #[derive(serde::Serialize)]
        struct View { state:pki::State, policies:Vec<serde_json::Value>, pending_revision:Option<u64> }
        let v=View {state:s,policies,pending_revision:a.pending().map(|p|p.token.revision)};
        match serde_json::to_vec(&v){Ok(b)=>{*out=owned(b.into());0},Err(_)=>INVALID}
    })).unwrap_or(PANIC)
}

/// # Safety
/// Release the owned data reference returned by mesa_pki_batch_get, once.
#[no_mangle]
pub unsafe extern "C" fn mesa_pki_record_release(r: *mut PkiRecord) {
    if let Some(r) = unsafe { r.as_mut() } {
        if !r.data.is_null() {
            unsafe {
                Arc::decrement_strong_count(r.data);
            }
        }
        r.data = ptr::null();
    }
}
/// # Safety
/// Both handles are serialized. Sync current policy before further CORE work.
/// Outputs use the existing mesa_batch/result ownership contract. CORE only.
#[no_mangle]
pub unsafe extern "C" fn mesa_pki_sync_core(
    h: *const PkiHandle,
    e: *mut engine::Engine,
    peer: *const u8,
    budget: *const Budget,
    out: *mut *const Batch,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| unsafe {
        if out.is_null() {
            return ARG;
        }
        *out = ptr::null();
        if h.is_null() || e.is_null() || peer.is_null() || budget.is_null() {
            return ARG;
        }
        let h = &*h;
        let e = &mut *e;
        if h.poisoned || e.poisoned {
            return PANIC;
        }
        let budget = &*budget;
        if !budget.valid() {
            return ARG;
        }
        let (records, bytes) = e.core_envelope();
        let mut batch = Batch::default();
        if !budget.fits(&batch, records, bytes) {
            return CAPACITY;
        }
        let peer = u128::from_le_bytes(array(peer, 16).unwrap().try_into().unwrap());
        let Some(engine::Backend::Core(core)) = &mut e.backend else {
            return ARG;
        };
        let actions = match h.authority().sync_peer(core, peer) {
            Ok(a) => a,
            Err(_) => return INVALID,
        };
        for r in e.core_records(actions) {
            batch.push(r);
        }
        batch.push(e.timer_record());
        batch.processed = 1;
        *out = publish(batch);
        0
    }));
    match result {
        Ok(c) => c,
        Err(_) => {
            if !e.is_null() {
                unsafe {
                    (*e).poisoned = true;
                }
            }
            PANIC
        }
    }
}

/// # Safety
/// Live serialized handle and writable owned-buffer output. Immutable options.
#[no_mangle]
pub unsafe extern "C" fn mesa_pki_describe(h: *const PkiHandle, out: *mut *const Buffer) -> i32 {
    catch_unwind(AssertUnwindSafe(|| unsafe {
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
        *out = owned((*h).descriptor.clone());
        0
    }))
    .unwrap_or(PANIC)
}

/// # Safety
/// Live serialized handle, readable 64-byte domain and writable provider ticket.
/// Routing this capability to the authenticated verifier remains host-owned.
#[no_mangle]
pub unsafe extern "C" fn mesa_pki_provider(
    h: *const PkiHandle,
    name: *const u8,
    out: *mut PkiTicket,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| unsafe {
        if out.is_null() {
            return ARG;
        }
        *out = PkiTicket::default();
        if h.is_null() || name.is_null() {
            return ARG;
        }
        if (*h).poisoned {
            return PANIC;
        }
        let result = (|| {
            let name = domain(array(name, 64)?.try_into().unwrap())?;
            let p = (*h).authority().registered_provider(&name).map_err(code)?;
            Ok::<_, i32>(PkiTicket {
                domain_hash: p.domain_hash,
                incarnation: p.incarnation.to_le_bytes(),
                generation: p.generation,
                ..Default::default()
            })
        })();
        match result {
            Ok(p) => {
                *out = p;
                0
            }
            Err(e) => e,
        }
    }))
    .unwrap_or(PANIC)
}
