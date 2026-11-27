//! Serialized activation/custody component; all host persistence remains explicit.
use super::*;
use mesa_keys::{
    self as keys,
    operations::{Purpose, Reply, Request, Ticket},
    Activation, SoftwareStore,
};
#[repr(C)]
pub struct KeysOptions {
    version: u32,
    peer: [u8; 16],
    domain: [u8; 64],
    incarnation: [u8; 16],
    host_epoch: [u8; 16],
    history: usize,
    operations: usize,
    timeout: u64,
    checkpoint_bytes: usize,
    max_keys: usize,
    max_objects: usize,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct KeyRef {
    backend: [u8; 16],
    object: [u8; 16],
    version: u64,
}
impl From<KeyRef> for keys::KeyRef {
    fn from(r: KeyRef) -> Self {
        Self {
            backend: u128::from_le_bytes(r.backend),
            object: u128::from_le_bytes(r.object),
            version: r.version,
        }
    }
}
#[repr(C)]
pub struct KeyEvent {
    tag: u32,
    cookie: u64,
    reference: KeyRef,
    token: Token,
    value: u64,
    id: u64,
    generation: u64,
    incarnation: [u8; 16],
    peer: [u8; 16],
    life: u32,
    rift: u32,
    public_key: [u8; 32],
    data: *const Buffer,
    seed: *const Buffer,
    root: [u8; 32],
    signature: [u8; 64],
}
#[derive(serde::Serialize)]
struct Description<'a> {
    version: u32,
    activation: &'a keys::Config,
    max_keys: usize,
    max_objects: usize,
}
pub struct Keys {
    activation: Activation,
    store: SoftwareStore,
    requests: BTreeMap<u64, Request>,
    poisoned: bool,
    descriptor: Buffer,
}
fn domain(d: &[u8; 64]) -> Result<String, i32> {
    let end = d.iter().position(|b| *b == 0).ok_or(ARG)?;
    if d[end..].iter().any(|b| *b != 0) {
        return Err(ARG);
    }
    Ok(std::str::from_utf8(&d[..end]).map_err(|_| ARG)?.into())
}
fn code(e: keys::Error) -> i32 {
    match e {
        keys::Error::Capacity => CAPACITY,
        keys::Error::Stale | keys::Error::Rollback => STALE,
        _ => EVENT_ERROR,
    }
}
fn token(t: Token) -> keys::Token {
    keys::Token {
        incarnation: u128::from_le_bytes(t.incarnation),
        revision: t.revision,
    }
}
fn proposal(p: keys::Proposal) -> Record {
    let mut r = Record::new(301);
    r.c.token = Token {
        incarnation: p.token.incarnation.to_le_bytes(),
        revision: p.token.revision,
    };
    r.c.value = p.base_revision;
    r.data = Some(p.checkpoint);
    r.aux = Some(serde_json::to_vec(&p.retired).unwrap().into());
    r
}
impl Keys {
    unsafe fn event(
        &mut self,
        a: &mesa_pki::Authority,
        mut engine: Option<&mut engine::Engine>,
        e: &KeyEvent,
    ) -> Result<Vec<Record>, i32> {
        let reference = e.reference.into();
        let ticket = Ticket {
            incarnation: u128::from_le_bytes(e.incarnation),
            id: e.id,
            generation: e.generation,
        };
        let mut out = vec![];
        // SAFETY: input buffers are retained live for this serialized call.
        unsafe {
            match e.tag {
                1 => {
                    let c = mesa_pki::Candidate {
                        peer: u128::from_le_bytes(e.peer),
                        domain: self.activation.config().domain.clone(),
                        life: e.life,
                        rift: e.rift,
                        public_key: e.public_key,
                        evidence: buffer(e.data, MAX_BUFFER)?,
                    };
                    let seed = buffer(e.seed, 32)?;
                    if seed.len() != 32 {
                        return Err(ARG);
                    }
                    let material = seed
                        .with_bytes(|b| keys::Material::from_seed(c, b.try_into().unwrap()))
                        .map_err(code)?;
                    self.store.import(reference, material).map_err(code)?;
                }
                2 => out.push(proposal(
                    self.activation
                        .prepare(a, &self.store, reference, None)
                        .map_err(code)?,
                )),
                3 => self
                    .activation
                    .commit(a, &self.store, token(e.token))
                    .map_err(code)?,
                4 => self.activation.cancel(token(e.token)).map_err(code)?,
                5 => self.activation.advance(e.value).map_err(code)?,
                6 => self.activation.reconcile(a).map_err(code)?,
                7 => self.activation.pin(e.id, reference).map_err(code)?,
                8 => self.activation.unpin(e.id).map_err(code)?,
                9 => out.push(proposal(
                    self.activation.retire(a, reference).map_err(code)?,
                )),
                10 => self
                    .activation
                    .delete_retired(&mut self.store, reference)
                    .map_err(code)?,
                11 => {
                    let h = engine.as_mut().ok_or(ARG)?;
                    let Some(engine::Backend::Core(n)) = h.backend.as_mut() else {
                        return Err(ARG);
                    };
                    let actions = self.activation.sync_core(a, &self.store, n).map_err(code)?;
                    out.extend(h.core_records(actions));
                    out.push(h.timer_record());
                }
                12 => {
                    let h = engine.as_mut().ok_or(ARG)?;
                    let Some(engine::Backend::Flow(n)) = h.backend.as_mut() else {
                        return Err(ARG);
                    };
                    let p = self
                        .activation
                        .flow_plan(a, reference, &self.store, n)
                        .map_err(code)?;
                    out.push(proposal(p));
                    out.push(h.timer_record());
                }
                20 => {
                    let h = engine.as_mut().ok_or(ARG)?;
                    let Some(engine::Backend::Flow(n)) = h.backend.as_mut() else {
                        return Err(ARG);
                    };
                    let actions = self.activation.quiesce_flow(n).map_err(code)?;
                    out.extend(
                        actions
                            .into_iter()
                            .filter_map(|a| engine::flow_record(a, &mut h.timer)),
                    );
                    out.push(h.timer_record());
                }
                13 => {
                    let h = engine.as_mut().ok_or(ARG)?;
                    let Some(engine::Backend::Flow(n)) = h.backend.as_mut() else {
                        return Err(ARG);
                    };
                    self.activation
                        .sync_flow(a, &self.store, n, u128::from_le_bytes(e.incarnation))
                        .map_err(code)?;
                    h.incarnation = e.incarnation;
                    h.timer = None;
                    out.push(h.timer_record());
                }
                14 | 15 | 21 => {
                    let purpose = if e.tag == 14 {
                        Purpose::PublicRoot {
                            path: buffer(e.data, 256)?,
                            total: e.value,
                            root: e.root,
                        }
                    } else if e.tag == 21 {
                        Purpose::MesaRoot {
                            path: buffer(e.data, 320)?,
                            prefix: buffer(e.seed, 320)?,
                            root: e.root,
                        }
                    } else {
                        Purpose::Agreement {
                            peer: u128::from_le_bytes(e.peer),
                        }
                    };
                    let request = self
                        .activation
                        .operation(a, &self.store, purpose)
                        .map_err(code)?;
                    let mut r = Record::new(302);
                    r.c.id = request.ticket().id;
                    r.c.value = request.ticket().generation;
                    r.c.token.incarnation = request.ticket().incarnation.to_le_bytes();
                    r.data = Some(request.transcript().clone());
                    r.aux = Some(
                        request
                            .agreement()
                            .map(|p| p.to_vec())
                            .unwrap_or_default()
                            .into(),
                    );
                    self.requests.insert(request.ticket().id, request);
                    out.push(r);
                }
                16 | 17 => {
                    let r = self.requests.get(&e.id).ok_or(STALE)?;
                    if r.ticket() != ticket {
                        return Err(STALE);
                    }
                    let reply = if e.tag == 16 {
                        self.store.execute(r).map_err(code)?
                    } else {
                        Reply::Signature(e.signature)
                    };
                    let reply = self.activation.complete(a, ticket, reply).map_err(code)?;
                    self.requests.remove(&e.id);
                    let mut r = Record::new(303);
                    r.c.id = e.id;
                    match reply {
                        Reply::Signature(s) => r.data = Some(s.to_vec().into()),
                        Reply::Agreement(s) => r.secret = Some(s),
                    };
                    out.push(r);
                }
                18 => {
                    self.activation.cancel_operation(ticket).map_err(code)?;
                    self.requests.remove(&e.id);
                }
                #[cfg(feature = "suite-c")]
                19 => {
                    let material = mesa_identity::owned::suite_c_material(
                        buffer(e.data, MAX_BUFFER)?,
                        &self.activation.config().domain,
                        PeerId(u128::from_le_bytes(e.peer)),
                        e.life,
                        e.rift,
                        mesa_identity::suite_c::Limits::default(),
                    )
                    .map_err(code)?;
                    self.store.import(reference, material).map_err(code)?;
                }
                _ => return Err(ARG),
            }
        }
        Ok(out)
    }
}
/// # Safety
/// Pointers and serialization follow mesa_keys.h. Checkpoint may be null.
#[no_mangle]
pub unsafe extern "C" fn mesa_keys_new(
    o: *const KeysOptions,
    checkpoint: *const Buffer,
    floor: u64,
    out: *mut *mut Keys,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| unsafe {
        if out.is_null() {
            return ARG;
        }
        *out = ptr::null_mut();
        let Some(o) = o.as_ref() else { return ARG };
        if o.version != 1 {
            return ARG;
        }
        let result = (|| -> Result<Keys, i32> {
            let c = keys::Config {
                peer: u128::from_le_bytes(o.peer),
                domain: domain(&o.domain)?,
                incarnation: u128::from_le_bytes(o.incarnation),
                host_epoch: u128::from_le_bytes(o.host_epoch),
                history: o.history,
                operations: o.operations,
                timeout: o.timeout,
                checkpoint_bytes: o.checkpoint_bytes,
            };
            let descriptor = serde_json::to_vec(&Description {
                version: 1,
                activation: &c,
                max_keys: o.max_keys,
                max_objects: o.max_objects,
            })
            .map_err(|_| INVALID)?
            .into();
            let activation = if checkpoint.is_null() {
                if floor != 0 {
                    return Err(STALE);
                }
                Activation::new(c)
            } else {
                Activation::restore(c, &buffer(checkpoint, MAX_BUFFER)?, floor)
            }
            .map_err(code)?;
            Ok(Keys {
                activation,
                store: SoftwareStore::new(o.max_keys, o.max_objects).map_err(code)?,
                requests: BTreeMap::new(),
                poisoned: false,
                descriptor,
            })
        })();
        match result {
            Ok(h) => {
                *out = Box::into_raw(Box::new(h));
                0
            }
            Err(e) => e,
        }
    }))
    .unwrap_or(PANIC)
}
/// # Safety
/// Live unique handle, freed once; immutable output handles remain valid.
#[no_mangle]
pub unsafe extern "C" fn mesa_keys_free(h: *mut Keys) {
    if !h.is_null() {
        unsafe { drop(Box::from_raw(h)) }
    }
}
/// # Safety
/// Live serialized handles, writable out, and count readable events; see mesa_keys.h.
#[no_mangle]
pub unsafe extern "C" fn mesa_keys_submit(
    h: *mut Keys,
    pki: *const pki::PkiHandle,
    engine: *mut engine::Engine,
    events: *const KeyEvent,
    count: usize,
    budget: *const Budget,
    out: *mut *const Batch,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| unsafe {
        if out.is_null() {
            return ARG;
        }
        *out = ptr::null();
        let (Some(h), Some(p), Some(budget)) = (h.as_mut(), pki.as_ref(), budget.as_ref()) else {
            return ARG;
        };
        if h.poisoned {
            return PANIC;
        }
        if count > 64 || !budget.valid() {
            return ARG;
        }
        let events = match array(events, count) {
            Ok(e) => e,
            Err(e) => return e,
        };
        let mut engine = engine.as_mut();
        if engine
            .as_ref()
            .is_some_and(|e| e.poisoned || e.backend.is_none())
        {
            return CLOSED;
        }
        let (records, bytes) = engine.as_ref().map_or((2, 0), |e| e.core_envelope());
        let records = records + 4;
        let bytes = bytes + h.activation.config().checkpoint_bytes + 1024 * 1024;
        let mut b = Batch::default();
        if count > 0 && !budget.fits(&b, records + 1, bytes) {
            return CAPACITY;
        }
        if count == 0 && !budget.fits(&b, 1, 0) {
            return CAPACITY;
        }
        h.poisoned = true;
        if let Some(e) = engine.as_deref_mut() {
            e.poisoned = true;
        }
        for (i, e) in events.iter().take(budget.max_steps).enumerate() {
            if !budget.fits(&b, records + 1, bytes) {
                break;
            }
            let start = b.records.len();
            let before = b.bytes;
            let result = h.event(p.authority(), engine.as_deref_mut(), e);
            // Drop stale backend requests after timeout, cancellation or cutover.
            h.requests
                .retain(|_, r| h.activation.has_operation(r.ticket()));
            let failed = result.is_err();
            match result {
                Ok(rs) => {
                    b.push(Record::new(100));
                    for r in rs {
                        b.push(r)
                    }
                }
                Err(e) => b.push(Record::diagnostic(100, e, "key event rejected")),
            }
            for r in &mut b.records[start..] {
                r.c.event_index = i;
                r.c.cookie = e.cookie;
            }
            assert!(
                b.records.len() - start <= records && b.bytes - before <= bytes,
                "key step envelope"
            );
            b.processed += 1;
            if failed {
                break;
            }
        }
        let mut timer = Record::new(304);
        timer.c.flag = u32::from(h.activation.deadline().is_some());
        timer.c.value = h.activation.deadline().unwrap_or(0);
        b.push(timer);
        h.poisoned = false;
        if let Some(e) = engine {
            e.poisoned = false;
        }
        *out = publish(b);
        0
    }));
    match result {
        Ok(code) => code,
        Err(_) => unsafe {
            if let Some(h) = h.as_mut() {
                h.poisoned = true;
                let _ = h.activation.quiesce();
            }
            if let Some(e) = engine.as_mut() {
                e.poisoned = true;
                if let Some(g) = e.gate() {
                    let _ = g.change(false);
                }
            }
            PANIC
        },
    }
}
/// # Safety
/// Live serialized handle and writable output. view=0 immutable config, 1 owned snapshot.
#[no_mangle]
pub unsafe extern "C" fn mesa_keys_view(h: *const Keys, view: u32, out: *mut *const Buffer) -> i32 {
    catch_unwind(AssertUnwindSafe(|| unsafe {
        if out.is_null() {
            return ARG;
        }
        *out = ptr::null();
        let Some(h) = h.as_ref() else { return ARG };
        let b = match view {
            0 => h.descriptor.clone(),
            1 => {
                let s = h.activation.snapshot();
                serde_json::to_vec(&s).unwrap().into()
            }
            _ => return ARG,
        };
        *out = owned(b);
        0
    }))
    .unwrap_or(PANIC)
}
/// # Safety
/// Live batch and writable owned packet output; release it with mesa_packet_release.
#[no_mangle]
pub unsafe extern "C" fn mesa_batch_packet(
    b: *const Batch,
    i: usize,
    out: *mut *const core::credentials::FencedPacket,
) -> i32 {
    unsafe {
        if out.is_null() {
            return ARG;
        }
        *out = ptr::null();
        let Some(b) = b.as_ref() else { return ARG };
        let Some(p) = b.records.get(i).and_then(|r| r.packet.clone()) else {
            return ARG;
        };
        *out = Arc::into_raw(Arc::new(p));
        0
    }
}
/// # Safety
/// Owned immutable packet handle, with one release per retained reference.
#[no_mangle]
pub unsafe extern "C" fn mesa_packet_retain(p: *const core::credentials::FencedPacket) {
    if !p.is_null() {
        unsafe { Arc::increment_strong_count(p) }
    }
}
/// # Safety
/// Release exactly one owned packet reference.
#[no_mangle]
pub unsafe extern "C" fn mesa_packet_release(p: *const core::credentials::FencedPacket) {
    if !p.is_null() {
        unsafe { drop(Arc::from_raw(p)) }
    }
}
/// # Safety
/// Live batch and writable output. Secret is opaque; no checkpoint serialization.
#[no_mangle]
pub unsafe extern "C" fn mesa_batch_secret(
    b: *const Batch,
    i: usize,
    out: *mut *const mesa_crypto::SharedSecret,
) -> i32 {
    unsafe {
        if out.is_null() {
            return ARG;
        }
        *out = ptr::null();
        let Some(b) = b.as_ref() else { return ARG };
        let Some(s) = b.records.get(i).and_then(|r| r.secret.clone()) else {
            return ARG;
        };
        *out = Arc::into_raw(s);
        0
    }
}
/// # Safety
/// Live owned secret handle, released once per retained reference.
#[no_mangle]
pub unsafe extern "C" fn mesa_secret_retain(p: *const mesa_crypto::SharedSecret) {
    if !p.is_null() {
        unsafe { Arc::increment_strong_count(p) }
    }
}
/// # Safety
/// Release exactly one owned secret reference; final release zeroizes material.
#[no_mangle]
pub unsafe extern "C" fn mesa_secret_release(p: *const mesa_crypto::SharedSecret) {
    if !p.is_null() {
        unsafe { drop(Arc::from_raw(p)) }
    }
}
