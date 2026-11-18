use super::engine::{self, Engine};
use super::*;
enum Pending {
    Decide(flow::MessageId),
    Persist(flow::CommitRequest),
    Confirm(flow::CommitToken),
}
pub struct Inbox {
    engine: Engine,
    store: mesa_store::Store,
    pending: Option<Pending>,
    failed: bool,
    descriptor: Buffer,
}
impl Inbox {
    fn capture(&mut self, records: Vec<Record>, batch: &mut Batch, index: usize, cookie: u64) {
        for mut r in records {
            match r.c.tag {
                105 => {
                    assert!(self.pending.is_none());
                    let c = r.c.commit;
                    let id = c.message.into();
                    let change = match c.change {
                        1 => flow::Change::Enqueue { id },
                        2 => flow::Change::Deliver {
                            id,
                            bytes: r.payload.take().unwrap(),
                            outcome: outcome(c.outcome).unwrap(),
                        },
                        3 => flow::Change::Settle {
                            id,
                            outcome: outcome(c.outcome).unwrap(),
                        },
                        4 => flow::Change::RetireReceived { id },
                        5 => flow::Change::RetireSent { id },
                        _ => unreachable!(),
                    };
                    self.pending = Some(Pending::Persist(flow::CommitRequest {
                        token: flow::CommitToken {
                            incarnation: u128::from_le_bytes(c.token.incarnation),
                            revision: c.token.revision,
                        },
                        base_revision: c.base_revision,
                        checkpoint: serde_json::from_slice(&r.checkpoint.unwrap().to_vec())
                            .unwrap(),
                        change,
                    }));
                }
                106 => {
                    assert!(self.pending.is_none());
                    self.pending = Some(Pending::Decide(r.c.message.into()));
                }
                _ => {
                    if r.c.tag == 108 {
                        r.c.tag = 115
                    }
                    r.c.event_index = index;
                    r.c.cookie = cookie;
                    batch.push(r)
                }
            }
        }
    }
    #[allow(clippy::result_large_err)]
    fn internal(&mut self) -> Result<Vec<Record>, Record> {
        let actions = match self.pending.take().expect("pending step") {
            Pending::Decide(id) => self.engine.flow_step(flow::Event::Decide {
                id,
                outcome: flow::Outcome::Accepted,
            }),
            Pending::Confirm(token) => self.engine.flow_step(flow::Event::Committed(token)),
            Pending::Persist(request) => match self.store.commit(&request) {
                Ok(token) => {
                    self.pending = Some(Pending::Confirm(token));
                    return Ok(Vec::new());
                }
                Err(e) => {
                    self.failed = true;
                    return Err(Record::diagnostic(116, IO, e));
                }
            },
        }
        .map_err(|e| {
            self.failed = true;
            Record::diagnostic(116, e, "internal engine failure; reopen store")
        })?;
        Ok(actions
            .into_iter()
            .filter_map(|a| engine::flow_record(a, &mut self.engine.timer))
            .collect())
    }
}
#[allow(clippy::too_many_arguments)]
unsafe fn open(
    o: *const Options,
    keys: *const Key,
    nkeys: usize,
    flows: *const Flow,
    nflows: usize,
    path: *const Buffer,
    out: *mut *mut Inbox,
    create: bool,
) -> i32 {
    // SAFETY: exported wrapper forwards aligned, live input and output pointers.
    unsafe {
        if out.is_null() {
            return ARG;
        }
        *out = ptr::null_mut();
        if o.is_null() || nkeys > 16 || nflows > 4 {
            return ARG;
        }
        let result = (|| -> Result<Inbox, i32> {
            let mut o = *o;
            if o.kind != 2 {
                return Err(ARG);
            }
            o.incarnation = 1u128.to_le_bytes();
            let keys = array(keys, nkeys)?;
            let flows = array(flows, nflows)?;
            // Validate full configuration before creating or claiming a store.
            let provisional = engine::build(&o, keys, flows, None)?;
            let empty: flow::Checkpoint =
                serde_json::from_slice(&provisional.checkpoint()?.to_vec()).map_err(|_| INVALID)?;
            let bytes = buffer(path, 4096)?.to_vec();
            let path = std::str::from_utf8(&bytes).map_err(|_| ARG)?;
            if path.is_empty() || path.contains('\0') {
                return Err(ARG);
            }
            let store = if create {
                mesa_store::Store::create(path, &empty, Default::default())
            } else {
                mesa_store::Store::open(path, &empty, Default::default())
            }
            .map_err(|_| IO)?;
            let checkpoint = store.checkpoint().map_err(|_| IO)?;
            o.incarnation = store.incarnation().to_le_bytes();
            let engine = engine::build(&o, keys, flows, Some(checkpoint))?;
            let mut desc: serde_json::Value =
                serde_json::from_slice(&engine.descriptor.to_vec()).unwrap();
            desc["service"] = serde_json::json!({"kind":"sqlite-inbox","acceptance":"durable inbox insertion","max_scan":64,"max_consumption_batch":16,"retains_consumed_history":true,"store_limits":{"checkpoint_bytes":8388608,"message_bytes":65536,"delivery_records":16384,"delivery_bytes":67108864}});
            let descriptor = serde_json::to_vec(&desc).unwrap().into();
            Ok(Inbox {
                engine,
                store,
                pending: None,
                failed: false,
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
    }
}
/// # Safety
/// Callers must satisfy the pointer, ownership, and serialization contracts in
/// the corresponding include/mesa_*.h header and spec/14-c-embedding.md.
#[no_mangle]
pub unsafe extern "C" fn mesa_inbox_create(
    o: *const Options,
    keys: *const Key,
    nkeys: usize,
    flows: *const Flow,
    nflows: usize,
    path: *const Buffer,
    out: *mut *mut Inbox,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: all foreign pointers follow the exported caller contract.
        unsafe { open(o, keys, nkeys, flows, nflows, path, out, true) }
    }))
    .unwrap_or(PANIC)
}
/// # Safety
/// Callers must satisfy the pointer, ownership, and serialization contracts in
/// the corresponding include/mesa_*.h header and spec/14-c-embedding.md.
#[no_mangle]
pub unsafe extern "C" fn mesa_inbox_open(
    o: *const Options,
    keys: *const Key,
    nkeys: usize,
    flows: *const Flow,
    nflows: usize,
    path: *const Buffer,
    out: *mut *mut Inbox,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: all foreign pointers follow the exported caller contract.
        unsafe { open(o, keys, nkeys, flows, nflows, path, out, false) }
    }))
    .unwrap_or(PANIC)
}
/// # Safety
/// Callers must satisfy the pointer, ownership, and serialization contracts in
/// the corresponding include/mesa_*.h header and spec/14-c-embedding.md.
#[no_mangle]
pub unsafe extern "C" fn mesa_inbox_describe(h: *const Inbox, out: *mut *const Buffer) -> i32 {
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
pub unsafe extern "C" fn mesa_inbox_checkpoint(h: *mut Inbox, out: *mut *const Buffer) -> i32 {
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
            if (*h).engine.poisoned {
                return PANIC;
            }
            match (*h)
                .store
                .checkpoint()
                .and_then(|cp| serde_json::to_vec(&cp).map_err(Into::into))
            {
                Ok(b) => {
                    *out = owned(b.into());
                    0
                }
                Err(_) => IO,
            }
        }
    }))
    .unwrap_or(PANIC)
}
/// # Safety
/// Callers must satisfy the pointer, ownership, and serialization contracts in
/// the corresponding include/mesa_*.h header and spec/14-c-embedding.md.
#[no_mangle]
pub unsafe extern "C" fn mesa_inbox_submit(
    h: *mut Inbox,
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
            if h.is_null() || budget.is_null() {
                return ARG;
            }
            let h = &mut *h;
            let budget = &*budget;
            if h.engine.poisoned {
                return PANIC;
            }
            if h.failed || h.engine.backend.is_none() {
                return CLOSED;
            }
            if !budget.valid() || count > h.engine.max_events {
                return ARG;
            }
            let events = match array(events, count) {
                Ok(e) => e,
                Err(e) => return e,
            };
            let mut b = Batch::default();
            let has_work = count != 0 || h.pending.is_some();
            if !budget.fits(
                &b,
                if has_work { STEP_RECORDS + 2 } else { 2 },
                if has_work { STEP_BYTES } else { 0 },
            ) {
                return CAPACITY;
            }
            h.engine.poisoned = true;
            for _ in 0..budget.max_steps {
                if !budget.fits(&b, STEP_RECORDS + 2, STEP_BYTES) {
                    break;
                }
                let start = b.records.len();
                let before = b.bytes;
                let stop = if h.pending.is_some() {
                    match h.internal() {
                        Ok(rs) => {
                            h.capture(rs, &mut b, usize::MAX, 0);
                            false
                        }
                        Err(r) => {
                            b.push(r);
                            true
                        }
                    }
                } else if let Some(e) = events.get(b.processed) {
                    let index = b.processed;
                    b.processed += 1;
                    if !matches!(e.tag, 1 | 3 | 4 | 10 | 11 | 12 | 15 | 16 | 17) {
                        let mut r =
                            Record::diagnostic(100, ARG, "event belongs to raw engine interface");
                        r.c.cookie = e.cookie;
                        r.c.event_index = index;
                        b.push(r);
                        true
                    } else {
                        match h.engine.event(e) {
                            Ok(rs) => {
                                let mut r = Record::new(100);
                                r.c.cookie = e.cookie;
                                r.c.event_index = index;
                                b.push(r);
                                h.capture(rs, &mut b, index, e.cookie);
                                false
                            }
                            Err(mut r) => {
                                r.c.cookie = e.cookie;
                                r.c.event_index = index;
                                b.push(r);
                                true
                            }
                        }
                    }
                } else {
                    break;
                };
                assert!(
                    b.records.len() - start <= STEP_RECORDS && b.bytes - before <= STEP_BYTES,
                    "service step envelope"
                );
                if stop || h.engine.backend.is_none() {
                    break;
                }
            }
            if h.pending.is_some() {
                b.push(Record::new(114))
            }
            b.push(h.engine.timer_record());
            h.engine.poisoned = false;
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
pub unsafe extern "C" fn mesa_inbox_scan(
    h: *mut Inbox,
    after: u64,
    limit: usize,
    out: *mut *const Batch,
) -> i32 {
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
            if (*h).engine.poisoned {
                return PANIC;
            }
            match (*h).store.scan_inbox(after, limit) {
                Ok(rows) => {
                    let mut b = Batch::default();
                    for d in rows {
                        let mut r = Record::new(117);
                        r.c.message = (&d.id).into();
                        r.c.value = d.revision;
                        r.c.outcome = -1;
                        r.data = Some(d.bytes.into());
                        b.push(r)
                    }
                    *out = publish(b);
                    0
                }
                Err(_) => IO,
            }
        }
    }))
    .unwrap_or(PANIC)
}
/// # Safety
/// Callers must satisfy the pointer, ownership, and serialization contracts in
/// the corresponding include/mesa_*.h header and spec/14-c-embedding.md.
#[no_mangle]
pub unsafe extern "C" fn mesa_inbox_mark_consumed(
    h: *mut Inbox,
    ids: *const Message,
    count: usize,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: all foreign pointers follow the exported caller contract.
        unsafe {
            if h.is_null() || count > 16 {
                return ARG;
            }
            if (*h).engine.poisoned {
                return PANIC;
            }
            if (*h).failed || (*h).engine.backend.is_none() {
                return CLOSED;
            }
            let ids = match array(ids, count) {
                Ok(v) => v.iter().copied().map(Into::into).collect::<Vec<_>>(),
                Err(e) => return e,
            };
            (*h).store.mark_consumed(&ids).map_or(IO, |_| 0)
        }
    }))
    .unwrap_or(PANIC)
}
/// # Safety
/// Callers must satisfy the pointer, ownership, and serialization contracts in
/// the corresponding include/mesa_*.h header and spec/14-c-embedding.md.
#[no_mangle]
pub unsafe extern "C" fn mesa_inbox_release(h: *mut Inbox) {
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

#[repr(C)]
pub struct Progress {
    revision: u64,
    next_sequence: u64,
    send_floor: u64,
    receive_floor: u64,
    pending_messages: usize,
}
/// # Safety
/// Pointers follow mesa_inbox.h; the handle has one serialized caller.
#[no_mangle]
pub unsafe extern "C" fn mesa_inbox_flow_progress(
    h: *mut Inbox,
    id: u64,
    out: *mut Progress,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: aligned live handle and writable output supplied by caller.
        unsafe {
            if h.is_null() || out.is_null() {
                return ARG;
            }
            if (*h).engine.poisoned {
                return PANIC;
            }
            match (*h).store.checkpoint() {
                Ok(cp) => match cp.flow(id) {
                    Some(f) => {
                        *out = Progress {
                            revision: cp.revision,
                            next_sequence: f.next_send,
                            send_floor: f.send_floor,
                            receive_floor: f.receive_floor,
                            pending_messages: f.outbox.len(),
                        };
                        0
                    }
                    None => ARG,
                },
                Err(_) => IO,
            }
        }
    }))
    .unwrap_or(PANIC)
}
/// # Safety
/// Pointers follow mesa_inbox.h; returned batch owns its records.
#[no_mangle]
pub unsafe extern "C" fn mesa_inbox_outcomes(
    h: *mut Inbox,
    after: u64,
    limit: usize,
    out: *mut *const Batch,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: aligned live handle and writable output supplied by caller.
        unsafe {
            if out.is_null() {
                return ARG;
            }
            *out = ptr::null();
            if h.is_null() || !(1..=64).contains(&limit) {
                return ARG;
            }
            if (*h).engine.poisoned {
                return PANIC;
            }
            match (*h).store.scan_settlements(after, limit) {
                Ok(rows) => {
                    let mut b = Batch::default();
                    for row in rows {
                        let mut r = Record::new(109);
                        r.c.message = (&row.id).into();
                        r.c.outcome = outcome_code(row.outcome);
                        r.c.value = row.revision;
                        b.push(r);
                    }
                    *out = publish(b);
                    0
                }
                Err(_) => IO,
            }
        }
    }))
    .unwrap_or(PANIC)
}
