//! C embedding contracts live in include/mesa_embed.h and spec/14-c-embedding.md.
//! Raw pointers never escape this ABI except as opaque owned handles or views.
use mesa_bytes::Buffer;
use mesa_core::{
    self as core, policy::*, protection::SignedPublic, Attachment, KeyHandle, PeerId,
    PreconfiguredPeer,
};
use mesa_flow as flow;
use std::{
    collections::{BTreeMap, BTreeSet},
    panic::{catch_unwind, AssertUnwindSafe},
    ptr, slice,
    sync::Arc,
};
mod engine;
mod inbox;
mod pki;
#[cfg(unix)]
mod transport;
const ARG: i32 = 1;
const INVALID: i32 = 2;
const CAPACITY: i32 = 3;
const PANIC: i32 = 4;
const LIMIT: i32 = 5;
const CLOSED: i32 = 6;
const STALE: i32 = 7;
const EVENT_ERROR: i32 = 8;
const IO: i32 = 9;
const MAX_BUFFER: usize = 8 * 1024 * 1024;
const STEP_RECORDS: usize = 1024;
const STEP_BYTES: usize = 4 * 1024 * 1024;
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Peer {
    id: [u8; 16],
    domain: [u8; 64],
    life: u32,
    rift: u32,
    key: u64,
    allowed: u32,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Key {
    handle: u64,
    public_key: [u8; 32],
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Flow {
    flow: u64,
    peer: Peer,
    attachment: u64,
    attached: u32,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Options {
    abi_version: u32,
    kind: u32,
    local: Peer,
    seed: [u8; 32],
    incarnation: [u8; 16],
    retry_initial: u64,
    retry_maximum: u64,
    read_timeout: u64,
    max_attempts: u32,
    retry_mode: u32,
    congestion_mode: u32,
    peer_window_initial: u32,
    peer_window_maximum: u32,
    max_batch_events: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Message {
    sender: [u8; 16],
    receiver: [u8; 16],
    sender_rift: u32,
    receiver_rift: u32,
    flow: u64,
    sequence: u64,
}
impl From<&flow::MessageId> for Message {
    fn from(m: &flow::MessageId) -> Self {
        Self {
            sender: m.sender.to_le_bytes(),
            receiver: m.receiver.to_le_bytes(),
            sender_rift: m.sender_rift,
            receiver_rift: m.receiver_rift,
            flow: m.flow,
            sequence: m.sequence,
        }
    }
}
impl From<Message> for flow::MessageId {
    fn from(m: Message) -> Self {
        Self {
            sender: u128::from_le_bytes(m.sender),
            receiver: u128::from_le_bytes(m.receiver),
            sender_rift: m.sender_rift,
            receiver_rift: m.receiver_rift,
            flow: m.flow,
            sequence: m.sequence,
        }
    }
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Token {
    incarnation: [u8; 16],
    revision: u64,
}
impl From<flow::CommitToken> for Token {
    fn from(t: flow::CommitToken) -> Self {
        Self {
            incarnation: t.incarnation.to_le_bytes(),
            revision: t.revision,
        }
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Event {
    tag: u32,
    flag: u32,
    cookie: u64,
    id: u64,
    sequence: u64,
    value: u64,
    peer: Peer,
    data: *const Buffer,
    aux: *const Buffer,
    message: Message,
    token: Token,
    outcome: i32,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Proposal {
    token: Token,
    base_revision: u64,
    revision: u64,
    change: u32,
    message: Message,
    outcome: i32,
    checkpoint: *const Buffer,
    payload: *const Buffer,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ResultRecord {
    tag: u32,
    flag: u32,
    status: i32,
    detail: u32,
    event_index: usize,
    cookie: u64,
    id: u64,
    sequence: u64,
    attachment: u64,
    value: u64,
    peer: [u8; 16],
    data: *const Buffer,
    aux: *const Buffer,
    message: Message,
    token: Token,
    outcome: i32,
    commit: Proposal,
}
#[derive(Default)]
struct Record {
    c: ResultRecord,
    data: Option<Buffer>,
    aux: Option<Buffer>,
    checkpoint: Option<Buffer>,
    payload: Option<Buffer>,
}
// SAFETY: Record metadata contains only null buffer pointers. Owned Rust
// buffers live in its Option<Buffer> fields. batch_get fills a separate C copy.
unsafe impl Send for Record {}
// SAFETY: completed records are immutable and all owned buffers are Sync.
unsafe impl Sync for Record {}
impl Record {
    fn new(tag: u32) -> Self {
        Self {
            c: ResultRecord {
                tag,
                ..Default::default()
            },
            ..Default::default()
        }
    }
    fn bytes(&self) -> usize {
        [&self.data, &self.aux, &self.checkpoint, &self.payload]
            .into_iter()
            .flatten()
            .map(Buffer::len)
            .sum()
    }
    fn diagnostic(tag: u32, status: i32, text: impl std::fmt::Debug) -> Self {
        let mut r = Self::new(tag);
        r.c.status = status;
        r.data = Some(format!("{text:?}").into_bytes().into());
        r
    }
}
#[derive(Default)]
pub struct Batch {
    processed: usize,
    records: Vec<Record>,
    bytes: usize,
}
impl Batch {
    fn push(&mut self, r: Record) {
        self.bytes += r.bytes();
        self.records.push(r);
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Budget {
    max_results: usize,
    max_result_bytes: usize,
    max_steps: usize,
}
impl Budget {
    fn valid(&self) -> bool {
        self.max_results <= 16385
            && self.max_result_bytes <= 64 * 1024 * 1024
            && (1..=64).contains(&self.max_steps)
    }
    fn fits(&self, b: &Batch, records: usize, bytes: usize) -> bool {
        b.records.len() + records <= self.max_results && b.bytes + bytes <= self.max_result_bytes
    }
}
fn publish(b: Batch) -> *const Batch {
    Arc::into_raw(Arc::new(b))
}
fn owned(b: Buffer) -> *const Buffer {
    Arc::into_raw(Arc::new(b))
}
fn outcome(n: i32) -> Result<flow::Outcome, i32> {
    match n {
        -1 => Ok(flow::Outcome::Accepted),
        0..=65535 => Ok(flow::Outcome::Rejected(n as u16)),
        _ => Err(ARG),
    }
}
fn outcome_code(o: flow::Outcome) -> i32 {
    match o {
        flow::Outcome::Accepted => -1,
        flow::Outcome::Rejected(n) => n as i32,
    }
}
unsafe fn array<'a, T>(p: *const T, n: usize) -> Result<&'a [T], i32> {
    if n == 0 {
        return Ok(&[]);
    }
    if p.is_null() {
        return Err(ARG);
    }
    // SAFETY: readable aligned region of n elements supplied by caller.
    Ok(unsafe { slice::from_raw_parts(p, n) })
}
unsafe fn buffer(p: *const Buffer, max: usize) -> Result<Buffer, i32> {
    // SAFETY: non-null p must be an owned live buffer handle.
    let b = unsafe { p.as_ref() }.ok_or(ARG)?;
    if b.len() > max {
        return Err(LIMIT);
    }
    Ok(b.clone())
}
/// # Safety
/// Callers must satisfy the pointer, ownership, and serialization contracts in
/// the corresponding include/mesa_*.h header and spec/14-c-embedding.md.
#[no_mangle]
pub unsafe extern "C" fn mesa_buffer_new(
    dat: *const u8,
    dat_len: usize,
    wid: usize,
    out: *mut *const Buffer,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: all foreign pointers follow the exported caller contract.
        unsafe {
            if out.is_null() {
                return ARG;
            }
            *out = ptr::null();
            if dat_len > wid || wid > MAX_BUFFER {
                return LIMIT;
            }
            match array(dat, dat_len).and_then(|d| Buffer::new(d.to_vec(), wid).map_err(|_| ARG)) {
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
pub unsafe extern "C" fn mesa_buffer_retain(b: *const Buffer) -> *const Buffer {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: all foreign pointers follow the exported caller contract.
        unsafe {
            if !b.is_null() {
                Arc::increment_strong_count(b)
            }
            b
        }
    }))
    .unwrap_or(ptr::null())
}
/// # Safety
/// Callers must satisfy the pointer, ownership, and serialization contracts in
/// the corresponding include/mesa_*.h header and spec/14-c-embedding.md.
#[no_mangle]
pub unsafe extern "C" fn mesa_buffer_release(b: *const Buffer) {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: all foreign pointers follow the exported caller contract.
        unsafe {
            if !b.is_null() {
                Arc::decrement_strong_count(b)
            }
        }
    }))
    .unwrap_or(())
}
/// # Safety
/// Callers must satisfy the pointer, ownership, and serialization contracts in
/// the corresponding include/mesa_*.h header and spec/14-c-embedding.md.
#[no_mangle]
pub unsafe extern "C" fn mesa_buffer_dat(
    b: *const Buffer,
    dat: *mut *const u8,
    len: *mut usize,
    wid: *mut usize,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: all foreign pointers follow the exported caller contract.
        unsafe {
            if b.is_null() || dat.is_null() || len.is_null() || wid.is_null() {
                return ARG;
            }
            *dat = (*b).dat().as_ptr();
            *len = (*b).dat().len();
            *wid = (*b).len();
            0
        }
    }))
    .unwrap_or(PANIC)
}
/// # Safety
/// Callers must satisfy the pointer, ownership, and serialization contracts in
/// the corresponding include/mesa_*.h header and spec/14-c-embedding.md.
#[no_mangle]
pub unsafe extern "C" fn mesa_buffer_copy(
    b: *const Buffer,
    offset: usize,
    out: *mut u8,
    len: usize,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: all foreign pointers follow the exported caller contract.
        unsafe {
            if b.is_null() || (out.is_null() && len != 0) {
                return ARG;
            }
            if offset.checked_add(len).is_none_or(|n| n > (*b).len()) {
                return ARG;
            }
            if len == 0 {
                return 0;
            }
            (*b).copy_range(offset, slice::from_raw_parts_mut(out, len))
                .map_or(ARG, |_| 0)
        }
    }))
    .unwrap_or(PANIC)
}
/// # Safety
/// Callers must satisfy the pointer, ownership, and serialization contracts in
/// the corresponding include/mesa_*.h header and spec/14-c-embedding.md.
#[no_mangle]
pub unsafe extern "C" fn mesa_batch_retain(b: *const Batch) -> *const Batch {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: all foreign pointers follow the exported caller contract.
        unsafe {
            if !b.is_null() {
                Arc::increment_strong_count(b)
            }
            b
        }
    }))
    .unwrap_or(ptr::null())
}
/// # Safety
/// Callers must satisfy the pointer, ownership, and serialization contracts in
/// the corresponding include/mesa_*.h header and spec/14-c-embedding.md.
#[no_mangle]
pub unsafe extern "C" fn mesa_batch_release(b: *const Batch) {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: all foreign pointers follow the exported caller contract.
        unsafe {
            if !b.is_null() {
                Arc::decrement_strong_count(b)
            }
        }
    }))
    .unwrap_or(())
}
/// # Safety
/// Callers must satisfy the pointer, ownership, and serialization contracts in
/// the corresponding include/mesa_*.h header and spec/14-c-embedding.md.
#[no_mangle]
pub unsafe extern "C" fn mesa_batch_info(
    b: *const Batch,
    processed: *mut usize,
    results: *mut usize,
    bytes: *mut usize,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: all foreign pointers follow the exported caller contract.
        unsafe {
            if b.is_null() || processed.is_null() || results.is_null() || bytes.is_null() {
                return ARG;
            }
            *processed = (*b).processed;
            *results = (*b).records.len();
            *bytes = (*b).bytes;
            0
        }
    }))
    .unwrap_or(PANIC)
}
/// # Safety
/// Callers must satisfy the pointer, ownership, and serialization contracts in
/// the corresponding include/mesa_*.h header and spec/14-c-embedding.md.
#[no_mangle]
pub unsafe extern "C" fn mesa_batch_get(
    b: *const Batch,
    index: usize,
    out: *mut ResultRecord,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: all foreign pointers follow the exported caller contract.
        unsafe {
            if out.is_null() {
                return ARG;
            }
            *out = ResultRecord::default();
            if b.is_null() {
                return ARG;
            }
            let records = &(*b).records;
            let Some(r) = records.get(index) else {
                return ARG;
            };
            *out = r.c;
            (*out).data = r.data.clone().map_or(ptr::null(), owned);
            (*out).aux = r.aux.clone().map_or(ptr::null(), owned);
            (*out).commit.checkpoint = r.checkpoint.clone().map_or(ptr::null(), owned);
            (*out).commit.payload = r.payload.clone().map_or(ptr::null(), owned);
            0
        }
    }))
    .unwrap_or(PANIC)
}
/// # Safety
/// Callers must satisfy the pointer, ownership, and serialization contracts in
/// the corresponding include/mesa_*.h header and spec/14-c-embedding.md.
#[no_mangle]
pub unsafe extern "C" fn mesa_result_release(r: *mut ResultRecord) {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: all foreign pointers follow the exported caller contract.
        unsafe {
            if let Some(r) = r.as_mut() {
                for p in [r.data, r.aux, r.commit.checkpoint, r.commit.payload] {
                    if !p.is_null() {
                        Arc::decrement_strong_count(p)
                    }
                }
                *r = ResultRecord::default();
            }
        }
    }))
    .unwrap_or(())
}
