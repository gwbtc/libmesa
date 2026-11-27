use super::*;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Resources {
    version: u32,
    max_peers: u32,
    max_reads: u32,
    max_bindings: u32,
    window: u32,
    max_object_bytes: usize,
    max_binding_bytes: usize,
    max_reassembly_bytes: usize,
    max_unverified_bytes: usize,
}
impl Resources {
    pub(super) fn config(self) -> Result<core::Config, i32> {
        if self.version != 1
            || !(1..=256).contains(&self.max_peers)
            || !(1..=1024).contains(&self.max_reads)
            || !(1..=65536).contains(&self.max_bindings)
            || !(1..=16).contains(&self.window)
            || self.max_reads * self.window > 4096
            || !(1..=1024 * 1024).contains(&self.max_object_bytes)
            || !(self.max_object_bytes..=64 * 1024 * 1024).contains(&self.max_binding_bytes)
            || !(self.max_object_bytes..=64 * 1024 * 1024).contains(&self.max_reassembly_bytes)
            || !(1024..=8 * 1024 * 1024).contains(&self.max_unverified_bytes)
        {
            return Err(ARG);
        }
        Ok(core::Config {
            max_peers: self.max_peers as usize,
            max_reads: self.max_reads as usize,
            max_bindings: self.max_bindings as usize,
            window: self.window as usize,
            max_read_bytes: self.max_object_bytes,
            max_binding_bytes: self.max_binding_bytes,
            max_reassembly_bytes: self.max_reassembly_bytes,
            max_unverified_bytes: self.max_unverified_bytes,
            ..Default::default()
        })
    }
}

/// # Safety
/// Follows mesa_embed.h pointer and ownership contracts.
#[no_mangle]
pub unsafe extern "C" fn mesa_resources_default(out: *mut Resources) -> i32 {
    if out.is_null() {
        return ARG;
    }
    // SAFETY: caller provides a writable Resources.
    unsafe {
        *out = Resources {
            version: 1,
            max_peers: 64,
            max_reads: 32,
            max_bindings: 1024,
            window: 4,
            max_object_bytes: 65536,
            max_binding_bytes: 8 * 1024 * 1024,
            max_reassembly_bytes: 8 * 1024 * 1024,
            max_unverified_bytes: 128 * 1024,
        };
    }
    0
}

/// # Safety
/// Follows mesa_embed.h pointer and ownership contracts. CORE only.
#[no_mangle]
pub unsafe extern "C" fn mesa_engine_create_configured(
    o: *const Options,
    r: *const Resources,
    keys: *const Key,
    nkeys: usize,
    out: *mut *mut Engine,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: foreign inputs follow the header contract.
        unsafe {
            if out.is_null() {
                return ARG;
            }
            *out = ptr::null_mut();
            if o.is_null() || r.is_null() || (*o).kind != 1 || nkeys > 256 {
                return ARG;
            }
            let result = (|| {
                build_inner(
                    &*o,
                    array(keys, nkeys)?,
                    &[],
                    None,
                    Some((*r).config()?),
                    None,
                )
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
/// Follows mesa_embed.h pointer and ownership contracts. CORE only.
#[no_mangle]
pub unsafe extern "C" fn mesa_engine_snapshot(h: *const Engine, out: *mut *const Buffer) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: caller serializes the handle and owns the output reference.
        unsafe {
            if out.is_null() { return ARG; }
            *out = ptr::null();
            if h.is_null() { return ARG; }
            let h = &*h;
            if h.poisoned { return PANIC; }
            let n = match &h.backend { Some(Backend::Core(n)) => n, Some(_) => return ARG, None => return CLOSED };
            let s = n.snapshot(); let u = s.usage; let c = s.counters;
            let value = serde_json::json!({
                "local":{"id":format!("{:032x}",s.local.id.0),"domain":s.local.domain().as_str(),"life":s.local.life,"rift":s.local.rift,"generation":s.local_generation,"quiescent":s.quiescent},
                "version":1,"incarnation":h.incarnation,"revision":s.revision,"now":s.now,"deadline":s.deadline,
                "usage":{"peers":u.peers,"namespace_slots":u.namespace_slots,"bindings":u.bindings,
                    "binding_bytes":u.binding_bytes,"binding_proof_bytes":u.binding_proof_bytes,
                    "reads":u.reads,"reassembly_bytes":u.reassembly_bytes,"pending_interests":u.pending_interests,
                    "received_fragments":u.received_fragments,"unverified_bytes":u.unverified_bytes,"unverified_fragments":u.unverified_fragments},
                "counters":{"events":c.events,"sent_packets":c.sent_packets,"sent_bytes":c.sent_bytes,
                    "received_packets":c.received_packets,"received_bytes":c.received_bytes,
                    "retransmissions":c.retransmissions,"dropped":c.dropped,"completed":c.completed,
                    "cancelled":c.cancelled,"timeouts":c.timeouts},
                "peers":s.peers.iter().map(|p| serde_json::json!({
                    "id":format!("{:032x}",p.peer.id.0),"domain":p.peer.domain().as_str(),"life":p.peer.life,"rift":p.peer.rift,
                    "key":p.peer.key.0,"allowed":p.peer.service_allowed,
                    "credential_generation":p.credential_generation,"attachment_generation":p.attachment_generation,
                    "attachment":p.attachment.map(|a|a.0),"window":p.transfer.window,"in_flight":p.transfer.in_flight,"queued":p.transfer.queued,
                })).collect::<Vec<_>>()
            });
            match serde_json::to_vec(&value) {
                Ok(bytes) => { *out = owned(bytes.into()); 0 }
                Err(_) => INVALID,
            }
        }
    })).unwrap_or(PANIC)
}
