use super::*;
use mesa_transport::{Datagram, EndpointError, UdpEndpoint};
#[repr(C)]
pub struct EndpointOptions {
    version: u32,
    max_routes: u32,
    max_packet_bytes: usize,
}
#[repr(C)]
pub struct EndpointCommand {
    tag: u32,
    flag: u32,
    cookie: u64,
    expected_generation: u64,
    generation: u64,
    peer: [u8; 16],
    address: Address,
    packet: *const Buffer,
}
pub struct Endpoint {
    io: UdpEndpoint,
    fd: i32,
    max_packet: usize,
    descriptor: Buffer,
    poisoned: bool,
}
fn address(a: &Address) -> Result<SocketAddr, i32> {
    let ip = match a.ipv6 {
        0 => IpAddr::V4(Ipv4Addr::new(
            a.address[0],
            a.address[1],
            a.address[2],
            a.address[3],
        )),
        1 => IpAddr::V6(Ipv6Addr::from(a.address)),
        _ => return Err(ARG),
    };
    Ok(SocketAddr::new(ip, a.port))
}
fn error(e: EndpointError) -> i32 {
    match e {
        EndpointError::InvalidRoute => ARG,
        EndpointError::StaleGeneration => STALE,
        EndpointError::Capacity => CAPACITY,
        EndpointError::Io(_) => IO,
    }
}

/// # Safety
/// Follows mesa_transport.h. The descriptor must be an exclusively received UDP socket.
#[no_mangle]
pub unsafe extern "C" fn mesa_udp_endpoint_new(
    fd: i32,
    config: *const EndpointOptions,
    out: *mut *mut Endpoint,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: pointers and fd follow the public caller contract.
        unsafe {
            if out.is_null() { return ARG; }
            *out = ptr::null_mut();
            if config.is_null() || fd < 0 { return ARG; }
            let c = &*config;
            if c.version != 1 || !(1..=256).contains(&c.max_routes) || !(8..=1472).contains(&c.max_packet_bytes) { return ARG; }
            let result = (|| -> std::io::Result<Endpoint> {
                let socket = UdpSocket::from(BorrowedFd::borrow_raw(fd).try_clone_to_owned()?);
                let fd = socket.as_raw_fd();
                let io = UdpEndpoint::new(socket, c.max_packet_bytes, c.max_routes as usize)?;
                let descriptor = serde_json::to_vec(&serde_json::json!({"version":1,
                    "max_routes":c.max_routes,"max_packet_bytes":c.max_packet_bytes,
                    "reliable":false,"ordered":false,"framing":"datagram",
                    "max_commands":64,"receive_owner":"exclusive","route_generations":"strictly increasing"}))?.into();
                Ok(Endpoint {io,fd,max_packet:c.max_packet_bytes,descriptor,poisoned:false})
            })();
            match result { Ok(t) => {*out=Box::into_raw(Box::new(t));0}, Err(_) => IO }
        }
    })).unwrap_or(PANIC)
}
/// # Safety
/// Follows mesa_transport.h ownership and serialization contracts.
#[no_mangle]
pub unsafe extern "C" fn mesa_udp_endpoint_capabilities(t: *const Endpoint, out: *mut Caps) -> i32 {
    // SAFETY: the caller supplies a live serialized handle and writable output.
    unsafe {
        if t.is_null() || out.is_null() {
            return ARG;
        }
        if (*t).poisoned {
            return PANIC;
        }
        *out = Caps {
            max_packet_bytes: (*t).max_packet,
            reliable: 0,
            ordered: 0,
            framing: 0,
            fd: (*t).fd,
        };
    }
    0
}
/// # Safety
/// Follows mesa_transport.h ownership and serialization contracts.
#[no_mangle]
pub unsafe extern "C" fn mesa_udp_endpoint_describe(
    t: *const Endpoint,
    out: *mut *const Buffer,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: output owns a reference independent of endpoint lifetime.
        unsafe {
            if out.is_null() {
                return ARG;
            }
            *out = ptr::null();
            if t.is_null() {
                return ARG;
            }
            *out = owned((*t).descriptor.clone());
            0
        }
    }))
    .unwrap_or(PANIC)
}
/// # Safety
/// Follows mesa_transport.h ownership and serialization contracts.
#[no_mangle]
pub unsafe extern "C" fn mesa_udp_endpoint_snapshot(
    t: *const Endpoint,
    out: *mut *const Buffer,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: serialized handle; owned output.
        unsafe {
            if out.is_null() { return ARG; } *out = ptr::null();
            if t.is_null() { return ARG; } let t = &*t;
            if t.poisoned { return PANIC; }
            let c=t.io.counters();
            let value=serde_json::json!({"version":1,"send_calls":c.send_calls,"receive_calls":c.receive_calls,
                "sent_bytes":c.sent_bytes,"received_bytes":c.received_bytes,"discarded":c.discarded,"pressured":c.pressured,
                "routes":t.io.routes().iter().map(|r|serde_json::json!({"peer":format!("{:032x}",r.peer.0),
                    "generation":r.generation,"next_hop":r.next_hop.map(|a|a.to_string())})).collect::<Vec<_>>()});
            match serde_json::to_vec(&value) { Ok(b)=>{*out=owned(b.into());0},Err(_)=>INVALID }
        }
    })).unwrap_or(PANIC)
}
/// # Safety
/// Follows mesa_transport.h pointer, budget and serialization contracts.
#[no_mangle]
pub unsafe extern "C" fn mesa_udp_endpoint_submit(
    t: *mut Endpoint,
    commands: *const EndpointCommand,
    count: usize,
    budget: *const Budget,
    out: *mut *const Batch,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: all input buffers stay live for this call; results retain them.
        unsafe {
            if out.is_null() {
                return ARG;
            }
            *out = ptr::null();
            if t.is_null() || budget.is_null() {
                return ARG;
            }
            let t = &mut *t;
            let budget = &*budget;
            if t.poisoned {
                return PANIC;
            }
            if count > 64 || !budget.valid() {
                return ARG;
            }
            let commands = match array(commands, count) {
                Ok(c) => c,
                Err(e) => return e,
            };
            let mut b = Batch::default();
            if !budget.fits(
                &b,
                if count == 0 { 1 } else { 3 },
                if count == 0 { 0 } else { t.max_packet },
            ) {
                return CAPACITY;
            }
            t.poisoned = true;
            for (i, c) in commands.iter().take(budget.max_steps).enumerate() {
                if !budget.fits(&b, 3, t.max_packet) {
                    break;
                }
                let start = b.records.len();
                let peer = PeerId(u128::from_le_bytes(c.peer));
                let mut status = Record::new(201);
                status.c.peer = c.peer;
                status.c.attachment = c.generation;
                status.c.status = match c.tag {
                    1 => {
                        let next = match c.flag {
                            0 => Ok(None),
                            1 => address(&c.address).map(Some),
                            _ => Err(ARG),
                        };
                        next.and_then(|a| {
                            t.io.set_route(peer, c.expected_generation, c.generation, a)
                                .map_err(error)
                        })
                        .err()
                        .unwrap_or(0)
                    }
                    2 => buffer(c.packet, t.max_packet)
                        .and_then(|v| {
                            v.with_bytes(|bytes| {
                                t.io.send(peer, Attachment(c.generation), bytes)
                                    .map_err(error)
                            })
                        })
                        .map(|ok| if ok { 0 } else { CAPACITY })
                        .unwrap_or_else(|e| e),
                    3 => match t.io.receive() {
                        Ok(Datagram::Packet {
                            peer,
                            attachment,
                            bytes,
                        }) => {
                            let mut r = Record::new(200);
                            r.c.peer = peer.0.to_le_bytes();
                            r.c.attachment = attachment.0;
                            r.data = Some(bytes.into());
                            b.push(r);
                            0
                        }
                        Ok(Datagram::Discarded) => {
                            status.c.detail = 1;
                            0
                        }
                        Ok(Datagram::Idle) => {
                            status.c.detail = 2;
                            0
                        }
                        Err(e) => error(e),
                    },
                    _ => ARG,
                };
                let stop = (status.c.status != 0 && status.c.status != CAPACITY)
                    || (c.tag == 3 && status.c.detail == 2);
                b.push(status);
                for r in &mut b.records[start..] {
                    r.c.cookie = c.cookie;
                    r.c.event_index = i;
                }
                b.processed += 1;
                if stop {
                    break;
                }
            }
            let mut ready = Record::new(202);
            ready.c.event_index = usize::MAX;
            ready.c.flag = 1;
            b.push(ready);
            t.poisoned = false;
            *out = publish(b);
            0
        }
    }))
    .unwrap_or(PANIC)
}
/// # Safety
/// Release exactly once after all other access to the handle has ended.
#[no_mangle]
pub unsafe extern "C" fn mesa_udp_endpoint_release(t: *mut Endpoint) {
    // SAFETY: endpoint pointer was returned by new and has not been released.
    unsafe {
        if !t.is_null() {
            drop(Box::from_raw(t));
        }
    }
}
