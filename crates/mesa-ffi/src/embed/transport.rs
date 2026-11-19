use super::*;
mod endpoint;
use mesa_transport::{PacketIo, Received, Stream, Udp};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket},
    os::fd::{AsRawFd, BorrowedFd},
};
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Address {
    address: [u8; 16],
    ipv6: u32,
    port: u16,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Config {
    peer: [u8; 16],
    attachment: u64,
    max_packet_bytes: usize,
    queue_bytes: usize,
}
#[repr(C)]
pub struct Caps {
    max_packet_bytes: usize,
    reliable: u32,
    ordered: u32,
    framing: u32,
    fd: i32,
}
#[repr(C)]
pub struct Command {
    tag: u32,
    cookie: u64,
    packet: *const Buffer,
}
enum Lane {
    Udp(Udp),
    Tcp(Stream<TcpStream>),
}
pub struct Transport {
    lane: Lane,
    config: Config,
    fd: i32,
    closed: bool,
    poisoned: bool,
    descriptor: Buffer,
}
impl Transport {
    fn io(&mut self) -> &mut dyn PacketIo {
        match &mut self.lane {
            Lane::Udp(v) => v,
            Lane::Tcp(v) => v,
        }
    }
    fn queued(&self) -> usize {
        match &self.lane {
            Lane::Udp(_) => 0,
            Lane::Tcp(v) => v.queued_bytes(),
        }
    }
}
fn make(lane: Lane, config: Config, fd: i32) -> Transport {
    let tcp = matches!(lane, Lane::Tcp(_));
    let descriptor=serde_json::to_vec(&serde_json::json!({"abi":1,"peer":config.peer,"attachment":config.attachment,"max_packet_bytes":config.max_packet_bytes,"queue_bytes":if tcp{config.queue_bytes}else{0},"reliable":tcp,"ordered":tcp,"framing":if tcp{"length-prefix-u32-be"}else{"datagram"},"max_commands":64,"max_flush_writes":64,"max_write_frames":64})).unwrap().into();
    Transport {
        lane,
        config,
        fd,
        closed: false,
        poisoned: false,
        descriptor,
    }
}
/// # Safety
/// Callers must satisfy the pointer, ownership, and serialization contracts in
/// the corresponding include/mesa_*.h header and spec/14-c-embedding.md.
#[no_mangle]
pub unsafe extern "C" fn mesa_transport_udp(
    fd: i32,
    address: *const Address,
    c: *const Config,
    out: *mut *mut Transport,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: all foreign pointers follow the exported caller contract.
        unsafe {
            if out.is_null() {
                return ARG;
            }
            *out = ptr::null_mut();
            if address.is_null() || c.is_null() || fd < 0 {
                return ARG;
            }
            let a = &*address;
            let c = *c;
            if !(8..=1472).contains(&c.max_packet_bytes) {
                return ARG;
            }
            let ip = match a.ipv6 {
                0 => IpAddr::V4(Ipv4Addr::new(
                    a.address[0],
                    a.address[1],
                    a.address[2],
                    a.address[3],
                )),
                1 => IpAddr::V6(Ipv6Addr::from(a.address)),
                _ => return ARG,
            };
            let result = (|| -> std::io::Result<Transport> {
                let socket = UdpSocket::from(BorrowedFd::borrow_raw(fd).try_clone_to_owned()?);
                let duplicate = socket.as_raw_fd();
                let lane = Udp::new(socket, SocketAddr::new(ip, a.port), c.max_packet_bytes)?;
                Ok(make(Lane::Udp(lane), c, duplicate))
            })();
            match result {
                Ok(t) => {
                    *out = Box::into_raw(Box::new(t));
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
pub unsafe extern "C" fn mesa_transport_tcp(
    fd: i32,
    c: *const Config,
    out: *mut *mut Transport,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: all foreign pointers follow the exported caller contract.
        unsafe {
            if out.is_null() {
                return ARG;
            }
            *out = ptr::null_mut();
            if c.is_null() || fd < 0 {
                return ARG;
            }
            let c = *c;
            if !(8..=1472).contains(&c.max_packet_bytes)
                || !(c.max_packet_bytes + 4..=16 * 1024 * 1024).contains(&c.queue_bytes)
            {
                return ARG;
            }
            let result = (|| -> std::io::Result<Transport> {
                let socket = TcpStream::from(BorrowedFd::borrow_raw(fd).try_clone_to_owned()?);
                let duplicate = socket.as_raw_fd();
                let lane = Stream::tcp(socket, c.max_packet_bytes, c.queue_bytes)?;
                Ok(make(Lane::Tcp(lane), c, duplicate))
            })();
            match result {
                Ok(t) => {
                    *out = Box::into_raw(Box::new(t));
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
pub unsafe extern "C" fn mesa_transport_capabilities(t: *const Transport, out: *mut Caps) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: all foreign pointers follow the exported caller contract.
        unsafe {
            if t.is_null() || out.is_null() {
                return ARG;
            }
            if (*t).poisoned {
                return PANIC;
            }
            let tcp = matches!((*t).lane, Lane::Tcp(_));
            *out = Caps {
                max_packet_bytes: (*t).config.max_packet_bytes,
                reliable: tcp as u32,
                ordered: tcp as u32,
                framing: tcp as u32,
                fd: (*t).fd,
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
pub unsafe extern "C" fn mesa_transport_describe(
    t: *const Transport,
    out: *mut *const Buffer,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: all foreign pointers follow the exported caller contract.
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
/// Callers must satisfy the pointer, ownership, and serialization contracts in
/// the corresponding include/mesa_*.h header and spec/14-c-embedding.md.
#[no_mangle]
pub unsafe extern "C" fn mesa_transport_submit(
    t: *mut Transport,
    commands: *const Command,
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
            if t.is_null() || budget.is_null() {
                return ARG;
            }
            let t = &mut *t;
            let budget = &*budget;
            if t.poisoned {
                return PANIC;
            }
            if t.closed {
                return CLOSED;
            }
            if !budget.valid() || count > 64 {
                return ARG;
            }
            let commands = match array(commands, count) {
                Ok(c) => c,
                Err(e) => return e,
            };
            let mut batch = Batch::default();
            if !budget.fits(
                &batch,
                if count == 0 { 1 } else { 3 },
                if count == 0 {
                    0
                } else {
                    t.config.max_packet_bytes.max(256)
                },
            ) {
                return CAPACITY;
            }
            t.poisoned = true;
            for (i, c) in commands.iter().take(budget.max_steps).enumerate() {
                if !budget.fits(&batch, 3, t.config.max_packet_bytes.max(256)) {
                    break;
                }
                let start = batch.records.len();
                let mut status = Record::new(201);
                let operation = match c.tag {
                    1 => match buffer(c.packet, t.config.max_packet_bytes) {
                        Ok(b) if b.len() >= 8 => b.with_bytes(|b| t.io().send(b)).map(|ok| {
                            if !ok {
                                status.c.status = CAPACITY
                            }
                        }),
                        Ok(_) => {
                            status.c.status = ARG;
                            Ok(())
                        }
                        Err(e) => {
                            status.c.status = e;
                            Ok(())
                        }
                    },
                    2 => t.io().receive().map(|p| match p {
                        Received::Packet(b) => {
                            let mut r = Record::new(200);
                            r.c.peer = t.config.peer;
                            r.c.attachment = t.config.attachment;
                            r.data = Some(b.into());
                            batch.push(r)
                        }
                        Received::Discarded => status.c.detail = 1,
                        Received::Idle => status.c.detail = 2,
                    }),
                    3 => t.io().flush(),
                    _ => {
                        status.c.status = ARG;
                        Ok(())
                    }
                };
                if let Err(e) = operation {
                    t.closed = true;
                    status = Record::diagnostic(203, IO, e.kind());
                }
                let stop = status.c.status != 0 && status.c.status != CAPACITY;
                batch.push(status);
                for r in &mut batch.records[start..] {
                    r.c.cookie = c.cookie;
                    r.c.event_index = i;
                }
                batch.processed += 1;
                if stop {
                    break;
                }
            }
            let mut ready = Record::new(202);
            ready.c.event_index = usize::MAX;
            ready.c.flag = if t.closed {
                0
            } else {
                1 | if t.queued() > 0 { 2 } else { 0 }
            };
            ready.c.value = t.queued() as u64;
            batch.push(ready);
            t.poisoned = false;
            *out = publish(batch);
            0
        }
    }))
    .unwrap_or(PANIC)
}
/// # Safety
/// Callers must satisfy the pointer, ownership, and serialization contracts in
/// the corresponding include/mesa_*.h header and spec/14-c-embedding.md.
#[no_mangle]
pub unsafe extern "C" fn mesa_transport_release(t: *mut Transport) {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: all foreign pointers follow the exported caller contract.
        unsafe {
            if !t.is_null() {
                drop(Box::from_raw(t))
            }
        }
    }))
    .unwrap_or(())
}
