//! One UDP socket, one bounded route table, one receive owner.
use mesa_core::{Attachment, PeerId};
use std::{
    collections::BTreeMap,
    io,
    net::{SocketAddr, UdpSocket},
};

#[derive(Debug)]
pub enum EndpointError {
    InvalidRoute,
    StaleGeneration,
    Capacity,
    Io(io::Error),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Route {
    pub peer: PeerId,
    pub generation: u64,
    /// None retains a generation fence without an active route.
    pub next_hop: Option<SocketAddr>,
}
#[derive(Debug, PartialEq, Eq)]
pub enum Datagram {
    Packet {
        peer: PeerId,
        attachment: Attachment,
        bytes: Vec<u8>,
    },
    Discarded,
    Idle,
}
/// Transport input for an admission adapter. Unknown sources have no peer
/// authority. Existing `receive` continues to discard unknown sources.
#[derive(Debug)]
pub enum Unrouted {
    Packet {
        source: SocketAddr,
        installed: Option<(PeerId, Attachment)>,
        bytes: Vec<u8>,
    },
    Discarded,
    Idle,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EndpointCounters {
    pub send_calls: u64,
    pub receive_calls: u64,
    pub sent_bytes: u64,
    pub received_bytes: u64,
    pub discarded: u64,
    pub pressured: u64,
}

pub struct UdpEndpoint {
    socket: UdpSocket,
    routes: BTreeMap<PeerId, Route>,
    sources: BTreeMap<SocketAddr, PeerId>,
    receive: Vec<u8>,
    max_packet: usize,
    max_routes: usize,
    counters: EndpointCounters,
}
impl UdpEndpoint {
    pub fn new(socket: UdpSocket, max_packet: usize, max_routes: usize) -> io::Result<Self> {
        super::validate_max(max_packet)?;
        if !(1..=256).contains(&max_routes) {
            return Err(super::invalid("route bound must be 1..=256"));
        }
        socket.set_nonblocking(true)?;
        Ok(Self {
            socket,
            routes: BTreeMap::new(),
            sources: BTreeMap::new(),
            receive: vec![0; max_packet + 1],
            max_packet,
            max_routes,
            counters: EndpointCounters::default(),
        })
    }
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }
    pub fn counters(&self) -> EndpointCounters {
        self.counters
    }
    pub fn routes(&self) -> Vec<Route> {
        self.routes.values().cloned().collect()
    }

    /// Atomic host CAS. A socket address is only a route hint, never identity.
    /// Removed peers retain one bounded fence slot for this endpoint lifetime.
    pub fn set_route(
        &mut self,
        peer: PeerId,
        expected: u64,
        generation: u64,
        next_hop: Option<SocketAddr>,
    ) -> Result<(), EndpointError> {
        let old = self.routes.get(&peer);
        if old.map_or(0, |r| r.generation) != expected || generation <= expected {
            return Err(EndpointError::StaleGeneration);
        }
        if old.is_none() && self.routes.len() == self.max_routes {
            return Err(EndpointError::Capacity);
        }
        if let Some(address) = next_hop {
            if address.port() == 0 || self.sources.get(&address).is_some_and(|p| *p != peer) {
                return Err(EndpointError::InvalidRoute);
            }
        }
        if let Some(address) = old.and_then(|r| r.next_hop) {
            self.sources.remove(&address);
        }
        if let Some(address) = next_hop {
            self.sources.insert(address, peer);
        }
        self.routes.insert(
            peer,
            Route {
                peer,
                generation,
                next_hop,
            },
        );
        Ok(())
    }

    /// One send syscall at most. False means local loss/pressure, not delivery.
    pub fn send(
        &mut self,
        peer: PeerId,
        attachment: Attachment,
        bytes: &[u8],
    ) -> Result<bool, EndpointError> {
        let route = self.routes.get(&peer).ok_or(EndpointError::InvalidRoute)?;
        if route.generation != attachment.0 {
            return Err(EndpointError::StaleGeneration);
        }
        let address = route.next_hop.ok_or(EndpointError::InvalidRoute)?;
        if !(mesa_wire::HEADER_LEN..=self.max_packet).contains(&bytes.len()) {
            return Err(EndpointError::InvalidRoute);
        }
        self.counters.send_calls = self.counters.send_calls.saturating_add(1);
        match self.socket.send_to(bytes, address) {
            Ok(n) if n == bytes.len() => {
                self.counters.sent_bytes = self.counters.sent_bytes.saturating_add(n as u64);
                Ok(true)
            }
            Ok(_) => {
                self.counters.pressured = self.counters.pressured.saturating_add(1);
                Ok(false)
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                self.counters.pressured = self.counters.pressured.saturating_add(1);
                Ok(false)
            }
            Err(e) => Err(EndpointError::Io(e)),
        }
    }

    /// Check the credential fence while holding it through the send syscall.
    pub fn send_fenced(
        &mut self,
        packet: &mesa_core::credentials::FencedPacket,
    ) -> Result<bool, EndpointError> {
        packet
            .submit(|peer, attachment, bytes| bytes.with_bytes(|b| self.send(peer, attachment, b)))
            .map_err(|_| EndpointError::StaleGeneration)?
    }

    /// One recv syscall at most. Unknown sources remain transport input for a
    /// selected bounded admission module; callers must not deliver their data.
    pub fn receive_unrouted(&mut self) -> Result<Unrouted, EndpointError> {
        self.counters.receive_calls = self.counters.receive_calls.saturating_add(1);
        match self.socket.recv_from(&mut self.receive) {
            Ok((n, source)) => {
                self.counters.received_bytes =
                    self.counters.received_bytes.saturating_add(n as u64);
                if !(mesa_wire::HEADER_LEN..=self.max_packet).contains(&n) {
                    self.counters.discarded = self.counters.discarded.saturating_add(1);
                    return Ok(Unrouted::Discarded);
                }
                let installed = self
                    .sources
                    .get(&source)
                    .map(|peer| (*peer, Attachment(self.routes[peer].generation)));
                Ok(Unrouted::Packet {
                    source,
                    installed,
                    bytes: self.receive[..n].to_vec(),
                })
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                Ok(Unrouted::Idle)
            }
            Err(e) => Err(EndpointError::Io(e)),
        }
    }
    /// The admission module owns amplification limits and the hint's lifetime.
    /// This operation installs no route and confers no peer authority.
    pub fn send_to_hint(
        &mut self,
        source: SocketAddr,
        bytes: &[u8],
    ) -> Result<bool, EndpointError> {
        if source.port() == 0 || !(mesa_wire::HEADER_LEN..=self.max_packet).contains(&bytes.len()) {
            return Err(EndpointError::InvalidRoute);
        }
        self.counters.send_calls = self.counters.send_calls.saturating_add(1);
        match self.socket.send_to(bytes, source) {
            Ok(n) if n == bytes.len() => {
                self.counters.sent_bytes = self.counters.sent_bytes.saturating_add(n as u64);
                Ok(true)
            }
            Ok(_) => {
                self.counters.pressured = self.counters.pressured.saturating_add(1);
                Ok(false)
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                self.counters.pressured = self.counters.pressured.saturating_add(1);
                Ok(false)
            }
            Err(e) => Err(EndpointError::Io(e)),
        }
    }
    pub fn receive(&mut self) -> Result<Datagram, EndpointError> {
        Ok(match self.receive_unrouted()? {
            Unrouted::Packet {
                installed: Some((peer, attachment)),
                bytes,
                ..
            } => Datagram::Packet {
                peer,
                attachment,
                bytes,
            },
            Unrouted::Packet {
                installed: None, ..
            } => {
                self.counters.discarded = self.counters.discarded.saturating_add(1);
                Datagram::Discarded
            }
            Unrouted::Discarded => Datagram::Discarded,
            Unrouted::Idle => Datagram::Idle,
        })
    }

    /// Prefix results retain prior packets if a later receive fails. Stops on
    /// idle/error, never spins until a packet arrives. At most 64 syscalls.
    pub fn receive_batch(
        &mut self,
        attempts: usize,
    ) -> Result<Vec<Result<Datagram, EndpointError>>, EndpointError> {
        if attempts > 64 {
            return Err(EndpointError::Capacity);
        }
        let mut out = Vec::new();
        for _ in 0..attempts {
            let result = self.receive();
            let stop = matches!(result, Ok(Datagram::Idle) | Err(_));
            out.push(result);
            if stop {
                break;
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod credential_tests {
    use super::*;
    #[test]
    fn retained_packet_cutover_prevents_actual_udp_syscall() {
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver.set_nonblocking(true).unwrap();
        let mut sender =
            UdpEndpoint::new(UdpSocket::bind("127.0.0.1:0").unwrap(), 1472, 2).unwrap();
        sender
            .set_route(PeerId(2), 0, 1, Some(receiver.local_addr().unwrap()))
            .unwrap();
        let gate = mesa_core::credentials::SendGate::default();
        let packet = gate.packet(PeerId(2), Attachment(1), vec![7; 32].into());
        assert!(sender.send_fenced(&packet).unwrap());
        let calls = sender.counters().send_calls;
        gate.change(false).unwrap();
        gate.change(true).unwrap();
        assert!(matches!(
            sender.send_fenced(&packet),
            Err(EndpointError::StaleGeneration)
        ));
        assert_eq!(sender.counters().send_calls, calls);
        let fresh = gate.packet(PeerId(2), Attachment(1), vec![8; 32].into());
        assert!(sender.send_fenced(&fresh).unwrap());
        sender
            .set_route(PeerId(2), 1, 2, Some(receiver.local_addr().unwrap()))
            .unwrap();
        assert!(sender.send_fenced(&fresh).is_err());
    }
}
