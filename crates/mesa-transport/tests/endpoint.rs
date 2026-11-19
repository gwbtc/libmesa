use mesa_core::{Attachment, PeerId};
use mesa_transport::{Datagram, EndpointError, UdpEndpoint};
use std::net::UdpSocket;
fn socket() -> UdpSocket {
    UdpSocket::bind("127.0.0.1:0").unwrap()
}
fn endpoint() -> UdpEndpoint {
    UdpEndpoint::new(socket(), 1472, 4).unwrap()
}
#[test]
fn one_socket_demultiplexes_three_peers_and_unknown_sources_consume_bounded_work() {
    let mut hub = endpoint();
    let sources = [socket(), socket(), socket()];
    let stranger = socket();
    for (i, s) in sources.iter().enumerate() {
        hub.set_route(PeerId(i as u128 + 1), 0, 1, Some(s.local_addr().unwrap()))
            .unwrap();
    }
    for s in &sources {
        s.send_to(&[7; 8], hub.local_addr().unwrap()).unwrap();
    }
    stranger
        .send_to(&[7; 8], hub.local_addr().unwrap())
        .unwrap();
    sources[0]
        .send_to(&[7; 1473], hub.local_addr().unwrap())
        .unwrap();
    let mut peers = Vec::new();
    let mut discarded = 0;
    for _ in 0..1000 {
        for r in hub.receive_batch(2).unwrap() {
            match r.unwrap() {
                Datagram::Packet {
                    peer,
                    attachment,
                    bytes,
                } => {
                    assert_eq!(attachment, Attachment(1));
                    assert_eq!(bytes, vec![7; 8]);
                    peers.push(peer);
                }
                Datagram::Discarded => discarded += 1,
                Datagram::Idle => {}
            }
        }
        if peers.len() == 3 && discarded == 2 {
            break;
        }
        std::thread::yield_now();
    }
    peers.sort();
    assert_eq!(peers, vec![PeerId(1), PeerId(2), PeerId(3)]);
    assert_eq!(discarded, 2);
    let before = hub.counters();
    assert!(hub.receive_batch(0).unwrap().is_empty());
    assert_eq!(hub.counters(), before);
    assert!(matches!(
        hub.receive_batch(65),
        Err(EndpointError::Capacity)
    ));
    assert_eq!(hub.counters(), before);
}
#[test]
fn route_cas_rejects_stale_sends_before_syscalls_and_keeps_fences_on_removal() {
    let mut hub = endpoint();
    let old = socket();
    let new = socket();
    hub.set_route(PeerId(2), 0, 1, Some(old.local_addr().unwrap()))
        .unwrap();
    hub.set_route(PeerId(2), 1, 2, None).unwrap();
    assert!(matches!(
        hub.set_route(PeerId(2), 1, 3, Some(new.local_addr().unwrap())),
        Err(EndpointError::StaleGeneration)
    ));
    hub.set_route(PeerId(2), 2, 3, Some(new.local_addr().unwrap()))
        .unwrap();
    let before = hub.counters();
    assert!(matches!(
        hub.send(PeerId(2), Attachment(1), &[1; 8]),
        Err(EndpointError::StaleGeneration)
    ));
    assert_eq!(hub.counters(), before);
    let routes = hub.routes();
    assert!(matches!(
        hub.set_route(PeerId(3), 0, 1, Some(new.local_addr().unwrap())),
        Err(EndpointError::InvalidRoute)
    ));
    assert_eq!(hub.routes(), routes);
    old.send_to(&[1; 8], hub.local_addr().unwrap()).unwrap();
    for _ in 0..1000 {
        if hub.receive().unwrap() == Datagram::Discarded {
            return;
        }
        std::thread::yield_now();
    }
    panic!("old source was not discarded");
}
#[test]
fn removed_routes_are_bounded_and_cannot_be_reused_to_erase_generations() {
    let mut hub = UdpEndpoint::new(socket(), 1472, 1).unwrap();
    let remote = socket();
    hub.set_route(PeerId(2), 0, 1, Some(remote.local_addr().unwrap()))
        .unwrap();
    hub.set_route(PeerId(2), 1, 2, None).unwrap();
    assert!(matches!(
        hub.set_route(PeerId(3), 0, 1, Some(remote.local_addr().unwrap())),
        Err(EndpointError::Capacity)
    ));
    assert!(matches!(
        hub.set_route(PeerId(2), 0, 1, Some(remote.local_addr().unwrap())),
        Err(EndpointError::StaleGeneration)
    ));
    hub.set_route(PeerId(2), 2, 3, Some(remote.local_addr().unwrap()))
        .unwrap();
}

#[test]
fn one_destination_io_error_does_not_disconnect_other_routes() {
    let mut hub = endpoint();
    let remote = socket();
    remote
        .set_read_timeout(Some(std::time::Duration::from_secs(1)))
        .unwrap();
    hub.set_route(PeerId(2), 0, 1, Some(remote.local_addr().unwrap()))
        .unwrap();
    // An IPv4 socket cannot send to this IPv6 loopback destination.
    hub.set_route(PeerId(3), 0, 1, Some("[::1]:12345".parse().unwrap()))
        .unwrap();
    assert!(matches!(
        hub.send(PeerId(3), Attachment(1), &[1; 8]),
        Err(EndpointError::Io(_))
    ));
    assert!(hub.send(PeerId(2), Attachment(1), &[2; 8]).unwrap());
    let mut bytes = [0; 8];
    assert_eq!(remote.recv_from(&mut bytes).unwrap().0, 8);
    assert_eq!(bytes, [2; 8]);
    assert_eq!(hub.routes().len(), 2);
}
