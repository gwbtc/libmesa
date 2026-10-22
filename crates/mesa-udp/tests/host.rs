use mesa_core::{protection::SignedPublic, *};
use mesa_crypto::KeyPair;
use mesa_udp::UdpHost;
use std::{
    collections::BTreeMap,
    net::UdpSocket,
    time::{Duration, Instant},
};

fn engine() -> Engine<SignedPublic> {
    let local = PreconfiguredPeer::new(PeerId(1), "gw-btc", 1, 0, KeyHandle(1)).unwrap();
    let peer = PreconfiguredPeer::new(PeerId(2), "gw-btc", 1, 0, KeyHandle(2)).unwrap();
    let profile = SignedPublic::new(
        local.key,
        KeyPair::from_seed(&[1; 32]),
        BTreeMap::from([(peer.key, KeyPair::from_seed(&[2; 32]).public_key())]),
    );
    let mut engine = Engine::new(Config::default(), local, profile).unwrap();
    engine.step(Event::InstallPeer(peer)).unwrap();
    engine
}

#[test]
fn unknown_sources_and_oversized_datagrams_drop_before_core_dispatch() {
    let local = UdpSocket::bind("127.0.0.1:0").unwrap();
    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    let unknown = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut host = UdpHost::new(
        engine(),
        local,
        BTreeMap::from([(PeerId(2), (Attachment(7), peer.local_addr().unwrap()))]),
    )
    .unwrap();
    peer.send_to(&vec![0; 1473], host.local_addr().unwrap())
        .unwrap();
    unknown
        .send_to(&[0; 10], host.local_addr().unwrap())
        .unwrap();
    peer.send_to(&[0; 10], host.local_addr().unwrap()).unwrap();
    let start = Instant::now();
    let mut drops = 0;
    while start.elapsed() < Duration::from_secs(1) {
        drops += host
            .poll(start.elapsed().as_millis() as u64)
            .unwrap()
            .iter()
            .filter(|a| matches!(a, Action::Dropped(DropReason::Malformed)))
            .count();
        if drops == 1 && host.discarded_datagrams == 2 {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(drops, 1);
    assert_eq!(host.discarded_datagrams, 2);
    assert_eq!(host.engine().usage().reassembly_bytes, 0);
}

#[test]
fn uninstalled_route_rejected() {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    assert!(UdpHost::new(
        engine(),
        socket,
        BTreeMap::from([(PeerId(3), (Attachment(7), peer.local_addr().unwrap()))])
    )
    .is_err());
}
