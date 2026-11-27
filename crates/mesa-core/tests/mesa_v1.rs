use mesa_core::{protection::SignedPublic, *};
use mesa_crypto::{KeyPair, PublicKey};
use mesa_wire::mesa_v1 as wire;
use std::collections::{BTreeMap, VecDeque};
fn view(id: u128) -> PreconfiguredPeer {
    PreconfiguredPeer::new(PeerId(id), "gw-btc", 1, 0, KeyHandle(id as u64)).unwrap()
}
fn engine(id: u128, other: u128, key: PublicKey) -> Engine<SignedPublic> {
    let protection = SignedPublic::new(
        KeyHandle(id as u64),
        KeyPair::from_seed(&[id as u8; 32]),
        BTreeMap::from([(KeyHandle(other as u64), key)]),
    )
    .mesa_v1(BTreeMap::from([
        (PeerId(0), b"/~zod//1/".to_vec()),
        (PeerId(1), b"/~nec//1/".to_vec()),
    ]));
    let mut e = Engine::new(Config::default(), view(id), protection).unwrap();
    e.step(Event::InstallPeer(view(other))).unwrap();
    e.step(Event::SetAttachment {
        peer: PeerId(other),
        attachment: Some(Attachment(1)),
    })
    .unwrap();
    e
}
fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
#[test]
fn pinned_vere_pages_verify_in_shared_engine() {
    let rows: serde_json::Value = serde_json::from_str(include_str!(
        "../../../investigation/native/evidence/udp-packets.json"
    ))
    .unwrap();
    let key: serde_json::Value = serde_json::from_str(include_str!(
        "../../../investigation/native/evidence/public-key.json"
    ))
    .unwrap();
    let mut e = engine(
        1,
        0,
        PublicKey::from_bytes(
            hex(key["signing_key_le_hex"].as_str().unwrap())
                .try_into()
                .unwrap(),
        )
        .unwrap(),
    );
    let mut finished = Vec::new();
    for row in rows
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["direction"] == "receive")
    {
        let bytes = hex(row["hex"].as_str().unwrap());
        let wire::Body::Page { name, data, .. } =
            wire::decode(&bytes, wire::Checksum::VereBytes, wire::Limits::DATAGRAM)
                .unwrap()
                .body
        else {
            panic!()
        };
        if name.fragment == wire::Fragment::Init {
            e.step(Event::Read {
                id: if data.total_bytes <= 1024 { 1 } else { 2 },
                peer: PeerId(0),
                path: name.path.into(),
            })
            .unwrap();
        }
        let actions = e
            .step(Event::Receive {
                claimed_peer: PeerId(0),
                attachment: Attachment(1),
                bytes: &bytes,
            })
            .unwrap();
        for a in actions {
            match a {
                Action::ReadFinished { id, result } => finished.push((id, result.unwrap())),
                Action::Dropped(reason) => {
                    panic!("captured page {} rejected: {reason:?}", row["case"])
                }
                _ => {}
            }
        }
    }
    assert_eq!(
        finished
            .iter()
            .map(|(id, b)| (*id, b.len()))
            .collect::<Vec<_>>(),
        vec![(1, 24), (2, 4115)]
    );
    assert_eq!(e.usage().reads, 0);
}
struct Harness {
    engines: [Engine<SignedPublic>; 2],
    queue: VecDeque<(usize, Vec<u8>)>,
    results: Vec<(usize, Result<Vec<u8>, ReadFailure>)>,
}
impl Harness {
    fn new() -> Self {
        Self {
            engines: [
                engine(0, 1, KeyPair::from_seed(&[1; 32]).public_key()),
                engine(1, 0, KeyPair::from_seed(&[0; 32]).public_key()),
            ],
            queue: VecDeque::new(),
            results: Vec::new(),
        }
    }
    fn step(&mut self, i: usize, event: Event<'_>) {
        for a in self.engines[i].step(event).unwrap() {
            match a {
                Action::Send { bytes, .. } => {
                    assert!(wire::sift_head(&bytes).is_some());
                    self.queue.push_back((i, bytes));
                }
                Action::ReadFinished { result, .. } => self.results.push((i, result)),
                _ => {}
            }
        }
    }
    fn deliver(&mut self, (from, bytes): (usize, Vec<u8>)) {
        self.step(
            1 - from,
            Event::Receive {
                claimed_peer: PeerId(from as u128),
                attachment: Attachment(1),
                bytes: &bytes,
            },
        );
    }
    fn start(&mut self, data: &[u8]) {
        for i in 0..2 {
            self.step(
                i,
                Event::Bind {
                    path: b"publ/1/test".to_vec(),
                    bytes: data.into(),
                    access: Access::Public,
                },
            );
            self.step(
                i,
                Event::Read {
                    id: 1,
                    peer: PeerId((1 - i) as u128),
                    path: b"publ/1/test".to_vec(),
                },
            );
        }
    }
    fn pump(&mut self) {
        for _ in 0..10000 {
            if let Some(p) = self.queue.pop_front() {
                self.deliver(p);
            } else {
                return;
            }
        }
        panic!("loop");
    }
}
#[test]
fn shared_mesa_transfers_cover_boundaries_loss_duplication_reordering() {
    for size in [0, 1, 1023, 1024, 1025, 2048, 7169, 65536, 1048576] {
        let bytes: Vec<_> = (0..size)
            .map(|i| if i % 13 > 8 { 0 } else { (i % 251) as u8 })
            .collect();
        let mut h = Harness::new();
        h.start(&bytes);
        // Lose initial requests. Timers regenerate both through the same scheduler.
        h.queue.clear();
        for i in 0..2 {
            h.step(i, Event::AdvanceTo(100));
        }
        let mut counter = 0;
        while let Some(p) = if counter % 3 == 0 {
            h.queue.pop_back()
        } else {
            h.queue.pop_front()
        } {
            counter += 1;
            assert!(counter < 10000);
            h.deliver(p.clone());
            h.deliver(p);
        }
        h.results.sort_by_key(|r| r.0);
        assert_eq!(h.results, vec![(0, Ok(bytes.clone())), (1, Ok(bytes))]);
        for e in &h.engines {
            assert_eq!(
                (
                    e.usage().reads,
                    e.usage().unverified_bytes,
                    e.usage().reassembly_bytes
                ),
                (0, 0, 0)
            );
        }
    }
}
#[test]
fn timeout_cancellation_and_wrong_profile_leave_no_read_state() {
    let mut h = Harness::new();
    h.start(&vec![1; 4096]);
    h.step(0, Event::Cancel { id: 1 });
    h.step(1, Event::AdvanceTo(2000));
    h.pump();
    assert_eq!(
        h.results,
        vec![
            (0, Err(ReadFailure::Cancelled)),
            (1, Err(ReadFailure::Timeout))
        ]
    );
    for e in &h.engines {
        assert_eq!(e.usage().reads, 0);
    }
    let mut e = engine(0, 1, KeyPair::from_seed(&[1; 32]).public_key());
    let mut h = Harness::new();
    h.start(b"test");
    let (_, bytes) = h.queue.pop_front().unwrap();
    let mut wrong = bytes.clone();
    wrong[0] = (wrong[0] & !0x70) | 0x20;
    assert!(e
        .step(Event::Receive {
            claimed_peer: PeerId(1),
            attachment: Attachment(1),
            bytes: &wrong
        })
        .unwrap()
        .contains(&Action::Dropped(DropReason::Malformed)));
}

#[test]
fn vere_followup_peek_hint_is_accepted_only_by_the_mesa_profile() {
    let v: serde_json::Value =
        serde_json::from_str(include_str!("../../../vectors/urbit-mesa/peek-hop.json")).unwrap();
    for fixture in ["hex", "long_hint_hex"] {
        let bytes = hex(v[fixture].as_str().unwrap());
        assert!(mesa_wire::legacy_v1::decode(
            &bytes,
            wire::Checksum::VereBytes,
            wire::Limits::DATAGRAM
        )
        .is_err());
        let p = wire::decode(&bytes, wire::Checksum::VereBytes, wire::Limits::DATAGRAM).unwrap();
        assert!(matches!(p.body, wire::Body::Peek(_)));
        let canonical =
            wire::encode(&p, wire::Checksum::VereBytes, wire::Limits::DATAGRAM).unwrap();
        assert_eq!(&canonical[1..], &bytes[1..]);
        assert_eq!(canonical[0], bytes[0] & !12);
        for hint in [1, 2, 3] {
            let mut hinted = bytes.clone();
            hinted[0] = (hinted[0] & !12) | (hint << 2);
            assert_eq!(
                wire::decode(&hinted, wire::Checksum::VereBytes, wire::Limits::DATAGRAM),
                Ok(p)
            );
            // The exemption applies only to peek framing. It grants no page
            // trailer support and no route or payload authority.
            for typ in [1, 3] {
                let mut other = hinted.clone();
                other[0] = (other[0] & !0x80) | ((typ & 1) << 7);
                other[1] = (other[1] & !1) | (typ >> 1);
                assert!(
                    wire::decode(&other, wire::Checksum::VereBytes, wire::Limits::DATAGRAM)
                        .is_err()
                );
            }
        }
    }
}

#[test]
fn default_is_mesa_and_missing_namespace_never_falls_back() {
    struct NoProtection;
    impl Protection for NoProtection {
        fn verify(&mut self, _: &PreconfiguredPeer, _: &PreconfiguredPeer, _: &[u8]) -> bool {
            false
        }
    }
    assert_eq!(NoProtection.profile(), Profile::MesaV1);
    let p = SignedPublic::new(KeyHandle(1), KeyPair::from_seed(&[1; 32]), BTreeMap::new());
    assert_eq!(p.profile(), Profile::default());
    assert_eq!(p.profile(), Profile::MesaV1);
    let old =
        SignedPublic::experimental_v2(KeyHandle(1), KeyPair::from_seed(&[1; 32]), BTreeMap::new());
    assert_eq!(old.profile(), Profile::LibmesaExpV2);
    let mut e = Engine::new(Config::mesa_v1(), view(1), p).unwrap();
    assert!(e
        .step(Event::Bind {
            path: b"public".to_vec(),
            bytes: vec![3],
            access: Access::Public
        })
        .is_err());
    e.install_namespace(PeerId(1), b"/profile/1/".to_vec())
        .unwrap();
    e.step(Event::Bind {
        path: b"public".to_vec(),
        bytes: vec![3],
        access: Access::Public,
    })
    .unwrap();
}

#[test]
fn private_pokes_and_peek_pages_use_publisher_domains_across_authorities() {
    for poke in [false, true] {
        for sender in [0usize, 1] {
            let domains = ["authority-a", "authority-b"];
            let make = |i: usize| {
                let local = PreconfiguredPeer::new(
                    PeerId(i as u128),
                    domains[i],
                    1,
                    0,
                    KeyHandle(i as u64),
                )
                .unwrap();
                let remote = PreconfiguredPeer::new(
                    PeerId((1 - i) as u128),
                    domains[1 - i],
                    1,
                    0,
                    KeyHandle((1 - i) as u64),
                )
                .unwrap();
                let protection = SignedPublic::new(
                    local.key,
                    KeyPair::from_seed(&[i as u8; 32]),
                    BTreeMap::from([(
                        remote.key,
                        KeyPair::from_seed(&[(1 - i) as u8; 32]).public_key(),
                    )]),
                )
                .mesa_v1(BTreeMap::from([
                    (PeerId(0), b"/~zod//1/".to_vec()),
                    (PeerId(1), b"/~nec//1/".to_vec()),
                ]));
                let mut engine = Engine::new(Config::mesa_v1(), local, protection).unwrap();
                engine.step(Event::InstallPeer(remote.clone())).unwrap();
                engine
                    .step(Event::SetAttachment {
                        peer: remote.id,
                        attachment: Some(Attachment(1)),
                    })
                    .unwrap();
                engine
            };
            let receiver = 1 - sender;
            let mut a = make(sender);
            let mut b = make(receiver);
            a.step(Event::Bind {
                path: b"private-object".to_vec(),
                bytes: vec![7, 0, 0],
                access: Access::Peer(PeerId(receiver as u128)),
            })
            .unwrap();
            let reads = b
                .step(Event::ReadPrivate {
                    id: 1,
                    peer: PeerId(sender as u128),
                    path: b"private-object".to_vec(),
                })
                .unwrap();
            let sent = if poke {
                a.step(Event::Poke {
                    peer: PeerId(receiver as u128),
                    path: b"private-object".to_vec(),
                    ack: b"ack".to_vec(),
                })
                .unwrap()
            } else {
                let bytes = reads
                    .iter()
                    .find_map(|a| match a {
                        Action::Send { bytes, .. } => Some(bytes),
                        _ => None,
                    })
                    .unwrap();
                a.step(Event::Receive {
                    claimed_peer: PeerId(receiver as u128),
                    attachment: Attachment(1),
                    bytes,
                })
                .unwrap()
            };
            let bytes = sent
                .iter()
                .find_map(|a| match a {
                    Action::Send { bytes, .. } => Some(bytes),
                    _ => None,
                })
                .unwrap();
            let received = b
                .step(Event::Receive {
                    claimed_peer: PeerId(sender as u128),
                    attachment: Attachment(1),
                    bytes,
                })
                .unwrap();
            assert!(
                received.contains(&Action::ReadFinished {
                    id: 1,
                    result: Ok(vec![7, 0, 0])
                }),
                "poke={poke} sender={sender}: {received:?}"
            );
            assert_eq!(b.usage().reads, 0);
        }
    }
}
