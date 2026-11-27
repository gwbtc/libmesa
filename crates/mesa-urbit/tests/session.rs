use mesa_core::{
    self as core, protection::SignedPublic, Attachment, KeyHandle, PeerId, PreconfiguredPeer,
};
use mesa_crypto::KeyPair;
use mesa_flow::ordered::{self as flow, Flow, Kind, Outcome};
use mesa_urbit::{
    gage, path,
    session::{Action, Session},
    Buffer,
};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
fn view(i: usize) -> PreconfiguredPeer {
    PreconfiguredPeer::new(
        PeerId(i as u128),
        "mesa-test",
        1,
        0,
        KeyHandle(i as u64 + 1),
    )
    .unwrap()
}
fn session(i: usize, state: Option<flow::State>, incarnation: u128) -> Session {
    let local = view(i);
    let remote = view(1 - i);
    let protection = SignedPublic::new(
        local.key,
        KeyPair::from_seed(&[i as u8; 32]),
        BTreeMap::from([(
            remote.key,
            KeyPair::from_seed(&[(1 - i) as u8; 32]).public_key(),
        )]),
    )
    .mesa_v1(BTreeMap::from([
        (local.id, path::beam_prefix(local.id.0, 0).unwrap()),
        (remote.id, path::beam_prefix(remote.id.0, 0).unwrap()),
    ]));
    let mut core = core::Engine::new(core::Config::mesa_v1(), local.clone(), protection).unwrap();
    core.step(core::Event::InstallPeer(remote.clone())).unwrap();
    core.step(core::Event::SetAttachment {
        peer: remote.id,
        attachment: Some(Attachment(1)),
    })
    .unwrap();
    let state = state.unwrap_or_else(|| {
        flow::State::empty(
            flow::Epoch {
                domain: local.domain().as_str().into(),
                remote_domain: remote.domain().as_str().into(),
                local: local.id.0,
                local_rift: 0,
                remote: remote.id.0,
                remote_rift: 0,
            },
            4,
        )
    });
    let node = flow::Node::new(flow::Config::default(), state, incarnation).unwrap();
    Session::new(core, node, "mesa-bytes".into()).unwrap()
}
struct Harness {
    nodes: [Session; 2],
    packets: VecDeque<(usize, Vec<u8>)>,
    effects: BTreeSet<(usize, u64, bool, u64)>,
    settled: Vec<(usize, Outcome)>,
    durable: [flow::State; 2],
    reject: bool,
}
impl Harness {
    fn new() -> Self {
        let nodes = [session(0, None, 1), session(1, None, 1)];
        let durable = [nodes[0].state().clone(), nodes[1].state().clone()];
        Self {
            nodes,
            packets: VecDeque::new(),
            effects: BTreeSet::new(),
            settled: Vec::new(),
            durable,
            reject: false,
        }
    }
    fn actions(&mut self, i: usize, actions: Vec<Action>) {
        let mut queue: VecDeque<_> = actions.into();
        while let Some(a) = queue.pop_front() {
            match a {
                Action::Send(packet) => {
                    packet
                        .submit(|_, _, bytes| self.packets.push_back((i, bytes.to_vec())))
                        .unwrap();
                }
                Action::Flow(flow::Action::Commit(p)) => {
                    if let flow::Change::Accept(id, _) = &p.change {
                        assert!(self.effects.insert((
                            i,
                            id.flow.bone,
                            id.flow.backward,
                            id.sequence
                        )));
                    }
                    self.durable[i] = p.state;
                    queue.extend(
                        self.nodes[i]
                            .command(flow::Event::Committed(p.token))
                            .unwrap(),
                    );
                }
                Action::Flow(flow::Action::Deliver { id, kind, .. }) => {
                    let outcome = if self.reject && kind == Kind::Plea {
                        Outcome::Rejected(gage::rejection(1024).unwrap())
                    } else {
                        Outcome::Accepted
                    };
                    queue.extend(
                        self.nodes[i]
                            .command(flow::Event::Decide { id, outcome })
                            .unwrap(),
                    );
                }
                Action::Flow(flow::Action::Settled { outcome, .. }) => {
                    self.settled.push((i, outcome))
                }
                Action::Stalled { reason, .. } => panic!("unexpected stalled {reason:?}"),
                _ => {}
            }
        }
    }
    fn command(&mut self, i: usize, event: flow::Event) {
        let actions = self.nodes[i].command(event).unwrap();
        self.actions(i, actions);
    }
    fn packet(&mut self, (from, bytes): (usize, Vec<u8>)) {
        let actions = self.nodes[1 - from].receive(Attachment(1), &bytes).unwrap();
        self.actions(1 - from, actions);
    }
    fn pump(&mut self) {
        for _ in 0..10000 {
            if let Some(p) = self.packets.pop_front() {
                self.packet(p);
            } else {
                return;
            }
        }
        panic!("packet loop");
    }
    fn tick(&mut self, time: u64) {
        for i in 0..2 {
            let a = self.nodes[i].advance(time).unwrap();
            self.actions(i, a);
        }
    }
    fn restart(&mut self, i: usize, incarnation: u128) {
        self.nodes[i] = session(i, Some(self.durable[i].clone()), incarnation);
        let actions = self.nodes[i].recover().unwrap();
        self.actions(i, actions);
    }
}
fn forward() -> Flow {
    Flow {
        bone: 4,
        backward: false,
    }
}
#[test]
fn private_messages_receipts_explanations_and_boons_use_shared_mesa_engine() {
    let mut h = Harness::new();
    h.command(0, flow::Event::Allocate { backward: false });
    for n in [0, 1, 1000, 1024, 1025, 4096, 16000] {
        let data = Buffer::new(vec![7, 8], n.max(2)).unwrap();
        h.command(
            0,
            flow::Event::Enqueue {
                flow: forward(),
                kind: Kind::Plea,
                bytes: data,
            },
        );
        h.pump();
    }
    assert_eq!(h.settled.len(), 7);
    assert_eq!(h.effects.len(), 7);
    h.reject = true;
    h.command(
        0,
        flow::Event::Enqueue {
            flow: forward(),
            kind: Kind::Plea,
            bytes: vec![3].into(),
        },
    );
    h.pump();
    assert!(matches!(h.settled.last(), Some((0, Outcome::Rejected(_)))));
    h.command(
        1,
        flow::Event::Enqueue {
            flow: Flow {
                backward: true,
                ..forward()
            },
            kind: Kind::Boon,
            bytes: vec![9, 0, 0].into(),
        },
    );
    h.pump();
    assert_eq!(h.settled.last(), Some(&(1, Outcome::Accepted)));
    assert_eq!(h.effects.len(), 9);
}
#[test]
fn lost_poke_and_lost_ack_reorder_duplicates_and_restart_do_not_repeat_effects() {
    let mut h = Harness::new();
    h.command(0, flow::Event::Allocate { backward: false });
    h.command(
        0,
        flow::Event::Enqueue {
            flow: forward(),
            kind: Kind::Plea,
            bytes: vec![7; 8192].into(),
        },
    );
    h.packets.clear();
    h.tick(100); // Lost initial poke; CORE retries the payload-bearing request.
    let p = h.packets.pop_front().unwrap();
    h.packet(p.clone());
    h.packet(p);
    let mut held = Vec::new();
    let mut i = 0;
    while let Some(p) = if i % 2 == 0 {
        h.packets.pop_back()
    } else {
        h.packets.pop_front()
    } {
        i += 1;
        assert!(i < 1000);
        // Hold all receiver receipts once delivery is durable.
        let pkt = mesa_wire::mesa_v1::decode(
            &p.1,
            mesa_wire::mesa_v1::Checksum::VereBytes,
            mesa_wire::mesa_v1::Limits::DATAGRAM,
        )
        .unwrap();
        if p.0 == 1
            && matches!(pkt.body,mesa_wire::mesa_v1::Body::Page {data,..} if data.total_bytes<100)
            && !h.effects.is_empty()
        {
            held.push(p);
            continue;
        }
        h.packet(p);
    }
    assert_eq!(h.effects.len(), 1);
    assert!(h.settled.is_empty());
    assert!(!held.is_empty());
    h.restart(0, 2);
    h.restart(1, 3);
    h.pump();
    assert_eq!(h.effects.len(), 1);
    assert_eq!(h.settled.len(), 1);
    for p in held {
        h.packet(p);
    }
    h.pump();
    assert_eq!(h.effects.len(), 1);
    assert_eq!(h.settled.len(), 1);
}
#[test]
fn long_flow_reclaims_encrypted_names_and_close_survives_lost_receipt() {
    let mut h = Harness::new();
    h.command(0, flow::Event::Allocate { backward: false });
    for i in 0..120 {
        h.command(
            0,
            flow::Event::Enqueue {
                flow: forward(),
                kind: Kind::Plea,
                bytes: vec![i].into(),
            },
        );
        h.pump();
    }
    assert_eq!(h.effects.len(), 120);
    assert!(h.nodes[1].core().usage().namespace_slots <= 10);
    assert_eq!(h.nodes[0].core().usage().namespace_slots, 0);
    h.command(0, flow::Event::Close(forward()));
    let p = h.packets.pop_front().unwrap();
    h.packet(p);
    h.packets.clear();
    h.restart(0, 2);
    h.restart(1, 3);
    h.pump();
    h.tick(100);
    h.pump();
    assert!(h.nodes[0].state().is_closed(forward()));
    assert!(h.nodes[1].state().is_closed(Flow {
        backward: true,
        ..forward()
    }));
}

#[test]
fn simultaneous_life_changes_revoke_retained_packets_and_preserve_outbox_identity() {
    let mut h = Harness::new();
    h.command(0, flow::Event::Allocate { backward: false });
    let initial = h.nodes[0]
        .command(flow::Event::Enqueue {
            flow: forward(),
            kind: Kind::Plea,
            bytes: vec![7; 4096].into(),
        })
        .unwrap();
    let Action::Flow(flow::Action::Commit(p)) = &initial[0] else {
        panic!()
    };
    let token = p.token;
    h.durable[0] = p.state.clone();
    let sent = h.nodes[0].command(flow::Event::Committed(token)).unwrap();
    let retained: Vec<_> = sent
        .into_iter()
        .filter_map(|a| match a {
            Action::Send(p) => Some(p),
            _ => None,
        })
        .collect();
    assert!(!retained.is_empty());
    let stable = h.nodes[0].state().flow(forward()).unwrap().outbox.clone();
    for (i, node) in h.nodes.iter_mut().enumerate() {
        let mut local = view(i);
        local.life = 2;
        node.activate_local(
            local,
            std::sync::Arc::new(KeyPair::from_seed(&[10 + i as u8; 32])),
            0,
            1,
        )
        .unwrap();
    }
    for packet in retained {
        assert!(packet
            .submit(|_, _, _| panic!("retired packet reached transport"))
            .is_err());
    }
    for (i, node) in h.nodes.iter_mut().enumerate() {
        let mut remote = view(1 - i);
        remote.life = 2;
        node.install_remote(
            core::host::CredentialUpdate {
                peer: remote,
                expected_generation: 0,
                generation: 1,
                breach: false,
            },
            KeyPair::from_seed(&[10 + (1 - i) as u8; 32]).public_key(),
        )
        .unwrap();
    }
    assert_eq!(h.nodes[0].state().flow(forward()).unwrap().outbox, stable);
    // Announcements and first replacement packets were lost. CORE retries.
    h.tick(100);
    h.pump();
    assert_eq!(h.effects.len(), 1);
    assert_eq!(h.settled, vec![(0, Outcome::Accepted)]);
}

#[test]
fn wrong_attachment_cannot_start_a_payload_read() {
    let mut h = Harness::new();
    h.command(0, flow::Event::Allocate { backward: false });
    h.command(
        0,
        flow::Event::Enqueue {
            flow: forward(),
            kind: Kind::Plea,
            bytes: vec![3; 8192].into(),
        },
    );
    let (_, bytes) = h.packets.pop_front().unwrap();
    assert!(h.nodes[1].receive(Attachment(99), &bytes).is_err());
    assert_eq!(h.nodes[1].core().usage().reads, 0);
    assert_eq!(h.nodes[1].state().revision, 0);
}
