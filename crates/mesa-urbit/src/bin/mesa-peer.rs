//! Runnable preconfigured Mesa-v1 UDP peer. Configuration contains test keys;
//! the executable reports only packet bytes, public state and read results.
use mesa_core::{protection::SignedPublic, *};
use mesa_crypto::{KeyPair, PublicKey};
use mesa_transport::{Datagram, UdpEndpoint};
use mesa_urbit::path;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, VecDeque},
    fs,
    net::UdpSocket,
    time::{Duration, Instant},
};
fn hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2));
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}
fn render(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn main() {
    let file = std::env::args().nth(1).expect("mesa-peer CONFIG.json");
    let c: Value = serde_json::from_slice(&fs::read(file).expect("config")).expect("JSON");
    let local =
        path::parse_ship(c["local"].as_str().expect("local")).expect("comet or fixture name");
    let remote =
        path::parse_ship(c["remote"].as_str().expect("remote")).expect("comet or fixture name");
    let view = |id, key| {
        PreconfiguredPeer::new(
            PeerId(id),
            c["domain"].as_str().unwrap_or("mesa-test"),
            if id == local {
                c["local_life"].as_u64().unwrap_or(1) as u32
            } else {
                c["remote_life"].as_u64().unwrap_or(1) as u32
            },
            0,
            KeyHandle(key),
        )
        .unwrap()
    };
    let protection = SignedPublic::new(
        KeyHandle(1),
        KeyPair::from_seed(
            &hex(c["seed"].as_str().expect("seed"))
                .try_into()
                .expect("32-byte seed"),
        ),
        BTreeMap::from([(
            KeyHandle(2),
            PublicKey::from_bytes(
                hex(c["remote_key"].as_str().expect("remote_key"))
                    .try_into()
                    .expect("32-byte public key"),
            )
            .unwrap(),
        )]),
    )
    .mesa_v1(BTreeMap::from([
        (PeerId(local), path::beam_prefix(local, 0).unwrap()),
        (PeerId(remote), path::beam_prefix(remote, 0).unwrap()),
    ]));
    let config = Config {
        max_attempts: c["max_attempts"].as_u64().unwrap_or(4) as u32,
        retry_after: c["retry_ms"].as_u64().unwrap_or(100),
        read_timeout: c["timeout_ms"].as_u64().unwrap_or(2000),
        ..Config::mesa_v1()
    };
    let mut engine = Engine::new(config.clone(), view(local, 1), protection).unwrap();
    engine.step(Event::InstallPeer(view(remote, 2))).unwrap();
    engine
        .step(Event::SetAttachment {
            peer: PeerId(remote),
            attachment: Some(Attachment(1)),
        })
        .unwrap();
    let mut udp = UdpEndpoint::new(
        UdpSocket::bind(c["bind"].as_str().expect("bind")).unwrap(),
        config.wire.max_packet,
        2,
    )
    .unwrap();
    udp.set_route(
        PeerId(remote),
        0,
        1,
        Some(c["address"].as_str().expect("address").parse().unwrap()),
    )
    .unwrap();
    if let Some(pass) = c["pass"].as_str() {
        let proof = mesa_urbit::admission::encode(&mesa_urbit::admission::Open {
            pass: hex(pass).into(),
            sender: local,
            sender_life: c["local_life"].as_u64().unwrap_or(1) as u32,
            receiver: remote,
            receiver_life: c["remote_life"].as_u64().unwrap_or(1) as u32,
        })
        .unwrap();
        engine
            .step(Event::BindBuffer {
                path: path::proof(remote, c["remote_life"].as_u64().unwrap_or(1) as u32).unwrap(),
                bytes: proof,
                access: Access::Public,
            })
            .unwrap();
    }
    if c["session"].as_bool() == Some(true) {
        run_session(engine, udp, &c);
        return;
    }
    let mut pending = VecDeque::new();
    if let Some(bind) = c.get("publish") {
        for obj in bind.as_array().expect("publish array") {
            engine
                .step(Event::Bind {
                    path: obj["path"].as_str().unwrap().as_bytes().to_vec(),
                    bytes: hex(obj["hex"].as_str().unwrap()),
                    access: Access::Public,
                })
                .unwrap();
        }
    }
    if let Some(reads) = c.get("read") {
        for (i, read) in reads.as_array().expect("read array").iter().enumerate() {
            pending.extend(
                engine
                    .step(Event::Read {
                        id: i as u64 + 1,
                        peer: PeerId(remote),
                        path: read.as_str().unwrap().as_bytes().to_vec(),
                    })
                    .unwrap(),
            );
        }
    }
    let started = Instant::now();
    let until = c["duration_ms"].as_u64().unwrap_or(3000);
    let mut results = Vec::new();
    let mut packets = Vec::new();
    let mut dropped = Vec::new();
    while started.elapsed().as_millis() < until as u128 {
        while let Some(action) = pending.pop_front() {
            match action {
                Action::Send {
                    peer,
                    attachment,
                    bytes,
                } => {
                    packets.push(json!({"direction":"send","hex":render(&bytes)}));
                    udp.send(peer, attachment, &bytes).unwrap();
                }
                Action::ReadFinished { id, result } => results.push(match result {
                    Ok(bytes) => json!({"id":id,"hex":render(&bytes)}),
                    Err(reason) => json!({"id":id,"error":format!("{reason:?}")}),
                }),
                Action::Dropped(reason) => dropped.push(format!("{reason:?}")),
                _ => {}
            }
        }
        let now = started.elapsed().as_millis() as u64;
        if engine.next_timer().is_some_and(|t| now >= t) {
            pending.extend(engine.step(Event::AdvanceTo(now)).unwrap());
        }
        match udp.receive().unwrap() {
            Datagram::Packet {
                peer,
                attachment,
                bytes,
            } => {
                packets.push(json!({"direction":"receive","hex":render(&bytes)}));
                pending.extend(
                    engine
                        .step(Event::Receive {
                            claimed_peer: peer,
                            attachment,
                            bytes: &bytes,
                        })
                        .unwrap(),
                );
            }
            Datagram::Idle => std::thread::sleep(Duration::from_millis(1)),
            Datagram::Discarded => {}
        }
    }
    let report = json!({"profile":"Mesa-v1","results":results,"packets":packets,"dropped":dropped});
    fs::write(
        c["report"].as_str().expect("report path"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
    println!(
        "Mesa-v1 run: {} read results, {} packets",
        results.len(),
        packets.len()
    );
}
fn persist(path: &std::path::Path, world: &Value) {
    use std::io::Write;
    let tmp = path.with_extension("pending");
    let mut file = fs::File::create(&tmp).unwrap();
    file.write_all(&serde_json::to_vec(world).unwrap()).unwrap();
    file.sync_all().unwrap();
    fs::rename(&tmp, path).unwrap();
    fs::File::open(path.parent().unwrap())
        .unwrap()
        .sync_all()
        .unwrap();
}
// Fixture-only crash hook. The test supervisor sends SIGKILL after observing
// this marker; no hook exists in the engine or production embedding API.
fn crash_boundary(c: &Value, change: &str, point: &str) {
    if c["stop_at"]["change"] == change && c["stop_at"]["point"] == point {
        fs::write(c["stop_at"]["marker"].as_str().unwrap(), b"ready").unwrap();
        loop {
            std::thread::park();
        }
    }
}
fn open_control(c: &Value, recovery: bool) -> Option<mesa_bytes::Buffer> {
    let pass = c["pass"].as_str()?;
    mesa_urbit::identity_control::encode(
        &mesa_urbit::admission::Open {
            pass: hex(pass).into(),
            sender: path::parse_ship(c["local"].as_str()?).ok()?,
            sender_life: c["local_life"].as_u64().unwrap_or(1) as u32,
            receiver: path::parse_ship(c["remote"].as_str()?).ok()?,
            receiver_life: if recovery {
                1
            } else {
                c["remote_life"].as_u64().unwrap_or(1) as u32
            },
        },
        &KeyPair::from_seed(&hex(c["seed"].as_str()?).try_into().ok()?),
    )
    .ok()
}
fn run_session(engine: Engine<SignedPublic>, mut udp: UdpEndpoint, c: &Value) {
    use mesa_flow::ordered as flow;
    use mesa_urbit::session::{Action, Session};
    let world_path = std::path::Path::new(c["world"].as_str().expect("world"));
    let mut world: Value = if world_path.exists() {
        serde_json::from_slice(&fs::read(world_path).unwrap()).unwrap()
    } else {
        json!({"effects":[],"settlements":[],"submitted":false})
    };
    let snap = engine.snapshot();
    let remote = &snap.peers[0].peer;
    let epoch = flow::Epoch {
        domain: snap.local.domain().as_str().into(),
        remote_domain: remote.domain().as_str().into(),
        local: snap.local.id.0,
        local_rift: snap.local.rift,
        remote: remote.id.0,
        remote_rift: remote.rift,
    };
    let state = if let Some(s) = world["checkpoint"].as_str() {
        serde_json::from_str(s).unwrap()
    } else {
        flow::State::empty(epoch, c["bone"].as_u64().unwrap_or(4))
    };
    let incarnation = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let node = flow::Node::new(flow::Config::default(), state, incarnation).unwrap();
    let mut session = Session::new(
        engine,
        node,
        c["agent"].as_str().unwrap_or("mesa-bytes").into(),
    )
    .unwrap();
    let mut queue: VecDeque<_> = session.recover().unwrap().into();
    let mut packets = Vec::new();
    let mut errors = Vec::new();
    let mut dropped = Vec::new();
    let mut offered = BTreeMap::new();
    let mut initialized = false;
    let mut announcement = if c["announce"].as_bool() == Some(true) {
        let packet = session.core().send_gate().packet(
            remote.id,
            Attachment(1),
            open_control(c, false).expect("announcement"),
        );
        Some(
            mesa_urbit::identity_control::Announcement::new(
                packet,
                0,
                mesa_core::policy::RetryTimer::Exponential {
                    initial: 200,
                    maximum: 1000,
                },
                4,
                5000,
            )
            .unwrap(),
        )
    } else {
        None
    };
    let mut drop_announcement = c["drop_first_announcement"].as_bool() == Some(true);
    let start = Instant::now();
    while start.elapsed().as_millis() < c["duration_ms"].as_u64().unwrap_or(5000) as u128 {
        while let Some(action) = queue.pop_front() {
            match action {
                Action::Send(packet) => {
                    packets
                        .push(json!({"direction":"send","hex":render(&packet.bytes().to_vec())}));
                    udp.send_fenced(&packet).unwrap();
                }
                Action::Flow(flow::Action::Commit(p)) => {
                    let change = match &p.change {
                        flow::Change::Enqueue(_) => "enqueue",
                        flow::Change::Accept(..) => "accept",
                        flow::Change::Settlement(..) => "settlement",
                        flow::Change::Close(_) => "close",
                        flow::Change::Closed { .. } => "closed",
                        _ => "other",
                    };
                    crash_boundary(c, change, "before_persist");
                    match &p.change {
                        flow::Change::Enqueue(_) => world["submitted"] = json!(true),
                        flow::Change::Accept(id, outcome) => {
                            let id = format!("{id:?}");
                            if let Some(bytes) = offered.remove(&id) {
                                let effects = world["effects"].as_array_mut().unwrap();
                                assert!(!effects.iter().any(|e| e["id"] == id));
                                effects.push(
                                    json!({"id":id,"hex":bytes,"outcome":format!("{outcome:?}")}),
                                );
                            }
                        }
                        flow::Change::Settlement(id, outcome)
                            if session
                                .state()
                                .flow(id.flow)
                                .and_then(|f| f.outbox.as_ref())
                                .is_some_and(|m| m.kind != flow::Kind::Cork) =>
                        {
                            world["settlements"].as_array_mut().unwrap().push(
                                json!({"id":format!("{id:?}"),"outcome":format!("{outcome:?}")}),
                            )
                        }
                        _ => {}
                    }
                    world["checkpoint"] = json!(serde_json::to_string(&p.state).unwrap());
                    persist(world_path, &world);
                    crash_boundary(c, change, "after_persist");
                    queue.extend(session.command(flow::Event::Committed(p.token)).unwrap());
                    crash_boundary(c, change, "after_confirm");
                }
                Action::Flow(flow::Action::Deliver { id, bytes, kind }) => {
                    offered.insert(format!("{id:?}"), render(&bytes.to_vec()));
                    let outcome = if c["reject"].as_bool() == Some(true) && kind == flow::Kind::Plea
                    {
                        flow::Outcome::Rejected(mesa_urbit::gage::rejection(1024).unwrap())
                    } else {
                        flow::Outcome::Accepted
                    };
                    queue.extend(
                        session
                            .command(flow::Event::Decide { id, outcome })
                            .unwrap(),
                    );
                }
                Action::Core(mesa_core::host::Record::Dropped(reason)) => {
                    dropped.push(format!("{reason:?}"))
                }
                Action::Stalled { reason, .. } => errors.push(format!("{reason:?}")),
                _ => {}
            }
        }
        if !initialized {
            initialized = true;
            if let Some(send) = c["send"].as_str() {
                let f = flow::Flow {
                    bone: c["bone"].as_u64().unwrap_or(4),
                    backward: false,
                };
                if session.state().is_closed(f) {
                    continue;
                }
                if session.state().flow(f).is_none() {
                    queue.extend(session.command(flow::Event::Admit(f)).unwrap());
                    initialized = false;
                    continue;
                }
                if world["submitted"] != true {
                    queue.extend(
                        session
                            .command(flow::Event::Enqueue {
                                flow: f,
                                kind: flow::Kind::Plea,
                                bytes: hex(send).into(),
                            })
                            .unwrap(),
                    );
                    continue;
                }
            }
        }
        if c["close"].as_bool() == Some(true)
            && !world["settlements"].as_array().unwrap().is_empty()
        {
            let f = flow::Flow {
                bone: c["bone"].as_u64().unwrap_or(4),
                backward: false,
            };
            if session
                .state()
                .flow(f)
                .is_some_and(|s| s.closing == flow::Closing::Open)
            {
                queue.extend(session.command(flow::Event::Close(f)).unwrap());
                continue;
            }
        }
        let now = start.elapsed().as_millis() as u64;
        if let Some(a) = &mut announcement {
            if !world["settlements"].as_array().unwrap().is_empty() {
                a.cancel();
            }
            if let Some(packet) = a.advance(now).unwrap() {
                if drop_announcement {
                    drop_announcement = false;
                    packets.push(
                        json!({"direction":"injected-loss","hex":render(&packet.bytes().to_vec())}),
                    );
                } else {
                    udp.send_fenced(&packet).unwrap();
                    packets
                        .push(json!({"direction":"send","hex":render(&packet.bytes().to_vec())}));
                }
            }
        }
        if session.core().next_timer().is_some_and(|t| now >= t) {
            queue.extend(session.advance(now).unwrap());
        }
        match udp.receive().unwrap() {
            Datagram::Packet {
                attachment, bytes, ..
            } => {
                packets.push(json!({"direction":"receive","hex":render(&bytes)}));
                if let Ok(mesa_urbit::identity_control::Control::Keys {
                    sender, receiver, ..
                }) = mesa_urbit::identity_control::decode(&bytes.clone().into())
                {
                    if sender == remote.id.0 && receiver == snap.local.id.0 {
                        if let Some(reply) = open_control(c, true) {
                            packets.push(json!({"direction":"send","hex":render(&reply.to_vec())}));
                            udp.send(remote.id, attachment, &reply.to_vec()).unwrap();
                        }
                    }
                    continue;
                }
                match session.receive(attachment, &bytes) {
                    Ok(actions) => queue.extend(actions),
                    Err(e) => errors.push(format!("{e:?}")),
                };
            }
            Datagram::Idle => std::thread::sleep(Duration::from_millis(1)),
            Datagram::Discarded => {}
        }
    }
    let report = json!({"profile":"Urbit-Mesa","packets":packets,"errors":errors,"dropped":dropped,"effects":world["effects"],"settlements":world["settlements"]});
    fs::write(
        c["report"].as_str().unwrap(),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
    println!(
        "Urbit-Mesa run: {} effects, {} settlements, {} packets",
        world["effects"].as_array().unwrap().len(),
        world["settlements"].as_array().unwrap().len(),
        packets.len()
    );
}
