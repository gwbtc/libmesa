use mesa_core::Attachment;
use mesa_pki::{Authority, Limits, ProviderStatus};
use mesa_urbit::{
    admission::ProofProfile,
    contact::{self, Action, Contact},
    path, Buffer,
};
use mesa_wire::mesa_v1::{self as wire, Body};
fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn fixture() -> (u128, Buffer, Buffer) {
    let local =
        path::parse_ship("~hantyl-dochus-dilryl-narmul--tabtyv-tantel-dotmeb-nacnub").unwrap();
    let mut poke = None;
    let mut proof = None;
    for line in
        include_str!("../../../investigation/native/contact/evidence/request-first/packets.jsonl")
            .lines()
    {
        let row: serde_json::Value = serde_json::from_str(line).unwrap();
        let b = hex(row["hex"].as_str().unwrap());
        let Ok(p) = wire::decode(&b, wire::Checksum::VereBytes, wire::Limits::DATAGRAM) else {
            continue;
        };
        match p.body {
            Body::Poke { ack, payload, .. }
                if ack.ship == local && payload.path.starts_with(b"chum/") && poke.is_none() =>
            {
                poke = Some(b.into())
            }
            Body::Page { name, .. }
                if name.path == path::proof(local, 1).unwrap() && proof.is_none() =>
            {
                proof = Some(b.into())
            }
            _ => {}
        }
    }
    (local, poke.unwrap(), proof.unwrap())
}
fn driver(local: u128) -> Contact {
    Contact::new(
        contact::Config::default(),
        ProofProfile {
            local,
            life: 1,
            local_rift: 0,
            rift: 0,
            domain: "mesa-test".into(),
            historical_life_one: true,
        },
        1,
    )
    .unwrap()
}
fn authority() -> Authority {
    let mut a = Authority::new(Limits::default(), 1).unwrap();
    let p = a.register("mesa-test", 0, 1).unwrap();
    a.commit(p.token).unwrap();
    let provider = a.provider("mesa-test").unwrap();
    a.set_status(
        "mesa-test",
        provider,
        ProviderStatus {
            available: true,
            ready: true,
        },
    )
    .unwrap();
    a
}
#[test]
fn first_contact_solicits_in_adapter_and_first_host_event_is_verification() {
    let (local, poke, proof) = fixture();
    let mut d = driver(local);
    let mut a = authority();
    assert!(d.receive(Attachment(1), &proof).is_err()); // Proactive proof cannot create relationship state.
    let actions = d.receive(Attachment(1), &poke).unwrap();
    assert!(matches!(
        &actions[..],
        [Action::Send { .. }, Action::Timer(_)]
    ));
    assert!(d.receive(Attachment(2), &proof).is_err());
    let actions = d.receive(Attachment(1), &proof).unwrap();
    let Action::Verify { token, candidate } = &actions[0] else {
        panic!()
    };
    let token = *token;
    let candidate = candidate.clone();
    assert!(d.promote(token, &a).is_err());
    let provider = a.provider("mesa-test").unwrap();
    let proposal = a.accept(provider, 0, candidate, None, None).unwrap();
    assert!(d.promote(token, &a).is_err());
    a.commit(proposal.token).unwrap();
    assert!(matches!(
        &d.promote(token, &a).unwrap()[..],
        [
            Action::Ready {
                route: Attachment(1),
                ..
            },
            Action::Timer(None)
        ]
    ));
    assert_eq!(d.pending(), 0);
}
#[test]
fn loss_retry_budget_timeout_cancellation_rotation_and_stale_provider_are_bounded() {
    let (local, poke, proof) = fixture();
    let mut d = driver(local);
    d.receive(Attachment(1), &poke).unwrap();
    assert_eq!(d.deadline(), Some(100));
    assert!(matches!(
        &d.advance(100).unwrap()[..],
        [Action::Send { .. }, Action::Timer(_)]
    ));
    let actions = d.receive(Attachment(1), &proof).unwrap();
    let Action::Verify { token, candidate } = &actions[0] else {
        panic!()
    };
    let token = *token;
    let candidate = candidate.clone();
    let mut a = authority();
    let provider = a.provider("mesa-test").unwrap();
    let p = a.accept(provider, 0, candidate, None, None).unwrap();
    a.commit(p.token).unwrap();
    a.set_status(
        "mesa-test",
        provider,
        ProviderStatus {
            available: false,
            ready: false,
        },
    )
    .unwrap();
    assert!(d.promote(token, &a).is_err());
    d.activate(2).unwrap();
    assert_eq!(d.pending(), 0);
    assert!(d.promote(token, &a).is_err());
    assert!(d.receive(Attachment(1), &proof).is_err());
    let mut d = driver(local);
    d.receive(Attachment(1), &poke).unwrap();
    assert!(matches!(
        &d.advance(2000).unwrap()[..],
        [Action::Expired(_), Action::Timer(None)]
    ));
    let mut d = driver(local);
    d.receive(Attachment(1), &poke).unwrap();
    let actions = d.receive(Attachment(1), &proof).unwrap();
    let Action::Verify { token, .. } = actions[0] else {
        panic!()
    };
    d.cancel(token).unwrap();
    assert_eq!(d.pending(), 0);
    assert!(d.receive(Attachment(1), &proof).is_err());
}
#[test]
fn budget_exhaustion_never_arms_a_past_timer() {
    let (local, poke, _) = fixture();
    let mut d = Contact::new(
        contact::Config {
            dispatches: 1,
            ..Default::default()
        },
        ProofProfile {
            local,
            life: 1,
            local_rift: 0,
            rift: 0,
            domain: "mesa-test".into(),
            historical_life_one: false,
        },
        1,
    )
    .unwrap();
    d.receive(Attachment(1), &poke).unwrap();
    d.advance(100).unwrap();
    assert_eq!(d.deadline(), Some(1000));
    d.advance(1000).unwrap();
    assert_eq!(d.deadline(), Some(1100));
    d.advance(1100).unwrap();
    assert_eq!(d.deadline(), Some(2000));
    d.advance(2000).unwrap();
    assert_eq!(d.deadline(), None);
}
#[test]
fn udp_listener_never_delivers_unverified_payload_and_promotes_only_committed_authority() {
    use mesa_transport::UdpEndpoint;
    use mesa_urbit::udp::{Action as U, Listener};
    use std::net::UdpSocket;
    let (local, poke, proof) = fixture();
    let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = receiver.local_addr().unwrap();
    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    sender
        .set_read_timeout(Some(std::time::Duration::from_secs(1)))
        .unwrap();
    fn poll(listener: &mut Listener, a: &Authority) -> Vec<U> {
        for _ in 0..1000 {
            let out = listener.poll(a).unwrap();
            if !out.is_empty() {
                return out;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        panic!("UDP deadline");
    }
    let mut listener = Listener::new(
        UdpEndpoint::new(receiver, 1472, 4).unwrap(),
        driver(local),
        4,
    )
    .unwrap();
    let mut a = authority();
    sender.send_to(&poke.to_vec(), address).unwrap();
    let out = poll(&mut listener, &a);
    assert!(!out
        .iter()
        .any(|a| matches!(a, U::AdmittedPacket { .. } | U::Verify { .. })));
    let mut buf = [0; 1472];
    let n = sender.recv(&mut buf).unwrap();
    assert!(matches!(
        wire::decode(&buf[..n], wire::Checksum::VereBytes, wire::Limits::DATAGRAM)
            .unwrap()
            .body,
        Body::Peek(_)
    ));
    sender.send_to(&proof.to_vec(), address).unwrap();
    let out = poll(&mut listener, &a);
    let (token, candidate) = out
        .into_iter()
        .find_map(|a| {
            if let U::Verify { token, candidate } = a {
                Some((token, candidate))
            } else {
                None
            }
        })
        .unwrap();
    let provider = a.provider("mesa-test").unwrap();
    let p = a.accept(provider, 0, candidate, None, None).unwrap();
    assert!(listener.promote(token, &a).is_err());
    a.commit(p.token).unwrap();
    listener.promote(token, &a).unwrap();
    sender.send_to(&poke.to_vec(), address).unwrap();
    assert!(matches!(
        &poll(&mut listener, &a)[..],
        [U::AdmittedPacket { .. }]
    ));
    a.set_status(
        "mesa-test",
        provider,
        ProviderStatus {
            available: false,
            ready: false,
        },
    )
    .unwrap();
    sender.send_to(&poke.to_vec(), address).unwrap();
    assert!(!poll(&mut listener, &a)
        .iter()
        .any(|a| matches!(a, U::AdmittedPacket { .. })));
}

#[test]
fn retained_controls_cannot_outlive_admission_generation() {
    let (local, poke, proof) = fixture();
    for end in ["activation", "cancel", "timeout", "drop", "promotion"] {
        let mut d = driver(local);
        let actions = d.receive(Attachment(1), &poke).unwrap();
        let Action::Send { packet } = &actions[0] else {
            panic!()
        };
        assert!(packet
            .submit(|_, _, bytes| assert!(!bytes.is_empty()))
            .is_ok());
        match end {
            "activation" => {
                d.activate(2).unwrap();
            }
            "cancel" | "promotion" => {
                let actions = d.receive(Attachment(1), &proof).unwrap();
                let Action::Verify { token, candidate } = &actions[0] else {
                    panic!()
                };
                if end == "cancel" {
                    d.cancel(*token).unwrap();
                } else {
                    let mut a = authority();
                    let p = a
                        .accept(
                            a.provider("mesa-test").unwrap(),
                            0,
                            candidate.clone(),
                            None,
                            None,
                        )
                        .unwrap();
                    a.commit(p.token).unwrap();
                    d.promote(*token, &a).unwrap();
                }
            }
            "timeout" => {
                d.advance(2000).unwrap();
            }
            "drop" => drop(d),
            _ => unreachable!(),
        }
        assert!(
            packet
                .submit(|_, _, _| panic!("expired control reached syscall"))
                .is_err(),
            "{end}"
        );
    }
}
