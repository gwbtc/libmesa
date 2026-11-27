use mesa_core::Attachment;
use mesa_crypto::KeyPair;
use mesa_pki::{Authority, Limits, ProviderStatus};
use mesa_urbit::{
    admission::{Open, ProofProfile},
    contact::{Action, Config, Contact},
    identity_control as control, path, Buffer,
};
fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn fixture(index: usize, life: u32) -> (Open, KeyPair) {
    let v: serde_json::Value =
        serde_json::from_str(include_str!("../../../vectors/crypto/suite-c.json")).unwrap();
    let v = &v["vectors"][index];
    let ring = hex(v["ring"].as_str().unwrap());
    let key = KeyPair::from_seed(ring[1..33].try_into().unwrap());
    let open = Open {
        pass: hex(v["pass"].as_str().unwrap()).into(),
        sender: u128::from_le_bytes(hex(v["name128"].as_str().unwrap()).try_into().unwrap()),
        sender_life: life,
        receiver: path::parse_ship("~hantyl-dochus-dilryl-narmul--tabtyv-tantel-dotmeb-nacnub")
            .unwrap(),
        receiver_life: 1,
    };
    (open, key)
}
#[test]
fn signed_open_matches_pinned_hoon_and_ticks_cannot_select_authority() {
    let (open, key) = fixture(0, 17);
    let v: serde_json::Value = serde_json::from_str(include_str!(
        "../../../vectors/urbit-mesa/open-control.json"
    ))
    .unwrap();
    let encoded = control::encode(&open, &key).unwrap();
    assert_eq!(encoded.to_vec(), hex(v["hex"].as_str().unwrap()));
    let c = control::screen(&encoded, open.receiver, 35, 7, "gw-btc", false).unwrap();
    assert_eq!(c.life, 17);
    assert_eq!(c.rift, 7);
    // The four-bit header is outside the signature: even with a valid checksum,
    // changing it never changes the authenticated full life in the signed body.
    let mut bytes = encoded.to_vec();
    bytes[4] ^= 0xff;
    let h = 0x80000780 | ((mesa_bytes::mug::mug_bytes(&bytes[4..]) & 0xfffff) << 11);
    bytes[..4].copy_from_slice(&h.to_le_bytes());
    assert_eq!(
        control::screen(&bytes.into(), open.receiver, 35, 7, "gw-btc", false).unwrap(),
        c
    );
    assert!(control::screen(&encoded, open.receiver + 1, 1, 0, "gw-btc", false).is_err());
    let mut wrong = encoded.to_vec();
    *wrong.last_mut().unwrap() ^= 1;
    assert!(control::screen(&wrong.into(), open.receiver, 1, 0, "gw-btc", false).is_err());
    let mut exact = open;
    exact.receiver_life = 35;
    let exact = control::encode(&exact, &key).unwrap();
    assert!(control::screen(&exact, c.peer, 36, 0, "gw-btc", false).is_err());
}
#[test]
fn adapter_controls_require_durable_current_authority_and_expire_stale_verdicts() {
    let (old, key) = fixture(0, 1);
    let mut authority = Authority::new(Limits::default(), 1).unwrap();
    let p = authority.register("gw-btc", 0, 1).unwrap();
    authority.commit(p.token).unwrap();
    let provider = authority.provider("gw-btc").unwrap();
    authority
        .set_status(
            "gw-btc",
            provider,
            ProviderStatus {
                available: true,
                ready: true,
            },
        )
        .unwrap();
    let c = control::screen(
        &control::encode(&old, &key).unwrap(),
        old.receiver,
        1,
        0,
        "gw-btc",
        false,
    )
    .unwrap();
    let p = authority.accept(provider, 0, c, None, None).unwrap();
    authority.commit(p.token).unwrap();
    let mut d = Contact::new(
        Config::default(),
        ProofProfile {
            local: old.receiver,
            life: 1,
            local_rift: 0,
            rift: 0,
            domain: "gw-btc".into(),
            historical_life_one: false,
        },
        9,
    )
    .unwrap();
    let (new, key) = fixture(1, 2);
    assert_eq!(new.sender, old.sender);
    let packet = control::encode(&new, &key).unwrap();
    let a = d
        .receive_control(Attachment(7), &packet, &authority)
        .unwrap();
    let Action::Verify { token, candidate } = &a[0] else {
        panic!()
    };
    let token = *token;
    let candidate = candidate.clone();
    assert!(d.promote(token, &authority).is_err());
    let p = authority
        .accept(
            provider,
            authority.revision(old.sender),
            candidate,
            None,
            None,
        )
        .unwrap();
    assert!(d.promote(token, &authority).is_err());
    authority.commit(p.token).unwrap();
    assert!(matches!(
        &d.promote(token, &authority).unwrap()[0],
        Action::Ready { .. }
    ));
    assert!(d
        .receive_control(
            Attachment(7),
            &control::encode(&old, &fixture(0, 1).1).unwrap(),
            &authority
        )
        .is_err());
    let a = d
        .receive_control(Attachment(7), &packet, &authority)
        .unwrap();
    let Action::Verify { token, .. } = &a[0] else {
        panic!()
    };
    let token = *token;
    d.activate(2).unwrap();
    assert!(d.promote(token, &authority).is_err());
    // Oversized controls are rejected before cue or key work.
    assert!(control::decode(&Buffer::new(vec![1], 1473).unwrap()).is_err());
}

#[test]
fn lost_announcement_retries_are_bounded_cancelled_and_key_fenced() {
    use mesa_core::{credentials::SendGate, policy::RetryTimer, PeerId};
    let (open, key) = fixture(0, 17);
    let gate = SendGate::default();
    let packet = gate.packet(
        PeerId(open.receiver),
        Attachment(1),
        control::encode(&open, &key).unwrap(),
    );
    let mut retry = control::Announcement::new(
        packet.clone(),
        0,
        RetryTimer::Exponential {
            initial: 100,
            maximum: 400,
        },
        3,
        1000,
    )
    .unwrap();
    assert!(retry.advance(0).unwrap().is_some()); // lost initial announcement
    assert!(retry.advance(99).unwrap().is_none());
    let retained = retry.advance(100).unwrap().unwrap();
    assert!(retained.submit(|_, _, _| ()).is_ok());
    assert_eq!(retry.deadline(), Some(300));
    gate.change(false).unwrap();
    assert!(retry.advance(300).unwrap().is_none());
    assert_eq!(retry.deadline(), None);
    assert!(retained
        .submit(|_, _, _| panic!("retired control sent"))
        .is_err());
    gate.change(true).unwrap();
    let mut retry = control::Announcement::new(
        gate.packet(packet.peer(), Attachment(1), packet.bytes()),
        0,
        RetryTimer::Fixed { after: 100 },
        2,
        1000,
    )
    .unwrap();
    assert!(retry.advance(0).unwrap().is_some());
    assert!(retry.advance(100).unwrap().is_some());
    assert_eq!(retry.deadline(), None);
    assert!(retry.advance(200).unwrap().is_none());
    assert!(retry.advance(199).is_err());
    retry.cancel();
    assert!(retry.advance(300).unwrap().is_none());
}

#[test]
fn current_proof_signers_work_without_historical_policy() {
    use mesa_wire::mesa_v1 as wire;
    for life in [1, 2] {
        let (open, key) = fixture(0, life);
        let gage = mesa_urbit::admission::encode(&open).unwrap().to_vec();
        let path = path::proof(open.receiver, open.receiver_life).unwrap();
        let mut transcript = path::beam_prefix(open.sender, 0).unwrap();
        transcript.extend(&path);
        transcript.extend(mesa_lss::Tree::build(&gage).unwrap().mesa_root());
        let signature = key.sign(&transcript);
        let packet = wire::Packet {
            hop: 0,
            body: wire::Body::Page {
                name: wire::Name {
                    ship: open.sender,
                    rift: 0,
                    bloq: 13,
                    fragment: wire::Fragment::Data(0),
                    path: &path,
                },
                data: wire::Data {
                    total_bytes: gage.len() as u64,
                    auth: wire::Auth::Signature(&signature),
                    fragment: &gage,
                },
                next: None,
            },
        };
        let packet: Buffer =
            wire::encode(&packet, wire::Checksum::VereBytes, wire::Limits::DATAGRAM)
                .unwrap()
                .into();
        let profile = ProofProfile {
            local: open.receiver,
            life: open.receiver_life,
            local_rift: 0,
            rift: 0,
            domain: "gw-btc".into(),
            historical_life_one: false,
        };
        assert_eq!(profile.screen_proof(&packet).unwrap().life, life);
        let mut oversized = open;
        oversized.pass = Buffer::new(vec![1], 1025).unwrap();
        assert!(mesa_urbit::admission::encode(&oversized).is_err());
    }
}
