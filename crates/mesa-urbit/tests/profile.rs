use mesa_urbit::{admission::ProofProfile, gage, path, Buffer};
use mesa_wire::mesa_v1::{self as wire, Body, Fragment};
fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
#[test]
fn captured_comet_names_and_signed_first_contact_proofs() {
    let records: serde_json::Value = serde_json::from_str(include_str!(
        "../../../investigation/native/contact/evidence/public-keys.json"
    ))
    .unwrap();
    for r in records.as_array().unwrap() {
        let id = u128::from_str_radix(r["ship_hex"].as_str().unwrap(), 16).unwrap();
        let name = r["name"].as_str().unwrap();
        assert_eq!(path::ship(id).unwrap(), name);
        assert_eq!(path::parse_ship(name).unwrap(), id);
    }
    let mut verified = 0;
    for line in
        include_str!("../../../investigation/native/contact/evidence/request-first/packets.jsonl")
            .lines()
    {
        let row: serde_json::Value = serde_json::from_str(line).unwrap();
        let bytes = hex(row["hex"].as_str().unwrap());
        let Ok(packet) = wire::decode(&bytes, wire::Checksum::VereBytes, wire::Limits::DATAGRAM)
        else {
            continue;
        };
        let (name, data) = match packet.body {
            Body::Page { name, data, .. } => (name, data),
            Body::Poke { payload, data, .. } => (payload, data),
            _ => continue,
        };
        if !std::str::from_utf8(name.path)
            .unwrap()
            .contains("/pawn/proof/")
        {
            continue;
        }
        if !matches!(name.fragment, Fragment::Init | Fragment::Data(0)) {
            continue;
        }
        let open = mesa_urbit::admission::decode(data.fragment).unwrap();
        let encoded = mesa_urbit::admission::encode(&open).unwrap();
        assert_eq!(encoded.to_vec(), data.fragment);
        let profile = ProofProfile {
            local: open.receiver,
            life: open.receiver_life,
            local_rift: 0,
            rift: 0,
            domain: "mesa-test".into(),
            historical_life_one: true,
        };
        let candidate = profile.screen_proof(&bytes.clone().into()).unwrap();
        assert_eq!(candidate.peer, open.sender);
        let strict = ProofProfile {
            historical_life_one: false,
            ..profile.clone()
        };
        assert_eq!(
            strict.screen_proof(&bytes.clone().into()).unwrap(),
            candidate
        );
        let wrong = ProofProfile { life: 2, ..profile };
        assert!(wrong
            .screen_proof(&hex(row["hex"].as_str().unwrap()).into())
            .is_err());
        verified += 1;
    }
    assert!(verified >= 1);
}
#[test]
fn codecs_preserve_width_and_owned_data_and_reject_bad_shapes() {
    for n in [0, 1, 1024, 4100, 65536] {
        let data = Buffer::new(vec![7], n.max(1)).unwrap();
        let encoded = gage::encode_bytes(&data, 131072).unwrap();
        let decoded = gage::decode_bytes(&encoded, 131072).unwrap();
        drop(encoded);
        assert_eq!(decoded, data);
        let plea = gage::encode_plea("mesa-bytes", &data, 131072).unwrap();
        let (agent, out) = gage::decode_plea(&plea, 131072).unwrap();
        assert_eq!(agent, "mesa-bytes");
        assert_eq!(out, data);
    }
    for rejected in [false, true] {
        let b = gage::encode_ack(rejected, 128).unwrap();
        assert_eq!(gage::decode_ack(&b, 128), Ok(rejected));
        assert!(gage::decode_bytes(&b, 128).is_err());
    }
    assert!(gage::decode_bytes(&vec![255; 1025].into(), 1024).is_err());
    for n in [0, 1, 31, 32, 1024, u64::MAX] {
        assert_eq!(path::parse_decimal(&path::decimal(n)), Ok(n));
    }
    for n in 0..100 {
        let bytes: Vec<u8> = (0..n).map(|i| (i + 1) as u8).collect();
        assert_eq!(path::parse_uv(&path::uv(&bytes), 128), Ok(bytes));
    }
}
#[test]
fn marked_gages_match_pinned_hoon_including_zero_version_and_empty_error() {
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("../../../vectors/urbit-mesa/gages.json")).unwrap();
    let data = Buffer::new(vec![7], 3).unwrap();
    for row in vectors["cases"].as_array().unwrap() {
        let expected = Buffer::from(hex(row["hex"].as_str().unwrap()));
        let actual = match row["case"].as_str().unwrap() {
            "bytes" => gage::encode_bytes(&data, 1024).unwrap(),
            "plea" => gage::encode_plea("mesa-bytes", &data, 1024).unwrap(),
            "boon" => gage::encode_boon(&data, 1024).unwrap(),
            "ack" => gage::encode_ack(false, 1024).unwrap(),
            "nack" => gage::encode_ack(true, 1024).unwrap(),
            "rejection" => gage::rejection(1024).unwrap(),
            "cork" => gage::encode_cork(1024).unwrap(),
            "gone" => gage::encode_gone(1024).unwrap(),
            "empty-error" => {
                gage::validate_rejection(&expected, 1024).unwrap();
                continue;
            }
            _ => panic!(),
        };
        assert_eq!(actual, expected, "{}", row["case"]);
    }
}
#[test]
fn keys_controls_match_hoon_and_ticks_do_not_claim_current_life() {
    use mesa_urbit::identity_control::{self as c, Control};
    let v: serde_json::Value = serde_json::from_str(include_str!(
        "../../../vectors/urbit-mesa/identity-controls.json"
    ))
    .unwrap();
    for r in v["cases"].as_array().unwrap() {
        let sender = path::parse_ship(r["sender"].as_str().unwrap()).unwrap();
        let receiver = path::parse_ship(r["receiver"].as_str().unwrap()).unwrap();
        let life = r["life"].as_u64().unwrap() as u32;
        let bytes = c::keys(sender, receiver, life).unwrap();
        assert_eq!(bytes.to_vec(), hex(r["hex"].as_str().unwrap()));
        assert_eq!(
            c::decode(&bytes),
            Ok(Control::Keys {
                sender,
                receiver,
                sender_tick: (life % 16) as u8
            })
        );
        assert!(c::screen(&bytes, receiver, life, 0, "mesa-test", true).is_err());
    }
}

#[test]
fn historical_name_signer_is_only_a_policy_selected_life_one_attestation() {
    use mesa_core::{protection::SignedPublic, KeyHandle, PeerId, PreconfiguredPeer, Protection};
    use mesa_crypto::{KeyPair, PublicKey};
    use std::collections::BTreeMap;
    let v: serde_json::Value = serde_json::from_str(include_str!(
        "../../../vectors/urbit-mesa/historical-proof.json"
    ))
    .unwrap();
    for row in v["cases"].as_array().unwrap() {
        let gage = hex(row["gage"].as_str().unwrap());
        let signature: [u8; 64] = hex(row["signature"].as_str().unwrap()).try_into().unwrap();
        let open = mesa_urbit::admission::decode(&gage).unwrap();
        assert_eq!(u64::from(open.sender_life), row["life"].as_u64().unwrap());
        let path = path::proof(open.receiver, open.receiver_life).unwrap();
        let packet = wire::Packet {
            hop: 0,
            body: Body::Page {
                name: wire::Name {
                    ship: open.sender,
                    rift: 0,
                    bloq: 13,
                    fragment: Fragment::Data(0),
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
        let bytes: Buffer =
            wire::encode(&packet, wire::Checksum::VereBytes, wire::Limits::DATAGRAM)
                .unwrap()
                .into();
        let profile = ProofProfile {
            local: open.receiver,
            life: open.receiver_life,
            local_rift: 0,
            rift: 0,
            domain: "gw-btc".into(),
            historical_life_one: true,
        };
        let result = profile.screen_proof(&bytes);
        assert_eq!(result.is_ok(), open.sender_life == 1);
        let strict = ProofProfile {
            historical_life_one: false,
            ..profile
        };
        assert!(strict.screen_proof(&bytes).is_err());
        if let Ok(candidate) = result {
            let peer = PreconfiguredPeer::new(
                PeerId(candidate.peer),
                &candidate.domain,
                1,
                0,
                KeyHandle(2),
            )
            .unwrap();
            let protection = SignedPublic::new(
                KeyHandle(1),
                KeyPair::from_seed(&[0; 32]),
                BTreeMap::from([(
                    KeyHandle(2),
                    PublicKey::from_bytes(candidate.public_key).unwrap(),
                )]),
            )
            .mesa_v1(BTreeMap::from([(
                peer.id,
                path::beam_prefix(candidate.peer, 0).unwrap(),
            )]));
            let name = mesa_wire::Name {
                publisher: peer.id,
                domain: peer.domain(),
                rift: 0,
                bloq: 13,
                fragment: mesa_wire::Fragment::Data(0),
                path: &path,
            };
            assert!(!protection.verify_root(
                &peer,
                name,
                gage.len() as u64,
                &mesa_lss::Tree::build(&gage).unwrap().mesa_root(),
                &signature
            ));
        }
    }
}
