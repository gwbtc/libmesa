use mesa_core::{host::*, protection::SignedPublic, *};
use mesa_crypto::KeyPair;
use std::collections::BTreeMap;

fn peer(id: u128) -> PreconfiguredPeer {
    PreconfiguredPeer::new(PeerId(id), "gw-btc", 1, 0, KeyHandle(id as u64)).unwrap()
}
fn engine(config: Config) -> Engine<SignedPublic> {
    Engine::new(
        config,
        peer(1),
        SignedPublic::experimental_v2(
            KeyHandle(1),
            KeyPair::from_seed(&[1; 32]),
            BTreeMap::from([(KeyHandle(2), KeyPair::from_seed(&[2; 32]).public_key())]),
        ),
    )
    .unwrap()
}
fn connected() -> Engine<SignedPublic> {
    let mut e = engine(Config::default());
    e.step(Event::InstallCredential(CredentialUpdate {
        peer: peer(2),
        expected_generation: 0,
        generation: 1,
        breach: false,
    }))
    .unwrap();
    e.step(Event::ReplaceAttachment(AttachmentUpdate {
        peer: PeerId(2),
        expected_generation: 0,
        generation: 1,
        attached: true,
    }))
    .unwrap();
    e
}
#[test]
fn fenced_updates_cancel_old_work_and_reject_stale_completions_without_mutation() {
    let mut e = connected();
    e.step(Event::Read {
        id: 9,
        peer: PeerId(2),
        path: b"object".to_vec(),
    })
    .unwrap();
    let before = e.snapshot();
    let stale = CredentialUpdate {
        peer: peer(2),
        expected_generation: 0,
        generation: 2,
        breach: false,
    };
    assert_eq!(
        e.step(Event::InstallCredential(stale)).unwrap_err(),
        Error::StaleGeneration
    );
    assert_eq!(e.snapshot(), before);
    assert_eq!(
        e.step(Event::InstallPeer(peer(2))).unwrap_err(),
        Error::StaleGeneration
    );
    let actions = e
        .step(Event::InstallCredential(CredentialUpdate {
            peer: peer(2),
            expected_generation: 1,
            generation: 2,
            breach: false,
        }))
        .unwrap();
    assert!(actions.contains(&Action::ReadFinished {
        id: 9,
        result: Err(ReadFailure::PeerReset)
    }));
    assert_eq!(e.usage().reads, 0);
    assert_eq!(e.next_timer(), None);
    assert_eq!(
        before.peers[0].credential_generation, 1,
        "old snapshots are owned"
    );
    assert_eq!(e.snapshot().peers[0].credential_generation, 2);
    assert!(e
        .step(Event::AdvanceTo(1000))
        .unwrap()
        .iter()
        .all(|a| !matches!(a, Action::Send { .. })));
}
#[test]
fn attachment_cas_fences_delayed_packets_and_legacy_updates() {
    let mut e = connected();
    let update = AttachmentUpdate {
        peer: PeerId(2),
        expected_generation: 1,
        generation: 2,
        attached: false,
    };
    e.step(Event::ReplaceAttachment(update)).unwrap();
    assert_eq!(
        e.step(Event::ReplaceAttachment(update)).unwrap_err(),
        Error::StaleGeneration
    );
    assert_eq!(
        e.step(Event::SetAttachment {
            peer: PeerId(2),
            attachment: Some(Attachment(1))
        })
        .unwrap_err(),
        Error::StaleGeneration
    );
    e.step(Event::ReplaceAttachment(AttachmentUpdate {
        expected_generation: 2,
        generation: 3,
        attached: true,
        ..update
    }))
    .unwrap();
    let a = e
        .step(Event::Receive {
            claimed_peer: PeerId(2),
            attachment: Attachment(1),
            bytes: &[0; 8],
        })
        .unwrap();
    assert!(a.contains(&Action::Dropped(DropReason::Attachment)));
    assert_eq!(e.snapshot().peers[0].attachment, Some(Attachment(3)));
}
#[test]
fn bounded_batches_keep_prefix_and_error_positions_and_do_not_mutate_on_capacity() {
    let config = Config::default();
    let envelope = config.event_envelope().unwrap();
    let mut e = engine(config);
    let events = [
        Event::InstallPeer(peer(2)),
        Event::AdvanceTo(8),
        Event::AdvanceTo(7),
        Event::AdvanceTo(9),
    ];
    let budget = Budget {
        events: 4,
        records: envelope.records * 4,
        bytes: envelope.bytes * 4,
    };
    let before = e.snapshot();
    assert_eq!(
        e.step_batch(
            &events,
            Budget {
                bytes: envelope.bytes - 1,
                ..budget
            }
        )
        .unwrap_err(),
        Error::ResourceLimit
    );
    assert_eq!(e.snapshot(), before);
    let first = e
        .step_batch(
            &events,
            Budget {
                events: 1,
                ..budget
            },
        )
        .unwrap();
    assert_eq!(first.results.len(), 1);
    let rest = e.step_batch(&events[1..], budget).unwrap();
    assert_eq!(rest.results.len(), 2);
    assert_eq!(rest.results[1], Err(Error::ClockRegression));
    assert_eq!(e.snapshot().now, 8);
    let before = e.snapshot();
    assert!(e.step_batch(&[], budget).unwrap().results.is_empty());
    assert_eq!(e.snapshot(), before);
}
#[test]
fn publication_retirement_reclaims_slots_without_allowing_name_reuse_after_restore() {
    let config = Config {
        max_bindings: 3,
        max_binding_bytes: 1024,
        ..Config::default()
    };
    let mut e = engine(config.clone());
    let mut retained = None;
    for i in 0u32..1000 {
        let suffix = i.to_be_bytes().to_vec();
        let path = [b"history/".as_slice(), &suffix].concat();
        let bytes = Buffer::new(vec![7], 1024).unwrap();
        retained = Some(bytes.clone());
        e.step(Event::BindBuffer {
            path: path.clone(),
            bytes,
            access: Access::Public,
        })
        .unwrap();
        e.step(Event::Unbind { path: &path }).unwrap();
        assert_eq!(
            e.step(Event::Bind {
                path: path.clone(),
                bytes: vec![8],
                access: Access::Public
            })
            .unwrap_err(),
            Error::RetiredName
        );
        e.step(Event::RetireBefore {
            prefix: b"history/".to_vec(),
            suffix: (i + 1).to_be_bytes().to_vec(),
        })
        .unwrap();
        assert_eq!(e.usage().namespace_slots, 1);
        assert_eq!(e.usage().binding_bytes, 0);
    }
    drop(e);
    assert_eq!(retained.unwrap().len(), 1024);
    let mut restored = engine(config);
    restored
        .step(Event::RetireBefore {
            prefix: b"history/".to_vec(),
            suffix: 1000u32.to_be_bytes().to_vec(),
        })
        .unwrap();
    assert_eq!(
        restored
            .step(Event::Bind {
                path: [b"history/".as_slice(), &999u32.to_be_bytes()].concat(),
                bytes: vec![99],
                access: Access::Public
            })
            .unwrap_err(),
        Error::RetiredName
    );
}
#[test]
fn cancelled_and_overdue_work_has_no_timer_storm_and_detached_reads_timeout() {
    let mut e = connected();
    e.step(Event::Read {
        id: 1,
        peer: PeerId(2),
        path: b"never".to_vec(),
    })
    .unwrap();
    e.step(Event::Cancel { id: 1 }).unwrap();
    assert_eq!(e.next_timer(), None);
    e.step(Event::Read {
        id: 2,
        peer: PeerId(2),
        path: b"never".to_vec(),
    })
    .unwrap();
    e.step(Event::ReplaceAttachment(AttachmentUpdate {
        peer: PeerId(2),
        expected_generation: 1,
        generation: 2,
        attached: false,
    }))
    .unwrap();
    let a = e.step(Event::AdvanceTo(u64::MAX)).unwrap();
    assert!(a.contains(&Action::ReadFinished {
        id: 2,
        result: Err(ReadFailure::Timeout)
    }));
    assert!(a.iter().all(|a| !matches!(a, Action::Send { .. })));
    assert_eq!(
        e.step(Event::AdvanceTo(u64::MAX)).unwrap(),
        vec![Action::SetTimer(None)]
    );
    assert_eq!(e.snapshot().counters.cancelled, 1);
    assert_eq!(e.snapshot().counters.timeouts, 1);
}

#[test]
fn maximum_profile_timeout_batch_fits_the_advertised_envelope() {
    let config = Config {
        max_reads: 1024,
        ..Config::default()
    };
    let envelope = config.event_envelope().unwrap();
    let mut e = engine(config);
    e.step(Event::InstallPeer(peer(2))).unwrap();
    e.step(Event::SetAttachment {
        peer: PeerId(2),
        attachment: Some(Attachment(1)),
    })
    .unwrap();
    for id in 0..1024u64 {
        e.step(Event::Read {
            id,
            peer: PeerId(2),
            path: id.to_be_bytes().to_vec(),
        })
        .unwrap();
    }
    let batch = e
        .step_batch(
            &[Event::AdvanceTo(3000)],
            Budget {
                events: 1,
                records: envelope.records,
                bytes: envelope.bytes,
            },
        )
        .unwrap();
    assert_eq!(batch.results[0].as_ref().unwrap().len(), 1025);
    assert_eq!(e.snapshot().counters.timeouts, 1024);
    assert_eq!(e.usage().reads, 0);
    assert_eq!(e.next_timer(), None);
}

#[test]
fn rust_batch_buffers_survive_batch_and_engine_destruction() {
    use std::collections::VecDeque;
    let mut publisher = Engine::new(
        Config::default(),
        peer(2),
        SignedPublic::experimental_v2(
            KeyHandle(2),
            KeyPair::from_seed(&[2; 32]),
            BTreeMap::from([(KeyHandle(1), KeyPair::from_seed(&[1; 32]).public_key())]),
        ),
    )
    .unwrap();
    publisher.step(Event::InstallPeer(peer(1))).unwrap();
    publisher
        .step(Event::SetAttachment {
            peer: PeerId(1),
            attachment: Some(Attachment(1)),
        })
        .unwrap();
    publisher
        .step(Event::BindBuffer {
            path: b"shared".to_vec(),
            bytes: Buffer::new(vec![7], 1025).unwrap(),
            access: Access::Public,
        })
        .unwrap();
    let mut nodes = [connected(), publisher];
    let budget = Budget {
        events: 1,
        records: 10000,
        bytes: 16 * 1024 * 1024,
    };
    let first = nodes[0]
        .step_batch(
            &[Event::Read {
                id: 1,
                peer: PeerId(2),
                path: b"shared".to_vec(),
            }],
            budget,
        )
        .unwrap();
    let mut queue = VecDeque::new();
    for record in first.results.into_iter().flatten().flatten() {
        if let Record::Send { bytes, .. } = record {
            queue.push_back((0, bytes));
        }
    }
    let mut retained = None;
    while let Some((from, bytes)) = queue.pop_front() {
        let receiver = 1 - from;
        let records = bytes.with_bytes(|packet| {
            nodes[receiver]
                .step_batch(
                    &[Event::Receive {
                        claimed_peer: peer(from as u128 + 1).id,
                        attachment: Attachment(1),
                        bytes: packet,
                    }],
                    budget,
                )
                .unwrap()
        });
        for record in records.results.into_iter().flatten().flatten() {
            match record {
                Record::Send { bytes, .. } => queue.push_back((receiver, bytes)),
                Record::ReadFinished {
                    result: Ok(bytes), ..
                } => {
                    let copy = bytes.clone();
                    assert!(copy.shares_storage(&bytes));
                    retained = Some(copy);
                }
                _ => {}
            }
        }
    }
    drop(nodes);
    let bytes = retained.unwrap();
    assert_eq!(bytes.len(), 1025);
    assert_eq!(bytes.dat(), &[7]);
    std::thread::spawn(move || {
        let logical = bytes.to_vec();
        assert_eq!(logical[0], 7);
        assert!(logical[1..].iter().all(|b| *b == 0));
    })
    .join()
    .unwrap();
}
