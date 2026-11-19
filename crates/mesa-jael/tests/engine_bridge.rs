//! Identical real-signature read harness with Jael and direct authority orchestration.
use mesa_core::{protection::SignedPublic, *};
use mesa_crypto::KeyPair;
use mesa_jael::{Action as JAction, Config as JConfig, Jael, Verdict};
use mesa_pki::{Authority, Candidate, Limits, Provider, ProviderStatus};
use std::collections::{BTreeMap, VecDeque};
fn key(seed: u8) -> KeyPair {
    KeyPair::from_seed(&[seed; 32])
}
fn view(id: u128, life: u32) -> PreconfiguredPeer {
    PreconfiguredPeer::new(PeerId(id), "gw-btc", life, 0, KeyHandle(id as u64)).unwrap()
}
fn candidate(life: u32) -> Candidate {
    Candidate {
        peer: 2,
        domain: "gw-btc".into(),
        life,
        rift: 0,
        public_key: *key(life as u8 + 1).public_key().as_bytes(),
        evidence: vec![5, 0].into(),
    }
}
enum Manager {
    Raw(Box<Authority>),
    Jael(Box<Jael>),
}
impl Manager {
    fn new(jael: bool) -> Self {
        let mut m = if jael {
            Self::Jael(Box::new(Jael::new(JConfig::default(), 1).unwrap()))
        } else {
            Self::Raw(Box::new(Authority::new(Limits::default(), 1).unwrap()))
        };
        match &mut m {
            Self::Raw(a) => {
                let p = a.register("gw-btc", 0, 1).unwrap();
                a.commit(p.token).unwrap();
                let p = a.provider("gw-btc").unwrap();
                a.set_status(
                    "gw-btc",
                    p,
                    ProviderStatus {
                        available: true,
                        ready: true,
                    },
                )
                .unwrap();
            }
            Self::Jael(j) => {
                let actions = j.register("gw-btc", 0, 1).unwrap();
                let JAction::Persist(p) = actions
                    .iter()
                    .find(|a| matches!(a, JAction::Persist(_)))
                    .unwrap()
                else {
                    panic!()
                };
                j.commit(p.token).unwrap();
                let p = j.authority().provider("gw-btc").unwrap();
                j.set_status(
                    "gw-btc",
                    p,
                    ProviderStatus {
                        available: true,
                        ready: true,
                    },
                )
                .unwrap();
            }
        }
        m
    }
    fn a(&self) -> &Authority {
        match self {
            Self::Raw(a) => a,
            Self::Jael(j) => j.authority(),
        }
    }
    fn provider(&self) -> Provider {
        self.a().provider("gw-btc").unwrap()
    }
    fn propose(&mut self, c: Candidate) -> mesa_pki::Token {
        let provider = self.provider();
        match self {
            Self::Raw(a) => {
                a.accept(provider, a.revision(2), c, None, None)
                    .unwrap()
                    .token
            }
            Self::Jael(j) => {
                let actions = j.resolve(c).unwrap();
                let t = actions
                    .iter()
                    .find_map(|a| {
                        if let JAction::Verify { ticket, .. } = a {
                            Some(*ticket)
                        } else {
                            None
                        }
                    })
                    .unwrap();
                j.complete(
                    "gw-btc",
                    t,
                    Verdict::Accept {
                        sponsor: None,
                        fief: None,
                    },
                )
                .unwrap()
                .iter()
                .find_map(|a| {
                    if let JAction::Persist(p) = a {
                        Some(p.token)
                    } else {
                        None
                    }
                })
                .unwrap()
            }
        }
    }
    fn commit(&mut self, t: mesa_pki::Token) {
        match self {
            Self::Raw(a) => a.commit(t).unwrap(),
            Self::Jael(j) => {
                j.commit(t).unwrap();
            }
        }
    }
    fn withdraw(&mut self) {
        let p = self.provider();
        let revision = self.a().revision(2);
        match self {
            Self::Raw(a) => {
                a.withdraw("gw-btc", p, 2, revision).unwrap();
            }
            Self::Jael(j) => {
                j.withdraw("gw-btc", p, 2, revision).unwrap();
            }
        }
    }
}
fn reader() -> Engine<SignedPublic> {
    Engine::new(
        Config {
            max_peers: 1,
            ..Config::default()
        },
        view(1, 1),
        SignedPublic::new(KeyHandle(1), key(1), BTreeMap::new()),
    )
    .unwrap()
}
fn publisher(life: u32, seed: u8) -> Engine<SignedPublic> {
    let mut e = Engine::new(
        Config::default(),
        view(2, life),
        SignedPublic::new(
            KeyHandle(2),
            key(seed),
            BTreeMap::from([(KeyHandle(1), key(1).public_key())]),
        ),
    )
    .unwrap();
    e.step(Event::InstallPeer(view(1, 1))).unwrap();
    e.step(Event::SetAttachment {
        peer: PeerId(1),
        attachment: Some(Attachment(7)),
    })
    .unwrap();
    e.step(Event::Bind {
        path: b"object".to_vec(),
        bytes: vec![42; 8192],
        access: Access::Public,
    })
    .unwrap();
    e
}
fn exchange(
    reader: &mut Engine<SignedPublic>,
    publisher: &mut Engine<SignedPublic>,
    id: u64,
) -> Vec<Action> {
    let mut queue = VecDeque::from([(
        true,
        reader
            .step(Event::Read {
                id,
                peer: PeerId(2),
                path: b"object".to_vec(),
            })
            .unwrap(),
    )]);
    let mut observed = vec![];
    let mut count = 0;
    while let Some((from_reader, actions)) = queue.pop_front() {
        for a in actions {
            if let Action::Send { bytes, .. } = &a {
                let receiver = if from_reader {
                    &mut *publisher
                } else {
                    &mut *reader
                };
                let output = receiver
                    .step(Event::Receive {
                        claimed_peer: PeerId(if from_reader { 1 } else { 2 }),
                        attachment: Attachment(7),
                        bytes,
                    })
                    .unwrap();
                queue.push_back((!from_reader, output));
            }
            observed.push(a);
        }
        count += 1;
        assert!(count < 1000);
    }
    observed
}
#[test]
fn raw_and_jael_install_rotate_gate_and_reject_old_signers() {
    for use_jael in [false, true] {
        let mut m = Manager::new(use_jael);
        let mut reader = reader();
        let token = m.propose(candidate(1));
        assert!(m.a().sync_peer(&mut reader, 2).unwrap().is_empty());
        assert_eq!(reader.usage().peers, 0);
        m.commit(token);
        m.a().sync_peer(&mut reader, 2).unwrap();
        reader
            .step(Event::SetAttachment {
                peer: PeerId(2),
                attachment: Some(Attachment(7)),
            })
            .unwrap();
        assert!(exchange(&mut reader, &mut publisher(1, 2), 1)
            .iter()
            .any(|a| matches!(a,Action::ReadFinished{result:Ok(b),..} if b==&vec![42;8192])));
        reader
            .step(Event::Read {
                id: 2,
                peer: PeerId(2),
                path: b"pending".to_vec(),
            })
            .unwrap();
        let token = m.propose(candidate(2));
        let actions = m.a().sync_peer(&mut reader, 2).unwrap();
        assert!(actions.contains(&Action::ReadFinished {
            id: 2,
            result: Err(ReadFailure::Blocked)
        }));
        m.commit(token);
        m.a().sync_peer(&mut reader, 2).unwrap();
        let attack = exchange(&mut reader, &mut publisher(2, 2), 3);
        assert!(attack.contains(&Action::Dropped(DropReason::Protection)));
        assert!(!attack
            .iter()
            .any(|a| matches!(a, Action::ReadFinished { result: Ok(_), .. })));
        reader.step(Event::Cancel { id: 3 }).unwrap();
        assert!(exchange(&mut reader, &mut publisher(2, 3), 4)
            .iter()
            .any(|a| matches!(a, Action::ReadFinished { result: Ok(_), .. })));
        // A dedicated key slot supports many rotations even at one-peer capacity.
        for life in 3..20 {
            let t = m.propose(candidate(life));
            m.commit(t);
            m.a().sync_peer(&mut reader, 2).unwrap();
        }
        m.withdraw();
        m.a().sync_peer(&mut reader, 2).unwrap();
        assert_eq!(
            reader.step(Event::Read {
                id: 5,
                peer: PeerId(2),
                path: b"object".to_vec()
            }),
            Err(Error::Blocked)
        );
    }
}
#[test]
fn dynamic_key_cas_failure_and_same_life_substitution_preserve_key() {
    let mut reader = reader();
    let mut m = Manager::new(false);
    let t = m.propose(candidate(1));
    m.commit(t);
    m.a().sync_peer(&mut reader, 2).unwrap();
    let before = reader.snapshot();
    let old = before.peers[0].clone();
    let mut changed = old.peer.clone();
    changed.life = 2;
    assert_eq!(
        reader.install_public_credential(
            host::CredentialUpdate {
                peer: changed,
                expected_generation: 99,
                generation: 100,
                breach: false
            },
            key(9).public_key()
        ),
        Err(Error::StaleGeneration)
    );
    assert_eq!(reader.snapshot(), before);
    assert_eq!(
        reader.remote_public_key(PeerId(2)),
        Some(*key(2).public_key().as_bytes())
    );
    assert_eq!(
        reader.install_public_credential(
            host::CredentialUpdate {
                peer: old.peer,
                expected_generation: old.credential_generation,
                generation: old.credential_generation + 1,
                breach: false
            },
            key(9).public_key()
        ),
        Err(Error::KeyConflict)
    );
}
