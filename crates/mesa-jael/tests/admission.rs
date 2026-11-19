use mesa_crypto::KeyPair;
use mesa_jael::*;
use mesa_pki::{Candidate, Error, Lifecycle, Provider, ProviderStatus};
fn c(peer: u128, life: u32) -> Candidate {
    Candidate {
        peer,
        domain: "gw-btc".into(),
        life,
        rift: 0,
        public_key: *KeyPair::from_seed(&[life as u8; 32])
            .public_key()
            .as_bytes(),
        evidence: vec![1, 2, 0, 0].into(),
    }
}
fn persist(actions: &[Action]) -> mesa_pki::Proposal {
    actions
        .iter()
        .find_map(|a| {
            if let Action::Persist(p) = a {
                Some(p.clone())
            } else {
                None
            }
        })
        .unwrap()
}
fn ticket(actions: &[Action]) -> Ticket {
    actions
        .iter()
        .find_map(|a| {
            if let Action::Verify { ticket, .. } = a {
                Some(*ticket)
            } else {
                None
            }
        })
        .unwrap()
}
fn setup(config: Config) -> (Jael, Provider) {
    let mut j = Jael::new(config, 1).unwrap();
    let p = persist(&j.register("gw-btc", 0, 1).unwrap());
    j.commit(p.token).unwrap();
    let provider = j.authority().provider("gw-btc").unwrap();
    j.set_status(
        "gw-btc",
        provider,
        ProviderStatus {
            available: true,
            ready: true,
        },
    )
    .unwrap();
    (j, provider)
}
fn accept(j: &mut Jael, c: Candidate) {
    let t = ticket(&j.resolve(c).unwrap());
    let p = persist(
        &j.complete(
            "gw-btc",
            t,
            Verdict::Accept {
                sponsor: None,
                fief: None,
            },
        )
        .unwrap(),
    );
    j.commit(p.token).unwrap();
}
struct FixtureProfile;
impl AdmissionProfile for FixtureProfile {
    fn screen(&self, p: &Buffer) -> Result<Candidate, Error> {
        if p.to_vec() != b"attestation" {
            return Err(Error::Invalid);
        }
        Ok(c(10, 1))
    }
}
#[test]
fn mesa_ingress_screens_before_host_notification_and_never_queues_messages() {
    let (mut j, _) = setup(Config::default());
    assert_eq!(
        j.receive(&FixtureProfile, b"application message".to_vec().into()),
        Err(Error::Invalid)
    );
    assert_eq!(j.pending_count(), 0);
    let result = j
        .receive(&FixtureProfile, b"attestation".to_vec().into())
        .unwrap();
    let t = ticket(&result);
    assert!(j.authority().peer(10).is_none());
    assert!(matches!(result[0], Action::Verify { .. }));
    assert_eq!(
        j.receive(&FixtureProfile, b"attestation".to_vec().into())
            .unwrap(),
        vec![Action::Timer(j.deadline())]
    );
    let p = persist(
        &j.complete(
            "gw-btc",
            t,
            Verdict::Accept {
                sponsor: None,
                fief: None,
            },
        )
        .unwrap(),
    );
    assert!(!j.authority().policy(10).unwrap().ordinary());
    j.commit(p.token).unwrap();
    assert!(j.authority().policy(10).unwrap().ordinary());
}
#[test]
fn rejection_unavailability_and_withdrawal_are_distinct() {
    let (mut j, p) = setup(Config::default());
    accept(&mut j, c(10, 1));
    let accepted = j.authority().peer(10).unwrap().clone();
    let t = ticket(&j.resolve(c(10, 2)).unwrap());
    j.complete("gw-btc", t, Verdict::Reject).unwrap();
    assert_eq!(j.authority().peer(10).unwrap(), &accepted);
    assert!(j.authority().policy(10).unwrap().ordinary());
    let t = ticket(&j.resolve(c(10, 2)).unwrap());
    j.complete("gw-btc", t, Verdict::Unavailable).unwrap();
    assert!(j.authority().policy(10).unwrap().ordinary());
    assert_eq!(
        j.complete(
            "gw-btc",
            t,
            Verdict::Accept {
                sponsor: None,
                fief: None
            }
        ),
        Err(Error::Stale)
    );
    let actions = j
        .withdraw("gw-btc", p, 10, j.authority().revision(10))
        .unwrap();
    assert!(actions.contains(&Action::Solicit { peer: 10 }));
    assert_eq!(j.pending_count(), 0);
    assert!(j.authority().policy(10).unwrap().recovery());
    assert!(!j.authority().policy(10).unwrap().ordinary());
    assert_eq!(
        j.complete(
            "gw-btc",
            t,
            Verdict::Accept {
                sponsor: None,
                fief: None
            }
        ),
        Err(Error::Stale)
    );
    let w = persist(&actions);
    j.commit(w.token).unwrap();
    accept(&mut j, c(10, 2));
    assert!(j.authority().policy(10).unwrap().ordinary());
}
#[test]
fn unknown_withdrawal_wrong_result_and_domain_removal_fence_pending_work() {
    let (mut j, p) = setup(Config::default());
    let t = ticket(&j.resolve(c(10, 1)).unwrap());
    let mut forged = t;
    forged.digest[0] ^= 1;
    for (domain, ticket) in [("wrong", t), ("gw-btc", forged)] {
        assert_eq!(
            j.complete(domain, ticket, Verdict::Reject),
            Err(Error::Stale)
        );
    }
    j.withdraw("gw-btc", p, 10, 0).unwrap();
    assert_eq!(j.pending_count(), 0);
    assert_eq!(
        j.complete(
            "gw-btc",
            t,
            Verdict::Accept {
                sponsor: None,
                fief: None
            }
        ),
        Err(Error::Stale)
    );
    let t = ticket(&j.resolve(c(10, 1)).unwrap());
    j.lifecycle("gw-btc", p, Lifecycle::Removed).unwrap();
    assert_eq!(j.pending_count(), 0);
    let proposal = persist(&j.register("gw-btc", 1, 2).unwrap());
    j.commit(proposal.token).unwrap();
    let p2 = j.authority().provider("gw-btc").unwrap();
    j.set_status(
        "gw-btc",
        p2,
        ProviderStatus {
            available: true,
            ready: true,
        },
    )
    .unwrap();
    assert_eq!(j.complete("gw-btc", t, Verdict::Reject), Err(Error::Stale));
    accept(&mut j, c(10, 1));
    assert!(j.authority().policy(10).unwrap().ordinary());
}
#[test]
fn provider_restart_readiness_and_operator_blocks_do_not_resurrect_jobs() {
    let (mut j, p) = setup(Config::default());
    accept(&mut j, c(10, 1));
    let t = ticket(&j.resolve(c(10, 2)).unwrap());
    j.set_status(
        "gw-btc",
        p,
        ProviderStatus {
            available: false,
            ready: true,
        },
    )
    .unwrap();
    assert!(j.authority().policy(10).unwrap().ordinary());
    j.set_status(
        "gw-btc",
        p,
        ProviderStatus {
            available: true,
            ready: false,
        },
    )
    .unwrap();
    assert_eq!(j.pending_count(), 0);
    j.set_status(
        "gw-btc",
        p,
        ProviderStatus {
            available: true,
            ready: true,
        },
    )
    .unwrap();
    assert!(!j.authority().policy(10).unwrap().ordinary());
    assert_eq!(j.complete("gw-btc", t, Verdict::Reject), Err(Error::Stale));
    accept(&mut j, c(10, 1));
    let t = ticket(&j.resolve(c(10, 2)).unwrap());
    let b = persist(&j.operator_block(10, true).unwrap());
    j.commit(b.token).unwrap();
    assert_eq!(j.complete("gw-btc", t, Verdict::Reject), Err(Error::Stale));
    assert_eq!(j.resolve(c(10, 2)), Err(Error::Unavailable));
}
#[test]
fn bounded_retries_new_tickets_cancellation_and_large_time_jumps() {
    let config = Config {
        request_timeout: 10,
        retry_after: 3,
        attempts: 2,
        work_per_tick: 1,
        ..Config::default()
    };
    let (mut j, _) = setup(config);
    let t1 = ticket(&j.resolve(c(10, 1)).unwrap());
    let t2 = ticket(&j.resolve(c(11, 1)).unwrap());
    let retry = ticket(&j.advance(1000).unwrap());
    assert_ne!(retry.request, t1.request);
    assert_eq!(j.deadline(), Some(10));
    assert_eq!(j.complete("gw-btc", t1, Verdict::Reject), Err(Error::Stale));
    j.cancel(retry.request).unwrap();
    let retry2 = ticket(&j.advance(1000).unwrap());
    assert_ne!(retry2.request, t2.request);
    let end = j.advance(2000).unwrap();
    assert!(end.iter().any(|a| matches!(
        a,
        Action::Finished {
            reason: End::TimedOut,
            ..
        }
    )));
    assert_eq!(j.pending_count(), 0);
    assert_eq!(j.advance(1999), Err(Error::Clock));
    assert_eq!(j.advance(u64::MAX).unwrap(), vec![Action::Timer(None)]);
    assert_eq!(j.resolve(c(12, 1)), Err(Error::Clock));
    assert_eq!(j.pending_count(), 0);
}
#[test]
fn global_screening_pending_bytes_and_batch_prefix_are_bounded() {
    let config = Config {
        pending: 1,
        pending_bytes: 4,
        dispatches: 3,
        ..Config::default()
    };
    let (mut j, _) = setup(config);
    assert_eq!(
        j.receive(&FixtureProfile, b"bad".to_vec().into()),
        Err(Error::Invalid)
    );
    let t = ticket(&j.resolve(c(10, 1)).unwrap());
    assert_eq!(j.resolve(c(11, 1)), Err(Error::Capacity));
    j.cancel(t.request).unwrap();
    assert_eq!(j.resolve(c(12, 1)), Err(Error::Capacity));
    j.advance(1000).unwrap();
    assert!(j.resolve(c(12, 1)).is_ok());
    let (mut j, _) = setup(Config::default());
    let before = j.authority().snapshot();
    assert!(matches!(
        j.step_batch(
            &[Input::Resolve(c(10, 1))],
            Budget {
                events: 1,
                records: 0,
                bytes: 0
            }
        ),
        Err(Error::Capacity)
    ));
    assert_eq!(j.authority().snapshot(), before);
    assert_eq!(j.pending_count(), 0);
    let (r, b) = j.envelope();
    let batch = j
        .step_batch(
            &[Input::Resolve(c(10, 1)), Input::Advance(0)],
            Budget {
                events: 2,
                records: r,
                bytes: b,
            },
        )
        .unwrap();
    assert_eq!(batch.results.len(), 1);
    let retained = match &batch.results[0].as_ref().unwrap()[0] {
        Action::Verify { candidate, .. } => candidate.evidence.clone(),
        _ => panic!(),
    };
    drop(batch);
    drop(j);
    assert_eq!(retained.to_vec(), [1, 2, 0, 0]);
}
#[test]
fn subscriptions_report_changes_and_restore_drops_jobs() {
    let config = Config {
        subscriptions: 1,
        ..Config::default()
    };
    let (mut j, _) = setup(config.clone());
    j.subscribe(10).unwrap();
    assert_eq!(j.subscribe(11), Err(Error::Capacity));
    let t = ticket(&j.resolve(c(10, 1)).unwrap());
    let actions = j
        .complete(
            "gw-btc",
            t,
            Verdict::Accept {
                sponsor: None,
                fief: None,
            },
        )
        .unwrap();
    assert!(actions
        .iter()
        .any(|a| matches!(a, Action::Changed { peer: 10, .. })));
    let p = persist(&actions);
    let mut restart = Jael::restore(config, 2, &p.checkpoint).unwrap();
    assert_eq!(restart.pending_count(), 0);
    assert_eq!(restart.deadline(), None);
    assert_eq!(
        restart.complete("gw-btc", t, Verdict::Reject),
        Err(Error::Stale)
    );
    assert!(!restart.authority().policy(10).unwrap().ordinary());
    j.unsubscribe(10);
    j.subscribe(11).unwrap();
}

#[test]
fn direct_lookup_needs_only_name_and_uses_the_same_acceptance_and_fences() {
    let (mut j, p) = setup(Config::default());
    let lookup = j.resolve_peer("gw-btc", 10).unwrap();
    let t = match lookup[0] {
        Action::Resolve { ticket, .. } => ticket,
        _ => panic!(),
    };
    assert_eq!(j.pending_bytes(), 0);
    assert_eq!(
        j.resolved("gw-btc", t, c(11, 1), None, None),
        Err(Error::Stale)
    );
    let proposal = persist(&j.resolved("gw-btc", t, c(10, 1), None, None).unwrap());
    assert!(!j.authority().policy(10).unwrap().ordinary());
    j.commit(proposal.token).unwrap();
    assert!(j.authority().policy(10).unwrap().ordinary());
    let lookup = j.resolve_peer("gw-btc", 10).unwrap();
    let t = match lookup[0] {
        Action::Resolve { ticket, .. } => ticket,
        _ => panic!(),
    };
    assert_eq!(
        j.resolved("gw-btc", t, c(10, 0), None, None),
        Err(Error::Invalid)
    );
    j.withdraw("gw-btc", p, 10, j.authority().revision(10))
        .unwrap();
    assert_eq!(
        j.resolved("gw-btc", t, c(10, 2), None, None),
        Err(Error::Stale)
    );
}
#[test]
fn lookup_timeout_retries_are_correlated_and_bounded() {
    let (mut j, _) = setup(Config {
        request_timeout: 5,
        attempts: 2,
        ..Config::default()
    });
    let lookup = j.resolve_peer("gw-btc", 10).unwrap();
    let t = match lookup[0] {
        Action::Resolve { ticket, .. } => ticket,
        _ => panic!(),
    };
    let retry = j.advance(5).unwrap();
    let t2 = retry
        .iter()
        .find_map(|a| {
            if let Action::Resolve { ticket, .. } = a {
                Some(*ticket)
            } else {
                None
            }
        })
        .unwrap();
    assert_ne!(t, t2);
    assert_eq!(
        j.resolved("gw-btc", t, c(10, 1), None, None),
        Err(Error::Stale)
    );
    assert!(j.advance(10).unwrap().contains(&Action::Finished {
        request: t2.request,
        reason: End::TimedOut
    }));
    assert_eq!(j.pending_count(), 0);
}
