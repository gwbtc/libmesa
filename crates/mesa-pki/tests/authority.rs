use mesa_crypto::KeyPair;
use mesa_pki::*;
fn candidate(peer: Peer, life: u32, rift: u32, seed: u8) -> Candidate {
    Candidate {
        peer,
        domain: "gw-btc".into(),
        life,
        rift,
        public_key: *KeyPair::from_seed(&[seed; 32]).public_key().as_bytes(),
        evidence: Buffer::new(vec![1, 2], 4).unwrap(),
    }
}
fn setup() -> (Authority, Provider) {
    let mut a = Authority::new(Limits::default(), 1).unwrap();
    let p = a.register("gw-btc", 0, 1).unwrap();
    a.commit(p.token).unwrap();
    let provider = a.provider("gw-btc").unwrap();
    a.set_status(
        "gw-btc",
        provider,
        ProviderStatus {
            available: true,
            ready: true,
        },
    )
    .unwrap();
    (a, provider)
}
fn install(a: &mut Authority, p: Provider, c: Candidate) -> Proposal {
    let prop = a.accept(p, a.revision(c.peer), c, None, None).unwrap();
    a.commit(prop.token).unwrap();
    prop
}
#[test]
fn proposal_commit_restore_revalidation_and_owned_buffers() {
    let (mut a, p) = setup();
    let c = candidate(u128::MAX, 1, 0, 3);
    let retained = c.evidence.clone();
    let proposal = a.accept(p, 0, c, None, None).unwrap();
    assert!(!a.policy(u128::MAX).unwrap().ordinary());
    assert!(a
        .peer(u128::MAX)
        .unwrap()
        .point
        .candidate
        .evidence
        .shares_storage(&retained));
    a.commit(proposal.token).unwrap();
    assert!(a.policy(u128::MAX).unwrap().ordinary());
    let mut restored = Authority::restore(Limits::default(), 2, &proposal.checkpoint).unwrap();
    assert!(!restored.policy(u128::MAX).unwrap().ordinary());
    assert_eq!(restored.commit(proposal.token), Err(Error::Stale));
    assert_eq!(
        restored.set_status(
            "gw-btc",
            p,
            ProviderStatus {
                available: true,
                ready: true
            }
        ),
        Err(Error::Stale)
    );
    let p2 = restored.provider("gw-btc").unwrap();
    restored
        .set_status(
            "gw-btc",
            p2,
            ProviderStatus {
                available: true,
                ready: true,
            },
        )
        .unwrap();
    assert!(!restored.policy(u128::MAX).unwrap().ordinary());
    install(&mut restored, p2, candidate(u128::MAX, 1, 0, 3));
    assert!(restored.policy(u128::MAX).unwrap().ordinary());
    drop(a);
    drop(restored);
    assert_eq!(retained.to_vec(), [1, 2, 0, 0]);
}
#[test]
fn lifecycle_history_provenance_and_operator_block() {
    let (mut a, p) = setup();
    install(&mut a, p, candidate(10, 1, 0, 3));
    let b = a.operator_block(10, true).unwrap();
    a.commit(b.token).unwrap();
    let w = a.withdraw("gw-btc", p, 10, a.revision(10)).unwrap();
    a.commit(w.token).unwrap();
    assert!(!a.policy(10).unwrap().recovery());
    install(&mut a, p, candidate(10, 2, 0, 4));
    let policy = a.policy(10).unwrap();
    assert!(policy.operator_blocked);
    assert!(!policy.withdrawn);
    assert!(!policy.ordinary());
    assert_eq!(a.peer(10).unwrap().history.len(), 1);
    let b = a.operator_block(10, false).unwrap();
    assert!(!a.policy(10).unwrap().ordinary());
    a.commit(b.token).unwrap();
    assert!(a.policy(10).unwrap().ordinary());
    let b = a.lifecycle("gw-btc", p, Lifecycle::Suspended).unwrap();
    assert!(!a.policy(10).unwrap().ordinary());
    a.commit(b.token).unwrap();
    assert!(a.peer(10).is_some());
    let b = a.register("gw-btc", 1, 2).unwrap();
    a.commit(b.token).unwrap();
    let p2 = a.provider("gw-btc").unwrap();
    a.set_status(
        "gw-btc",
        p2,
        ProviderStatus {
            available: true,
            ready: true,
        },
    )
    .unwrap();
    assert!(!a.policy(10).unwrap().ordinary());
    assert_eq!(
        a.accept(p, a.revision(10), candidate(10, 2, 0, 4), None, None),
        Err(Error::Stale)
    );
    install(&mut a, p2, candidate(10, 2, 0, 4));
    assert!(a.policy(10).unwrap().ordinary());
    let b = a.lifecycle("gw-btc", p2, Lifecycle::Removed).unwrap();
    a.commit(b.token).unwrap();
    assert!(!a.policy(10).unwrap().ordinary());
    assert!(a.register("gw-btc", 0, 1).is_err());
    let b = a.register("gw-btc", 2, 3).unwrap();
    a.commit(b.token).unwrap();
    assert_eq!(a.peer(10).unwrap().point.candidate.life, 2);
}
#[test]
fn rollback_domain_and_same_life_substitution_leave_state_unchanged() {
    let (mut a, p) = setup();
    install(&mut a, p, candidate(10, 3, 2, 3));
    let before = a.snapshot();
    for (c, error) in [
        (candidate(10, 2, 2, 3), Error::Rollback),
        (candidate(10, 3, 1, 3), Error::Rollback),
        (candidate(10, 3, 2, 4), Error::Conflict),
    ] {
        assert_eq!(a.accept(p, a.revision(10), c, None, None), Err(error));
        assert_eq!(a.snapshot(), before);
    }
    assert_eq!(
        a.accept(p, a.revision(10), candidate(10, 3, 2, 3), Some(10), None),
        Err(Error::Invalid)
    );
    let b = a.register("other", 0, 1).unwrap();
    a.commit(b.token).unwrap();
    let q = a.provider("other").unwrap();
    a.set_status(
        "other",
        q,
        ProviderStatus {
            available: true,
            ready: true,
        },
    )
    .unwrap();
    let mut c = candidate(10, 4, 2, 4);
    c.domain = "other".into();
    assert_eq!(
        a.accept(q, a.revision(10), c, None, None),
        Err(Error::Conflict)
    );
}
#[test]
fn superseded_commit_cannot_clear_withdrawal_and_unknown_peers_have_fences() {
    let (mut a, p) = setup();
    let first = a.accept(p, 0, candidate(10, 1, 0, 3), None, None).unwrap();
    let withdrawal = a.withdraw("gw-btc", p, 10, a.revision(10)).unwrap();
    assert_eq!(a.commit(first.token), Err(Error::Stale));
    assert!(!a.policy(10).unwrap().ordinary());
    a.commit(withdrawal.token).unwrap();
    assert!(a.policy(10).unwrap().withdrawn);
    // Even a durable but unconfirmed positive checkpoint is quarantined on crash.
    let restored = Authority::restore(Limits::default(), 2, &first.checkpoint).unwrap();
    assert!(!restored.policy(10).unwrap().ordinary());
    let w = a.withdraw("gw-btc", p, 99, 0).unwrap();
    assert!(a.revision(99) > 0);
    a.commit(w.token).unwrap();
    assert_eq!(
        a.accept(p, 0, candidate(99, 1, 0, 4), None, None),
        Err(Error::Stale)
    );
    install(&mut a, p, candidate(99, 1, 0, 4));
    assert!(a.policy(99).unwrap().ordinary());
}
#[test]
fn bounds_tombstones_exact_width_digest_and_recovery_validation() {
    let limits = Limits {
        peers: 1,
        domains: 1,
        history: 1,
        ..Limits::default()
    };
    let mut a = Authority::new(limits.clone(), 1).unwrap();
    let b = a.register("gw-btc", 0, 1).unwrap();
    a.commit(b.token).unwrap();
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
    let w = a.withdraw("gw-btc", p, 1, 0).unwrap();
    a.commit(w.token).unwrap();
    assert_eq!(a.withdraw("gw-btc", p, 2, 0), Err(Error::Capacity));
    install(&mut a, p, candidate(1, 1, 0, 3));
    install(&mut a, p, candidate(1, 2, 0, 4));
    let b = install(&mut a, p, candidate(1, 3, 0, 5));
    assert_eq!(a.peer(1).unwrap().history.len(), 1);
    assert_eq!(a.peer(1).unwrap().history[0].candidate.life, 2);
    assert_eq!(a.register("other", 0, 1), Err(Error::Capacity));
    let c = candidate(1, 1, 0, 3);
    let mut changed = c.clone();
    changed.evidence = vec![1, 2].into();
    assert_ne!(c.digest(), changed.digest());
    let mut malformed: serde_json::Value = serde_json::from_slice(&b.checkpoint.to_vec()).unwrap();
    malformed["peers"]["1"]["point"]["candidate"]["life"] = 0.into();
    assert!(
        Authority::restore(limits, 2, &serde_json::to_vec(&malformed).unwrap().into()).is_err()
    );
}

#[test]
fn evidence_refresh_only_updates_matching_point_and_fences_delayed_work() {
    let (mut a, p) = setup();
    install(&mut a, p, candidate(10, 1, 0, 3));
    let revision = a.revision(10);
    let mut fresh = candidate(10, 1, 0, 3);
    fresh.evidence = vec![9, 0, 0].into();
    let b = a.refresh_evidence(p, revision, fresh.clone()).unwrap();
    a.commit(b.token).unwrap();
    assert_eq!(
        a.peer(10).unwrap().point.candidate.evidence.to_vec(),
        [9, 0, 0]
    );
    assert_eq!(
        a.refresh_evidence(p, revision, fresh.clone()),
        Err(Error::Stale)
    );
    fresh.life = 2;
    assert_eq!(
        a.refresh_evidence(p, a.revision(10), fresh),
        Err(Error::Conflict)
    );
    let b = a.lifecycle("gw-btc", p, Lifecycle::Suspended).unwrap();
    a.commit(b.token).unwrap();
    let b = a.lifecycle("gw-btc", p, Lifecycle::Removed).unwrap();
    a.commit(b.token).unwrap();
    assert!(!a.policy(10).unwrap().ordinary());
}
#[test]
fn direct_batch_preserves_suffix_and_error_index() {
    let mut a = Authority::new(Limits::default(), 1).unwrap();
    let cmds = [
        Command::Register {
            domain: "gw-btc".into(),
            expected: 0,
            generation: 1,
        },
        Command::Register {
            domain: "other".into(),
            expected: 0,
            generation: 1,
        },
    ];
    let result = a
        .step_batch(
            &cmds,
            Budget {
                events: 2,
                proposals: 1,
                bytes: Limits::default().checkpoint_bytes,
            },
        )
        .unwrap();
    assert_eq!(result.results.len(), 1);
    assert!(!a.snapshot().domains.contains_key("other"));
    let result = a
        .step_batch(
            &cmds,
            Budget {
                events: 2,
                proposals: 2,
                bytes: Limits::default().checkpoint_bytes * 2,
            },
        )
        .unwrap();
    assert_eq!(result.results, vec![Err(Error::Stale)]);
}

#[test]
fn restriction_closes_readiness_even_when_checkpoint_capacity_is_exhausted() {
    let (mut original, p) = setup();
    let saved = install(&mut original, p, candidate(10, 1, 0, 3));
    let limits = Limits {
        checkpoint_bytes: saved.checkpoint.len(),
        ..Limits::default()
    };
    let mut a = Authority::restore(limits, 2, &saved.checkpoint).unwrap();
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
    install(&mut a, p, candidate(10, 1, 0, 3));
    assert!(a.policy(10).unwrap().ordinary());
    assert_eq!(
        a.lifecycle("gw-btc", p, Lifecycle::Suspended),
        Err(Error::Capacity)
    );
    assert!(!a.policy(10).unwrap().ordinary());
    assert!(!a.provider_status("gw-btc").ready);
}
