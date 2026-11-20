mod support;
use mesa_crypto::KeyPair;
use mesa_keys::{operations::Reply, *};
use support::*;
#[test]
fn both_arrival_orders_require_exact_committed_authority_and_reopened_material() {
    for ring_first in [false, true] {
        let (mut a, p) = authority();
        let mut s = store();
        let mut k = Activation::new(config()).unwrap();
        let c = candidate(1, 1, 0, 1);
        if ring_first {
            stage(&mut s, 1, c.clone(), 1);
            assert!(k.prepare(&a, &s, reference(1), None).is_err());
        } else {
            install(&mut a, p, c.clone());
            assert!(matches!(
                k.prepare(&a, &s, reference(1), None),
                Err(Error::MissingKey)
            ));
        }
        if ring_first {
            install(&mut a, p, c.clone())
        } else {
            stage(&mut s, 1, c, 1)
        }
        let q = k.prepare(&a, &s, reference(1), None).unwrap();
        assert!(k.operation(&a, &s, root()).is_err());
        let bytes = q.checkpoint.to_vec();
        assert!(!bytes.windows(32).any(|b| b == [1; 32]));
        k.commit(&a, &s, q.token).unwrap();
        let r = k.operation(&a, &s, root()).unwrap();
        let reply = s.execute(&r).unwrap();
        let Reply::Signature(sig) = k.complete(&a, r.ticket(), reply).unwrap() else {
            panic!()
        };
        r.transcript()
            .with_bytes(|b| KeyPair::from_seed(&[1; 32]).public_key().verify(b, &sig))
            .unwrap();
        assert!(k.complete(&a, r.ticket(), Reply::Signature(sig)).is_err());
        let mut c = config();
        c.incarnation += 1;
        let mut restored = Activation::restore(c, &q.checkpoint, 1).unwrap();
        assert_eq!(restored.snapshot().phase, Phase::Quiescent);
        assert!(restored.operation(&a, &s, root()).is_err());
        assert_eq!(restored.commit(&a, &s, q.token), Err(Error::Stale));
        commit(&mut restored, &a, &s, 1);
        assert!(restored.operation(&a, &s, root()).is_ok());
    }
}
#[test]
fn mismatches_and_evidence_refresh_never_activate_stale_material() {
    let (mut a, p) = authority();
    let mut s = store();
    let mut k = Activation::new(config()).unwrap();
    let c = candidate(1, 1, 0, 1);
    install(&mut a, p, c.clone());
    assert!(matches!(
        Material::from_seed(c.clone(), &[2; 32]),
        Err(Error::Conflict)
    ));
    let mut stale = c.clone();
    stale.evidence = vec![9].into();
    stage(&mut s, 1, stale, 1);
    assert!(matches!(
        k.prepare(&a, &s, reference(1), None),
        Err(Error::Conflict)
    ));
    stage(&mut s, 2, c.clone(), 1);
    commit(&mut k, &a, &s, 2);
    let mut refresh = c.clone();
    refresh.evidence = Buffer::new(vec![2], 4).unwrap();
    let q = a
        .refresh_evidence(p, a.revision(1), refresh.clone())
        .unwrap();
    a.commit(q.token).unwrap();
    assert!(k.operation(&a, &s, root()).is_err());
    assert!(k.prepare(&a, &s, reference(2), None).is_err());
    stage(&mut s, 3, refresh, 1);
    commit(&mut k, &a, &s, 3);
    assert_eq!(k.snapshot().manifest.history.len(), 1);
    let mut wrong = c;
    wrong.peer = 2;
    stage(&mut s, 4, wrong, 1);
    assert!(k.prepare(&a, &s, reference(4), None).is_err());
}
#[test]
fn cutover_cancels_jobs_checks_backend_reply_and_fences_tokens() {
    let (mut a, p) = authority();
    let mut s = store();
    let mut k = Activation::new(config()).unwrap();
    let c = candidate(1, 1, 0, 1);
    install(&mut a, p, c.clone());
    stage(&mut s, 1, c, 1);
    commit(&mut k, &a, &s, 1);
    let r = k.operation(&a, &s, root()).unwrap();
    assert!(matches!(
        k.complete(&a, r.ticket(), Reply::Signature([0; 64])),
        Err(Error::Backend)
    ));
    let old = s.execute(&r).unwrap();
    let c = candidate(1, 2, 0, 2);
    stage(&mut s, 2, c.clone(), 2);
    install(&mut a, p, c);
    let q = k.prepare(&a, &s, reference(2), None).unwrap();
    assert!(!k.has_operation(r.ticket()));
    assert!(matches!(k.complete(&a, r.ticket(), old), Err(Error::Stale)));
    let mut stale = q.token;
    stale.incarnation += 1;
    assert_eq!(k.commit(&a, &s, stale), Err(Error::Stale));
    k.commit(&a, &s, q.token).unwrap();
    let r = k.operation(&a, &s, root()).unwrap();
    let Reply::Signature(sig) = s.execute(&r).unwrap() else {
        panic!()
    };
    assert!(r
        .transcript()
        .with_bytes(|b| KeyPair::from_seed(&[1; 32]).public_key().verify(b, &sig))
        .is_err());
    k.complete(&a, r.ticket(), Reply::Signature(sig)).unwrap();
}
#[test]
fn timeout_cancel_limits_and_authority_loss_are_fail_closed() {
    let (mut a, p) = authority();
    let mut s = store();
    let mut k = Activation::new(config()).unwrap();
    let c = candidate(1, 1, 0, 1);
    stage(&mut s, 1, c.clone(), 1);
    install(&mut a, p, c);
    let q = k.prepare(&a, &s, reference(1), None).unwrap();
    k.advance(20).unwrap();
    assert_eq!(k.commit(&a, &s, q.token), Err(Error::Stale));
    assert_eq!(k.advance(19), Err(Error::Clock));
    let q = k.prepare(&a, &s, reference(1), None).unwrap();
    k.cancel(q.token).unwrap();
    assert_eq!(k.cancel(q.token), Err(Error::Stale));
    commit(&mut k, &a, &s, 1);
    let mut jobs = vec![];
    for _ in 0..4 {
        jobs.push(k.operation(&a, &s, root()).unwrap())
    }
    assert!(matches!(k.operation(&a, &s, root()), Err(Error::Capacity)));
    k.cancel_operation(jobs[0].ticket()).unwrap();
    k.advance(40).unwrap();
    assert_eq!(k.snapshot().operations, 0);
    let q = k.prepare(&a, &s, reference(1), None).unwrap();
    let w = a.withdraw("gw-btc", p, 1, a.revision(1)).unwrap();
    a.commit(w.token).unwrap();
    assert_eq!(k.commit(&a, &s, q.token), Err(Error::Stale));
    assert_eq!(k.snapshot().phase, Phase::Quiescent);
}
#[test]
fn agreement_is_scoped_to_current_peer_and_zeroizing_opaque_result() {
    let (mut a, p) = authority();
    let mut s = store();
    let mut k = Activation::new(config()).unwrap();
    let c = candidate(1, 1, 0, 1);
    stage(&mut s, 1, c.clone(), 1);
    install(&mut a, p, c);
    install(&mut a, p, candidate(2, 1, 0, 2));
    commit(&mut k, &a, &s, 1);
    let r = k
        .operation(&a, &s, operations::Purpose::Agreement { peer: 2 })
        .unwrap();
    let Reply::Agreement(secret) = k.complete(&a, r.ticket(), s.execute(&r).unwrap()).unwrap()
    else {
        panic!()
    };
    assert_eq!(
        secret.as_bytes(),
        KeyPair::from_seed(&[2; 32])
            .agree(&KeyPair::from_seed(&[1; 32]).public_key())
            .unwrap()
            .as_bytes()
    );
    let r = k
        .operation(&a, &s, operations::Purpose::Agreement { peer: 2 })
        .unwrap();
    install(&mut a, p, candidate(2, 2, 0, 3));
    assert!(matches!(
        k.complete(&a, r.ticket(), s.execute(&r).unwrap()),
        Err(Error::Stale)
    ));
}
#[test]
fn bounded_history_pins_retirement_and_idempotent_delete_replay() {
    let (mut a, p) = authority();
    let mut s = store();
    let mut cfg = config();
    cfg.history = 1;
    let mut k = Activation::new(cfg.clone()).unwrap();
    for i in 1..=2 {
        let c = candidate(1, i, 0, i as u8);
        install(&mut a, p, c.clone());
        stage(&mut s, i as u64, c, i as u8);
        commit(&mut k, &a, &s, i as u64);
    }
    k.pin(1, reference(1)).unwrap();
    assert!(matches!(k.retire(&a, reference(1)), Err(Error::Busy)));
    k.unpin(1).unwrap();
    let c = candidate(1, 3, 0, 3);
    install(&mut a, p, c.clone());
    stage(&mut s, 3, c, 3);
    assert!(matches!(
        k.prepare(&a, &s, reference(3), None),
        Err(Error::Capacity)
    ));
    let q = k.retire(&a, reference(1)).unwrap();
    assert_eq!(k.delete_retired(&mut s, reference(1)), Err(Error::Busy));
    k.commit(&a, &s, q.token).unwrap();
    assert_eq!(k.snapshot().phase, Phase::Quiescent);
    k.delete_retired(&mut s, reference(1)).unwrap();
    assert!(!s.contains(reference(1)));
    cfg.incarnation += 1;
    let mut restored = Activation::restore(cfg, &q.checkpoint, q.token.revision).unwrap();
    restored.delete_retired(&mut s, reference(1)).unwrap();
    assert!(s.contains(reference(2)));
    commit(&mut restored, &a, &s, 3);
    assert_eq!(
        s.import(
            reference(1),
            Material::from_seed(candidate(1, 1, 0, 1), &[1; 32]).unwrap()
        ),
        Err(Error::Stale)
    );
}
#[test]
fn old_world_restore_requires_external_epoch_and_revision_floor() {
    let (mut a, p) = authority();
    let mut s = store();
    let mut k = Activation::new(config()).unwrap();
    let c = candidate(1, 1, 0, 1);
    stage(&mut s, 1, c.clone(), 1);
    install(&mut a, p, c);
    let q = commit(&mut k, &a, &s, 1);
    assert!(matches!(
        Activation::restore(config(), &q.checkpoint, 2),
        Err(Error::Rollback)
    ));
    let mut c = config();
    c.host_epoch += 1;
    assert!(matches!(
        Activation::restore(c, &q.checkpoint, 0),
        Err(Error::Rollback)
    ));
    let missing = store();
    let mut restored = Activation::restore(config(), &q.checkpoint, 1).unwrap();
    assert!(matches!(
        restored.prepare(&a, &missing, reference(1), None),
        Err(Error::MissingKey)
    ));
    let mut v: serde_json::Value = serde_json::from_slice(&q.checkpoint.to_vec()).unwrap();
    v["active"] = serde_json::Value::Null;
    assert!(matches!(
        Activation::restore(config(), &serde_json::to_vec(&v).unwrap().into(), 1),
        Err(Error::Invalid)
    ));
}
#[test]
fn full_width_identifiers_survive_public_snapshots_and_checkpoint_restore() {
    let (mut a, p) = authority();
    let mut cfg = config();
    cfg.peer = u128::MAX;
    cfg.incarnation = u128::MAX;
    cfg.host_epoch = u128::MAX;
    let reference = KeyRef {
        backend: u128::MAX,
        object: u128::MAX,
        version: 1,
    };
    let c = candidate(u128::MAX, 1, 0, 1);
    install(&mut a, p, c.clone());
    let mut s = store();
    s.import(reference, Material::from_seed(c, &[1; 32]).unwrap())
        .unwrap();
    let mut k = Activation::new(cfg.clone()).unwrap();
    let q = k.prepare(&a, &s, reference, None).unwrap();
    k.commit(&a, &s, q.token).unwrap();
    let bytes = serde_json::to_vec(&k.snapshot()).unwrap();
    assert!(String::from_utf8(bytes)
        .unwrap()
        .contains(&u128::MAX.to_string()));
    cfg.incarnation -= 1;
    let restored = Activation::restore(cfg, &q.checkpoint, 1).unwrap();
    assert_eq!(
        restored.snapshot().manifest.active.unwrap().reference,
        reference
    );
}

#[test]
fn pending_retirement_rejects_pins_without_blocking_other_keys() {
    let (mut a, p) = authority();
    let mut s = store();
    let mut k = Activation::new(config()).unwrap();
    for life in 1..=3 {
        let c = candidate(1, life, 0, life as u8);
        install(&mut a, p, c.clone());
        stage(&mut s, life as u64, c, life as u8);
        commit(&mut k, &a, &s, life as u64);
    }
    let q = k.retire(&a, reference(1)).unwrap();
    assert_eq!(k.pin(77, reference(1)), Err(Error::Busy));
    // Rejection must not consume the pin ID or block unrelated history/active keys.
    k.pin(77, reference(2)).unwrap();
    k.pin(78, reference(3)).unwrap();
    k.commit(&a, &s, q.token).unwrap();
    assert_eq!(k.pin(79, reference(1)), Err(Error::MissingKey));
    k.delete_retired(&mut s, reference(1)).unwrap();
    assert!(!s.contains(reference(1)));
    assert!(s.contains(reference(2)) && s.contains(reference(3)));
    assert!(matches!(k.retire(&a, reference(2)), Err(Error::Busy)));
    k.unpin(77).unwrap();
    assert!(k.retire(&a, reference(2)).is_ok());
}

#[test]
fn cancelled_or_expired_retirement_allows_pinning_again() {
    for expire in [false, true] {
        let (mut a, p) = authority();
        let mut s = store();
        let mut k = Activation::new(config()).unwrap();
        for life in 1..=2 {
            let c = candidate(1, life, 0, life as u8);
            install(&mut a, p, c.clone());
            stage(&mut s, life as u64, c, life as u8);
            commit(&mut k, &a, &s, life as u64);
        }
        let q = k.retire(&a, reference(1)).unwrap();
        assert_eq!(k.pin(77, reference(1)), Err(Error::Busy));
        if expire {
            k.advance(k.deadline().unwrap()).unwrap();
        } else {
            k.cancel(q.token).unwrap();
        }
        assert_eq!(k.commit(&a, &s, q.token), Err(Error::Stale));
        k.pin(77, reference(1)).unwrap();
        assert!(matches!(k.retire(&a, reference(1)), Err(Error::Busy)));
        assert_eq!(k.delete_retired(&mut s, reference(1)), Err(Error::Busy));
        assert!(s.contains(reference(1)));
    }
}
