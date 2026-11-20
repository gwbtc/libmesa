mod support;
use mesa_crypto::KeyPair;
use mesa_flow::*;
use std::sync::Arc;
use support::*;
fn rotate(
    h: &mut Harness,
    i: usize,
    local: mesa_core::PreconfiguredPeer,
    remote: mesa_core::PreconfiguredPeer,
    seed: u8,
    remote_seed: u8,
) {
    h.nodes[i].quiesce().unwrap();
    let plan = h.nodes[i]
        .credential_plan(&local, std::slice::from_ref(&remote))
        .unwrap();
    assert!(plan.retired.is_empty());
    let before = h.nodes[i].checkpoint().clone();
    assert_eq!(plan.checkpoint, before);
    h.boot[i] += 2;
    h.stores[i].incarnation = h.boot[i];
    let generation = h.nodes[i].local_generation() + 1;
    h.nodes[i]
        .activate_credentials(
            local,
            Arc::new(KeyPair::from_seed(&[seed; 32])),
            vec![(remote, KeyPair::from_seed(&[remote_seed; 32]).public_key())],
            plan.checkpoint,
            generation,
            h.boot[i],
        )
        .unwrap();
}
#[test]
fn real_same_rift_exchange_preserves_committed_outbox_receipts_and_message_ids() {
    let mut h = Harness::new(config());
    h.send(0, 0, payload(8192));
    h.pump();
    h.run(60);
    h.settled(0, 1);
    h.send(0, 1, payload(4096));
    h.queue.clear();
    let before = h.nodes[0].checkpoint().clone();
    let mut changed = view(0);
    changed.life = 2;
    rotate(&mut h, 0, changed.clone(), view(1), 9, 2);
    rotate(&mut h, 1, view(1), changed, 2, 9);
    assert_eq!(h.nodes[0].checkpoint(), &before);
    assert!(h.nodes[0].step(Event::AdvanceTo(59)).is_err());
    h.run(300);
    h.settled(0, 2);
    assert_eq!(h.stores[1].effects.len(), 2);
    assert_eq!(h.stores[1].effects.values().last().unwrap(), &payload(4096));
}
#[test]
fn local_and_remote_rift_retire_outbox_and_old_completion_tokens() {
    for local_change in [false, true] {
        let mut h = Harness::new(config());
        h.send(0, 0, payload(100));
        h.queue.clear();
        h.nodes[0].quiesce().unwrap();
        let old = h.nodes[0].checkpoint().clone();
        let mut local = view(0);
        let mut remote = view(1);
        if local_change {
            local.rift = 1
        } else {
            remote.rift = 1
        }
        let p = h.nodes[0]
            .credential_plan(&local, std::slice::from_ref(&remote))
            .unwrap();
        assert_eq!(
            p.retired,
            vec![MessageId {
                sender: old.local.name,
                receiver: 2,
                sender_rift: 0,
                receiver_rift: 0,
                flow: 7,
                sequence: 0
            }]
        );
        assert!(p.checkpoint.flows[0].outbox.is_empty());
        h.nodes[0]
            .activate_credentials(
                local,
                Arc::new(KeyPair::from_seed(&[1; 32])),
                vec![(remote, KeyPair::from_seed(&[2; 32]).public_key())],
                p.checkpoint,
                1,
                100,
            )
            .unwrap();
        assert!(h.nodes[0]
            .step(Event::Committed(CommitToken {
                incarnation: 1,
                revision: 1
            }))
            .is_err());
    }
}
#[test]
fn pending_storage_finishes_during_quiescence_without_sending() {
    let mut h = Harness::new(config());
    h.auto = false;
    h.send(0, 0, payload(100));
    let (_, q) = h.commits.pop_front().unwrap();
    h.nodes[0].quiesce().unwrap();
    assert!(matches!(
        h.nodes[0].credential_plan(&view(0), &[view(1)]),
        Err(Error::Busy)
    ));
    let out = h.nodes[0].step(Event::Committed(q.token)).unwrap();
    assert!(!out
        .iter()
        .any(|a| matches!(a, Action::Send { .. } | Action::Deliver { .. })));
    assert!(h.nodes[0].credential_plan(&view(0), &[view(1)]).is_ok());
}
