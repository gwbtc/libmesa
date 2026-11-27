mod support;
use mesa_core::{protection::SignedPublic, Attachment, KeyHandle, PeerId, PreconfiguredPeer};
use mesa_crypto::KeyPair;
use mesa_keys::*;
use std::collections::BTreeMap;
use support::*;
fn view(id: u128) -> PreconfiguredPeer {
    PreconfiguredPeer::new(PeerId(id), "gw-btc", 1, 0, KeyHandle(id as u64)).unwrap()
}
fn core() -> mesa_core::Engine<SignedPublic> {
    mesa_core::Engine::new(
        Default::default(),
        view(1),
        SignedPublic::experimental_v2(KeyHandle(1), KeyPair::from_seed(&[1; 32]), BTreeMap::new()),
    )
    .unwrap()
}
fn node() -> mesa_flow::Node {
    let flows = vec![mesa_flow::FlowConfig {
        id: 7,
        peer: view(2),
        attachment: Some(Attachment(1)),
    }];
    let cp = mesa_flow::Checkpoint::empty(&view(1), &flows);
    mesa_flow::Node::new(
        Default::default(),
        view(1),
        SignedPublic::experimental_v2(
            KeyHandle(1),
            KeyPair::from_seed(&[1; 32]),
            BTreeMap::from([(KeyHandle(2), KeyPair::from_seed(&[2; 32]).public_key())]),
        ),
        flows,
        cp,
        1,
    )
    .unwrap()
}
#[test]
fn revoked_authority_closes_retained_core_sends_and_reactivation_uses_new_generation() {
    let (mut a, p) = authority();
    let mut s = store();
    let mut k = Activation::new(config()).unwrap();
    let mut n = core();
    k.sync_core(&a, &s, &mut n).unwrap();
    assert!(n.is_quiescent());
    let c = candidate(1, 1, 0, 1);
    stage(&mut s, 1, c.clone(), 1);
    install(&mut a, p, c);
    commit(&mut k, &a, &s, 1);
    k.sync_core(&a, &s, &mut n).unwrap();
    let old = n
        .send_gate()
        .packet(PeerId(2), Attachment(1), vec![1; 32].into());
    assert!(old.submit(|_, _, _| ()).is_ok());
    let w = a.withdraw("gw-btc", p, 1, a.revision(1)).unwrap();
    a.commit(w.token).unwrap();
    k.reconcile(&a).unwrap();
    assert!(old.submit(|_, _, _| ()).is_err());
    assert!(!n.send_gate().is_open());
    install(&mut a, p, candidate(1, 1, 0, 1));
    commit(&mut k, &a, &s, 1);
    k.sync_core(&a, &s, &mut n).unwrap();
    assert!(n.send_gate().is_open());
    assert!(old.submit(|_, _, _| ()).is_err());
    drop(k);
    assert!(!n.send_gate().is_open());
}
#[test]
fn remote_epoch_race_cancels_flow_activation_and_rebuilt_nodes_do_not_leak_gate_slots() {
    let (mut a, p) = authority();
    let mut s = store();
    let mut k = Activation::new(config()).unwrap();
    let mut n = node();
    let c = candidate(1, 1, 0, 1);
    stage(&mut s, 1, c.clone(), 1);
    install(&mut a, p, c);
    install(&mut a, p, candidate(2, 1, 0, 2));
    k.quiesce_flow(&mut n).unwrap();
    let q = k.flow_plan(&a, reference(1), &s, &mut n).unwrap();
    install(&mut a, p, candidate(2, 2, 1, 3));
    assert_eq!(k.commit(&a, &s, q.token), Err(Error::Stale));
    assert!(!n.send_gate().is_open());
    for i in 2..24 {
        k.quiesce_flow(&mut n).unwrap();
        let q = k.flow_plan(&a, reference(1), &s, &mut n).unwrap();
        k.commit(&a, &s, q.token).unwrap();
        k.sync_flow(&a, &s, &mut n, i).unwrap();
        assert!(n.send_gate().is_open());
    }
    let packet = n
        .send_gate()
        .packet(PeerId(2), Attachment(1), vec![1; 32].into());
    install(&mut a, p, candidate(2, 3, 2, 4));
    k.reconcile(&a).unwrap();
    assert!(packet.submit(|_, _, _| ()).is_err());
    assert!(n.step(mesa_flow::Event::AdvanceTo(1)).is_err());
}
#[test]
fn restored_authority_requires_fresh_vouch_even_with_matching_ring() {
    let (mut a, p) = authority();
    let c = candidate(1, 1, 0, 1);
    let q = a.accept(p, 0, c.clone(), None, None).unwrap();
    a.commit(q.token).unwrap();
    let mut s = store();
    stage(&mut s, 1, c.clone(), 1);
    let mut k = Activation::new(config()).unwrap();
    let checkpoint = commit(&mut k, &a, &s, 1).checkpoint;
    let mut a =
        mesa_pki::Authority::restore(mesa_pki::Limits::default(), 2, &q.checkpoint).unwrap();
    let p = a.provider("gw-btc").unwrap();
    a.set_status(
        "gw-btc",
        p,
        mesa_pki::ProviderStatus {
            available: true,
            ready: true,
        },
    )
    .unwrap();
    let mut cfg = config();
    cfg.incarnation += 1;
    let mut k = Activation::restore(cfg, &checkpoint, 1).unwrap();
    assert!(matches!(
        k.prepare(&a, &s, reference(1), None),
        Err(Error::Unavailable)
    ));
    install(&mut a, p, c);
    commit(&mut k, &a, &s, 1);
}
