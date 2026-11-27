use mesa_bytes::Buffer;
use mesa_flow::ordered::*;
fn epoch() -> Epoch {
    Epoch {
        domain: "mesa-test".into(),
        remote_domain: "mesa-test".into(),
        local: 1,
        local_rift: 0,
        remote: 2,
        remote_rift: 0,
    }
}
fn node(c: Config) -> Node {
    Node::new(c, State::empty(epoch(), 4), 1).unwrap()
}
fn flow() -> Flow {
    Flow {
        bone: 4,
        backward: false,
    }
}
fn proposal(n: &mut Node, e: Event) -> Proposal {
    let a = n.step(e).unwrap();
    assert_eq!(a.len(), 1);
    let Action::Commit(p) = a.into_iter().next().unwrap() else {
        panic!("no proposal")
    };
    *p
}
fn commit(n: &mut Node, e: Event) -> Vec<Action> {
    let p = proposal(n, e);
    n.step(Event::Committed(p.token)).unwrap()
}
fn admitted() -> Node {
    let mut n = node(Config::default());
    commit(&mut n, Event::Admit(flow()));
    n
}
fn receive(n: &mut Node, sequence: u64, kind: Kind) -> Id {
    let a = n
        .step(Event::Receive {
            flow: flow(),
            sequence,
            kind,
            bytes: vec![sequence as u8, 0, 0].into(),
        })
        .unwrap();
    let Action::Deliver { id, .. } = &a[0] else {
        panic!()
    };
    id.clone()
}
fn reload(state: State, incarnation: u128) -> Node {
    let bytes = Buffer::from(serde_json::to_vec(&state).unwrap());
    Node::restore(Config::default(), &bytes, &epoch(), incarnation).unwrap()
}
#[test]
fn enqueue_receiver_effect_and_settlement_are_three_local_commit_boundaries() {
    let mut a = admitted();
    let mut b = admitted();
    let before = a.state().clone();
    let enq = proposal(
        &mut a,
        Event::Enqueue {
            flow: flow(),
            kind: Kind::Plea,
            bytes: vec![4, 0].into(),
        },
    );
    assert_eq!(a.state(), &before);
    assert!(reload(before, 2).recover().is_empty());
    // Persist succeeded but callback was lost: restore releases the same ID/data.
    let mut a = reload(enq.state, 2);
    assert_eq!(a.recover().len(), 1);
    assert_eq!(a.step(Event::Committed(enq.token)), Err(Error::Token));
    let id = receive(&mut b, 1, Kind::Plea);
    let old = b.state().clone();
    let received = proposal(
        &mut b,
        Event::Decide {
            id: id.clone(),
            outcome: Outcome::Accepted,
        },
    );
    assert_eq!(b.state(), &old);
    let mut before = reload(old, 3);
    assert_eq!(receive(&mut before, 1, Kind::Plea), id);
    // The atomic host transaction records one effect and this exact snapshot.
    let effect_count = 1;
    let mut b = reload(received.state, 4);
    let duplicate = b
        .step(Event::Receive {
            flow: flow(),
            sequence: 1,
            kind: Kind::Plea,
            bytes: vec![4, 0].into(),
        })
        .unwrap();
    assert!(matches!(
        &duplicate[..],
        [Action::Receipt {
            outcome: Outcome::Accepted,
            ..
        }]
    ));
    assert_eq!(effect_count, 1);
    let settled = proposal(
        &mut a,
        Event::Ack {
            flow: flow(),
            sequence: 1,
            rejected: false,
        },
    );
    assert_eq!(a.recover().len(), 1); // Commit proposal does not remove the old outbox.
    let a = reload(settled.state, 5);
    assert!(a.recover().is_empty());
}
#[test]
fn retained_results_survive_node_destruction_and_boon_ack_waits_for_commit() {
    let mut n = admitted();
    let id = receive(&mut n, 1, Kind::Boon);
    assert_eq!(
        n.step(Event::Decide {
            id: id.clone(),
            outcome: Outcome::Rejected(vec![1].into())
        }),
        Err(Error::Decision)
    );
    let p = proposal(
        &mut n,
        Event::Decide {
            id,
            outcome: Outcome::Accepted,
        },
    );
    assert!(n.recover().is_empty());
    let token = p.token;
    let out = n.step(Event::Committed(token)).unwrap();
    drop(n);
    assert!(matches!(
        &out[..],
        [Action::Receipt {
            outcome: Outcome::Accepted,
            ..
        }]
    ));
    let mut n = reload(p.state, 2);
    assert!(matches!(
        &n.step(Event::Receive {
            flow: flow(),
            sequence: 1,
            kind: Kind::Boon,
            bytes: vec![1].into()
        })
        .unwrap()[..],
        [Action::Receipt { .. }]
    ));
}
#[test]
fn rejection_explanation_is_durable_bounded_and_cannot_be_overwritten_by_positive_ack() {
    let mut n = admitted();
    commit(
        &mut n,
        Event::Enqueue {
            flow: flow(),
            kind: Kind::Plea,
            bytes: vec![3].into(),
        },
    );
    let p = proposal(
        &mut n,
        Event::Ack {
            flow: flow(),
            sequence: 1,
            rejected: true,
        },
    );
    let mut n = reload(p.state, 2);
    assert!(matches!(&n.recover()[..], [Action::FetchExplanation(_)]));
    assert_eq!(
        n.step(Event::Ack {
            flow: flow(),
            sequence: 1,
            rejected: false
        }),
        Err(Error::Decision)
    );
    assert_eq!(
        n.step(Event::Explanation {
            flow: flow(),
            sequence: 1,
            bytes: vec![0; 4097].into()
        }),
        Err(Error::Limit)
    );
    assert!(matches!(&n.recover()[..], [Action::FetchExplanation(_)]));
    let p = proposal(
        &mut n,
        Event::Explanation {
            flow: flow(),
            sequence: 1,
            bytes: vec![9, 0, 0].into(),
        },
    );
    let results = n.step(Event::Committed(p.token)).unwrap();
    drop(n);
    assert!(
        matches!(&results[..],[Action::Settled { outcome:Outcome::Rejected(b),.. }] if b.len()==3)
    );
    assert!(reload(p.state, 3).recover().is_empty());
}
#[test]
fn sparse_rejections_prune_every_old_entry_and_frontier_never_invents_an_ack() {
    let mut n = admitted();
    for seq in 1..=34 {
        let id = receive(&mut n, seq, Kind::Plea);
        let outcome = if [1, 12, 23].contains(&seq) {
            Outcome::Rejected(vec![seq as u8].into())
        } else {
            Outcome::Accepted
        };
        commit(&mut n, Event::Decide { id, outcome });
        assert!(n.state().flows[0].outcomes.len() <= 10);
    }
    assert_eq!(n.state().flows[0].outcomes.first().unwrap().sequence, 25);
    assert!(n.state().flows[0]
        .outcomes
        .iter()
        .all(|r| r.outcome == Outcome::Accepted));
    for sequence in [1, 12, 23, 24] {
        assert!(n
            .step(Event::Receive {
                flow: flow(),
                sequence,
                kind: Kind::Plea,
                bytes: vec![7].into()
            })
            .unwrap()
            .is_empty());
    }
}
#[test]
fn close_drains_outbox_recovers_lost_cork_ack_and_never_reopens() {
    let mut a = admitted();
    let mut b = admitted();
    commit(
        &mut a,
        Event::Enqueue {
            flow: flow(),
            kind: Kind::Plea,
            bytes: vec![1].into(),
        },
    );
    assert!(commit(&mut a, Event::Close(flow())).is_empty());
    assert_eq!(
        a.step(Event::Enqueue {
            flow: flow(),
            kind: Kind::Plea,
            bytes: vec![2].into()
        }),
        Err(Error::Closed)
    );
    assert_eq!(a.step(Event::Gone(flow())), Err(Error::Decision)); // Ordinary outbox still unsettled.
    let id = receive(&mut b, 1, Kind::Plea);
    commit(
        &mut b,
        Event::Decide {
            id,
            outcome: Outcome::Accepted,
        },
    );
    assert!(matches!(
        &commit(
            &mut a,
            Event::Ack {
                flow: flow(),
                sequence: 1,
                rejected: false
            }
        )[..],
        [
            Action::Settled { .. },
            Action::Transmit {
                kind: Kind::Cork,
                ..
            }
        ]
    ));
    let p = proposal(
        &mut b,
        Event::Receive {
            flow: flow(),
            sequence: 2,
            kind: Kind::Cork,
            bytes: Buffer::default(),
        },
    );
    let mut b = reload(p.state, 2);
    assert_eq!(b.recover(), vec![Action::FetchGone(flow())]);
    let mut a = reload(a.state().clone(), 3);
    assert!(matches!(
        &a.recover()[..],
        [Action::Transmit {
            kind: Kind::Cork,
            ..
        }]
    ));
    let p = proposal(
        &mut a,
        Event::Ack {
            flow: flow(),
            sequence: 2,
            rejected: false,
        },
    );
    let a = reload(p.state, 4);
    assert!(a.state().is_closed(flow()));
    let p = proposal(&mut b, Event::Gone(flow()));
    let mut b = reload(p.state, 5);
    assert_eq!(
        b.step(Event::Receive {
            flow: flow(),
            sequence: 1,
            kind: Kind::Plea,
            bytes: vec![1].into()
        })
        .unwrap(),
        vec![Action::Gone(flow())]
    );
    assert_eq!(b.step(Event::Admit(flow())), Err(Error::Closed));
}
#[test]
fn closure_slots_are_reserved_and_sparse_holes_remain_open() {
    let c = Config {
        max_intervals: 2,
        ..Default::default()
    };
    let mut n = node(c);
    let f = |bone| Flow {
        bone,
        backward: false,
    };
    commit(&mut n, Event::Admit(f(4)));
    commit(&mut n, Event::Admit(f(12)));
    assert_eq!(n.step(Event::Admit(f(8))), Err(Error::Backpressure));
    for bone in [4, 12] {
        commit(&mut n, Event::Close(f(bone)));
        commit(
            &mut n,
            Event::Ack {
                flow: f(bone),
                sequence: 1,
                rejected: false,
            },
        );
    }
    assert_eq!(n.state().closed.len(), 2);
    assert!(!n.state().is_closed(f(8)));
    assert_eq!(n.step(Event::Admit(f(8))), Err(Error::Backpressure));
    let mut n = admitted();
    commit(&mut n, Event::Admit(f(8)));
    for bone in [4, 8] {
        commit(&mut n, Event::Close(f(bone)));
        commit(
            &mut n,
            Event::Ack {
                flow: f(bone),
                sequence: 1,
                rejected: false,
            },
        );
    }
    assert_eq!(n.state().closed.len(), 1);
    assert_eq!(
        (n.state().closed[0].first, n.state().closed[0].last),
        (1, 2)
    );
}
#[test]
fn malformed_cross_profile_and_epoch_restores_fail_and_tokens_are_incarnation_bound() {
    let n = admitted();
    let mut s = n.state().clone();
    s.profile = "libmesa-flow/2".into();
    assert!(matches!(
        Node::new(Config::default(), s, 2),
        Err(Error::Profile)
    ));
    let mut e = epoch();
    e.remote_rift = 1;
    assert!(matches!(
        Node::restore(Config::default(), &n.snapshot().unwrap(), &e, 2),
        Err(Error::Epoch)
    ));
    let mut n = admitted();
    let p = proposal(&mut n, Event::Close(flow()));
    assert_eq!(
        n.step(Event::Committed(Token {
            incarnation: 2,
            revision: p.token.revision
        })),
        Err(Error::Token)
    );
    assert_eq!(n.state().flows[0].closing, Closing::Open);
    n.step(Event::Committed(p.token)).unwrap();
    let mut s = n.state().clone();
    s.flows[0].next_send = 0;
    assert!(Node::new(Config::default(), s, 3).is_err());
}

#[test]
fn closing_records_an_unconfirmed_opposite_message_in_the_host_transaction() {
    let mut n = admitted();
    commit(
        &mut n,
        Event::Enqueue {
            flow: flow(),
            kind: Kind::Boon,
            bytes: vec![3].into(),
        },
    );
    commit(
        &mut n,
        Event::Receive {
            flow: flow(),
            sequence: 1,
            kind: Kind::Cork,
            bytes: Buffer::default(),
        },
    );
    let p = proposal(&mut n, Event::Gone(flow()));
    let Change::Closed {
        unconfirmed: Some(id),
        ..
    } = &p.change
    else {
        panic!()
    };
    assert_eq!(id.sequence, 1);
    assert!(n.state().flow(flow()).unwrap().outbox.is_some());
    let outputs = n.step(Event::Committed(p.token)).unwrap();
    assert!(outputs.iter().any(|a| matches!(a, Action::Unconfirmed(_))));
    assert!(!outputs.iter().any(|a| matches!(a, Action::Settled { .. })));
    assert!(reload(p.state, 9).state().is_closed(flow()));
}

#[test]
fn malformed_close_checkpoints_and_cork_payloads_fail_closed() {
    let mut n = admitted();
    assert_eq!(
        n.step(Event::Receive {
            flow: flow(),
            sequence: 1,
            kind: Kind::Cork,
            bytes: vec![1].into()
        }),
        Err(Error::Limit)
    );
    let mut state = n.state().clone();
    state.flows[0].closing = Closing::Received;
    assert!(Node::new(Config::default(), state, 3).is_err());
    let state = n.state().clone();
    assert!(Node::new(
        Config {
            max_checkpoint: usize::MAX,
            ..Config::default()
        },
        state,
        3
    )
    .is_err());
    // Rejected cork proposal leaves no invisible delivery reservation.
    let mut state = n.state().clone();
    state.revision = u64::MAX;
    let mut n = Node::new(Config::default(), state, 4).unwrap();
    assert_eq!(
        n.step(Event::Receive {
            flow: flow(),
            sequence: 1,
            kind: Kind::Cork,
            bytes: Buffer::default()
        }),
        Err(Error::Limit)
    );
    assert!(matches!(
        &n.step(Event::Receive {
            flow: flow(),
            sequence: 1,
            kind: Kind::Plea,
            bytes: vec![2].into()
        })
        .unwrap()[..],
        [Action::Deliver { .. }]
    ));
}

#[test]
fn simultaneous_corks_close_without_reusing_a_bone() {
    let mut n = admitted();
    commit(&mut n, Event::Close(flow()));
    let actions = commit(
        &mut n,
        Event::Receive {
            flow: flow(),
            sequence: 1,
            kind: Kind::Cork,
            bytes: Buffer::default(),
        },
    );
    assert!(actions.iter().any(|a| matches!(a, Action::FetchGone(_))));
    let mut n = reload(n.state().clone(), 7);
    assert!(n.recover().iter().any(|a| matches!(
        a,
        Action::Transmit {
            kind: Kind::Cork,
            ..
        }
    )));
    commit(
        &mut n,
        Event::Ack {
            flow: flow(),
            sequence: 1,
            rejected: false,
        },
    );
    assert!(n.state().is_closed(flow()));
    assert!(n.step(Event::Admit(flow())).is_err());
}

#[test]
fn closure_waits_for_deliveries_offered_before_or_during_close() {
    for delivery_first in [false, true] {
        for gone in [false, true] {
            let mut n = admitted();
            let other = Flow {
                bone: 8,
                backward: false,
            };
            commit(&mut n, Event::Admit(other));
            let id = if delivery_first {
                let id = receive(&mut n, 1, Kind::Boon);
                commit(&mut n, Event::Close(flow()));
                id
            } else {
                commit(&mut n, Event::Close(flow()));
                receive(&mut n, 1, Kind::Boon)
            };
            let finish = if gone {
                Event::Gone(flow())
            } else {
                Event::Ack {
                    flow: flow(),
                    sequence: 1,
                    rejected: false,
                }
            };
            let before = n.state().clone();
            assert_eq!(n.step(finish.clone()), Err(Error::Busy));
            assert_eq!(n.state(), &before);
            assert!(n.pending().is_none());
            assert!(matches!(
                &n.recover()[..],
                [Action::Transmit {
                    kind: Kind::Cork,
                    ..
                }]
            ));
            // Losing RAM before the effect transaction permits the same offer.
            let mut before_commit = reload(before, 2);
            assert_eq!(receive(&mut before_commit, 1, Kind::Boon), id);
            let p = proposal(
                &mut n,
                Event::Decide {
                    id: id.clone(),
                    outcome: Outcome::Accepted,
                },
            );
            assert_eq!(n.step(finish.clone()), Err(Error::Busy));
            // Persisted effect with a lost callback retains the exact receipt.
            let mut restored = reload(p.state.clone(), 3);
            assert!(matches!(
                &restored
                    .step(Event::Receive {
                        flow: flow(),
                        sequence: 1,
                        kind: Kind::Boon,
                        bytes: vec![1, 0, 0].into()
                    })
                    .unwrap()[..],
                [Action::Receipt { .. }]
            ));
            n.step(Event::Committed(p.token)).unwrap();
            for node in [&mut n, &mut restored] {
                commit(node, finish.clone());
                assert!(node.state().is_closed(flow()));
                let actions = node
                    .step(Event::Receive {
                        flow: other,
                        sequence: 1,
                        kind: Kind::Boon,
                        bytes: vec![9].into(),
                    })
                    .unwrap();
                assert!(matches!(&actions[..], [Action::Deliver { .. }]));
            }
        }
    }
}

#[test]
fn closing_one_flow_preserves_another_flows_delivery_reservation() {
    let mut n = admitted();
    let other = Flow {
        bone: 8,
        backward: false,
    };
    commit(&mut n, Event::Admit(other));
    let actions = n
        .step(Event::Receive {
            flow: other,
            sequence: 1,
            kind: Kind::Boon,
            bytes: vec![9].into(),
        })
        .unwrap();
    let Action::Deliver { id, .. } = &actions[0] else {
        panic!()
    };
    let id = id.clone();
    commit(&mut n, Event::Close(flow()));
    commit(
        &mut n,
        Event::Ack {
            flow: flow(),
            sequence: 1,
            rejected: false,
        },
    );
    commit(
        &mut n,
        Event::Decide {
            id,
            outcome: Outcome::Accepted,
        },
    );
    assert_eq!(n.state().flow(other).unwrap().received, 1);
}
