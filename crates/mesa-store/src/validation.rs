use crate::{Delivery, Error, Limits};
use mesa_flow::{Change, Checkpoint, CommitRequest, MessageId, Receipt};

pub(super) fn initial(s: &Checkpoint) -> Result<(), Error> {
    state(s, Limits::default())?;
    if s.revision != 0 {
        return Err(Error::InvalidState);
    }
    Ok(())
}
pub(super) fn scope(a: &Checkpoint, b: &Checkpoint) -> Result<(), Error> {
    if a.version != b.version
        || a.local != b.local
        || a.flows.len() != b.flows.len()
        || a.flows
            .iter()
            .zip(&b.flows)
            .any(|(a, b)| a.flow != b.flow || a.remote != b.remote)
    {
        return Err(Error::Scope);
    }
    Ok(())
}
pub(super) fn state(s: &Checkpoint, limits: Limits) -> Result<(), Error> {
    if s.version != 1 || s.flows.is_empty() || s.flows.len() > 16 {
        return Err(Error::InvalidState);
    }
    let mut revision = 0u64;
    for (i, f) in s.flows.iter().enumerate() {
        if i > 0 && s.flows[i - 1].flow >= f.flow
            || f.remote.name == s.local.name
            || f.next_send > 1024
            || f.received.len() > 1024
            || f.outbox.len() + f.settled.len() != f.next_send as usize
            || f.outbox.iter().any(|(seq, bytes)| {
                *seq >= f.next_send
                    || f.settled.contains_key(seq)
                    || bytes.len() > limits.message_bytes
            })
            || f.settled.keys().any(|seq| *seq >= f.next_send)
        {
            return Err(Error::InvalidState);
        }
        for endpoint in [&s.local, &f.remote] {
            if mesa_core::PreconfiguredPeer::new(
                mesa_core::PeerId(endpoint.name),
                &endpoint.domain,
                0,
                endpoint.rift,
                mesa_core::KeyHandle(0),
            )
            .is_err()
            {
                return Err(Error::InvalidState);
            }
        }
        revision += f.next_send + f.received.len() as u64 + f.settled.len() as u64;
    }
    if revision != s.revision {
        return Err(Error::InvalidState);
    }
    Ok(())
}
fn matches_id(s: &Checkpoint, id: &MessageId, incoming: bool) -> bool {
    let Some(flow) = s.flow(id.flow) else {
        return false;
    };
    let (sender, receiver) = if incoming {
        (&flow.remote, &s.local)
    } else {
        (&s.local, &flow.remote)
    };
    id.sender == sender.name
        && id.sender_rift == sender.rift
        && id.receiver == receiver.name
        && id.receiver_rift == receiver.rift
}
pub(super) fn transition(old: &Checkpoint, r: &CommitRequest, limits: Limits) -> Result<(), Error> {
    state(&r.checkpoint, limits)?;
    scope(old, &r.checkpoint)?;
    if old.revision.checked_add(1) != Some(r.checkpoint.revision)
        || r.token.revision != r.checkpoint.revision
    {
        return Err(Error::Revision);
    }
    let (id, incoming) = match &r.change {
        Change::Enqueue { id } | Change::Settle { id, .. } => (id, false),
        Change::Deliver { id, .. } => (id, true),
    };
    if !matches_id(old, id, incoming) {
        return Err(Error::Transition);
    }
    let mut expected = old.clone();
    expected.revision += 1;
    let flow = expected
        .flows
        .iter_mut()
        .find(|f| f.flow == id.flow)
        .ok_or(Error::Transition)?;
    match &r.change {
        Change::Enqueue { id } => {
            if id.sequence != flow.next_send {
                return Err(Error::Transition);
            }
            let bytes = r
                .checkpoint
                .flow(id.flow)
                .and_then(|f| f.outbox.get(&id.sequence))
                .ok_or(Error::Transition)?;
            if bytes.len() > limits.message_bytes {
                return Err(Error::Limit);
            }
            flow.outbox.insert(id.sequence, bytes.clone());
            flow.next_send += 1;
        }
        Change::Deliver { id, bytes, outcome } => {
            if id.sequence != flow.received.len() as u64 || bytes.len() > limits.message_bytes {
                return Err(Error::Transition);
            }
            flow.received.push(Receipt {
                digest: mesa_crypto::sha256(bytes),
                outcome: *outcome,
            });
        }
        Change::Settle { id, outcome } => {
            if flow.outbox.remove(&id.sequence).is_none() {
                return Err(Error::Transition);
            }
            flow.settled.insert(id.sequence, *outcome);
        }
    }
    if expected != r.checkpoint {
        return Err(Error::Transition);
    }
    Ok(())
}
pub(super) fn inbox(s: &Checkpoint, deliveries: &[Delivery]) -> Result<(), Error> {
    let mut seen = std::collections::BTreeMap::<u64, u64>::new();
    for d in deliveries {
        if d.revision > s.revision || !matches_id(s, &d.id, true) {
            return Err(Error::InvalidState);
        }
        let seq = seen.entry(d.id.flow).or_default();
        if *seq != d.id.sequence {
            return Err(Error::InvalidState);
        }
        let receipt = s
            .flow(d.id.flow)
            .and_then(|f| f.received.get(*seq as usize))
            .ok_or(Error::InvalidState)?;
        if receipt.digest != mesa_crypto::sha256(&d.bytes) || receipt.outcome != d.outcome {
            return Err(Error::InvalidState);
        }
        *seq += 1;
    }
    if s.flows
        .iter()
        .any(|f| seen.get(&f.flow).copied().unwrap_or(0) != f.received.len() as u64)
    {
        return Err(Error::InvalidState);
    }
    Ok(())
}
