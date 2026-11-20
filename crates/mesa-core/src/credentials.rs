//! Credential cutover and immutable send records. The gate serializes the final
//! send submission with cutover, including caller-retained packets.
use crate::*;
use std::sync::{Arc, Mutex};
#[derive(Clone)]
pub struct SendGate(Arc<Mutex<u64>>);
impl Default for SendGate {
    fn default() -> Self {
        Self(Arc::new(Mutex::new(1)))
    }
}
impl SendGate {
    pub fn same(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
    pub fn is_open(&self) -> bool {
        self.0.lock().is_ok_and(|s| *s & 1 != 0)
    }
    pub fn change(&self, open: bool) -> Result<(), Error> {
        let mut state = self.0.lock().map_err(|_| Error::Blocked)?;
        let next = (*state & !1).checked_add(2);
        match next {
            Some(n) => {
                *state = n | u64::from(open);
                Ok(())
            }
            None => {
                *state = u64::MAX - 1;
                Err(Error::GenerationOverflow)
            }
        }
    }
    pub fn packet(&self, peer: PeerId, attachment: Attachment, bytes: Buffer) -> FencedPacket {
        let stamp = *self.0.lock().unwrap_or_else(|p| p.into_inner());
        FencedPacket {
            gate: self.clone(),
            stamp,
            peer,
            attachment,
            bytes,
        }
    }
}
/// Immutable bytes plus a revocable send capability. Never restamp an old
/// packet. Engines/flow nodes stamp newly generated outputs in their wrappers.
#[derive(Clone)]
pub struct FencedPacket {
    gate: SendGate,
    stamp: u64,
    peer: PeerId,
    attachment: Attachment,
    bytes: Buffer,
}
impl FencedPacket {
    pub fn peer(&self) -> PeerId {
        self.peer
    }
    pub fn attachment(&self) -> Attachment {
        self.attachment
    }
    pub fn bytes(&self) -> Buffer {
        self.bytes.clone()
    }
    /// Keep the lock through the driver's nonblocking syscall. No adapter may
    /// enqueue bytes here and later send them without repeating this check.
    pub fn submit<T>(
        &self,
        send: impl FnOnce(PeerId, Attachment, &Buffer) -> T,
    ) -> Result<T, Error> {
        let current = self.gate.0.lock().map_err(|_| Error::Blocked)?;
        if *current != self.stamp || self.stamp & 1 == 0 {
            return Err(Error::StaleGeneration);
        }
        Ok(send(self.peer, self.attachment, &self.bytes))
    }
}
impl<P: Protection> Engine<P> {
    pub fn local_view(&self) -> PreconfiguredPeer {
        self.local.clone()
    }
    pub fn local_generation(&self) -> u64 {
        self.local_generation
    }
    pub fn is_quiescent(&self) -> bool {
        self.quiescent || !self.send_gate.is_open()
    }
    pub fn send_gate(&self) -> SendGate {
        self.send_gate.clone()
    }
    pub fn quiesce(&mut self) -> Result<Vec<Action>, Error> {
        self.send_gate.change(false)?;
        self.quiescent = true;
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(Error::GenerationOverflow)?;
        let mut actions = vec![];
        for id in self.reads.keys().copied().collect::<Vec<_>>() {
            self.finish(id, Err(ReadFailure::PeerReset), &mut actions);
        }
        actions.push(Action::SetTimer(None));
        self.counters.observe(None, &actions);
        Ok(actions)
    }
}
impl<P> Drop for Engine<P> {
    fn drop(&mut self) {
        let _ = self.send_gate.change(false);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cutover_serializes_with_final_submission() {
        let gate = SendGate::default();
        let packet = gate.packet(PeerId(2), Attachment(1), vec![1; 32].into());
        let (entered_rx_tx, entered) = std::sync::mpsc::channel();
        let (release, release_rx) = std::sync::mpsc::channel();
        let p = packet.clone();
        let sending = std::thread::spawn(move || {
            p.submit(|_, _, _| {
                entered_rx_tx.send(()).unwrap();
                release_rx.recv().unwrap();
            })
            .unwrap()
        });
        entered.recv().unwrap();
        let (closed_tx, closed) = std::sync::mpsc::channel();
        let closing = std::thread::spawn(move || {
            gate.change(false).unwrap();
            closed_tx.send(()).unwrap();
        });
        assert!(closed.try_recv().is_err());
        release.send(()).unwrap();
        sending.join().unwrap();
        closing.join().unwrap();
        closed.recv().unwrap();
        assert!(packet.submit(|_, _, _| panic!("stale syscall")).is_err());
    }
}
