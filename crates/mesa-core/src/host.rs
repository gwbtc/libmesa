//! Raw host contracts. Credentials are trusted configuration, not PKI verdicts.
use crate::*;

#[derive(Clone, Debug)]
pub struct CredentialUpdate {
    pub peer: PreconfiguredPeer,
    pub expected_generation: u64,
    pub generation: u64,
    pub breach: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct AttachmentUpdate {
    pub peer: PeerId,
    pub expected_generation: u64,
    /// Also the attachment ID when attached. Never reuse within an engine.
    pub generation: u64,
    pub attached: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counters {
    pub events: u64,
    pub received_packets: u64,
    pub received_bytes: u64,
    pub sent_packets: u64,
    pub sent_bytes: u64,
    pub retransmissions: u64,
    pub dropped: u64,
    pub completed: u64,
    pub cancelled: u64,
    pub timeouts: u64,
}
impl Counters {
    pub(crate) fn observe(&mut self, received: Option<usize>, actions: &[Action]) {
        self.events = self.events.saturating_add(1);
        if let Some(bytes) = received {
            self.received_packets = self.received_packets.saturating_add(1);
            self.received_bytes = self.received_bytes.saturating_add(bytes as u64);
        }
        for a in actions {
            match a {
                Action::Send { bytes, .. } => {
                    self.sent_packets = self.sent_packets.saturating_add(1);
                    self.sent_bytes = self.sent_bytes.saturating_add(bytes.len() as u64);
                }
                Action::Dropped(_) => self.dropped = self.dropped.saturating_add(1),
                Action::ReadFinished { result, .. } => match result {
                    Ok(_) => self.completed = self.completed.saturating_add(1),
                    Err(ReadFailure::Cancelled) => {
                        self.cancelled = self.cancelled.saturating_add(1)
                    }
                    Err(ReadFailure::Timeout) => self.timeouts = self.timeouts.saturating_add(1),
                    _ => {}
                },
                _ => {}
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerSnapshot {
    pub peer: PreconfiguredPeer,
    pub credential_generation: u64,
    pub attachment_generation: u64,
    pub attachment: Option<Attachment>,
    pub transfer: TransferState,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub revision: u64,
    pub now: Tick,
    pub deadline: Option<Tick>,
    pub usage: Usage,
    pub counters: Counters,
    pub peers: Vec<PeerSnapshot>,
}

/// Conservative output allowance per event, including its timer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Envelope {
    pub records: usize,
    pub bytes: usize,
}
#[derive(Clone, Copy, Debug)]
pub struct Budget {
    pub events: usize,
    pub records: usize,
    pub bytes: usize,
}
#[derive(Debug)]
pub struct Batch {
    /// Each entry consumes one event, including a rejected final event.
    pub results: Vec<Result<Vec<Record>, Error>>,
}

/// Owned immutable buffers at the batched Rust boundary. The original step()
/// API remains available; conversion moves its vectors into shared storage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Record {
    Send {
        peer: PeerId,
        attachment: Attachment,
        bytes: Buffer,
    },
    ReadFinished {
        id: ReadId,
        result: Result<Buffer, ReadFailure>,
    },
    Dropped(DropReason),
    SetTimer(Option<Tick>),
}
impl From<Action> for Record {
    fn from(action: Action) -> Self {
        match action {
            Action::Send {
                peer,
                attachment,
                bytes,
            } => Self::Send {
                peer,
                attachment,
                bytes: bytes.into(),
            },
            Action::ReadFinished { id, result } => Self::ReadFinished {
                id,
                result: result.map(Buffer::from),
            },
            Action::Dropped(reason) => Self::Dropped(reason),
            Action::SetTimer(t) => Self::SetTimer(t),
        }
    }
}

impl Config {
    pub fn event_envelope(&self) -> Result<Envelope, Error> {
        let interests = self
            .max_reads
            .checked_mul(self.window)
            .ok_or(Error::InvalidConfig)?;
        let sends = interests.checked_add(1).ok_or(Error::InvalidConfig)?;
        Ok(Envelope {
            records: sends
                .checked_add(self.max_reads)
                .and_then(|v| v.checked_add(3))
                .ok_or(Error::InvalidConfig)?,
            // A receive can complete one object and schedule other interests.
            bytes: sends
                .checked_mul(self.wire.max_packet)
                .and_then(|v| v.checked_add(self.max_read_bytes))
                .ok_or(Error::InvalidConfig)?,
        })
    }
}

impl<P: Protection> Engine<P> {
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            revision: self.revision,
            now: self.now,
            deadline: self.next_timer(),
            usage: self.usage(),
            counters: self.counters,
            peers: self
                .peers
                .values()
                .map(|p| PeerSnapshot {
                    peer: p.view.clone(),
                    credential_generation: p.credential_generation,
                    attachment_generation: p.attachment_generation,
                    attachment: p.attachment,
                    transfer: self.transfer_state(p.view.id).expect("present peer"),
                })
                .collect(),
        }
    }

    /// Prefix acceptance with a conservative reservation before each event.
    /// No pending output queue. Retry only the unprocessed suffix. An empty
    /// batch is observation only; obtain the current timer with next_timer().
    pub fn step_batch(&mut self, events: &[Event<'_>], budget: Budget) -> Result<Batch, Error> {
        if budget.events == 0 {
            return Err(Error::InvalidConfig);
        }
        let envelope = self.config.event_envelope()?;
        let mut batch = Batch {
            results: Vec::new(),
        };
        let mut records = 0;
        let mut bytes = 0;
        for event in events.iter().take(budget.events) {
            if envelope.records > budget.records.saturating_sub(records)
                || envelope.bytes > budget.bytes.saturating_sub(bytes)
            {
                if batch.results.is_empty() {
                    return Err(Error::ResourceLimit);
                }
                break;
            }
            let result = self.step(event.clone());
            if let Ok(actions) = &result {
                records += actions.len();
                bytes += actions
                    .iter()
                    .map(|a| match a {
                        Action::Send { bytes, .. } => bytes.len(),
                        Action::ReadFinished {
                            result: Ok(bytes), ..
                        } => bytes.len(),
                        _ => 0,
                    })
                    .sum::<usize>();
            } else {
                records += 1;
            }
            let failed = result.is_err();
            batch
                .results
                .push(result.map(|actions| actions.into_iter().map(Record::from).collect()));
            if failed {
                break;
            }
        }
        Ok(batch)
    }

    pub(crate) fn require_unfenced_credentials(&self, peer: PeerId) -> Result<(), Error> {
        if self.peers.get(&peer).is_some_and(|p| p.fenced_credentials) {
            return Err(Error::StaleGeneration);
        }
        Ok(())
    }

    pub(crate) fn install_credential(
        &mut self,
        update: CredentialUpdate,
        actions: &mut Vec<Action>,
    ) -> Result<(), Error> {
        let id = update.peer.id;
        let generation = self.peers.get(&id).map_or(0, |p| p.credential_generation);
        if generation != update.expected_generation || update.generation <= generation {
            return Err(Error::StaleGeneration);
        }
        // install validates every coordinate/key before mutation. A generation
        // change cancels all old reads, including cached authenticated roots.
        self.install(update.peer, update.breach, actions)?;
        let p = self.peers.get_mut(&id).expect("installed peer");
        p.credential_generation = update.generation;
        p.fenced_credentials = true;
        self.fail_peer(id, ReadFailure::PeerReset, actions);
        Ok(())
    }

    pub(crate) fn replace_attachment(&mut self, update: AttachmentUpdate) -> Result<(), Error> {
        let p = self.peers.get_mut(&update.peer).ok_or(Error::UnknownPeer)?;
        if p.attachment_generation != update.expected_generation
            || update.generation <= p.attachment_generation
        {
            return Err(Error::StaleGeneration);
        }
        p.attachment_generation = update.generation;
        p.fenced_attachment = true;
        p.attachment = update.attached.then_some(Attachment(update.generation));
        Ok(())
    }
}
