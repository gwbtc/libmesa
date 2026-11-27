//! Durable ordered flows independent of packet framing and Urbit serialization.
//! The caller supplies authenticated events and atomically stores each proposal
//! with its local effect or durable handoff. Only `Committed` releases results.
use mesa_bytes::Buffer;
use serde::{Deserialize, Serialize};

const SCHEMA: u32 = 1;
const PROFILE: &str = "mesa-v1/ordered";
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Flow {
    pub bone: u64,
    pub backward: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Epoch {
    pub domain: String,
    pub remote_domain: String,
    pub local: u128,
    pub local_rift: u32,
    pub remote: u128,
    pub remote_rift: u32,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Id {
    pub epoch: Epoch,
    pub flow: Flow,
    pub sequence: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Outcome {
    Accepted,
    Rejected(Buffer),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Kind {
    Plea,
    Boon,
    Cork,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Message {
    pub sequence: u64,
    pub kind: Kind,
    pub bytes: Buffer,
    pub rejection_known: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    pub sequence: u64,
    pub outcome: Outcome,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Closing {
    Open,
    Requested,
    Received,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowState {
    pub flow: Flow,
    pub next_send: u64,
    pub received: u64,
    pub outbox: Option<Message>,
    pub outcomes: Vec<Receipt>,
    pub closing: Closing,
}
/// Closed normalized bone indices, partitioned by low-two-bit allocator class
/// and direction. An interval contains only flows that have actually closed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Interval {
    pub class: u8,
    pub backward: bool,
    pub first: u64,
    pub last: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub schema: u32,
    pub profile: String,
    pub revision: u64,
    pub epoch: Epoch,
    pub next_bone: u64,
    pub flows: Vec<FlowState>,
    pub closed: Vec<Interval>,
}
impl State {
    pub fn empty(epoch: Epoch, first_bone: u64) -> Self {
        Self {
            schema: SCHEMA,
            profile: PROFILE.into(),
            revision: 0,
            epoch,
            next_bone: first_bone,
            flows: Vec::new(),
            closed: Vec::new(),
        }
    }
    pub fn is_closed(&self, flow: Flow) -> bool {
        self.closed.iter().any(|r| {
            r.class == (flow.bone % 4) as u8
                && r.backward == flow.backward
                && (r.first..=r.last).contains(&(flow.bone / 4))
        })
    }
    pub fn flow(&self, flow: Flow) -> Option<&FlowState> {
        self.flows.iter().find(|f| f.flow == flow)
    }
}
#[derive(Clone, Debug)]
pub struct Config {
    pub max_flows: usize,
    pub max_intervals: usize,
    pub max_message: usize,
    pub max_error: usize,
    pub max_retained_errors: usize,
    pub max_checkpoint: usize,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            max_flows: 64,
            max_intervals: 1024,
            max_message: 65536,
            max_error: 4096,
            max_retained_errors: 64 * 10 * 4096,
            max_checkpoint: 16 * 1024 * 1024,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Profile,
    Epoch,
    Busy,
    UnknownFlow,
    Sequence,
    Closed,
    Backpressure,
    Limit,
    Token,
    Decision,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Token {
    pub incarnation: u128,
    pub revision: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Change {
    Open(Flow),
    Enqueue(Id),
    Accept(Id, Outcome),
    Settlement(Id, Outcome),
    RejectionKnown(Id),
    Close(Flow),
    Closed { flow: Flow, unconfirmed: Option<Id> },
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proposal {
    pub token: Token,
    pub base_revision: u64,
    pub state: State,
    pub change: Change,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Commit(Box<Proposal>),
    Deliver { id: Id, kind: Kind, bytes: Buffer },
    Transmit { id: Id, kind: Kind, bytes: Buffer },
    Receipt { id: Id, outcome: Outcome },
    FetchExplanation(Id),
    FetchGone(Flow),
    Gone(Flow),
    Unconfirmed(Id),
    Settled { id: Id, outcome: Outcome },
}
#[derive(Clone, Debug)]
pub enum Event {
    Allocate {
        backward: bool,
    },
    Admit(Flow),
    Enqueue {
        flow: Flow,
        kind: Kind,
        bytes: Buffer,
    },
    Receive {
        flow: Flow,
        sequence: u64,
        kind: Kind,
        bytes: Buffer,
    },
    Decide {
        id: Id,
        outcome: Outcome,
    },
    Ack {
        flow: Flow,
        sequence: u64,
        rejected: bool,
    },
    Explanation {
        flow: Flow,
        sequence: u64,
        bytes: Buffer,
    },
    Close(Flow),
    Gone(Flow),
    Committed(Token),
}
/// One transaction domain. Hosts may group several such domains in one local
/// transaction; neither a global checkpoint nor a distributed commit is needed.
pub struct Node {
    config: Config,
    state: State,
    incarnation: u128,
    pending: Option<(Proposal, Vec<Action>)>,
    delivery: Option<(Id, Kind)>,
}
impl Node {
    pub fn new(config: Config, state: State, incarnation: u128) -> Result<Self, Error> {
        if incarnation == 0
            || config.max_flows > 1024
            || config.max_intervals > 65536
            || config.max_message > 1024 * 1024
            || config.max_checkpoint > 64 * 1024 * 1024
            || config.max_checkpoint == 0
            || config.max_flows == 0
            || config.max_intervals == 0
            || config.max_error == 0
            || config.max_message == 0
            || config.max_error > config.max_message
        {
            return Err(Error::Invalid);
        }
        validate(&config, &state)?;
        encode(&config, &state)?;
        Ok(Self {
            config,
            state,
            incarnation,
            pending: None,
            delivery: None,
        })
    }
    pub fn pending(&self) -> Option<&Proposal> {
        self.pending.as_ref().map(|p| &p.0)
    }
    pub fn state(&self) -> &State {
        &self.state
    }
    pub fn snapshot(&self) -> Result<Buffer, Error> {
        encode(&self.config, &self.state)
    }
    pub fn restore(
        config: Config,
        bytes: &Buffer,
        epoch: &Epoch,
        incarnation: u128,
    ) -> Result<Self, Error> {
        if bytes.len() > config.max_checkpoint {
            return Err(Error::Limit);
        }
        let state: State = bytes
            .with_bytes(|b| serde_json::from_slice(b))
            .map_err(|_| Error::Invalid)?;
        if &state.epoch != epoch {
            return Err(Error::Epoch);
        }
        Self::new(config, state, incarnation)
    }
    fn id(&self, flow: Flow, sequence: u64) -> Id {
        Id {
            epoch: self.state.epoch.clone(),
            flow,
            sequence,
        }
    }
    pub fn recover(&self) -> Vec<Action> {
        let mut out = Vec::new();
        for f in &self.state.flows {
            if let Some(m) = &f.outbox {
                let id = self.id(f.flow, m.sequence);
                out.push(if m.rejection_known {
                    Action::FetchExplanation(id)
                } else {
                    Action::Transmit {
                        id,
                        kind: m.kind,
                        bytes: m.bytes.clone(),
                    }
                });
            }
            if f.closing == Closing::Received {
                out.push(Action::FetchGone(f.flow));
            }
        }
        out
    }
    pub fn step(&mut self, event: Event) -> Result<Vec<Action>, Error> {
        if let Event::Committed(token) = event {
            let Some((proposal, _)) = &self.pending else {
                return Err(Error::Token);
            };
            if token != proposal.token {
                return Err(Error::Token);
            }
            let (p, out) = self.pending.take().unwrap();
            self.state = p.state;
            if matches!(p.change, Change::Accept(..)) {
                self.delivery = None;
            }
            return Ok(out);
        }
        if self.pending.is_some() {
            return Err(Error::Busy);
        }
        match event {
            Event::Allocate { backward } => {
                let flow = Flow {
                    bone: self.state.next_bone,
                    backward,
                };
                let mut s = self.state.clone();
                s.next_bone = s.next_bone.checked_add(4).ok_or(Error::Limit)?;
                self.open(s, flow)
            }
            Event::Admit(flow) => self.open(self.state.clone(), flow),
            Event::Enqueue { flow, kind, bytes } => {
                if kind == Kind::Cork {
                    return Err(Error::Invalid);
                }
                if bytes.len() > self.config.max_message {
                    return Err(Error::Limit);
                }
                let mut s = self.state.clone();
                let f = get(&mut s, flow)?;
                if f.closing != Closing::Open {
                    return Err(Error::Closed);
                }
                if f.outbox.is_some() {
                    return Err(Error::Backpressure);
                }
                let sequence = f.next_send;
                f.next_send = f.next_send.checked_add(1).ok_or(Error::Limit)?;
                f.outbox = Some(Message {
                    sequence,
                    kind,
                    bytes: bytes.clone(),
                    rejection_known: false,
                });
                let id = self.id(flow, sequence);
                self.propose(
                    s,
                    Change::Enqueue(id.clone()),
                    vec![Action::Transmit { id, kind, bytes }],
                )
            }
            Event::Receive {
                flow,
                sequence,
                kind,
                bytes,
            } => {
                if sequence == 0
                    || bytes.len() > self.config.max_message
                    || kind == Kind::Cork && !bytes.is_empty()
                {
                    return Err(Error::Limit);
                }
                if self.state.is_closed(flow) {
                    return Ok(vec![Action::Gone(flow)]);
                }
                let f = self.state.flow(flow).ok_or(Error::UnknownFlow)?;
                if sequence <= f.received {
                    return Ok(f
                        .outcomes
                        .iter()
                        .find(|r| r.sequence == sequence)
                        .map(|r| {
                            vec![Action::Receipt {
                                id: self.id(flow, sequence),
                                outcome: r.outcome.clone(),
                            }]
                        })
                        .unwrap_or_default());
                }
                if f.closing == Closing::Received {
                    return Err(Error::Closed);
                }
                if sequence != f.received.checked_add(1).ok_or(Error::Limit)? {
                    return Err(Error::Sequence);
                }
                if self.delivery.is_some() {
                    return Err(Error::Busy);
                }
                let id = self.id(flow, sequence);
                self.delivery = Some((id.clone(), kind));
                if kind == Kind::Cork {
                    let result = self.decide(id, Outcome::Accepted);
                    if result.is_err() {
                        self.delivery = None;
                    }
                    return result;
                }
                Ok(vec![Action::Deliver { id, kind, bytes }])
            }
            Event::Decide { id, outcome } => self.decide(id, outcome),
            Event::Ack {
                flow,
                sequence,
                rejected,
            } => {
                let mut s = self.state.clone();
                let f = get(&mut s, flow)?;
                let m = f.outbox.as_mut().ok_or(Error::Sequence)?;
                if m.sequence != sequence {
                    return Err(Error::Sequence);
                }
                if rejected {
                    if m.kind != Kind::Plea {
                        return Err(Error::Decision);
                    }
                    if m.rejection_known {
                        return Ok(vec![Action::FetchExplanation(self.id(flow, sequence))]);
                    }
                    m.rejection_known = true;
                    let id = self.id(flow, sequence);
                    self.propose(
                        s,
                        Change::RejectionKnown(id.clone()),
                        vec![Action::FetchExplanation(id)],
                    )
                } else {
                    // A positive packet cannot erase an already authenticated NACK.
                    if m.rejection_known {
                        return Err(Error::Decision);
                    }
                    self.settle(s, flow, sequence, Outcome::Accepted)
                }
            }
            Event::Explanation {
                flow,
                sequence,
                bytes,
            } => {
                if bytes.len() > self.config.max_error {
                    return Err(Error::Limit);
                }
                let s = self.state.clone();
                let m = s
                    .flow(flow)
                    .and_then(|f| f.outbox.as_ref())
                    .ok_or(Error::Sequence)?;
                if m.sequence != sequence || !m.rejection_known {
                    return Err(Error::Sequence);
                }
                self.settle(s, flow, sequence, Outcome::Rejected(bytes))
            }
            Event::Close(flow) => {
                let mut s = self.state.clone();
                let f = get(&mut s, flow)?;
                if f.closing != Closing::Open {
                    return Err(Error::Closed);
                }
                f.closing = Closing::Requested;
                let mut out = Vec::new();
                if f.outbox.is_none() {
                    out.push(self.cork(f)?);
                }
                self.propose(s, Change::Close(flow), out)
            }
            Event::Gone(flow) => {
                if self.state.is_closed(flow) {
                    return Ok(vec![Action::Gone(flow)]);
                }
                let mut s = self.state.clone();
                let f = get(&mut s, flow)?;
                let sole_cork = f.closing == Closing::Requested
                    && f.outbox.as_ref().is_some_and(|m| m.kind == Kind::Cork);
                if f.closing != Closing::Received && !sole_cork {
                    return Err(Error::Decision);
                }
                let unconfirmed = f
                    .outbox
                    .as_ref()
                    .filter(|m| m.kind != Kind::Cork)
                    .map(|m| self.id(flow, m.sequence));
                let mut out = vec![Action::Gone(flow)];
                if let Some(id) = &unconfirmed {
                    out.push(Action::Unconfirmed(id.clone()));
                }
                close(&mut s, flow)?;
                self.propose(s, Change::Closed { flow, unconfirmed }, out)
            }
            Event::Committed(_) => unreachable!(),
        }
    }
    fn open(&mut self, mut s: State, flow: Flow) -> Result<Vec<Action>, Error> {
        if flow.bone == 0 || s.is_closed(flow) {
            return Err(Error::Closed);
        }
        if s.flow(flow).is_some() {
            return Err(Error::Invalid);
        }
        if s.flows.len() >= self.config.max_flows
            || s.closed.len() + s.flows.len() >= self.config.max_intervals
        {
            return Err(Error::Backpressure);
        }
        // Reserve the worst-case rejection window before any delivery offer.
        if s.flows
            .len()
            .checked_add(1)
            .and_then(|n| n.checked_mul(10))
            .and_then(|n| n.checked_mul(self.config.max_error))
            .is_none_or(|n| n > self.config.max_retained_errors)
        {
            return Err(Error::Backpressure);
        }
        s.flows.push(FlowState {
            flow,
            next_send: 1,
            received: 0,
            outbox: None,
            outcomes: Vec::new(),
            closing: Closing::Open,
        });
        s.flows.sort_by_key(|f| f.flow);
        self.propose(s, Change::Open(flow), Vec::new())
    }
    fn decide(&mut self, id: Id, outcome: Outcome) -> Result<Vec<Action>, Error> {
        let Some((expected, kind)) = &self.delivery else {
            return Err(Error::Decision);
        };
        if &id != expected {
            return Err(Error::Decision);
        }
        if let Outcome::Rejected(bytes) = &outcome {
            if *kind != Kind::Plea {
                return Err(Error::Decision);
            }
            if bytes.len() > self.config.max_error {
                return Err(Error::Limit);
            }
        }
        let mut s = self.state.clone();
        let f = get(&mut s, id.flow)?;
        f.received = id.sequence;
        f.outcomes.push(Receipt {
            sequence: id.sequence,
            outcome: outcome.clone(),
        });
        let floor = id.sequence.saturating_sub(9).max(1);
        f.outcomes.retain(|r| r.sequence >= floor);
        let mut out = vec![Action::Receipt {
            id: id.clone(),
            outcome: outcome.clone(),
        }];
        if *kind == Kind::Cork {
            f.closing = Closing::Received;
            out.push(Action::FetchGone(id.flow));
        }
        self.propose(s, Change::Accept(id, outcome), out)
    }
    fn cork(&self, f: &mut FlowState) -> Result<Action, Error> {
        let sequence = f.next_send;
        f.next_send = f.next_send.checked_add(1).ok_or(Error::Limit)?;
        f.outbox = Some(Message {
            sequence,
            kind: Kind::Cork,
            bytes: Buffer::default(),
            rejection_known: false,
        });
        Ok(Action::Transmit {
            id: self.id(f.flow, sequence),
            kind: Kind::Cork,
            bytes: Buffer::default(),
        })
    }
    fn settle(
        &mut self,
        mut s: State,
        flow: Flow,
        sequence: u64,
        outcome: Outcome,
    ) -> Result<Vec<Action>, Error> {
        let f = get(&mut s, flow)?;
        let m = f.outbox.take().ok_or(Error::Sequence)?;
        let id = self.id(flow, sequence);
        let mut out = Vec::new();
        if m.kind == Kind::Cork {
            close(&mut s, flow)?;
            out.push(Action::Gone(flow));
        } else {
            out.push(Action::Settled {
                id: id.clone(),
                outcome: outcome.clone(),
            });
            if f.closing == Closing::Requested {
                out.push(self.cork(f)?);
            }
        }
        self.propose(s, Change::Settlement(id, outcome), out)
    }
    fn propose(
        &mut self,
        mut state: State,
        change: Change,
        out: Vec<Action>,
    ) -> Result<Vec<Action>, Error> {
        state.revision = state.revision.checked_add(1).ok_or(Error::Limit)?;
        validate(&self.config, &state)?;
        encode(&self.config, &state)?;
        let proposal = Proposal {
            token: Token {
                incarnation: self.incarnation,
                revision: state.revision,
            },
            base_revision: self.state.revision,
            state,
            change,
        };
        self.pending = Some((proposal.clone(), out));
        Ok(vec![Action::Commit(Box::new(proposal))])
    }
}
fn get(s: &mut State, flow: Flow) -> Result<&mut FlowState, Error> {
    s.flows
        .iter_mut()
        .find(|f| f.flow == flow)
        .ok_or(Error::UnknownFlow)
}
fn close(s: &mut State, flow: Flow) -> Result<(), Error> {
    s.flows.retain(|f| f.flow != flow);
    s.closed.push(Interval {
        class: (flow.bone % 4) as u8,
        backward: flow.backward,
        first: flow.bone / 4,
        last: flow.bone / 4,
    });
    s.closed.sort_by_key(|r| (r.class, r.backward, r.first));
    let mut merged: Vec<Interval> = Vec::new();
    for range in s.closed.drain(..) {
        if let Some(last) = merged.last_mut() {
            if last.class == range.class
                && last.backward == range.backward
                && last
                    .last
                    .checked_add(1)
                    .is_some_and(|end| range.first <= end)
            {
                last.last = last.last.max(range.last);
                continue;
            }
        }
        merged.push(range);
    }
    s.closed = merged;
    Ok(())
}
fn encode(c: &Config, s: &State) -> Result<Buffer, Error> {
    struct Limited {
        bytes: Vec<u8>,
        max: usize,
    }
    impl std::io::Write for Limited {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > self.max.saturating_sub(self.bytes.len()) {
                return Err(std::io::Error::other("checkpoint limit"));
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut out = Limited {
        bytes: Vec::new(),
        max: c.max_checkpoint,
    };
    serde_json::to_writer(&mut out, s).map_err(|_| Error::Limit)?;
    Ok(out.bytes.into())
}
fn validate(c: &Config, s: &State) -> Result<(), Error> {
    mesa_wire::DomainTag::new(&s.epoch.domain).map_err(|_| Error::Epoch)?;
    mesa_wire::DomainTag::new(&s.epoch.remote_domain).map_err(|_| Error::Epoch)?;
    if s.schema != SCHEMA || s.profile != PROFILE {
        return Err(Error::Profile);
    }
    if s.next_bone == 0
        || s.flows.len() > c.max_flows
        || s.closed
            .len()
            .checked_add(s.flows.len())
            .is_none_or(|n| n > c.max_intervals)
    {
        return Err(Error::Limit);
    }
    if s.flows
        .len()
        .checked_mul(10)
        .and_then(|n| n.checked_mul(c.max_error))
        .is_none_or(|n| n > c.max_retained_errors)
    {
        return Err(Error::Limit);
    }
    for (i, f) in s.flows.iter().enumerate() {
        if f.flow.bone == 0
            || f.next_send == 0
            || s.is_closed(f.flow)
            || i > 0 && s.flows[i - 1].flow >= f.flow
        {
            return Err(Error::Invalid);
        }
        if let Some(m) = &f.outbox {
            if m.sequence == 0
                || m.sequence.checked_add(1) != Some(f.next_send)
                || m.bytes.len() > c.max_message
                || m.rejection_known && m.kind != Kind::Plea
                || m.kind == Kind::Cork
                    && (!matches!(f.closing, Closing::Requested | Closing::Received)
                        || !m.bytes.is_empty())
            {
                return Err(Error::Invalid);
            }
        }
        if f.closing == Closing::Received
            && !f
                .outcomes
                .last()
                .is_some_and(|r| r.outcome == Outcome::Accepted)
        {
            return Err(Error::Invalid);
        }
        if f.closing == Closing::Requested && f.outbox.is_none() {
            return Err(Error::Invalid);
        }
        let floor = f.received.saturating_sub(9).max(1);
        if f.outcomes.len() != f.received.min(10) as usize {
            return Err(Error::Invalid);
        }
        for (i, r) in f.outcomes.iter().enumerate() {
            if r.sequence != floor + i as u64
                || matches!(&r.outcome,Outcome::Rejected(b) if b.len()>c.max_error)
            {
                return Err(Error::Invalid);
            }
        }
    }
    for (i, r) in s.closed.iter().enumerate() {
        if r.class > 3 || r.first > r.last || r.last > u64::MAX / 4 {
            return Err(Error::Invalid);
        }
        if i > 0 {
            let p = &s.closed[i - 1];
            if (p.class, p.backward, p.first) >= (r.class, r.backward, r.first)
                || p.class == r.class
                    && p.backward == r.backward
                    && p.last.checked_add(1).is_none_or(|end| end >= r.first)
            {
                return Err(Error::Invalid);
            }
        }
    }
    Ok(())
}
