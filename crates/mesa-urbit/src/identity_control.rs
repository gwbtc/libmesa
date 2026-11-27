//! Direct suite-C old-Ames identity controls only. No old-Ames messages, relay,
//! Azimuth lookup, or transport migration. Four-bit ticks never select a key.
use crate::{
    admission::Open,
    gage::{self, Builder},
    Buffer, Error,
};
use mesa_crypto::KeyPair;
use mesa_identity::suite_c::{self, crypto::BoundPass};
use mesa_noun::{bits::Bits, serial};
use mesa_pki::Candidate;
use mesa_wire::{DomainTag, PeerId};
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Control {
    Keys {
        sender: u128,
        receiver: u128,
        sender_tick: u8,
    },
    Open {
        sender: u128,
        receiver: u128,
        content: Buffer,
    },
}
fn header(
    sender: u128,
    receiver: u128,
    life: u32,
    receiver_life: u32,
    content: &[u8],
) -> Result<Buffer, Error> {
    if sender <= u64::MAX as u128
        || receiver <= u64::MAX as u128
        || content.len() > 1400
        || content.is_empty()
        || content.last() == Some(&0)
    {
        return Err(Error::Limit);
    }
    let mut body = vec![(life as u8 & 15) | ((receiver_life as u8 & 15) << 4)];
    body.extend(sender.to_le_bytes());
    body.extend(receiver.to_le_bytes());
    body.extend(content);
    let checksum = mesa_bytes::mug::mug_bytes(&body) & 0xfffff;
    let head = 0x8000_0780u32 | (checksum << 11);
    let mut out = head.to_le_bytes().to_vec();
    out.extend(body);
    Ok(out.into())
}
pub fn keys(sender: u128, receiver: u128, life: u32) -> Result<Buffer, Error> {
    header(sender, receiver, life, 1, b"keys")
}
pub fn decode(bytes: &Buffer) -> Result<Control, Error> {
    if !(38..=1472).contains(&bytes.len()) {
        return Err(Error::Limit);
    }
    bytes.with_bytes(|b| {
        let h = u32::from_le_bytes(b[..4].try_into().unwrap());
        if h & 0x8000_07ff != 0x8000_0780
            || b.last() == Some(&0)
            || ((h >> 11) & 0xfffff) != mesa_bytes::mug::mug_bytes(&b[4..]) & 0xfffff
        {
            return Err(Error::Encoding);
        }
        let sender = u128::from_le_bytes(b[5..21].try_into().unwrap());
        let receiver = u128::from_le_bytes(b[21..37].try_into().unwrap());
        if sender <= u64::MAX as u128 || receiver <= u64::MAX as u128 {
            return Err(Error::Unsupported);
        }
        if &b[37..] == b"keys" {
            Ok(Control::Keys {
                sender,
                receiver,
                sender_tick: b[4] & 15,
            })
        } else {
            Ok(Control::Open {
                sender,
                receiver,
                content: b[37..].to_vec().into(),
            })
        }
    })
}
fn body(open: &Open) -> Result<Buffer, Error> {
    if open.pass.len() > 1024 || open.sender_life == 0 || open.receiver_life == 0 {
        return Err(Error::Limit);
    }
    let mut b = Builder::new();
    let p = b.atom(open.pass.dat().to_vec());
    let s = b.atom(open.sender.to_le_bytes().to_vec());
    let sl = b.uint(open.sender_life as u64);
    let r = b.atom(open.receiver.to_le_bytes().to_vec());
    let rl = b.uint(open.receiver_life as u64);
    let root = b.tuple(&[p, s, sl, r, rl]);
    b.finish(root, 1200)
}
/// `%keys` recovery addresses receiver life 1, never its unauthenticated tick.
/// Proactive current-key announcements use the exact known receiver life.
pub fn encode(open: &Open, key: &KeyPair) -> Result<Buffer, Error> {
    let signed = body(open)?;
    let signature = signed.with_bytes(|b| key.sign(b));
    let mut b = Builder::new();
    let signature = b.atom(signature.to_vec());
    let signed = b.atom(signed.dat().to_vec());
    let root = b.cell(signature, signed);
    let content = b.finish(root, 1400)?;
    content.with_bytes(|c| {
        header(
            open.sender,
            open.receiver,
            open.sender_life,
            open.receiver_life,
            c,
        )
    })
}
fn uint128(n: &serial::Noun<'_>, id: usize) -> Result<u128, Error> {
    let a = gage::atom(n, id, 16)?;
    let mut out = [0; 16];
    out[..a.len()].copy_from_slice(&a);
    Ok(u128::from_le_bytes(out))
}
/// Screen a signed open packet before provider dispatch. `rift` comes from
/// authority state, since the old-Ames signed body contains no epoch field.
pub fn screen(
    bytes: &Buffer,
    local: u128,
    life: u32,
    rift: u32,
    domain: &str,
    historical_life_one: bool,
) -> Result<Candidate, Error> {
    let Control::Open {
        sender,
        receiver,
        content,
    } = decode(bytes)?
    else {
        return Err(Error::Shape);
    };
    if receiver != local {
        return Err(Error::Coordinate);
    }
    content.with_bytes(|content| {
        let n = serial::cue(
            Bits::from_atom_bytes(content).map_err(|_| Error::Encoding)?,
            gage::limits(1400)?,
        )
        .map_err(|_| Error::Encoding)?;
        let (sig, signed) = gage::cell(&n, n.root())?;
        let sig = gage::atom(&n, sig, 64)?;
        let mut signature = [0; 64];
        signature[..sig.len()].copy_from_slice(&sig);
        let signed = gage::atom(&n, signed, 1200)?;
        let n = serial::cue(
            Bits::from_atom_bytes(&signed).map_err(|_| Error::Encoding)?,
            gage::limits(1200)?,
        )
        .map_err(|_| Error::Encoding)?;
        let (pass, rest) = gage::cell(&n, n.root())?;
        let (s, rest) = gage::cell(&n, rest)?;
        let (sl, rest) = gage::cell(&n, rest)?;
        let (r, rl) = gage::cell(&n, rest)?;
        let sl: u32 = gage::uint(&n, sl)?
            .try_into()
            .map_err(|_| Error::Coordinate)?;
        let rl: u32 = gage::uint(&n, rl)?
            .try_into()
            .map_err(|_| Error::Coordinate)?;
        if uint128(&n, s)? != sender
            || uint128(&n, r)? != receiver
            || sl == 0
            || (rl != life && rl != 1)
        {
            return Err(Error::Coordinate);
        }
        let pass = gage::atom(&n, pass, 1024)?;
        let parsed = suite_c::parse_pass(
            &pass,
            DomainTag::new(domain).map_err(|_| Error::Coordinate)?,
            suite_c::Limits {
                max_blob_bytes: 1024,
                ..Default::default()
            },
        )
        .map_err(|_| Error::Shape)?;
        let bound = BoundPass::new(parsed).map_err(|_| Error::Encoding)?;
        bound
            .require_name(PeerId(sender))
            .map_err(|_| Error::Coordinate)?;
        if bound.live_key().verify(&signed, &signature).is_err()
            && !(historical_life_one
                && sl == 1
                && bound.name_key().verify(&signed, &signature).is_ok())
        {
            return Err(Error::Encoding);
        }
        Ok(Candidate {
            peer: sender,
            life: sl,
            rift,
            domain: domain.into(),
            public_key: *bound.live_key().as_bytes(),
            evidence: pass.into(),
        })
    })
}

/// Bounded current-key announcements after durable activation. The pinned Urbit
/// kernel does not solicit a new point merely from a mismatched private life.
/// Retransmission therefore belongs to the sender. A completed budget is not an
/// acknowledgment; the host observes authenticated traffic before claiming use.
pub struct Announcement {
    packet: mesa_core::credentials::FencedPacket,
    retry: mesa_core::policy::RetryTimer,
    attempts: u32,
    maximum: u32,
    now: u64,
    due: Option<u64>,
    deadline: u64,
}
impl Announcement {
    pub fn new(
        packet: mesa_core::credentials::FencedPacket,
        now: u64,
        retry: mesa_core::policy::RetryTimer,
        maximum: u32,
        timeout: u64,
    ) -> Result<Self, Error> {
        if !(1..=8).contains(&maximum)
            || retry.delay(1) < 100
            || retry.delay(8) > 60000
            || !(1..=60000).contains(&timeout)
        {
            return Err(Error::Limit);
        }
        if !matches!(decode(&packet.bytes())?,Control::Open {receiver,..} if receiver==packet.peer().0)
        {
            return Err(Error::Coordinate);
        }
        let deadline = now.checked_add(timeout).ok_or(Error::Limit)?;
        Ok(Self {
            packet,
            retry,
            attempts: 0,
            maximum,
            now,
            due: Some(now),
            deadline,
        })
    }
    pub fn deadline(&self) -> Option<u64> {
        self.due.map(|d| d.min(self.deadline))
    }
    pub fn cancel(&mut self) {
        self.due = None;
    }
    pub fn advance(
        &mut self,
        now: u64,
    ) -> Result<Option<mesa_core::credentials::FencedPacket>, Error> {
        if now < self.now {
            return Err(Error::Coordinate);
        }
        self.now = now;
        let Some(due) = self.due else {
            return Ok(None);
        };
        if now >= self.deadline || self.packet.submit(|_, _, _| ()).is_err() {
            self.cancel();
            return Ok(None);
        }
        if now < due {
            return Ok(None);
        }
        self.attempts += 1;
        self.due = if self.attempts < self.maximum {
            Some(
                now.checked_add(self.retry.delay(self.attempts))
                    .ok_or(Error::Limit)?,
            )
        } else {
            None
        };
        Ok(Some(self.packet.clone()))
    }
}
