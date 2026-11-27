//! Suite-C proof screening. Only a domain provider can authorize the candidate.
//! Public-life-1 proof coordinates are bootstrap conventions, not key currency.
use crate::{
    gage::{self, Builder},
    path, Buffer, Error,
};
use mesa_identity::suite_c::{self, crypto::BoundPass};
use mesa_noun::{
    bits::Bits,
    serial::{self, Noun},
};
use mesa_pki::Candidate;
use mesa_wire::mesa_v1::{self as wire, Auth, Body, Fragment};

pub const MAX_PROOF: usize = 1024;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Open {
    pub pass: Buffer,
    pub sender: u128,
    pub sender_life: u32,
    pub receiver: u128,
    pub receiver_life: u32,
}
pub fn encode(open: &Open) -> Result<Buffer, Error> {
    if open.pass.len() > MAX_PROOF || open.sender_life == 0 || open.receiver_life == 0 {
        return Err(Error::Limit);
    }
    let mut b = Builder::new();
    let mark = b.text("open-packet");
    let pass = b.atom(open.pass.dat().to_vec());
    let sender = b.atom(open.sender.to_le_bytes().to_vec());
    let sl = b.uint(open.sender_life as u64);
    let receiver = b.atom(open.receiver.to_le_bytes().to_vec());
    let rl = b.uint(open.receiver_life as u64);
    let root = b.tuple(&[mark, pass, sender, sl, receiver, rl]);
    b.finish(root, MAX_PROOF)
}
fn peer(n: &Noun<'_>, id: usize) -> Result<u128, Error> {
    let v = gage::atom(n, id, 16)?;
    let mut a = [0; 16];
    a[..v.len()].copy_from_slice(&v);
    Ok(u128::from_le_bytes(a))
}
pub fn decode(bytes: &[u8]) -> Result<Open, Error> {
    if bytes.len() > MAX_PROOF {
        return Err(Error::Limit);
    }
    let n = serial::cue(
        Bits::from_atom_bytes(bytes).map_err(|_| Error::Encoding)?,
        gage::limits(MAX_PROOF)?,
    )
    .map_err(|_| Error::Encoding)?;
    let (mark, rest) = gage::cell(&n, n.root())?;
    if !gage::is(&n, mark, b"open-packet") {
        return Err(Error::Shape);
    }
    let (pass, rest) = gage::cell(&n, rest)?;
    let (sender, rest) = gage::cell(&n, rest)?;
    let (sl, rest) = gage::cell(&n, rest)?;
    let (receiver, rl) = gage::cell(&n, rest)?;
    let open = Open {
        pass: gage::atom(&n, pass, MAX_PROOF)?.into(),
        sender: peer(&n, sender)?,
        sender_life: gage::uint(&n, sl)?
            .try_into()
            .map_err(|_| Error::Coordinate)?,
        receiver: peer(&n, receiver)?,
        receiver_life: gage::uint(&n, rl)?
            .try_into()
            .map_err(|_| Error::Coordinate)?,
    };
    if open.sender_life == 0 || open.receiver_life == 0 {
        return Err(Error::Coordinate);
    }
    Ok(open)
}
/// Construct this from the local active identity and registered provider policy.
/// `rift` is the authority's expected epoch, never copied from a UDP packet.
#[derive(Clone)]
pub struct ProofProfile {
    pub local: u128,
    pub life: u32,
    pub local_rift: u32,
    pub rift: u32,
    pub domain: String,
    pub historical_life_one: bool,
}
impl mesa_jael::AdmissionProfile for ProofProfile {
    fn screen(&self, packet: &Buffer) -> Result<Candidate, mesa_pki::Error> {
        self.screen_proof(packet)
            .map_err(|_| mesa_pki::Error::Invalid)
    }
}
impl ProofProfile {
    pub fn screen_proof(&self, packet: &Buffer) -> Result<Candidate, Error> {
        if packet.len() > 1472 {
            return Err(Error::Limit);
        }
        packet.with_bytes(|bytes| {
            let packet = wire::decode(bytes, wire::Checksum::VereBytes, wire::Limits::DATAGRAM)
                .map_err(|_| Error::Encoding)?;
            let (name, data) = match packet.body {
                Body::Page {
                    name,
                    data,
                    next: None,
                } => (name, data),
                Body::Poke { payload, data, .. } => (payload, data),
                _ => return Err(Error::Shape),
            };
            if name.ship <= u64::MAX as u128
                || name.rift != self.rift
                || name.bloq != 13
                || !matches!(name.fragment, Fragment::Init | Fragment::Data(0))
                || data.total_bytes as usize != data.fragment.len()
                || data.fragment.len() > MAX_PROOF
            {
                return Err(Error::Coordinate);
            }
            if name.path != path::proof(self.local, self.life)? {
                return Err(Error::Coordinate);
            }
            let Auth::Signature(signature) = data.auth else {
                return Err(Error::Shape);
            };
            let open = decode(data.fragment)?;
            if open.sender != name.ship
                || open.receiver != self.local
                || open.receiver_life != self.life
            {
                return Err(Error::Coordinate);
            }
            let tag = mesa_wire::DomainTag::new(&self.domain).map_err(|_| Error::Coordinate)?;
            let key = open.pass.with_bytes(|bytes| {
                let parsed = suite_c::parse_pass(
                    bytes,
                    tag,
                    suite_c::Limits {
                        max_blob_bytes: MAX_PROOF,
                        ..Default::default()
                    },
                )
                .map_err(|_| Error::Shape)?;
                let bound = BoundPass::new(parsed).map_err(|_| Error::Shape)?;
                bound
                    .require_name(mesa_core::PeerId(open.sender))
                    .map_err(|_| Error::Coordinate)?;
                let root = mesa_lss::Tree::build(data.fragment)
                    .map_err(|_| Error::Limit)?
                    .mesa_root();
                let mut context = path::beam_prefix(open.sender, self.rift)?;
                context.extend(name.path);
                context.extend(root);
                let current = bound.live_key().verify(&context, signature).is_ok();
                let historical = self.historical_life_one
                    && open.sender_life == 1
                    && bound.name_key().verify(&context, signature).is_ok();
                if !current && !historical {
                    return Err(Error::Encoding);
                }
                Ok(*bound.live_key().as_bytes())
            })?;
            Ok(Candidate {
                peer: open.sender,
                domain: self.domain.clone(),
                life: open.sender_life,
                rift: self.rift,
                public_key: key,
                evidence: open.pass,
            })
        })
    }
}
