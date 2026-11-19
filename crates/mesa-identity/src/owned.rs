//! Owned profile boundary. Parsing/name binding stays inside Mesa. The full
//! canonical pass is retained as verifier evidence so exact bit framing and
//! genesis/domain material remain available without exporting borrowed nouns.
use crate::suite_c::{self, crypto::BoundPass};
use mesa_pki::{Buffer, Candidate, Error};
use mesa_wire::{DomainTag, PeerId};

pub fn suite_c_candidate(
    pass: Buffer,
    domain: &str,
    expected: PeerId,
    life: u32,
    rift: u32,
    limits: suite_c::Limits,
) -> Result<Candidate, Error> {
    if pass.len() > limits.max_blob_bytes || life == 0 {
        return Err(Error::Invalid);
    }
    let domain_tag = DomainTag::new(domain).map_err(|_| Error::Invalid)?;
    let public_key = pass.with_bytes(|bytes| {
        let parsed = suite_c::parse_pass(bytes, domain_tag, limits).map_err(|_| Error::Invalid)?;
        let bound = BoundPass::new(parsed).map_err(|_| Error::Invalid)?;
        bound.require_name(expected).map_err(|_| Error::Invalid)?;
        Ok(*bound.live_key().as_bytes())
    })?;
    Ok(Candidate {
        peer: expected.0,
        domain: domain.into(),
        life,
        rift,
        public_key,
        evidence: pass,
    })
}
