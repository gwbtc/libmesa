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

/// Import the explicitly selected current ring layout. The returned public
/// candidate reconstructs the exact pass, including evidence and byte width.
/// The caller owns the source buffer; destroying Material cannot wipe aliases.
pub fn suite_c_material(
    ring: Buffer,
    domain: &str,
    expected: PeerId,
    life: u32,
    rift: u32,
    limits: suite_c::Limits,
) -> Result<mesa_keys::Material, mesa_keys::Error> {
    use mesa_keys::Error;
    if ring.len() > limits.max_blob_bytes {
        return Err(Error::Invalid);
    }
    let tag = DomainTag::new(domain).map_err(|_| Error::Invalid)?;
    ring.with_bytes(|bytes| {
        let parsed = suite_c::parse_current_ring(bytes, tag, limits).map_err(|_| Error::Invalid)?;
        let public = mesa_crypto::KeyPair::from_seed(parsed.live_seed()).public_key();
        let mut pass = Vec::with_capacity(bytes.len());
        pass.push(b'c');
        pass.extend_from_slice(&bytes[33..65]);
        pass.extend_from_slice(public.as_bytes());
        pass.extend_from_slice(&bytes[65..]);
        let bound =
            BoundPass::new(suite_c::parse_pass(&pass, tag, limits).map_err(|_| Error::Invalid)?)
                .map_err(|_| Error::Invalid)?;
        bound.require_name(expected).map_err(|_| Error::Conflict)?;
        bound.check_ring(&parsed).map_err(|_| Error::Conflict)?;
        let candidate = suite_c_candidate(pass.into(), domain, expected, life, rift, limits)
            .map_err(|_| Error::Invalid)?;
        mesa_keys::Material::from_seed(candidate, parsed.live_seed())
    })
}
