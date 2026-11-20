#![allow(dead_code)]
use mesa_crypto::KeyPair;
use mesa_keys::*;
use mesa_pki::{Authority, Candidate, Limits, Provider, ProviderStatus};
pub fn candidate(peer: u128, life: u32, rift: u32, seed: u8) -> Candidate {
    Candidate {
        peer,
        domain: "gw-btc".into(),
        life,
        rift,
        public_key: *KeyPair::from_seed(&[seed; 32]).public_key().as_bytes(),
        evidence: Buffer::new(vec![life as u8], 4).unwrap(),
    }
}
pub fn authority() -> (Authority, Provider) {
    let mut a = Authority::new(Limits::default(), 1).unwrap();
    let p = a.register("gw-btc", 0, 1).unwrap();
    a.commit(p.token).unwrap();
    let p = a.provider("gw-btc").unwrap();
    a.set_status(
        "gw-btc",
        p,
        ProviderStatus {
            available: true,
            ready: true,
        },
    )
    .unwrap();
    (a, p)
}
pub fn install(a: &mut Authority, p: Provider, c: Candidate) {
    let q = a.accept(p, a.revision(c.peer), c, None, None).unwrap();
    a.commit(q.token).unwrap();
}
pub fn reference(v: u64) -> KeyRef {
    KeyRef {
        backend: 1,
        object: 1,
        version: v,
    }
}
pub fn config() -> Config {
    Config {
        peer: 1,
        domain: "gw-btc".into(),
        incarnation: 10,
        host_epoch: 99,
        history: 2,
        operations: 4,
        timeout: 20,
        checkpoint_bytes: 1024 * 1024,
    }
}
pub fn stage(s: &mut SoftwareStore, v: u64, c: Candidate, seed: u8) {
    s.import(reference(v), Material::from_seed(c, &[seed; 32]).unwrap())
        .unwrap()
}
pub fn store() -> SoftwareStore {
    SoftwareStore::new(8, 8).unwrap()
}
pub fn commit(k: &mut Activation, a: &Authority, s: &SoftwareStore, v: u64) -> Proposal {
    let q = k.prepare(a, s, reference(v), None).unwrap();
    k.commit(a, s, q.token).unwrap();
    q
}
pub fn root() -> mesa_keys::operations::Purpose {
    mesa_keys::operations::Purpose::PublicRoot {
        path: Buffer::new(vec![1], 4).unwrap(),
        total: 64,
        root: [6; 32],
    }
}
