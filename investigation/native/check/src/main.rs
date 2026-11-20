use mesa_wire::legacy_v1::{self as wire, Auth, Body, Checksum, Fragment, Limits};
use serde_json::{json, Value};
use std::{env, fs};
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn main() {
    let args: Vec<_> = env::args().collect();
    let records: Vec<Value> = serde_json::from_slice(&fs::read(&args[1]).unwrap()).unwrap();
    let key_record: Value = serde_json::from_slice(&fs::read(&args[4]).unwrap()).unwrap();
    let key_hex = key_record["signing_key_le_hex"].as_str().unwrap();
    let key: Vec<_> = (0..key_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&key_hex[i..i + 2], 16).unwrap())
        .collect();
    let public = mesa_crypto::PublicKey::from_bytes(key.try_into().unwrap()).unwrap();
    let mut signatures_verified = 0;
    let mut multi_auth = None;
    let mut proof = None;
    let mut leaves = Vec::new();
    let mut summary = Vec::new();
    for row in records.iter().filter(|r| r["direction"] == "receive") {
        let s = row["hex"].as_str().unwrap();
        let bytes: Vec<_> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect();
        let packet = wire::decode(&bytes, Checksum::VereBytes, Limits::DATAGRAM).unwrap();
        let Body::Page { name, data, next } = packet.body else {
            panic!("expected page")
        };
        let kind = match data.auth {
            Auth::Signature(_) => "signature",
            Auth::Mac(_) => "mac",
            Auth::Pair(_) => "pair",
            Auth::None => "none",
        };
        summary.push(json!({"case":row["case"],"fragment":format!("{:?}",name.fragment),"total":data.total_bytes,"bytes":data.fragment.len(),"auth":kind,"trailer":next,"path":String::from_utf8_lossy(name.path),"hoon_checksum_accepts":wire::decode(&bytes,Checksum::HoonAtom,Limits::DATAGRAM).is_ok()}));
        if row["case"] == "multi-init" {
            let Auth::Signature(sig) = data.auth else {
                panic!("missing signature")
            };
            multi_auth = Some((sig.to_vec(), name.path.to_vec()));
        }
        if row["case"] == "public-read" {
            let root = *blake3::hash(data.fragment).as_bytes();
            let Auth::Signature(sig) = data.auth else {
                panic!("missing signature")
            };
            let mut binding = b"/~zod//1/".to_vec();
            binding.extend(name.path);
            binding.extend(root);
            public.verify(&binding, sig).unwrap();
            let mut v2_binding = binding[..binding.len() - 32].to_vec();
            v2_binding.extend(mesa_lss::Tree::build(data.fragment).unwrap().root());
            assert!(public.verify(&v2_binding, sig).is_err());
            binding[1] ^= 1;
            assert!(public.verify(&binding, sig).is_err());
            signatures_verified += 1;
        }
        if row["case"] == "public-read" {
            fs::write(&args[2], data.fragment).unwrap();
        }
        if row["case"] == "multi-init" {
            proof = Some((data.total_bytes as usize, data.fragment.to_vec()));
        }
        if row["case"].as_str().unwrap().starts_with("multi-data-") {
            let Fragment::Data(i) = name.fragment else {
                panic!("expected data")
            };
            let pair = if let Auth::Pair(b) = data.auth {
                Some([b[..32].try_into().unwrap(), b[32..].try_into().unwrap()])
            } else {
                None
            };
            leaves.push((i, data.fragment.to_vec(), pair));
        }
    }
    let (total, proof) = proof.expect("missing auth response");
    let mut verifier = mesa_lss::Verifier::new(total, &proof).unwrap();
    leaves.sort_by_key(|x| x.0);
    assert_eq!(leaves.len(), 5);
    let mut value = Vec::new();
    for (i, bytes, pair) in &leaves {
        assert_eq!(*i as usize, verifier.next_index());
        verifier.ingest(bytes, pair.as_ref()).unwrap();
        value.extend(bytes);
    }
    assert!(verifier.complete());
    assert_eq!(value.len(), total);
    assert_eq!(
        mesa_lss::Tree::build(&value).unwrap().root(),
        verifier.root()
    );
    let root = blake3::hash(&value);
    let (sig, path) = multi_auth.unwrap();
    let mut binding = b"/~zod//1/".to_vec();
    binding.extend(path);
    binding.extend(root.as_bytes());
    public
        .verify(&binding, sig.as_slice().try_into().unwrap())
        .unwrap();
    let mut v2_binding = binding[..binding.len() - 32].to_vec();
    v2_binding.extend(verifier.root());
    assert!(public
        .verify(&v2_binding, sig.as_slice().try_into().unwrap())
        .is_err());
    binding[1] ^= 1;
    assert!(public
        .verify(&binding, sig.as_slice().try_into().unwrap())
        .is_err());
    signatures_verified += 1;
    fs::write(&args[3], value).unwrap();
    assert_eq!(summary.len(), 7);
    assert_eq!(
        summary
            .iter()
            .filter(|r| r["hoon_checksum_accepts"] == false)
            .count(),
        4
    );
    println!("{}",serde_json::to_string_pretty(&json!({"pages":summary,"lss_verified":true,"signatures_verified":signatures_verified,"v2_cv_root":hex(&verifier.root()),"native_signed_root":hex(root.as_bytes())})).unwrap());
}
