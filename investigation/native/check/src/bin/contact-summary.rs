use mesa_wire::legacy_v1::{self as wire, Auth, Body, Checksum, Limits, Name};
use serde_json::{json, Value};
use std::{env, fs};
fn name(n: Name<'_>) -> Value {
    json!({"ship_hex":format!("{:032x}",n.ship),"rift":n.rift,"fragment":format!("{:?}",n.fragment),"path":String::from_utf8_lossy(n.path)})
}
fn main() {
    let input = fs::read_to_string(env::args().nth(1).expect("packet JSONL")).unwrap();
    let keys: Option<Vec<Value>> = env::args()
        .nth(2)
        .map(|path| serde_json::from_slice(&fs::read(path).unwrap()).unwrap());
    let mut verified = 0;
    let mut rows = Vec::new();
    for line in input.lines() {
        let mut row: Value = serde_json::from_str(line).unwrap();
        let hex = row["hex"].as_str().unwrap();
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        row.as_object_mut().unwrap().remove("hex");
        row["width"] = json!(bytes.len());
        if wire::sift_head(&bytes).is_some() {
            let packet = wire::decode(&bytes, Checksum::VereBytes, Limits::DATAGRAM).unwrap();
            let data = match packet.body {
                Body::Peek(n) => {
                    row["type"] = json!("peek");
                    row["name"] = name(n);
                    None
                }
                Body::Page {
                    name: n,
                    data,
                    next,
                } => {
                    row["type"] = json!("page");
                    row["name"] = name(n);
                    row["next"] = json!(next);
                    Some(data)
                }
                Body::Poke { ack, payload, data } => {
                    row["type"] = json!("poke");
                    row["ack"] = name(ack);
                    row["payload"] = name(payload);
                    Some(data)
                }
            };
            if let Some(data) = data {
                if let (Some(keys), Auth::Signature(sig)) = (&keys, data.auth) {
                    let n = match packet.body {
                        Body::Page { name, .. } => name,
                        Body::Poke { payload, .. } => payload,
                        _ => unreachable!(),
                    };
                    let path = std::str::from_utf8(n.path).unwrap();
                    assert_eq!(data.total_bytes as usize, data.fragment.len());
                    let ship = format!("{:032x}", n.ship);
                    let record = keys
                        .iter()
                        .find(|k| k["ship_hex"] == ship)
                        .expect("unknown fixture signer");
                    assert_eq!(record["life"], 1);
                    let h = record["signing_key_le_hex"].as_str().unwrap();
                    let key: Vec<u8> = (0..h.len())
                        .step_by(2)
                        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
                        .collect();
                    let public =
                        mesa_crypto::PublicKey::from_bytes(key.try_into().unwrap()).unwrap();
                    let mut binding =
                        format!("/{}//1/{}", record["name"].as_str().unwrap(), path).into_bytes();
                    binding.extend(blake3::hash(data.fragment).as_bytes());
                    public.verify(&binding, sig).unwrap();
                    binding[1] ^= 1;
                    assert!(public.verify(&binding, sig).is_err());
                    row["signature_valid"] = json!(true);
                    row["proof_signature_valid"] = json!(path.contains("/pawn/proof/"));
                    verified += 1;
                }
                row["body_bytes"] = json!(data.fragment.len());
                row["total_bytes"] = json!(data.total_bytes);
                row["auth"] = json!(match data.auth {
                    Auth::Signature(_) => "signature",
                    Auth::Mac(_) => "mac",
                    Auth::Pair(_) => "pair",
                    Auth::None => "none",
                });
            }
        } else {
            row["type"] = json!("not-mesa-v1");
        }
        rows.push(row);
    }
    assert!(!rows.is_empty());
    if keys.is_some() {
        assert!(verified > 0, "no proof signatures verified");
    }
    println!("{}", serde_json::to_string_pretty(&rows).unwrap());
}
