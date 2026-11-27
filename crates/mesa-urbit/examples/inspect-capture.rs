//! Inspect only explicitly supplied disposable fixture captures/configuration.
use mesa_wire::mesa_v1::{self as wire, Body};
fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    let c: serde_json::Value = serde_json::from_slice(&std::fs::read(&args[1]).unwrap()).unwrap();
    let capture: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&args[2]).unwrap()).unwrap();
    let key =
        mesa_crypto::KeyPair::from_seed(&hex(c["seed"].as_str().unwrap()).try_into().unwrap());
    let remote = mesa_crypto::PublicKey::from_bytes(
        hex(c["remote_key"].as_str().unwrap()).try_into().unwrap(),
    )
    .unwrap();
    let secret = mesa_crypto::mesa_v1::Secret::from_agreement(&key.agree(&remote).unwrap());
    for r in capture["packets"].as_array().unwrap() {
        let bytes = hex(r["hex"].as_str().unwrap());
        let p = match wire::decode(&bytes, wire::Checksum::VereBytes, wire::Limits::DATAGRAM) {
            Ok(p) => p,
            Err(e) => {
                println!(
                    "{} decode failed {e:?} length {}",
                    r["direction"],
                    bytes.len()
                );
                continue;
            }
        };
        let (n, d) = match p.body {
            Body::Peek(n) => {
                println!(
                    "{} peek {}",
                    r["direction"],
                    String::from_utf8_lossy(n.path)
                );
                if let Some(part) = std::str::from_utf8(n.path).unwrap().split('/').next_back() {
                    if let Ok(iv) = mesa_urbit::path::parse_uv(part, 1024) {
                        println!(
                            "opened peek: {:?}",
                            secret
                                .open_path(&iv, 1024)
                                .map(|p| String::from_utf8_lossy(&p).into_owned())
                        );
                    }
                }
                continue;
            }
            Body::Page { name, data, .. } => (name, data),
            Body::Poke { payload, data, .. } => (payload, data),
        };
        let path = std::str::from_utf8(n.path).unwrap();
        if !path.starts_with("chum/") {
            continue;
        }
        let iv = mesa_urbit::path::parse_uv(path.split('/').next_back().unwrap(), 1024).unwrap();
        let plainpath = secret.open_path(&iv, 1024).unwrap();
        println!(
            "{} {:?} {}",
            r["direction"],
            n.fragment,
            String::from_utf8_lossy(&plainpath)
        );
        if d.total_bytes == d.fragment.len() as u64 {
            let data = secret.decrypt(&iv, d.fragment, 65536).unwrap();
            println!(
                "gage-le {}",
                data.iter().map(|b| format!("{b:02x}")).collect::<String>()
            );
        }
    }
}
