//! Golden-vector tests against ../../vectors/pact/.
//!
//! Vectors were extracted from a live zuse-408 ship (en:pact:ames /
//! fax:plot via dojo); see vectors/pact/NOTES.md for provenance and the
//! divergence probes they encode.

use mesa_wire::{sift_head, PactType, HEADER_LEN};

#[derive(serde::Deserialize)]
struct Vector {
    name: String,
    #[serde(rename = "type")]
    typ: String,
    len: usize,
    wire: String,
    #[serde(default)]
    hop_on_wire: Option<u8>,
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0);
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn load() -> Vec<Vector> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vectors/pact/v0-basic.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn headers_sift() {
    for v in load() {
        let wire = unhex(&v.wire);
        assert_eq!(wire.len(), v.len, "{}: length", v.name);
        let head = sift_head(&wire).unwrap_or_else(|| panic!("{}: no head", v.name));
        let want = match v.typ.as_str() {
            "page" => PactType::Page,
            "peek" => PactType::Peek,
            "poke" => PactType::Poke,
            t => panic!("{}: bad type {t}", v.name),
        };
        assert_eq!(head.typ, want, "{}: type", v.name);
        if let Some(hop) = v.hop_on_wire {
            assert_eq!(head.hop, hop, "{}: clamped hop", v.name);
        }
    }
}

/// The C-built divergence wire (vectors/pact/v0-divergence.json): its
/// header must sift (valid page, gum = C's exact-bytes mug 0xd436e) even
/// though Hoon rejects the packet at the body-gum recompute — pinning the
/// C1 finding until the spec settles the canonical fragment form.
#[test]
fn divergence_wire_header() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vectors/pact/v0-divergence.json"
    );
    let vs: Vec<serde_json::Value> =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let wire = unhex(vs[0]["wire"].as_str().unwrap());
    let head = sift_head(&wire).unwrap();
    assert_eq!(head.typ, PactType::Page);
    assert_eq!(head.gum, 0xd436e);
    assert_eq!(head.gum as u64, vs[0]["gum_on_wire"].as_u64().unwrap());
}

#[test]
fn corrupted_headers_rejected() {
    for v in load() {
        let wire = unhex(&v.wire);
        // Break the cookie.
        let mut bad = wire.clone();
        bad[5] ^= 0xff;
        assert!(sift_head(&bad).is_none(), "{}: cookie", v.name);
        // Set a reserved bit.
        let mut bad = wire.clone();
        bad[0] |= 0b01;
        assert!(sift_head(&bad).is_none(), "{}: reserved", v.name);
        // Truncate below the fixed header.
        assert!(sift_head(&wire[..HEADER_LEN - 1]).is_none(), "{}: short", v.name);
    }
}
