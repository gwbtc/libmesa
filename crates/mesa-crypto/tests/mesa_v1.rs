use mesa_crypto::mesa_v1::*;
fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
#[test]
fn pinned_hoon_crypto_vector_and_tamper_checks() {
    let v: serde_json::Value = serde_json::from_str(include_str!(
        "../../../investigation/native/evidence/crypto-vector.json"
    ))
    .unwrap();
    let bytes = |k: &str| hex(v[k]["bytes_le_hex"].as_str().unwrap());
    let secret = Secret::from_bytes(bytes("shared_key").try_into().unwrap());
    let path = v["path"].as_str().unwrap().as_bytes();
    let sealed = secret.seal_path(path, 1024).unwrap();
    assert_eq!(sealed, bytes("sealed_path"));
    assert_eq!(&**secret.open_path(&sealed, 1024).unwrap(), path);
    let encrypted = secret.encrypt(&sealed, &bytes("jam_value"), 1024).unwrap();
    assert_eq!(encrypted, bytes("ciphertext"));
    assert_eq!(
        &**secret.decrypt(&sealed, &encrypted, 1024).unwrap(),
        bytes("jam_value")
    );
    let root: [u8; 32] = bytes("native_root").try_into().unwrap();
    assert_eq!(&secret.mac(path, &root)[..], bytes("tag"));
    for i in 0..sealed.len() {
        let mut bad = sealed.clone();
        bad[i] ^= 1;
        assert!(secret.open_path(&bad, 1024).is_err());
    }
    assert!(secret.seal_path(path, sealed.len() - 1).is_err());
    assert!(secret.open_path(&sealed, sealed.len() - 1).is_err());
    assert!(secret.decrypt(&sealed, &[0], 1024).is_err());
    assert!(!secret.verify_mac(b"/wrong", &root, &bytes("tag").try_into().unwrap()));
}
