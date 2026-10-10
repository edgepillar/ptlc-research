//! Additive current-profile checks; the legacy fixtures and lockfile are unchanged.

mod support {
    pub mod pr138;
}
use musig2::{
    LiftedSignature,
    secp::Point,
    secp256k1::{Secp256k1, XOnlyPublicKey, schnorr::Signature},
};
use serde_json::Value;
use support::pr138::{bytes, hex, sha3};

#[test]
fn sha3_known_answers_are_separate_from_sha256_and_legacy_keccak() {
    assert_eq!(
        hex(&sha3(b"")),
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    );
    assert_eq!(
        hex(&sha3(b"abc")),
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
    );
}

#[test]
fn independent_rust_preimages_match_python_and_go_corpus() {
    let data: Value = serde_json::from_str(include_str!(
        "../../compatibility/fixtures/pr138_messages_v1.json"
    ))
    .unwrap();
    assert_eq!(
        data["core_commit"],
        "45e1bbb48ce6fc19d44c5fbf59ccf5784981fced"
    );
    let vectors = data["message_vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 48);
    for vector in vectors {
        let c = &vector["context"];
        assert_eq!(c["profile"], "zenon-ptlc-unlock:v1");
        let chain = c["chain_id"].as_str().unwrap().parse::<u64>().unwrap();
        let point = c["point_type"].as_u64().unwrap();
        assert!(point <= 2);
        let mut preimage = b"zenon-ptlc-unlock:v1".to_vec();
        preimage.extend(chain.to_be_bytes());
        preimage.extend(bytes("01b3b6e5adcb4c15ff06318c6318c6318c6318c6"));
        preimage.push(point as u8);
        preimage.extend(bytes(c["entry_id_hex"].as_str().unwrap()));
        preimage.extend(bytes(c["destination_hex"].as_str().unwrap()));
        assert_eq!(preimage.len(), 101);
        assert_eq!(hex(&preimage), vector["preimage_hex"]);
        let digest = sha3(&preimage);
        assert_eq!(hex(&digest), vector["message_hex"]);
        assert_eq!(hex(&sha3(&preimage[49..])), vector["legacy_message_hex"]);
        assert_ne!(hex(&digest), vector["legacy_message_hex"]);
        for offset in [0, 20, 28, 48, 49, 81] {
            let mut changed = preimage.clone();
            changed[offset] ^= 1;
            assert_ne!(sha3(&changed), digest);
        }
    }
}

#[test]
fn go_bip340_public_witnesses_match_two_locked_rust_verifiers() {
    let data: Value = serde_json::from_str(include_str!(
        "../../compatibility/fixtures/pr138_witnesses_v1.json"
    ))
    .unwrap();
    for v in data["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|v| v["point_type"] == 1)
    {
        let key = bytes(v["point_lock_hex"].as_str().unwrap());
        let signature = bytes(v["witness_hex"].as_str().unwrap());
        let message = bytes(v["message_hex"].as_str().unwrap());
        let native = key
            .as_slice()
            .try_into()
            .ok()
            .and_then(|k: [u8; 32]| XOnlyPublicKey::from_byte_array(k).ok())
            .zip(
                signature
                    .as_slice()
                    .try_into()
                    .ok()
                    .map(Signature::from_byte_array),
            )
            .is_some_and(|(key, sig)| {
                Secp256k1::verification_only()
                    .verify_schnorr(&sig, &message, &key)
                    .is_ok()
            });
        let other = key
            .as_slice()
            .try_into()
            .ok()
            .and_then(|k: [u8; 32]| Point::lift_x(k).ok())
            .zip(LiftedSignature::from_bytes(&signature).ok())
            .is_some_and(|(key, sig)| musig2::verify_single(key, sig, &message).is_ok());
        let expected = v["valid_witness"].as_bool().unwrap();
        assert_eq!([native, other], [expected; 2], "{}", v["id"]);
    }
}
