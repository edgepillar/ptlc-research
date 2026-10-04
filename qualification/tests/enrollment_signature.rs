//! Synthetic vectors for a signature fact, never owner-role or source authority.
//! Fixed scalar tags are public test material and must never secure funds.

#[allow(dead_code)]
#[path = "../examples/verify_enrollment.rs"]
mod verifier;

use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn key(tag: u8) -> Keypair {
    Keypair::from_secret_key(
        &Secp256k1::new(),
        &SecretKey::from_slice(&[tag; 32]).unwrap(),
    )
}
fn digest(domain: &[u8], value: &Value) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(serde_json::to_vec(value).unwrap());
    hash.finalize().into()
}
fn fixture() -> Value {
    serde_json::from_str(include_str!("../fixtures/enrollment_signature.json")).unwrap()
}
fn result(request: &Value) -> Value {
    json!({"schema": "ptlc-observation-enrollment-signature-result-v1", "signature_valid": true,
        "request_digest_hex": hex(&digest(b"PTLC/observation-enrollment-signature-request/v1\0", request))})
}
fn signed(intent: &Value, tag: u8) -> Value {
    let mut intent = intent.clone();
    intent["owner_auth_key_hex"] = json!(hex(&key(tag).x_only_public_key().0.serialize()));
    let message = digest(b"PTLC/observation-enrollment-owner-intent/v1\0", &intent);
    let signature =
        Secp256k1::new().sign_schnorr_no_aux_rand(&Message::from_digest(message), &key(tag));
    let request = json!({"schema": "ptlc-observation-enrollment-signature-request-v1", "intent": intent, "signature_hex": hex(signature.as_ref())});
    let mut envelope = request.clone();
    envelope["schema"] = json!("ptlc-observation-enrollment-signature-envelope-v1");
    json!({"intent": intent, "message_digest_hex": hex(&message), "request": request, "envelope": envelope, "result": result(&request)})
}
fn verify(request: &Value) -> Result<String, ()> {
    verifier::verify_request(&serde_json::to_vec(request).unwrap())
}

#[test]
fn public_vectors_reproduce_exact_signatures_messages_and_request_results() {
    let fixture = fixture();
    for (vector, tag) in [
        (&fixture, 83),
        (&fixture["alternate_owner"], 84),
        (&fixture["self_selected_source"], 83),
    ] {
        let generated = signed(&vector["intent"], tag);
        for field in [
            "intent",
            "message_digest_hex",
            "request",
            "envelope",
            "result",
        ] {
            assert_eq!(generated[field], vector[field]);
        }
        assert_eq!(verify(&vector["request"]), Ok(vector["result"].to_string()));
        let mut wire = serde_json::to_vec(&vector["request"]).unwrap();
        wire.push(b'\n');
        assert_eq!(
            verifier::verify_request(&wire),
            Ok(vector["result"].to_string())
        );
    }
    assert_eq!(
        hex(&digest(
            b"PTLC/observation-authority-scope/v1\0",
            &fixture["scope"]
        )),
        fixture["intent"]["scope_digest_hex"]
    );
    assert_eq!(
        hex(&digest(
            b"PTLC/observation-retained-resource/v1\0",
            &fixture["resource"]
        )),
        fixture["intent"]["resource_digest_hex"]
    );
}

#[test]
fn rejects_changes_to_all_eight_signed_intent_bindings() {
    let fixture = fixture();
    let source = &fixture["request"];
    for (field, value) in [
        ("schema", json!("ptlc-observation-enrollment-intent-v2")),
        ("purpose", json!("zenon-completion")),
        ("role", json!("alice")),
        ("algorithm", json!("Ed25519")),
        ("resource_digest_hex", json!("99".repeat(32))),
        ("scope_digest_hex", json!("98".repeat(32))),
        ("request_id_hex", json!("97".repeat(32))),
        (
            "owner_auth_key_hex",
            fixture["alternate_owner"]["intent"]["owner_auth_key_hex"].clone(),
        ),
    ] {
        let mut changed = source.clone();
        changed["intent"][field] = value;
        assert!(verify(&changed).is_err(), "accepted changed {field}");
    }
}

#[test]
fn rejects_missing_extra_and_nonstring_fields_at_each_object_level() {
    let source = fixture()["request"].clone();
    for nested in [false, true] {
        let object = if nested { &source["intent"] } else { &source };
        for field in object.as_object().unwrap().keys() {
            let mut changed = source.clone();
            let target = if nested {
                &mut changed["intent"]
            } else {
                &mut changed
            };
            target.as_object_mut().unwrap().remove(field);
            assert!(verify(&changed).is_err());
            for wrong in [json!(null), json!(true), json!(1), json!([]), json!({})] {
                let mut changed = source.clone();
                let target = if nested {
                    &mut changed["intent"]
                } else {
                    &mut changed
                };
                target[field] = wrong;
                assert!(verify(&changed).is_err());
            }
        }
        let mut changed = source.clone();
        let target = if nested {
            &mut changed["intent"]
        } else {
            &mut changed
        };
        target["authorized"] = json!(true);
        assert!(verify(&changed).is_err());
    }
}

#[test]
fn rejects_duplicate_alias_whitespace_nonascii_and_deep_wire() {
    let source = fixture()["request"].clone();
    let wire = source.to_string();
    for value in [
        format!(" {wire}"),
        format!("{wire} "),
        format!("{wire}\n\n"),
        format!("{wire}\r\n"),
        serde_json::to_string_pretty(&source).unwrap(),
        wire.replace("\"intent\":", "\"\\u0069ntent\":"),
        format!(
            "{{\"schema\":\"ptlc-observation-enrollment-signature-request-v1\",{}",
            &wire[1..]
        ),
        wire.replace("\"role\":", "\"role\":\"enrollment-governor\",\"role\":"),
        "[".repeat(512) + &"]".repeat(512),
    ] {
        assert!(verifier::verify_request(value.as_bytes()).is_err());
    }
    let mut nonascii = wire.into_bytes();
    nonascii[0] = 0xff;
    assert!(verifier::verify_request(&nonascii).is_err());
}

#[test]
fn rejects_empty_oversized_and_cross_schema_requests() {
    assert!(verifier::verify_request(b"").is_err());
    assert!(verifier::verify_request(&vec![b' '; verifier::MAX_REQUEST_BYTES + 1]).is_err());
    let fixture = fixture();
    assert!(verify(&fixture["envelope"]).is_err());
    for schema in [
        "ptlc-completion-auth-request-v1",
        "ptlc-observation-enrollment-signature-request-v2",
    ] {
        let mut changed = fixture["request"].clone();
        changed["schema"] = json!(schema);
        assert!(verify(&changed).is_err());
    }
}

#[test]
fn rejects_noncurve_owner_keys_and_invalid_key_encodings() {
    let source = fixture()["request"].clone();
    for key in [
        "00".repeat(32),
        "ff".repeat(32),
        "ff".repeat(31),
        "ab".repeat(33),
        "zz".repeat(32),
        source["intent"]["owner_auth_key_hex"]
            .as_str()
            .unwrap()
            .to_uppercase(),
    ] {
        let mut changed = source.clone();
        changed["intent"]["owner_auth_key_hex"] = json!(key);
        assert!(verify(&changed).is_err());
    }
}

#[test]
fn rejects_signature_lengths_encoding_and_out_of_range_scalars() {
    let source = fixture()["request"].clone();
    for signature in [
        "00".repeat(64),
        "ff".repeat(32) + &"00".repeat(32),
        "00".repeat(32) + &"ff".repeat(32),
        "00".repeat(63),
        "00".repeat(65),
        "z0".repeat(64),
        source["signature_hex"].as_str().unwrap().to_uppercase(),
    ] {
        let mut changed = source.clone();
        changed["signature_hex"] = json!(signature);
        assert!(verify(&changed).is_err());
    }
}

#[test]
fn rejects_a_valid_signature_for_another_message_domain() {
    let fixture = fixture();
    let other = digest(b"PTLC/completion-auth/signature/v1\0", &fixture["intent"]);
    let signature =
        Secp256k1::new().sign_schnorr_no_aux_rand(&Message::from_digest(other), &key(83));
    assert_eq!(
        hex(signature.as_ref()),
        fixture["wrong_domain_signature_hex"]
    );
    let mut changed = fixture["request"].clone();
    changed["signature_hex"] = fixture["wrong_domain_signature_hex"].clone();
    assert!(verify(&changed).is_err());
}

#[test]
fn alternate_valid_signature_changes_result_binding_but_not_the_intent() {
    let fixture = fixture();
    let digest = digest(
        b"PTLC/observation-enrollment-owner-intent/v1\0",
        &fixture["intent"],
    );
    let signature = Secp256k1::new().sign_schnorr_with_aux_rand(
        &Message::from_digest(digest),
        &key(83),
        &[19; 32],
    );
    assert_eq!(hex(signature.as_ref()), fixture["alternate_signature_hex"]);
    let mut request = fixture["request"].clone();
    request["signature_hex"] = fixture["alternate_signature_hex"].clone();
    assert_eq!(request["intent"], fixture["intent"]);
    assert_ne!(result(&request), fixture["result"]);
    assert_eq!(verify(&request), Ok(result(&request).to_string()));
}

#[test]
fn self_selected_source_commitments_can_have_a_valid_signature_without_source_truth() {
    let fixture = fixture();
    let vector = &fixture["self_selected_source"];
    assert_ne!(
        vector["intent"]["resource_digest_hex"],
        fixture["intent"]["resource_digest_hex"]
    );
    assert_eq!(
        vector["intent"]["owner_auth_key_hex"],
        fixture["intent"]["owner_auth_key_hex"]
    );
    assert_eq!(verify(&vector["request"]), Ok(vector["result"].to_string()));
    assert_eq!(vector["result"].as_object().unwrap().len(), 3);
}

#[test]
fn replay_and_reused_request_ids_are_not_registry_idempotency() {
    let fixture = fixture();
    let original = &fixture["request"];
    for _ in 0..3 {
        assert_eq!(verify(original), Ok(fixture["result"].to_string()));
    }
    let mut intent = fixture["intent"].clone();
    intent["scope_digest_hex"] = json!("ab".repeat(32));
    let changed = signed(&intent, 83);
    assert_eq!(
        changed["intent"]["request_id_hex"],
        fixture["intent"]["request_id_hex"]
    );
    assert_ne!(changed["result"], fixture["result"]);
    assert_eq!(
        verify(&changed["request"]),
        Ok(changed["result"].to_string())
    );
}

#[test]
fn rejects_single_byte_changes_throughout_the_signature() {
    let source = fixture()["request"].clone();
    let encoded = source["signature_hex"].as_str().unwrap();
    let bytes: Vec<u8> = encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
    for index in 0..64 {
        let mut signature = bytes.clone();
        signature[index] ^= 1;
        let mut changed = source.clone();
        changed["signature_hex"] = json!(hex(&signature));
        assert!(verify(&changed).is_err(), "accepted signature byte {index}");
    }
}
