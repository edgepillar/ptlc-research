//! Synthetic public authentication fixtures and strict verifier qualification.
//! Fixed scalar tags are public test material and must never secure funds.

#[allow(dead_code)]
#[path = "../examples/verify_authentication.rs"]
mod verifier;

use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn bytes(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn keypair(tag: u8) -> Keypair {
    Keypair::from_secret_key(
        &Secp256k1::new(),
        &SecretKey::from_slice(&[tag; 32]).unwrap(),
    )
}

fn message_digest(context: &Value, payload: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"PTLC/completion-auth/signature/v1\0");
    hash.update(serde_json::to_vec(context).unwrap());
    hash.update(b"\0");
    hash.update((payload.len() as u32).to_be_bytes());
    hash.update(payload);
    hash.finalize().into()
}

fn result(request: &Value) -> Value {
    let mut hash = Sha256::new();
    hash.update(b"PTLC/completion-auth/request/v1\0");
    hash.update(serde_json::to_vec(request).unwrap());
    json!({
        "schema": "ptlc-completion-auth-result-v1",
        "request_digest_hex": hex(&hash.finalize()),
        "valid": true
    })
}

fn fixture() -> Value {
    serde_json::from_str(include_str!("../fixtures/authentication.json")).unwrap()
}

fn request() -> Value {
    fixture()["request"].clone()
}

fn verify(request: &Value) -> Result<String, ()> {
    verifier::verify_request(&serde_json::to_vec(request).unwrap())
}

#[test]
fn public_fixture_reproduces_exact_synthetic_signature_context_and_result() {
    let fixture = fixture();
    let declared = fixture["request"].clone();
    let terms: Value =
        serde_json::from_str(include_str!("../../tests/fixtures/session_terms.json")).unwrap();
    let committed = json!({
        "schema": "ptlc-offline-transcript-v1", "stage": "terms",
        "session_id": terms["terms"]["session_id"], "terms": terms["terms"]
    });
    let mut terms_hash = Sha256::new();
    terms_hash.update(b"PTLC/offline-transcript/v1\0terms\0");
    terms_hash.update(serde_json::to_vec(&committed).unwrap());
    let context = json!({
        "schema": "ptlc-completion-auth-context-v1", "algorithm": "BIP340-SHA256",
        "purpose": "zenon-completion", "sender": "alice", "recipient": "bob",
        "session_id": terms["terms"]["session_id"], "terms_digest_hex": hex(&terms_hash.finalize()),
        "alice_id_hex": terms["terms"]["alice_id_hex"], "bob_id_hex": terms["terms"]["bob_id_hex"],
        "alice_auth_key_hex": hex(&keypair(71).x_only_public_key().0.serialize()),
        "bob_auth_key_hex": hex(&keypair(72).x_only_public_key().0.serialize())
    });
    assert_eq!(context, declared["context"]);
    let payload = bytes(declared["payload_hex"].as_str().unwrap());
    assert_eq!(payload.len(), 9841);
    assert_eq!(
        hex(&Sha256::digest(&payload)),
        "e7a1f06a6b8e5d3875728f08b91405b52137c0c18991b0fb4ffa3098db0bd2a2"
    );
    let digest = message_digest(&context, &payload);
    let signature =
        Secp256k1::new().sign_schnorr_no_aux_rand(&Message::from_digest(digest), &keypair(71));
    assert_eq!(
        hex(&digest),
        "3c8ff14317c6a40b48becde406f53eb2c7beedae118f63aebe9b094a3df1e0d0"
    );
    assert_eq!(
        hex(signature.as_ref()),
        "89cf597f930173c2611b018a6a0655ea0ef87b6bab402725edad8529eef1bbb946c6f0f76f11103c77ef46b0f4fc107a5b822ec1a683d2bde05c62d0c5831106"
    );
    let request = json!({
        "schema": "ptlc-completion-auth-request-v1",
        "context": context,
        "payload_hex": hex(&payload),
        "signature_hex": hex(signature.as_ref())
    });
    let mut envelope = request.clone();
    envelope["schema"] = json!("ptlc-completion-auth-envelope-v1");
    let generated = json!({
        "request": request,
        "envelope": envelope,
        "message_digest_hex": hex(&digest),
        "result": result(&request)
    });
    let mut primary = fixture.clone();
    primary
        .as_object_mut()
        .unwrap()
        .remove("authenticated_invalid_completion");
    assert_eq!(generated, primary);
    let wire = serde_json::to_vec(&request).unwrap();
    assert_eq!(
        verifier::verify_request(&wire),
        Ok(serde_json::to_string(&fixture["result"]).unwrap())
    );
    let mut with_lf = wire;
    with_lf.push(b'\n');
    assert_eq!(
        verifier::verify_request(&with_lf),
        Ok(serde_json::to_string(&fixture["result"]).unwrap())
    );
}

#[test]
fn authenticated_invalid_completion_fixture_reproduces_exact_signed_payload() {
    let fixture = fixture();
    let original = &fixture["request"];
    let original_payload = bytes(original["payload_hex"].as_str().unwrap());
    let mut completion: Value = serde_json::from_slice(&original_payload).unwrap();
    assert_ne!(completion["signature_hex"], json!("00".repeat(64)));
    completion["signature_hex"] = json!("00".repeat(64));
    let payload = serde_json::to_vec(&completion).unwrap();
    let digest = message_digest(&original["context"], &payload);
    let signature =
        Secp256k1::new().sign_schnorr_no_aux_rand(&Message::from_digest(digest), &keypair(71));
    let request = json!({
        "schema": "ptlc-completion-auth-request-v1",
        "context": original["context"],
        "payload_hex": hex(&payload),
        "signature_hex": hex(signature.as_ref())
    });
    let mut envelope = request.clone();
    envelope["schema"] = json!("ptlc-completion-auth-envelope-v1");
    let generated = json!({
        "request": request,
        "envelope": envelope,
        "message_digest_hex": hex(&digest),
        "result": result(&request)
    });
    assert_eq!(generated, fixture["authenticated_invalid_completion"]);
    assert_eq!(
        verify(&request),
        Ok(serde_json::to_string(&generated["result"]).unwrap())
    );
}

#[test]
fn rejects_mutations_of_every_context_binding_and_payload() {
    let source = request();
    for (field, value) in [
        ("schema", json!("ptlc-completion-auth-context-v2")),
        ("algorithm", json!("Ed25519")),
        ("purpose", json!("bitcoin-completion")),
        ("sender", json!("bob")),
        ("recipient", json!("alice")),
        ("session_id", json!("91".repeat(32))),
        ("terms_digest_hex", json!("92".repeat(32))),
        ("alice_id_hex", json!("93".repeat(32))),
        ("bob_id_hex", json!("94".repeat(32))),
        (
            "alice_auth_key_hex",
            json!(hex(&keypair(73).x_only_public_key().0.serialize())),
        ),
        (
            "bob_auth_key_hex",
            json!(hex(&keypair(74).x_only_public_key().0.serialize())),
        ),
    ] {
        let mut changed = source.clone();
        changed["context"][field] = value;
        assert!(verify(&changed).is_err(), "accepted changed {field}");
    }
    let mut changed = source.clone();
    let mut payload = bytes(source["payload_hex"].as_str().unwrap());
    payload[0] ^= 1;
    changed["payload_hex"] = json!(hex(&payload));
    assert!(verify(&changed).is_err());
    let mut signature = bytes(source["signature_hex"].as_str().unwrap());
    signature[0] ^= 1;
    changed = source;
    changed["signature_hex"] = json!(hex(&signature));
    assert!(verify(&changed).is_err());
}

#[test]
fn rejects_missing_extra_and_nonstring_fields_at_both_object_levels() {
    let source = request();
    for nested in [false, true] {
        let object = if nested { &source["context"] } else { &source };
        for field in object.as_object().unwrap().keys() {
            let mut missing = source.clone();
            let target = if nested {
                &mut missing["context"]
            } else {
                &mut missing
            };
            target.as_object_mut().unwrap().remove(field);
            assert!(verify(&missing).is_err());
            for wrong_type in [Value::Null, json!(true), json!(1), json!([]), json!({})] {
                let mut changed = source.clone();
                if nested {
                    changed["context"][field] = wrong_type;
                } else {
                    changed[field] = wrong_type;
                }
                assert!(verify(&changed).is_err());
            }
        }
        let mut extra = source.clone();
        let target = if nested {
            &mut extra["context"]
        } else {
            &mut extra
        };
        target["unknown"] = json!("synthetic");
        assert!(verify(&extra).is_err());
    }
    let mut envelope = source;
    envelope["schema"] = json!("ptlc-completion-auth-envelope-v1");
    assert!(verify(&envelope).is_err());
}

#[test]
fn rejects_noncanonical_duplicate_trailing_nonascii_deep_and_oversized_input() {
    let source = request();
    let wire = serde_json::to_string(&source).unwrap();
    let duplicate = format!(
        "{{\"schema\":\"ptlc-completion-auth-request-v1\",{}",
        &wire[1..]
    );
    let escaped = format!(
        "{{\"schem\\u0061\":\"ptlc-completion-auth-request-v1\",{}",
        &wire[1..]
    );
    let nested = wire.replacen("\"context\":{", "\"context\":{\"sender\":\"alice\",", 1);
    let escaped_value = wire.replacen("BIP340", "BIP\\u003340", 1);
    for malformed in [
        duplicate,
        escaped,
        nested,
        escaped_value,
        format!(" {wire}"),
        format!("{wire} "),
        format!("{wire}\n\n"),
        format!("{wire}\r\n"),
        format!("{wire}{{}}"),
        serde_json::to_string_pretty(&source).unwrap(),
        "[".repeat(200) + &"]".repeat(200),
        " ".repeat(verifier::MAX_REQUEST_BYTES + 1),
        "{\"unknown\":\"\u{00e9}\"}".to_owned(),
    ] {
        assert!(verifier::verify_request(malformed.as_bytes()).is_err());
    }
    assert!(verifier::verify_request(&[0xff]).is_err());
    assert!(verifier::verify_request(b"").is_err());
}

#[test]
fn rejects_noncanonical_hex_and_invalid_public_keys_and_signature_encodings() {
    let source = request();
    for field in [
        "session_id",
        "terms_digest_hex",
        "alice_id_hex",
        "bob_id_hex",
        "alice_auth_key_hex",
        "bob_auth_key_hex",
        "payload_hex",
        "signature_hex",
    ] {
        let nested = field != "payload_hex" && field != "signature_hex";
        let original = if nested {
            &source["context"][field]
        } else {
            &source[field]
        };
        let original = original.as_str().unwrap();
        for replacement in [
            original[1..].to_owned(),
            format!("{original}00"),
            "AA".repeat(original.len() / 2),
            "gg".repeat(original.len() / 2),
        ] {
            let mut changed = source.clone();
            if nested {
                changed["context"][field] = json!(replacement);
            } else {
                changed[field] = json!(replacement);
            }
            assert!(verify(&changed).is_err(), "accepted malformed {field}");
        }
    }
    for field in ["alice_auth_key_hex", "bob_auth_key_hex"] {
        for value in ["00".repeat(32), "ff".repeat(32)] {
            let mut changed = source.clone();
            changed["context"][field] = json!(value);
            assert!(verify(&changed).is_err());
        }
    }
    for signature in [
        "00".repeat(64),
        "ff".repeat(64),
        "ff".repeat(32) + &"00".repeat(32),
    ] {
        let mut changed = source.clone();
        changed["signature_hex"] = json!(signature);
        assert!(verify(&changed).is_err());
    }
}

#[test]
fn fixed_context_policy_rejects_even_correctly_resigned_invalid_roles_or_keys() {
    let source = request();
    for (field, value) in [
        ("schema", json!("other-context")),
        ("algorithm", json!("BIP340")),
        ("purpose", json!("other-purpose")),
        ("sender", json!("bob")),
        ("recipient", json!("alice")),
        ("bob_id_hex", source["context"]["alice_id_hex"].clone()),
        (
            "bob_auth_key_hex",
            source["context"]["alice_auth_key_hex"].clone(),
        ),
        ("bob_auth_key_hex", json!("ff".repeat(32))),
    ] {
        let mut changed = source.clone();
        changed["context"][field] = value;
        let digest = message_digest(
            &changed["context"],
            &bytes(changed["payload_hex"].as_str().unwrap()),
        );
        let signature =
            Secp256k1::new().sign_schnorr_no_aux_rand(&Message::from_digest(digest), &keypair(71));
        changed["signature_hex"] = json!(hex(signature.as_ref()));
        assert!(verify(&changed).is_err());
    }
}

#[test]
fn payload_bounds_accept_one_and_maximum_bytes_but_reject_zero_and_overflow() {
    for length in [
        0,
        1,
        verifier::MAX_PAYLOAD_BYTES,
        verifier::MAX_PAYLOAD_BYTES + 1,
    ] {
        let mut source = request();
        let payload = vec![0xa5; length];
        source["payload_hex"] = json!(hex(&payload));
        let digest = message_digest(&source["context"], &payload);
        let signature =
            Secp256k1::new().sign_schnorr_no_aux_rand(&Message::from_digest(digest), &keypair(71));
        source["signature_hex"] = json!(hex(signature.as_ref()));
        let wire = serde_json::to_vec(&source).unwrap();
        assert!(wire.len() + 1 <= verifier::MAX_REQUEST_BYTES);
        assert_eq!(
            verify(&source).is_ok(),
            (1..=verifier::MAX_PAYLOAD_BYTES).contains(&length)
        );
    }
}

#[test]
fn wrong_signer_and_domain_or_length_framing_signatures_do_not_authenticate() {
    let source = request();
    let payload = bytes(source["payload_hex"].as_str().unwrap());
    let context = serde_json::to_vec(&source["context"]).unwrap();
    let correct = message_digest(&source["context"], &payload);
    let bob_signature =
        Secp256k1::new().sign_schnorr_no_aux_rand(&Message::from_digest(correct), &keypair(72));
    let mut wrong_signer = source.clone();
    wrong_signer["signature_hex"] = json!(hex(bob_signature.as_ref()));
    assert!(verify(&wrong_signer).is_err());
    let mut materials = vec![payload.clone()];
    for variant in 0..4 {
        let mut material = if variant == 0 {
            b"PTLC/other-domain/v1\0".to_vec()
        } else {
            b"PTLC/completion-auth/signature/v1\0".to_vec()
        };
        material.extend_from_slice(&context);
        if variant != 1 {
            material.push(0);
        }
        let length = if variant == 2 {
            (payload.len() as u32).to_le_bytes()
        } else {
            (payload.len() as u32 + u32::from(variant == 3)).to_be_bytes()
        };
        material.extend_from_slice(&length);
        material.extend_from_slice(&payload);
        materials.push(material);
    }
    for material in materials {
        let digest: [u8; 32] = Sha256::digest(material).into();
        assert_ne!(digest, correct);
        let signature =
            Secp256k1::new().sign_schnorr_no_aux_rand(&Message::from_digest(digest), &keypair(71));
        let mut changed = source.clone();
        changed["signature_hex"] = json!(hex(signature.as_ref()));
        assert!(verify(&changed).is_err());
    }
}

#[test]
fn valid_signature_does_not_establish_local_pin_provenance_or_payload_semantics() {
    let mut source = request();
    source["context"]["session_id"] = json!("91".repeat(32));
    source["context"]["terms_digest_hex"] = json!("92".repeat(32));
    source["context"]["bob_id_hex"] = json!("93".repeat(32));
    let payload = b"Public test bytes, not a completion packet.";
    source["payload_hex"] = json!(hex(payload));
    let digest = message_digest(&source["context"], payload);
    let signature =
        Secp256k1::new().sign_schnorr_no_aux_rand(&Message::from_digest(digest), &keypair(71));
    source["signature_hex"] = json!(hex(signature.as_ref()));
    assert_eq!(verify(&source), Ok(result(&source).to_string()));
}
