//! Public synthetic vectors, never root provisioning or application signing.
//! Fixed public test scalar tags are reproducible and must never secure funds.

#[allow(dead_code)]
#[path = "../examples/verify_governor.rs"]
mod verifier;

use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const ASSIGNMENT: &[u8] = b"PTLC/observation-governor-assignment/v1\0";
const OWNER: &[u8] = b"PTLC/observation-enrollment-owner-intent/v2\0";
const REQUEST: &[u8] = b"PTLC/observation-governor-signature-request/v1\0";

fn hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn key(tag: u8) -> Keypair {
    Keypair::from_secret_key(
        &Secp256k1::new(),
        &SecretKey::from_slice(&[tag; 32]).unwrap(),
    )
}
fn public(tag: u8) -> Value {
    json!(hex(&key(tag).x_only_public_key().0.serialize()))
}
fn digest(domain: &[u8], value: &Value) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(serde_json::to_vec(value).unwrap());
    hash.finalize().into()
}
fn signature(domain: &[u8], value: &Value, tag: u8, aux: Option<[u8; 32]>) -> Value {
    let secp = Secp256k1::new();
    let message = Message::from_digest(digest(domain, value));
    let signed = match aux {
        Some(aux) => secp.sign_schnorr_with_aux_rand(&message, &key(tag), &aux),
        None => secp.sign_schnorr_no_aux_rand(&message, &key(tag)),
    };
    json!(hex(signed.as_ref()))
}
fn result(request: &Value) -> Value {
    json!({"schema": "ptlc-observation-governor-signature-result-v1",
        "request_digest_hex": hex(&digest(REQUEST, request)),
        "issuer_signature_valid": true, "owner_signature_valid": true})
}
fn vector(mut assignment: Value, mut intent: Value, issuer: u8, owner: u8) -> Value {
    assignment["issuer_auth_key_hex"] = public(issuer);
    assignment["governor_profile"]["owner_auth_key_hex"] = public(owner);
    intent["owner_auth_key_hex"] = public(owner);
    intent["governor_assignment_digest_hex"] = json!(hex(&digest(ASSIGNMENT, &assignment)));
    let request = json!({"schema": "ptlc-observation-governor-signature-request-v1",
        "assignment": assignment, "bound_intent": intent,
        "issuer_signature_hex": signature(ASSIGNMENT, &assignment, issuer, None),
        "owner_signature_hex": signature(OWNER, &intent, owner, None)});
    let mut envelope = request.clone();
    envelope["schema"] = json!("ptlc-observation-governor-signature-envelope-v1");
    json!({"assignment": assignment, "assignment_digest_hex": hex(&digest(ASSIGNMENT, &assignment)),
        "bound_intent": intent, "bound_message_digest_hex": hex(&digest(OWNER, &intent)),
        "envelope": envelope, "request": request, "result": result(&request)})
}

pub fn generated_fixture() -> Value {
    let unsigned: Value =
        serde_json::from_str(include_str!("../fixtures/governor_contract.json")).unwrap();
    let assignment = &unsigned["assignment"];
    let intent = &unsigned["bound_intent"];
    let primary = vector(assignment.clone(), intent.clone(), 84, 83);
    let mut broader = assignment.clone();
    broader["governor_profile"]["max_attempt_limit"] = json!(3);
    broader["governor_profile"]["max_target_limit"] = json!(3);
    let mut newer = assignment.clone();
    newer["governor_profile"]["authority_epoch"] = json!(2);
    let legacy: Value =
        serde_json::from_str(include_str!("../fixtures/enrollment_signature.json")).unwrap();
    let mut scope = legacy["scope"].clone();
    scope["authority_epoch"] = json!(2);
    let mut newer_intent = intent.clone();
    newer_intent["scope_digest_hex"] = json!(hex(&digest(
        b"PTLC/observation-authority-scope/v1\0",
        &scope
    )));
    let mut under_caps = assignment.clone();
    under_caps["governor_profile"]["max_attempt_limit"] = json!(1);
    under_caps["governor_profile"]["max_target_limit"] = json!(1);
    json!({"schema": "ptlc-governor-signature-public-vectors-v1", "primary": primary,
        "alternate_issuer": vector(assignment.clone(), intent.clone(), 85, 83),
        "alternate_owner": vector(assignment.clone(), intent.clone(), 84, 86),
        "broader_caps": vector(broader, intent.clone(), 84, 83),
        "new_epoch": vector(newer, newer_intent, 84, 83),
        "opaque_scope_under_caps": vector(under_caps, intent.clone(), 84, 83),
        "same_key_roles": vector(assignment.clone(), intent.clone(), 83, 83),
        "alternate_issuer_signature_hex": signature(ASSIGNMENT, assignment, 84, Some([29; 32])),
        "alternate_owner_signature_hex": signature(OWNER, intent, 83, Some([19; 32])),
        "wrong_domain_issuer_signature_hex": signature(OWNER, assignment, 84, None),
        "wrong_domain_owner_signature_hex": signature(b"PTLC/observation-enrollment-owner-intent/v1\0", intent, 83, None)})
}

fn fixture() -> Value {
    serde_json::from_str(include_str!("../fixtures/governor_signature.json")).unwrap()
}
fn verify(request: &Value) -> Result<String, ()> {
    verifier::verify_request(&serde_json::to_vec(request).unwrap())
}

#[test]
fn governor_public_vectors_reproduce_both_signatures_and_exact_domains() {
    let fixture = fixture();
    assert_eq!(generated_fixture(), fixture);
    let unsigned: Value =
        serde_json::from_str(include_str!("../fixtures/governor_contract.json")).unwrap();
    for field in [
        "assignment",
        "assignment_digest_hex",
        "bound_intent",
        "bound_message_digest_hex",
    ] {
        assert_eq!(fixture["primary"][field], unsigned[field]);
    }
    for name in [
        "primary",
        "alternate_issuer",
        "alternate_owner",
        "broader_caps",
        "new_epoch",
        "opaque_scope_under_caps",
        "same_key_roles",
    ] {
        let vector = &fixture[name];
        assert_eq!(verify(&vector["request"]), Ok(vector["result"].to_string()));
        let wire = vector["request"].to_string() + "\n";
        assert_eq!(
            verifier::verify_request(wire.as_bytes()),
            Ok(vector["result"].to_string())
        );
    }
}

#[test]
fn governor_rejects_mutations_of_every_assignment_profile_and_intent_field() {
    let source = fixture()["primary"]["request"].clone();
    for path in [
        vec!["assignment"],
        vec!["assignment", "governor_profile"],
        vec!["bound_intent"],
    ] {
        let mut fields = &source;
        for field in &path {
            fields = &fields[*field];
        }
        for (field, old) in fields.as_object().unwrap() {
            let mut changed = source.clone();
            let mut object = &mut changed;
            for field in &path {
                object = &mut object[*field];
            }
            object[field] = if old.is_u64() {
                json!(old.as_u64().unwrap() + 1)
            } else {
                json!("99".repeat(32))
            };
            assert!(
                verify(&changed).is_err(),
                "accepted changed {path:?}/{field}"
            );
        }
    }
}

#[test]
fn governor_requires_exact_fields_and_types_at_all_four_levels() {
    let source = fixture()["primary"]["request"].clone();
    for path in [
        vec![],
        vec!["assignment"],
        vec!["assignment", "governor_profile"],
        vec!["bound_intent"],
    ] {
        let mut object = &source;
        for field in &path {
            object = &object[*field];
        }
        for field in object.as_object().unwrap().keys() {
            let mut changed = source.clone();
            let mut target = &mut changed;
            for field in &path {
                target = &mut target[*field];
            }
            target.as_object_mut().unwrap().remove(field);
            assert!(verify(&changed).is_err());
            for wrong in [json!(null), json!(true), json!([]), json!({})] {
                let mut changed = source.clone();
                let mut target = &mut changed;
                for field in &path {
                    target = &mut target[*field];
                }
                target[field] = wrong;
                assert!(verify(&changed).is_err());
            }
        }
        let mut changed = source.clone();
        let mut target = &mut changed;
        for field in &path {
            target = &mut target[*field];
        }
        target["authorized"] = json!(true);
        assert!(verify(&changed).is_err());
    }
}

#[test]
fn governor_rejects_numeric_aliases_and_out_of_range_profile_values() {
    let source = fixture()["primary"].clone();
    for (field, maximum) in [
        ("authority_epoch", (1_u64 << 53) - 1),
        ("max_attempt_limit", 64),
        ("max_target_limit", 64),
    ] {
        for wrong in [
            json!(0),
            json!(-1),
            json!(maximum + 1),
            json!(1.0),
            json!("1"),
            json!(true),
        ] {
            let mut assignment = source["assignment"].clone();
            assignment["governor_profile"][field] = wrong;
            let changed = vector(assignment, source["bound_intent"].clone(), 84, 83);
            assert!(verify(&changed["request"]).is_err());
        }
        let mut assignment = source["assignment"].clone();
        assignment["governor_profile"][field] = json!(maximum);
        let boundary = vector(assignment, source["bound_intent"].clone(), 84, 83);
        assert_eq!(
            verify(&boundary["request"]),
            Ok(boundary["result"].to_string())
        );
    }
}

#[test]
fn governor_rejects_duplicates_aliases_deep_nonascii_and_oversized_wire() {
    let wire = fixture()["primary"]["request"].to_string();
    for input in [
        format!(" {wire}"),
        format!("{wire} "),
        format!("{wire}\n\n"),
        format!("{wire}\r\n"),
        wire.replace("\"assignment\":", "\"\\u0061ssignment\":"),
        format!(
            "{{\"schema\":\"ptlc-observation-governor-signature-request-v1\",{}",
            &wire[1..]
        ),
        wire.replace(
            "\"authority_epoch\":1",
            "\"authority_epoch\":1,\"authority_epoch\":1",
        ),
        wire.replace("\"authority_epoch\":1", "\"authority_epoch\":1e0"),
        "[".repeat(512) + &"]".repeat(512),
    ] {
        assert!(verifier::verify_request(input.as_bytes()).is_err());
    }
    assert!(verifier::verify_request(b"").is_err());
    assert!(verifier::verify_request(&vec![b' '; verifier::MAX_REQUEST_BYTES + 1]).is_err());
    assert!(verifier::verify_request(&[0xff]).is_err());
    assert!(verify(&fixture()["primary"]["envelope"]).is_err());
}

#[test]
fn governor_rejects_curve_invalid_keys_and_each_signature_byte_mutation() {
    let source = fixture()["primary"]["request"].clone();
    for issuer in [true, false] {
        for key in [
            "00".repeat(32),
            "ff".repeat(32),
            "aa".repeat(31),
            "AA".repeat(32),
            "zz".repeat(32),
        ] {
            let mut changed = source.clone();
            if issuer {
                changed["assignment"]["issuer_auth_key_hex"] = json!(key);
            } else {
                changed["bound_intent"]["owner_auth_key_hex"] = json!(key.clone());
                changed["assignment"]["governor_profile"]["owner_auth_key_hex"] = json!(key);
            }
            changed["bound_intent"]["governor_assignment_digest_hex"] =
                json!(hex(&digest(ASSIGNMENT, &changed["assignment"])));
            assert!(verify(&changed).is_err());
        }
    }
    for field in ["issuer_signature_hex", "owner_signature_hex"] {
        for wrong in [
            "00".repeat(64),
            "ff".repeat(32) + &"00".repeat(32),
            "00".repeat(32) + &"ff".repeat(32),
            "00".repeat(63),
            "00".repeat(65),
            "zz".repeat(64),
            source[field].as_str().unwrap().to_uppercase(),
        ] {
            let mut changed = source.clone();
            changed[field] = json!(wrong);
            assert!(verify(&changed).is_err());
        }
        let bytes: Vec<u8> = source[field]
            .as_str()
            .unwrap()
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        for index in 0..64 {
            let mut bytes = bytes.clone();
            bytes[index] ^= 1;
            let mut changed = source.clone();
            changed[field] = json!(hex(&bytes));
            assert!(verify(&changed).is_err());
        }
    }
}

#[test]
fn governor_rejects_cross_role_wrong_domain_and_legacy_signatures() {
    let f = fixture();
    let legacy: Value =
        serde_json::from_str(include_str!("../fixtures/enrollment_signature.json")).unwrap();
    for (field, signature) in [
        (
            "issuer_signature_hex",
            &f["wrong_domain_issuer_signature_hex"],
        ),
        (
            "owner_signature_hex",
            &f["wrong_domain_owner_signature_hex"],
        ),
        (
            "issuer_signature_hex",
            &f["primary"]["request"]["owner_signature_hex"],
        ),
        (
            "owner_signature_hex",
            &f["primary"]["request"]["issuer_signature_hex"],
        ),
        ("owner_signature_hex", &legacy["request"]["signature_hex"]),
    ] {
        let mut changed = f["primary"]["request"].clone();
        changed[field] = signature.clone();
        assert!(verify(&changed).is_err());
    }
    // Each signature is valid for these exact bytes under another public key.
    for (field, domain, message, tag) in [
        (
            "issuer_signature_hex",
            ASSIGNMENT,
            &f["primary"]["assignment"],
            85,
        ),
        (
            "owner_signature_hex",
            OWNER,
            &f["primary"]["bound_intent"],
            86,
        ),
    ] {
        let signed = signature(domain, message, tag, None);
        let raw: Vec<u8> = signed
            .as_str()
            .unwrap()
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        assert!(
            Secp256k1::verification_only()
                .verify_schnorr(
                    &bitcoin::secp256k1::schnorr::Signature::from_slice(&raw).unwrap(),
                    &Message::from_digest(digest(domain, message)),
                    &key(tag).x_only_public_key().0
                )
                .is_ok()
        );
        let mut changed = f["primary"]["request"].clone();
        changed[field] = signed;
        assert!(verify(&changed).is_err());
    }
}

#[test]
fn governor_both_signature_variants_change_complete_result_binding() {
    let f = fixture();
    for (field, alternate) in [
        ("issuer_signature_hex", "alternate_issuer_signature_hex"),
        ("owner_signature_hex", "alternate_owner_signature_hex"),
    ] {
        let mut changed = f["primary"]["request"].clone();
        changed[field] = f[alternate].clone();
        assert_ne!(result(&changed), f["primary"]["result"]);
        assert_eq!(verify(&changed), Ok(result(&changed).to_string()));
    }
}

#[test]
fn governor_old_signatures_cannot_follow_caps_issuer_owner_or_epoch_changes() {
    let f = fixture();
    for name in [
        "alternate_issuer",
        "alternate_owner",
        "broader_caps",
        "new_epoch",
    ] {
        for field in ["issuer_signature_hex", "owner_signature_hex"] {
            let mut changed = f[name]["request"].clone();
            changed[field] = f["primary"]["request"][field].clone();
            assert!(verify(&changed).is_err());
        }
    }
}

#[test]
fn governor_signatures_do_not_establish_scope_truth_freshness_or_role_separation() {
    let f = fixture();
    for name in ["primary", "opaque_scope_under_caps", "same_key_roles"] {
        for _ in 0..3 {
            assert_eq!(
                verify(&f[name]["request"]),
                Ok(f[name]["result"].to_string())
            );
        }
        assert_eq!(f[name]["result"].as_object().unwrap().len(), 4);
    }
    assert_eq!(
        f["primary"]["bound_intent"]["scope_digest_hex"],
        f["opaque_scope_under_caps"]["bound_intent"]["scope_digest_hex"]
    );
    assert_ne!(
        f["primary"]["assignment"],
        f["opaque_scope_under_caps"]["assignment"]
    );
    assert_eq!(
        f["same_key_roles"]["assignment"]["issuer_auth_key_hex"],
        f["same_key_roles"]["bound_intent"]["owner_auth_key_hex"]
    );
}
