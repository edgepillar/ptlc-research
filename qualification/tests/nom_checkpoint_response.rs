//! Public disclosed scalar tags generate only synthetic role/response vectors.
//! The verifier and application accept no private keys or signing requests.
#[allow(dead_code)]
#[path = "../examples/verify_nom_checkpoint_response.rs"]
mod verifier;
use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use serde_json::{Value, json};

fn hex(body: &[u8]) -> String {
    body.iter().map(|b| format!("{b:02x}")).collect()
}
fn key(tag: u8) -> Keypair {
    Keypair::from_secret_key(
        &Secp256k1::new(),
        &SecretKey::from_slice(&[tag; 32]).unwrap(),
    )
}
fn sign(domain: &[u8], value: &Value, tag: u8, aux: Option<[u8; 32]>) -> Value {
    let secp = Secp256k1::new();
    let message = Message::from_digest(verifier::message_digest(domain, value).unwrap());
    let signature = match aux {
        Some(aux) => secp.sign_schnorr_with_aux_rand(&message, &key(tag), &aux),
        None => secp.sign_schnorr_no_aux_rand(&message, &key(tag)),
    };
    json!(hex(signature.as_ref()))
}
fn output(request: &Value) -> Value {
    json!({"schema":"ptlc-nom-checkpoint-response-result-v1",
        "request_digest_hex":hex(&verifier::message_digest(verifier::REQUEST_DOMAIN,request).unwrap()),
        "root_signature_valid":true,"response_signature_valid":true})
}
pub fn generated_fixture() -> Value {
    let unsigned: Value = serde_json::from_str(include_str!(
        "../fixtures/nom_checkpoint_response_unsigned.json"
    ))
    .unwrap();
    let mut vectors = serde_json::Map::new();
    for (name, selected) in unsigned["cases"].as_object().unwrap() {
        let root_tag = if name == "root_rotation" { 112 } else { 111 };
        assert_eq!(
            selected["declaration"]["root_key_hex"],
            hex(&key(root_tag).x_only_public_key().0.serialize())
        );
        assert_eq!(
            selected["declaration"]["service_selection"]["checkpoint_key_hex"],
            hex(&key(83).x_only_public_key().0.serialize())
        );
        let mut request = selected.clone();
        request["root_signature_hex"] = sign(
            verifier::DECLARATION_DOMAIN,
            &selected["declaration"],
            root_tag,
            None,
        );
        request["response_signature_hex"] = sign(
            verifier::MESSAGE_DOMAIN,
            &verifier::signed_message(&request),
            83,
            None,
        );
        let envelope = json!({"schema":"ptlc-nom-checkpoint-response-envelope-v1","declaration":request["declaration"],
            "root_signature_hex":request["root_signature_hex"],"response_signature_hex":request["response_signature_hex"]});
        vectors.insert(name.clone(),json!({"request":request,"envelope":envelope,"result":output(&request),
            "declaration_message_digest_hex":hex(&verifier::message_digest(verifier::DECLARATION_DOMAIN,&request["declaration"]).unwrap()),
            "signed_response_message_digest_hex":hex(&verifier::message_digest(verifier::MESSAGE_DOMAIN,&verifier::signed_message(&request)).unwrap())}));
    }
    let primary = &vectors["newer_candidate"]["request"];
    let unrelated = b"ptlc-nom-checkpoint-unrelated-synthetic-message-v1\0";
    json!({"schema":"ptlc-nom-checkpoint-response-public-vectors-v1","positive_vectors":vectors,
        "wrong_domain_signatures":{"root_signature_hex":sign(unrelated,&primary["declaration"],111,None),
            "response_signature_hex":sign(unrelated,&verifier::signed_message(primary),83,None)},
        "wrong_role_signatures":{"root_signature_hex":sign(verifier::DECLARATION_DOMAIN,&primary["declaration"],83,None),
            "response_signature_hex":sign(verifier::MESSAGE_DOMAIN,&verifier::signed_message(primary),111,None)},
        "alternate_response_signature_hex":sign(verifier::MESSAGE_DOMAIN,&verifier::signed_message(primary),83,Some([41;32])),
        "synthetic_notice":"Fixed disclosed tags 111 and 112 for root, 83 for selected response; no provisioned authority or current service"})
}
fn fixture() -> Value {
    serde_json::from_str(include_str!("../fixtures/nom_checkpoint_response.json")).unwrap()
}
fn primary() -> Value {
    fixture()["positive_vectors"]["newer_candidate"]["request"].clone()
}
fn verify(value: &Value) -> Result<String, ()> {
    verifier::verify_request(&serde_json::to_vec(value).unwrap())
}

#[test]
fn checkpoint_response_generator_is_public_and_mathematical_only() {
    let generated = generated_fixture();
    for (_, v) in generated["positive_vectors"].as_object().unwrap() {
        assert_eq!(verify(&v["request"]), Ok(v["result"].to_string()));
    }
    let text = generated.to_string();
    for forbidden in ["secret_key", "private_key", "mnemonic", "permit"] {
        assert!(!text.contains(forbidden));
    }
    if std::env::var("PTLC_PUBLIC_CHECKPOINT_RESPONSE_OUTPUT").as_deref() == Ok("1") {
        println!("PUBLIC_CHECKPOINT_RESPONSE_VECTORS:{text}");
    }
}
#[test]
fn checkpoint_response_fixture_reproduces_every_role_and_response() {
    assert_eq!(generated_fixture(), fixture());
    assert_eq!(fixture()["positive_vectors"].as_object().unwrap().len(), 8);
    for (_, v) in fixture()["positive_vectors"].as_object().unwrap() {
        assert_eq!(verify(&v["request"]), Ok(v["result"].to_string()));
        let mut wire = serde_json::to_vec(&v["request"]).unwrap();
        wire.push(b'\n');
        assert_eq!(verifier::verify_request(&wire), Ok(v["result"].to_string()));
    }
}
#[test]
fn checkpoint_response_every_signed_field_and_exact_object_is_bound() {
    let source = primary();
    for path in [
        vec![],
        vec!["declaration"],
        vec!["declaration", "service_selection"],
        vec!["declaration", "service_selection", "realm"],
    ] {
        let mut at = &source;
        for p in &path {
            at = &at[*p];
        }
        for field in at.as_object().unwrap().keys() {
            for mode in ["missing", "changed", "wrong-type"] {
                let mut changed = source.clone();
                let mut at = &mut changed;
                for p in &path {
                    at = &mut at[*p];
                }
                match mode {
                    "missing" => {
                        at.as_object_mut().unwrap().remove(field);
                    }
                    "changed" => at[field] = json!("99".repeat(32)),
                    _ => at[field] = json!([]),
                }
                assert!(
                    verify(&changed).is_err(),
                    "accepted {path:?}/{field}/{mode}"
                );
            }
        }
        let mut changed = source.clone();
        let mut at = &mut changed;
        for p in &path {
            at = &mut at[*p];
        }
        at["unexpected"] = json!(true);
        assert!(verify(&changed).is_err());
    }
}
#[test]
fn checkpoint_response_domains_roles_and_old_permissions_are_separate() {
    let f = fixture();
    let p = primary();
    for vector in ["wrong_domain_signatures", "wrong_role_signatures"] {
        for field in ["root_signature_hex", "response_signature_hex"] {
            let mut changed = p.clone();
            changed[field] = f[vector][field].clone();
            assert!(verify(&changed).is_err());
        }
    }
    let old: Value =
        serde_json::from_str(include_str!("../fixtures/enrollment_signature.json")).unwrap();
    let mut changed = p.clone();
    changed["response_signature_hex"] = old["request"]["signature_hex"].clone();
    assert!(verify(&changed).is_err());
    changed = p.clone();
    changed["declaration"]["root_key_hex"] =
        p["declaration"]["service_selection"]["checkpoint_key_hex"].clone();
    assert!(verify(&changed).is_err());
    for value in [
        json!(0),
        json!(true),
        json!(1.0),
        json!(9007199254740992_u64),
    ] {
        let mut changed = p.clone();
        changed["declaration"]["authority_epoch"] = value;
        assert!(verify(&changed).is_err());
    }
}
#[test]
fn checkpoint_response_wire_points_scalars_and_resource_bounds_refuse() {
    let p = primary();
    let wire = p.to_string();
    for bad in [
        format!(" {wire}"),
        format!("{wire}\n\n"),
        wire.replacen("{", "{\"schema\":\"duplicate\",", 1),
        "[".repeat(13) + &"]".repeat(13),
        "x".repeat(8193),
        "\u{e9}".into(),
    ] {
        assert!(verifier::verify_request(bad.as_bytes()).is_err());
    }
    for field in ["root_signature_hex", "response_signature_hex"] {
        for sig in [
            "00".repeat(64),
            "ff".repeat(64),
            "FF".repeat(64),
            "00".repeat(63),
            "00".repeat(65),
        ] {
            let mut bad = p.clone();
            bad[field] = json!(sig);
            assert!(verify(&bad).is_err());
        }
    }
    let mut bad = p.clone();
    bad["declaration"]["root_key_hex"] = json!("ff".repeat(32));
    assert!(verify(&bad).is_err());
}
#[test]
fn checkpoint_response_alternate_valid_signature_binds_its_exact_request() {
    let p = primary();
    let mut changed = p.clone();
    changed["response_signature_hex"] = fixture()["alternate_response_signature_hex"].clone();
    assert_ne!(
        p["response_signature_hex"],
        changed["response_signature_hex"]
    );
    assert_eq!(verify(&changed), Ok(output(&changed).to_string()));
    assert_ne!(
        output(&p)["request_digest_hex"],
        output(&changed)["request_digest_hex"]
    );
    assert_eq!(
        verifier::signed_message(&p),
        verifier::signed_message(&changed)
    );
}
