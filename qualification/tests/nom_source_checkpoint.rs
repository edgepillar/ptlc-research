//! Signing exists only in this public synthetic vector generator, never in the
//! verifier or application. Disclosed scalar tags cannot secure real resources.
#[allow(dead_code)]
#[path = "../examples/verify_nom_source_checkpoint.rs"]
mod verifier;
use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
const DECLARATION: &[u8] = b"ptlc-nom-source-checkpoint-declaration-message-v1\0";
const SOURCE: &[u8] = b"ptlc-nom-historical-source-message-v1\0";
const CHECKPOINT: &[u8] = b"ptlc-nom-historical-custody-message-v1\0";
const REQUEST: &[u8] = b"ptlc-nom-source-checkpoint-request-v1\0";
fn hex(body: &[u8]) -> String {
    body.iter().map(|b| format!("{b:02x}")).collect()
}
fn key(tag: u8) -> Keypair {
    Keypair::from_secret_key(
        &Secp256k1::new(),
        &SecretKey::from_slice(&[tag; 32]).unwrap(),
    )
}
fn hash(domain: &[u8], value: &Value) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(domain);
    h.update(serde_json::to_vec(value).unwrap());
    h.finalize().into()
}
fn sign(domain: &[u8], value: &Value, tag: u8, aux: Option<[u8; 32]>) -> Value {
    let secp = Secp256k1::new();
    let message = Message::from_digest(hash(domain, value));
    let signature = match aux {
        Some(aux) => secp.sign_schnorr_with_aux_rand(&message, &key(tag), &aux),
        None => secp.sign_schnorr_no_aux_rand(&message, &key(tag)),
    };
    json!(hex(signature.as_ref()))
}
fn result(request: &Value) -> Value {
    json!({"schema":"ptlc-nom-source-checkpoint-result-v1", "request_digest_hex":hex(&hash(REQUEST, request)),
        "root_signature_valid":true, "source_signature_valid":true, "checkpoint_signature_valid":true})
}
fn vector(selected: &Value, tags: [u8; 3]) -> Value {
    for (field, tag) in [
        "root_key_hex",
        "source_response_key_hex",
        "consumer_checkpoint_key_hex",
    ]
    .iter()
    .zip(tags)
    {
        assert_eq!(
            selected["declaration"][*field],
            hex(&key(tag).x_only_public_key().0.serialize())
        );
    }
    let mut request = selected.clone();
    request["schema"] = json!("ptlc-nom-source-checkpoint-request-v1");
    for (field, domain, payload, tag) in [
        ("root_signature_hex", DECLARATION, "declaration", tags[0]),
        ("source_signature_hex", SOURCE, "source_statement", tags[1]),
        (
            "checkpoint_signature_hex",
            CHECKPOINT,
            "checkpoint_statement",
            tags[2],
        ),
    ] {
        request[field] = sign(domain, &selected[payload], tag, None);
    }
    let mut envelope = request.clone();
    envelope["schema"] = json!("ptlc-nom-source-checkpoint-envelope-v1");
    json!({"request":request, "envelope":envelope, "result":result(&request),
        "message_digests_hex":{"declaration":hex(&hash(DECLARATION,&selected["declaration"])),
            "source_statement":hex(&hash(SOURCE,&selected["source_statement"])),
            "checkpoint_statement":hex(&hash(CHECKPOINT,&selected["checkpoint_statement"]))}})
}
pub fn generated_fixture() -> Value {
    let unsigned: Value = serde_json::from_str(include_str!(
        "../fixtures/nom_source_checkpoint_unsigned.json"
    ))
    .unwrap();
    let mut vectors = serde_json::Map::new();
    for (name, selected) in unsigned["cases"].as_object().unwrap() {
        let tags = [
            if name == "root_rotation" { 99 } else { 96 },
            if name == "source_rotation" { 101 } else { 98 },
            if name == "checkpoint_rotation" {
                100
            } else {
                97
            },
        ];
        vectors.insert(name.clone(), vector(selected, tags));
    }
    let primary = &vectors["primary"]["request"];
    let mut wrong_domain = serde_json::Map::new();
    let mut wrong_role = serde_json::Map::new();
    for (field, domain, payload, tag, other) in [
        ("root_signature_hex", DECLARATION, "declaration", 96, 98),
        ("source_signature_hex", SOURCE, "source_statement", 98, 97),
        (
            "checkpoint_signature_hex",
            CHECKPOINT,
            "checkpoint_statement",
            97,
            96,
        ),
    ] {
        wrong_domain.insert(
            field.into(),
            sign(
                b"ptlc-nom-unrelated-test-message-v1\0",
                &primary[payload],
                tag,
                None,
            ),
        );
        wrong_role.insert(field.into(), sign(domain, &primary[payload], other, None));
    }
    let alternate = sign(SOURCE, &primary["source_statement"], 98, Some([31; 32]));
    json!({"schema":"ptlc-nom-source-checkpoint-public-vectors-v1", "positive_vectors":vectors,
        "wrong_domain_signatures":wrong_domain, "wrong_role_signatures":wrong_role,
        "alternate_source_signature_hex":alternate,
        "synthetic_notice":"Public reproducible vectors only; no source truth, root trust, or nonrollback custody"})
}
fn fixture() -> Value {
    serde_json::from_str(include_str!("../fixtures/nom_source_checkpoint.json")).unwrap()
}
fn primary() -> Value {
    fixture()["positive_vectors"]["primary"]["request"].clone()
}
fn verify(value: &Value) -> Result<String, ()> {
    verifier::verify_request(&serde_json::to_vec(value).unwrap())
}

#[test]
fn nom_source_checkpoint_public_generator_is_mathematical_and_test_only() {
    let generated = generated_fixture();
    for (_, v) in generated["positive_vectors"].as_object().unwrap() {
        assert_eq!(verify(&v["request"]), Ok(v["result"].to_string()));
    }
    let encoded = generated.to_string();
    for forbidden in [
        "secret_key",
        "private_key",
        "mnemonic",
        "authorized",
        "permit",
    ] {
        assert!(!encoded.contains(forbidden));
    }
    if std::env::var("PTLC_PUBLIC_NOM_SOURCE_CHECKPOINT_OUTPUT").as_deref() == Ok("1") {
        println!("PUBLIC_NOM_SOURCE_CHECKPOINT_VECTORS:{encoded}");
    }
}
#[test]
fn nom_source_checkpoint_fixture_reproduces_all_three_public_signatures() {
    let f = fixture();
    assert_eq!(generated_fixture(), f);
    assert_eq!(f["positive_vectors"].as_object().unwrap().len(), 7);
    for (_, v) in f["positive_vectors"].as_object().unwrap() {
        assert_eq!(verify(&v["request"]), Ok(v["result"].to_string()));
    }
}
#[test]
fn nom_source_checkpoint_every_selected_field_is_bound() {
    let r = primary();
    for path in [
        vec![],
        vec!["declaration"],
        vec!["declaration", "network_selection"],
        vec!["source_statement"],
        vec!["checkpoint_statement"],
    ] {
        let mut at = &r;
        for p in &path {
            at = &at[*p];
        }
        for field in at.as_object().unwrap().keys() {
            for mode in ["missing", "changed", "wrong-type"] {
                let mut changed = r.clone();
                let mut at = &mut changed;
                for p in &path {
                    at = &mut at[*p];
                }
                match mode {
                    "missing" => {
                        at.as_object_mut().unwrap().remove(field);
                    }
                    "changed" => {
                        at[field] = json!("99".repeat(32));
                    }
                    _ => {
                        at[field] = json!([]);
                    }
                }
                assert!(verify(&changed).is_err(), "unbound {path:?}/{field}/{mode}");
            }
        }
        let mut changed = r.clone();
        let mut at = &mut changed;
        for p in &path {
            at = &mut at[*p];
        }
        at["admitted"] = json!(true);
        assert!(verify(&changed).is_err());
    }
}
#[test]
fn nom_source_checkpoint_wrong_domains_roles_and_every_signature_byte_refuse() {
    let f = fixture();
    let r = primary();
    for field in [
        "root_signature_hex",
        "source_signature_hex",
        "checkpoint_signature_hex",
    ] {
        for group in ["wrong_domain_signatures", "wrong_role_signatures"] {
            let mut changed = r.clone();
            changed[field] = f[group][field].clone();
            assert!(verify(&changed).is_err());
        }
        for i in 0..64 {
            let mut signature: Vec<u8> = (0..64)
                .map(|j| {
                    u8::from_str_radix(&r[field].as_str().unwrap()[j * 2..j * 2 + 2], 16).unwrap()
                })
                .collect();
            signature[i] ^= 1;
            let mut changed = r.clone();
            changed[field] = json!(hex(&signature));
            assert!(verify(&changed).is_err());
        }
        for bad in [
            "00".repeat(64),
            "ff".repeat(64),
            "AB".repeat(64),
            "00".repeat(63),
        ] {
            let mut changed = r.clone();
            changed[field] = json!(bad);
            assert!(verify(&changed).is_err());
        }
    }
}
#[test]
fn nom_source_checkpoint_role_collisions_curve_membership_and_root_commitment_refuse() {
    let r = primary();
    for field in [
        "root_key_hex",
        "source_response_key_hex",
        "consumer_checkpoint_key_hex",
    ] {
        for bad in [
            "00".repeat(32),
            "ff".repeat(32),
            "AB".repeat(32),
            "00".repeat(31),
        ] {
            let mut changed = r.clone();
            changed["declaration"][field] = json!(bad);
            assert!(verify(&changed).is_err());
        }
        for other in [
            "root_key_hex",
            "source_response_key_hex",
            "consumer_checkpoint_key_hex",
        ] {
            if other != field {
                let mut changed = r.clone();
                changed["declaration"][field] = r["declaration"][other].clone();
                assert!(verify(&changed).is_err());
            }
        }
    }
    let mut changed = r.clone();
    changed["declaration"]["network_selection"]["provisioning_root_digest_hex"] =
        json!("00".repeat(32));
    assert!(verify(&changed).is_err());
}
#[test]
fn nom_source_checkpoint_numeric_and_boolean_aliases_refuse_even_when_resigned() {
    let r = primary();
    for (object, field) in [
        ("declaration", "declaration_epoch"),
        ("checkpoint_statement", "journal_sequence"),
        ("checkpoint_statement", "charged_work_count"),
        ("checkpoint_statement", "observer_retention_sequence"),
    ] {
        for bad in [
            json!(true),
            json!(0),
            json!(-1),
            json!(1.0),
            json!(9007199254740992_u64),
            json!("1"),
        ] {
            let mut selected = r.clone();
            selected[object][field] = bad;
            // Recompute declarations and signatures so refusal measures grammar, not stale signatures.
            let digest = hex(&hash(DECLARATION, &selected["declaration"]));
            selected["source_statement"]["declaration_digest_hex"] = json!(digest);
            selected["checkpoint_statement"]["declaration_digest_hex"] = json!(digest);
            assert!(verify(&vector(&selected, [96, 98, 97])["request"]).is_err());
        }
    }
    for bad in [json!(1), json!(false), json!("true")] {
        let mut selected = r.clone();
        selected["checkpoint_statement"]["disclosure_possible"] = bad;
        assert!(verify(&vector(&selected, [96, 98, 97])["request"]).is_err());
    }
}
#[test]
fn nom_source_checkpoint_noncanonical_aliases_depth_and_bounds_refuse() {
    let r = primary().to_string();
    for wire in [
        String::new(),
        " ".repeat(verifier::MAX_REQUEST_BYTES + 1),
        "[".repeat(13),
        r.clone() + "\n\n",
        r.clone() + " ",
        r.replace("\"schema\":", "\"\\u0073chema\":"),
        r.replace(
            "\"declaration_epoch\":1",
            "\"declaration_epoch\":1,\"declaration_epoch\":1",
        ),
        r.replace("\"declaration_epoch\":1", "\"declaration_epoch\":1e0"),
        r.replace("historical-nom", "historical-n\u{f6}m"),
    ] {
        assert!(verifier::verify_request(wire.as_bytes()).is_err());
    }
    assert!(verifier::verify_request((r + "\n").as_bytes()).is_ok());
}
#[test]
fn nom_source_checkpoint_cross_role_statement_and_network_schema_refuse() {
    let r = primary();
    let mut changed = r.clone();
    changed["source_statement"] = r["checkpoint_statement"].clone();
    assert!(verify(&changed).is_err());
    for bad in [
        json!("0"),
        json!("01"),
        json!("18446744073709551616"),
        json!(1),
    ] {
        let mut selected = r.clone();
        selected["declaration"]["network_selection"]["chain_id"] = bad;
        let digest = hex(&hash(DECLARATION, &selected["declaration"]));
        selected["source_statement"]["declaration_digest_hex"] = json!(digest);
        selected["checkpoint_statement"]["declaration_digest_hex"] = json!(digest);
        assert!(verify(&vector(&selected, [96, 98, 97])["request"]).is_err());
    }
}
#[test]
fn nom_source_checkpoint_alternate_valid_signature_changes_complete_request_result() {
    let f = fixture();
    let r = primary();
    let mut other = r.clone();
    other["source_signature_hex"] = f["alternate_source_signature_hex"].clone();
    assert_ne!(r["source_signature_hex"], other["source_signature_hex"]);
    assert_eq!(verify(&other), Ok(result(&other).to_string()));
    assert_ne!(verify(&other), verify(&r));
}
#[test]
fn nom_source_checkpoint_historical_replay_and_unavailable_claim_still_verify_only_math() {
    let f = fixture();
    for name in [
        "primary",
        "unavailable",
        "root_rotation",
        "source_rotation",
        "checkpoint_rotation",
        "new_epoch",
        "new_challenge",
    ] {
        let v = &f["positive_vectors"][name];
        assert_eq!(verify(&v["request"]), Ok(v["result"].to_string()));
        assert_eq!(verify(&v["request"]), verify(&v["request"]));
        assert_eq!(
            v["request"]["checkpoint_statement"]["work_outcome"],
            "UNKNOWN"
        );
        assert_eq!(
            v["request"]["checkpoint_statement"]["disclosure_possible"],
            true
        );
    }
    let a = &f["positive_vectors"]["primary"]["request"];
    let b = &f["positive_vectors"]["new_challenge"]["request"];
    assert_ne!(a["source_statement"], b["source_statement"]);
    assert_eq!(a["checkpoint_statement"], b["checkpoint_statement"]);
    assert_eq!(a["checkpoint_signature_hex"], b["checkpoint_signature_hex"]);
}
