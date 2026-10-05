//! Original public synthetic root vectors. Signing is confined to these tests.
//! Fixed public scalar tags must never secure funds or provision a real source.
#[allow(dead_code)]
#[path = "../examples/verify_source_root.rs"]
mod verifier;
use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
const DECLARATION: &[u8] = b"PTLC/observation-source-root-declaration/v1\0";
const REQUEST: &[u8] = b"PTLC/observation-source-root-request/v1\0";
fn hex(body: &[u8]) -> String {
    body.iter().map(|b| format!("{b:02x}")).collect()
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
    json!({"schema":"ptlc-observation-source-root-result-v1","request_digest_hex":hex(&hash(REQUEST,request)),"root_signature_valid":true})
}
fn vector(mut declaration: Value, root: u8) -> Value {
    declaration["source_context"]["provisioning_root_key_hex"] = public(root);
    let signature = sign(DECLARATION, &declaration, root, None);
    let request = json!({"schema":"ptlc-observation-source-root-request-v1","declaration":declaration,"root_signature_hex":signature});
    let mut envelope = request.clone();
    envelope["schema"] = json!("ptlc-observation-source-root-envelope-v1");
    json!({"declaration":declaration,"message_digest_hex":hex(&hash(DECLARATION,&declaration)),"request":request,"envelope":envelope,"result":result(&request)})
}
pub fn generated_fixture() -> Value {
    let current: Value =
        serde_json::from_str(include_str!("../fixtures/current_authority_contract.json")).unwrap();
    let governor: Value =
        serde_json::from_str(include_str!("../fixtures/governor_signature.json")).unwrap();
    let declaration = json!({"schema":"ptlc-observation-source-root-declaration-v1","purpose":"source-role-declaration","algorithm":"BIP340-SHA256","root_transition":"independent-reprovisioning","declaration_revision":1,"source_context":current["source_context"],"governor_profile":governor["primary"]["assignment"]["governor_profile"],"delegated_keys":{"policy_admin_key_hex":public(97),"source_response_key_hex":public(98),"governor_issuer_key_hex":governor["primary"]["assignment"]["issuer_auth_key_hex"]}});
    // Derive the two reused public fixture keys in this same process as well.
    // Distinct role bytes remain fully reproducible from known synthetic tags.
    assert_eq!(
        declaration["governor_profile"]["owner_auth_key_hex"],
        public(83)
    );
    assert_eq!(
        declaration["delegated_keys"]["governor_issuer_key_hex"],
        public(84)
    );
    let primary = vector(declaration.clone(), 96);
    let mut admin = declaration.clone();
    admin["delegated_keys"]["policy_admin_key_hex"] = public(100);
    let mut response = declaration.clone();
    response["delegated_keys"]["source_response_key_hex"] = public(101);
    let mut issuer = declaration.clone();
    issuer["delegated_keys"]["governor_issuer_key_hex"] = public(85);
    let mut owner = declaration.clone();
    owner["governor_profile"]["owner_auth_key_hex"] = public(86);
    let mut caps = declaration.clone();
    caps["governor_profile"]["max_attempt_limit"] = json!(3);
    caps["governor_profile"]["max_target_limit"] = json!(3);
    let mut revision = declaration.clone();
    revision["declaration_revision"] = json!(2);
    let mut incarnation = declaration.clone();
    incarnation["source_context"]["source_incarnation_hex"] = json!("a4".repeat(32));
    let mut epoch = declaration.clone();
    epoch["governor_profile"]["authority_epoch"] = json!(2);
    let mut repeated = primary["declaration"].clone();
    repeated["delegated_keys"]["policy_admin_key_hex"] = public(96);
    json!({"schema":"ptlc-source-root-public-vectors-v1","positive_vectors":{"primary":primary,"alternate_root":vector(declaration,99),"alternate_admin":vector(admin,96),"alternate_response":vector(response,96),"alternate_issuer":vector(issuer,96),"alternate_owner":vector(owner,96),"broader_caps":vector(caps,96),"new_revision":vector(revision,96),"new_incarnation":vector(incarnation,96),"new_epoch":vector(epoch,96)},"role_collision":vector(repeated,96),"alternate_root_signature_hex":sign(DECLARATION,&primary["declaration"],96,Some([31;32])),"wrong_domain_root_signature_hex":sign(b"PTLC/observation-governor-assignment/v1\0",&primary["declaration"],96,None),"wrong_signing_key_signature_hex":sign(DECLARATION,&primary["declaration"],99,None)})
}
fn fixture() -> Value {
    serde_json::from_str(include_str!("../fixtures/source_root_roles.json")).unwrap()
}
fn verify(value: &Value) -> Result<String, ()> {
    verifier::verify_request(&serde_json::to_vec(value).unwrap())
}
fn primary() -> Value {
    fixture()["positive_vectors"]["primary"]["request"].clone()
}

#[test]
fn source_root_public_generator_is_mathematical_and_test_only() {
    let generated = generated_fixture();
    for (_, vector) in generated["positive_vectors"].as_object().unwrap() {
        assert_eq!(verify(&vector["request"]), Ok(vector["result"].to_string()));
    }
    let encoded = generated.to_string();
    for forbidden in [
        "secret_key",
        "private_key",
        "mnemonic",
        "authorized",
        "permit",
        "current_authority",
    ] {
        assert!(!encoded.contains(forbidden));
    }
    if std::env::var("PTLC_PUBLIC_ROOT_VECTOR_OUTPUT").as_deref() == Ok("1") {
        println!("PUBLIC_ROOT_VECTORS:{encoded}");
    }
}
#[test]
fn source_root_fixture_reproduces_complete_public_declarations_and_results() {
    let retained = fixture();
    assert_eq!(generated_fixture(), retained);
    for (_, v) in retained["positive_vectors"].as_object().unwrap() {
        assert_eq!(verify(&v["request"]), Ok(v["result"].to_string()));
    }
}
#[test]
fn source_root_every_declaration_context_profile_and_role_field_is_bound() {
    let request = primary();
    for path in [
        vec!["declaration"],
        vec!["declaration", "source_context"],
        vec!["declaration", "governor_profile"],
        vec!["declaration", "delegated_keys"],
    ] {
        let mut old = &request;
        for field in &path {
            old = &old[*field];
        }
        for (field, value) in old.as_object().unwrap() {
            let mut changed = request.clone();
            let mut at = &mut changed;
            for p in &path {
                at = &mut at[*p];
            }
            at[field] = if value.is_u64() {
                json!(value.as_u64().unwrap() + 1)
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
fn source_root_each_object_requires_exact_fields_without_privilege_extras() {
    let request = primary();
    for path in [
        vec![],
        vec!["declaration"],
        vec!["declaration", "source_context"],
        vec!["declaration", "governor_profile"],
        vec!["declaration", "delegated_keys"],
    ] {
        let mut old = &request;
        for p in &path {
            old = &old[*p];
        }
        for field in old.as_object().unwrap().keys() {
            let mut changed = request.clone();
            let mut at = &mut changed;
            for p in &path {
                at = &mut at[*p];
            }
            at.as_object_mut().unwrap().remove(field);
            assert!(verify(&changed).is_err());
        }
        let mut changed = request.clone();
        let mut at = &mut changed;
        for p in &path {
            at = &mut at[*p];
        }
        at["authorized"] = json!(true);
        assert!(verify(&changed).is_err());
    }
}
#[test]
fn source_root_noncanonical_aliases_bounds_and_cross_schema_requests_refuse() {
    let request = primary().to_string();
    let variants = [
        String::new(),
        " ".repeat(verifier::MAX_REQUEST_BYTES + 1),
        "[".repeat(256),
        request.clone() + "\n\n",
        request.clone() + " ",
        request.replace("\"schema\":", "\"\\u0073chema\":"),
        request.replace(
            "\"declaration_revision\":1",
            "\"declaration_revision\":1,\"declaration_revision\":1",
        ),
        request.replace("\"declaration_revision\":1", "\"declaration_revision\":1.0"),
        request.replace("\"declaration_revision\":1", "\"declaration_revision\":1e0"),
        request.replace(
            "\"source-role-declaration\"",
            "\"source-role-d\u{e9}claration\"",
        ),
    ];
    for wire in variants {
        assert!(verifier::verify_request(wire.as_bytes()).is_err());
    }
    assert!(verifier::verify_request((request + "\n").as_bytes()).is_ok());
    let governor: Value =
        serde_json::from_str(include_str!("../fixtures/governor_signature.json")).unwrap();
    assert!(verify(&governor["primary"]["request"]).is_err());
}
#[test]
fn source_root_five_distinct_keys_are_encoding_policy_not_independent_control() {
    let retained = fixture();
    assert!(verify(&retained["role_collision"]["request"]).is_err());
    let original = primary();
    let keys = [
        original["declaration"]["source_context"]["provisioning_root_key_hex"].clone(),
        original["declaration"]["governor_profile"]["owner_auth_key_hex"].clone(),
        original["declaration"]["delegated_keys"]["policy_admin_key_hex"].clone(),
        original["declaration"]["delegated_keys"]["source_response_key_hex"].clone(),
        original["declaration"]["delegated_keys"]["governor_issuer_key_hex"].clone(),
    ];
    for i in 0..keys.len() {
        assert!(!keys[..i].contains(&keys[i]));
    }
    // All five test keys are generated by one test process; distinct bytes prove no governance.
    assert!(verify(&original).is_ok());
}
#[test]
fn source_root_zero_noncurve_and_noncanonical_keys_refuse_in_every_role() {
    for path in [
        vec!["source_context", "provisioning_root_key_hex"],
        vec!["governor_profile", "owner_auth_key_hex"],
        vec!["delegated_keys", "policy_admin_key_hex"],
        vec!["delegated_keys", "source_response_key_hex"],
        vec!["delegated_keys", "governor_issuer_key_hex"],
    ] {
        for encoded in [
            "00".repeat(32),
            "ff".repeat(32),
            "AA".repeat(32),
            "01".repeat(31),
        ] {
            let mut changed = primary();
            changed["declaration"][path[0]][path[1]] = json!(encoded);
            assert!(verify(&changed).is_err());
        }
    }
}
#[test]
fn source_root_revision_and_profile_number_aliases_refuse() {
    for path in [
        vec!["declaration_revision"],
        vec!["governor_profile", "authority_epoch"],
        vec!["governor_profile", "max_attempt_limit"],
        vec!["governor_profile", "max_target_limit"],
    ] {
        for value in [
            json!(false),
            json!(true),
            json!(0),
            json!(-1),
            json!(1.0),
            json!(1_u64 << 53),
        ] {
            let mut changed = primary();
            let mut at = &mut changed["declaration"];
            for field in &path {
                at = &mut at[*field];
            }
            *at = value;
            assert!(verify(&changed).is_err());
        }
    }
}
#[test]
fn source_root_wrong_root_role_domain_and_every_signature_byte_refuse() {
    let retained = fixture();
    let original = primary();
    for field in [
        "wrong_domain_root_signature_hex",
        "wrong_signing_key_signature_hex",
    ] {
        let mut changed = original.clone();
        changed["root_signature_hex"] = retained[field].clone();
        assert!(verify(&changed).is_err());
    }
    let text = original["root_signature_hex"].as_str().unwrap();
    let signature: Vec<u8> = text
        .as_bytes()
        .chunks_exact(2)
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
        .collect();
    for i in 0..64 {
        let mut bytes = signature.clone();
        bytes[i] ^= 1;
        let mut changed = original.clone();
        changed["root_signature_hex"] = json!(hex(&bytes));
        assert!(verify(&changed).is_err());
    }
    for invalid in [
        "00".repeat(64),
        "ff".repeat(64),
        "ff".repeat(32) + &"00".repeat(32),
        "00".repeat(32) + &"ff".repeat(32),
        "00".repeat(63),
        text.to_uppercase(),
    ] {
        let mut changed = original.clone();
        changed["root_signature_hex"] = json!(invalid);
        assert!(verify(&changed).is_err());
    }
}
#[test]
fn source_root_valid_alternate_signature_changes_full_result_binding() {
    let retained = fixture();
    let mut changed = primary();
    changed["root_signature_hex"] = retained["alternate_root_signature_hex"].clone();
    assert_eq!(verify(&changed), Ok(result(&changed).to_string()));
    assert_ne!(
        result(&changed),
        retained["positive_vectors"]["primary"]["result"]
    );
}
#[test]
fn source_root_self_selected_stale_and_replayed_math_supplies_no_current_roles() {
    let retained = fixture();
    let old = primary();
    for name in [
        "alternate_root",
        "alternate_admin",
        "alternate_response",
        "new_revision",
        "new_incarnation",
    ] {
        assert!(verify(&retained["positive_vectors"][name]["request"]).is_ok());
        assert!(verify(&old).is_ok());
    }
    for _ in 0..2 {
        assert_eq!(
            verify(&old),
            Ok(retained["positive_vectors"]["primary"]["result"].to_string())
        );
    }
    assert_eq!(
        retained["positive_vectors"]["primary"]["result"]
            .as_object()
            .unwrap()
            .len(),
        3
    );
}
