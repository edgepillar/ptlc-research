//! Original public command vectors, using deliberately known synthetic tags.
//! All signing stays in tests; these roles do not establish operational custody.
#[allow(dead_code)]
#[path = "../examples/verify_source_admin.rs"]
mod verifier;
use bitcoin::secp256k1::{
    Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey, schnorr::Signature,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
const COMMAND: &[u8] = b"PTLC/observation-source-admin-command/v1\0";
const REQUEST: &[u8] = b"PTLC/observation-source-admin-request/v1\0";
const DECLARATION: &[u8] = b"PTLC/observation-source-root-declaration/v1\0";
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
    let message = Message::from_digest(hash(domain, value));
    let secp = Secp256k1::new();
    let s = match aux {
        Some(aux) => secp.sign_schnorr_with_aux_rand(&message, &key(tag), &aux),
        None => secp.sign_schnorr_no_aux_rand(&message, &key(tag)),
    };
    json!(hex(s.as_ref()))
}
fn result(request: &Value) -> Value {
    json!({"schema":"ptlc-observation-source-admin-result-v1","request_digest_hex":hex(&hash(REQUEST,request)),"root_signature_valid":true,"administrator_signature_valid":true})
}
fn command(statement: &Value) -> Value {
    let d = &statement["declaration"];
    let mut reduced = d["governor_profile"].clone();
    reduced["max_attempt_limit"] = json!(1);
    reduced["max_target_limit"] = json!(1);
    json!({"schema":"ptlc-observation-source-admin-command-v1","purpose":"source-policy-command","algorithm":"BIP340-SHA256","administration_rule":"attenuate-or-revoke-v1","source_context":d["source_context"],"root_declaration_digest_hex":hex(&hash(DECLARATION,d)),"administrator_role":"policy-administrator","administrator_key_hex":d["delegated_keys"]["policy_admin_key_hex"],"original_command_id_hex":"d1".repeat(32),"expected_policy_revision":0,"old_profile":d["governor_profile"],"new_profile":reduced,"old_active":true,"new_active":true,"operation":"reduce-limits"})
}
fn vector(statement: &Value, command: Value, tag: u8) -> Value {
    let request = json!({"schema":"ptlc-observation-source-admin-request-v1","root_envelope":statement,"command":command,"admin_signature_hex":sign(COMMAND,&command,tag,None)});
    let mut envelope = request.clone();
    envelope["schema"] = json!("ptlc-observation-source-admin-envelope-v1");
    json!({"command":command,"message_digest_hex":hex(&hash(COMMAND,&command)),"request":request,"envelope":envelope,"result":result(&request)})
}
pub fn generated_fixture() -> Value {
    let roots: Value =
        serde_json::from_str(include_str!("../fixtures/source_root_roles.json")).unwrap();
    let statement = &roots["positive_vectors"]["primary"]["envelope"];
    let d = &statement["declaration"];
    // Every primary role is reproducible inside one test process from public tags.
    for (actual, tag) in [
        (&d["source_context"]["provisioning_root_key_hex"], 96),
        (&d["delegated_keys"]["policy_admin_key_hex"], 97),
        (&d["delegated_keys"]["source_response_key_hex"], 98),
        (&d["delegated_keys"]["governor_issuer_key_hex"], 84),
        (&d["governor_profile"]["owner_auth_key_hex"], 83),
    ] {
        assert_eq!(*actual, public(tag));
    }
    let base = command(statement);
    let mut positives = serde_json::Map::new();
    positives.insert("primary".into(), vector(statement, base.clone(), 97));
    for (name, field) in [
        ("reduce_attempt_only", "max_target_limit"),
        ("reduce_target_only", "max_attempt_limit"),
    ] {
        let mut c = base.clone();
        c["new_profile"][field] = json!(2);
        positives.insert(name.into(), vector(statement, c, 97));
    }
    let mut revoke = base.clone();
    revoke["operation"] = json!("revoke");
    revoke["new_active"] = json!(false);
    revoke["new_profile"] = revoke["old_profile"].clone();
    positives.insert("revoke".into(), vector(statement, revoke.clone(), 97));
    let mut c = revoke.clone();
    c["old_profile"] = base["new_profile"].clone();
    c["new_profile"] = c["old_profile"].clone();
    c["expected_policy_revision"] = json!(7);
    positives.insert("revoke_reduced".into(), vector(statement, c, 97));
    let mut c = base.clone();
    c["original_command_id_hex"] = json!("d2".repeat(32));
    positives.insert("alternate_id".into(), vector(statement, c, 97));
    for (name, revision) in [
        ("new_policy_revision", 1),
        ("max_policy_revision", (1_u64 << 53) - 2),
    ] {
        let mut c = base.clone();
        c["expected_policy_revision"] = json!(revision);
        positives.insert(name.into(), vector(statement, c, 97));
    }
    for (name, root_name, tag) in [
        ("alternate_root", "alternate_root", 97),
        ("alternate_admin", "alternate_admin", 100),
        ("new_incarnation", "new_incarnation", 97),
        ("new_root_revision", "new_revision", 97),
    ] {
        let s = &roots["positive_vectors"][root_name]["envelope"];
        positives.insert(name.into(), vector(s, command(s), tag));
    }
    let mut refused = serde_json::Map::new();
    let mut add = |name: &str, c: Value, tag: u8| {
        refused.insert(name.into(), vector(statement, c, tag));
    };
    let mut c = base.clone();
    c["old_profile"] = base["new_profile"].clone();
    c["new_profile"] = base["old_profile"].clone();
    add("increase", c, 97);
    let mut c = base.clone();
    c["old_profile"]["max_attempt_limit"] = json!(1);
    c["new_profile"]["max_attempt_limit"] = json!(2);
    add("mixed_increase", c, 97);
    let mut c = base.clone();
    c["new_profile"] = c["old_profile"].clone();
    add("no_op", c, 97);
    let mut c = base.clone();
    c["old_active"] = json!(false);
    add("reactivate", c, 97);
    let mut c = base.clone();
    c["operation"] = json!("rotate");
    add("unknown_operation", c, 97);
    for (name, field, value) in [
        ("changed_owner", "owner_auth_key_hex", public(86)),
        ("changed_epoch", "authority_epoch", json!(2)),
        (
            "changed_config",
            "verifier_profile_digest_hex",
            json!("ee".repeat(32)),
        ),
    ] {
        let mut c = base.clone();
        c["new_profile"][field] = value;
        add(name, c, 97);
    }
    let mut c = revoke.clone();
    c["new_profile"] = base["new_profile"].clone();
    add("revoke_changes_profile", c, 97);
    let mut c = revoke.clone();
    c["new_active"] = json!(true);
    add("revoke_stays_active", c, 97);
    let mut c = base.clone();
    c["root_declaration_digest_hex"] = json!("ee".repeat(32));
    add("different_root_digest", c, 97);
    let mut c = base.clone();
    c["source_context"]["source_incarnation_hex"] = json!("ee".repeat(32));
    add("different_source", c, 97);
    let mut c = base.clone();
    c["administration_rule"] = json!("allow-all");
    add("rule_expansion", c, 97);
    let mut c = base.clone();
    c["old_profile"]["max_attempt_limit"] = json!(3);
    add("exceeds_anchor", c, 97);
    for (name, tag) in [
        ("response_key_claim", 98),
        ("root_key_claim", 96),
        ("issuer_key_claim", 84),
        ("owner_key_claim", 83),
    ] {
        let mut c = base.clone();
        c["administrator_key_hex"] = public(tag);
        add(name, c, tag);
    }
    let wrong_keys: serde_json::Map<String, Value> = [
        ("root", 96),
        ("response", 98),
        ("issuer", 84),
        ("owner", 83),
        ("other", 99),
    ]
    .into_iter()
    .map(|(name, tag)| (name.into(), sign(COMMAND, &base, tag, None)))
    .collect();
    json!({"schema":"ptlc-source-admin-public-vectors-v1","positive_vectors":positives,"signed_refusal_vectors":refused,
        "alternate_admin_signature_hex":sign(COMMAND,&base,97,Some([32;32])),
        "alternate_root_signature_hex":roots["alternate_root_signature_hex"],
        "wrong_domain_admin_signature_hex":sign(DECLARATION,&base,97,None),"wrong_role_signatures":wrong_keys})
}
fn fixture() -> Value {
    serde_json::from_str(include_str!("../fixtures/source_admin_command.json")).unwrap()
}
fn primary() -> Value {
    fixture()["positive_vectors"]["primary"]["request"].clone()
}
fn verify(v: &Value) -> Result<String, ()> {
    verifier::verify_request(&serde_json::to_vec(v).unwrap())
}
fn decode_hex(v: &Value) -> Vec<u8> {
    v.as_str()
        .unwrap()
        .as_bytes()
        .chunks_exact(2)
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
        .collect()
}
fn at<'a>(value: &'a mut Value, path: &[&str]) -> &'a mut Value {
    let mut v = value;
    for p in path {
        v = &mut v[*p];
    }
    v
}

#[test]
fn source_admin_public_generator_is_test_only_and_checks_all_primary_roles() {
    let generated = generated_fixture();
    for v in generated["positive_vectors"].as_object().unwrap().values() {
        assert_eq!(verify(&v["request"]), Ok(v["result"].to_string()));
    }
    let wire = generated.to_string();
    for forbidden in [
        "secret_key",
        "private_key",
        "mnemonic",
        "authorized",
        "permit",
        "current_authority",
    ] {
        assert!(!wire.contains(forbidden));
    }
    if std::env::var("PTLC_PUBLIC_ADMIN_VECTOR_OUTPUT").as_deref() == Ok("1") {
        println!("PUBLIC_ADMIN_VECTORS:{wire}");
    }
}
#[test]
fn source_admin_fixture_reproduces_both_operations_and_complete_results() {
    let f = fixture();
    assert_eq!(generated_fixture(), f);
    assert_eq!(f["positive_vectors"].as_object().unwrap().len(), 12);
    for v in f["positive_vectors"].as_object().unwrap().values() {
        assert_eq!(verify(&v["request"]), Ok(v["result"].to_string()));
    }
}
#[test]
fn source_admin_valid_signatures_do_not_expand_selected_transition_powers() {
    let f = fixture();
    assert_eq!(f["signed_refusal_vectors"].as_object().unwrap().len(), 18);
    for (name, v) in f["signed_refusal_vectors"].as_object().unwrap() {
        let r = &v["request"];
        let k = XOnlyPublicKey::from_slice(&decode_hex(&r["command"]["administrator_key_hex"]))
            .unwrap();
        let s = Signature::from_slice(&decode_hex(&r["admin_signature_hex"])).unwrap();
        assert!(
            Secp256k1::verification_only()
                .verify_schnorr(&s, &Message::from_digest(hash(COMMAND, &r["command"])), &k)
                .is_ok()
        );
        assert!(verify(r).is_err(), "accepted signed forbidden {name}");
    }
}
#[test]
fn source_admin_all_command_profiles_context_and_root_fields_are_bound() {
    let r = primary();
    for path in [
        vec!["command"],
        vec!["command", "source_context"],
        vec!["command", "old_profile"],
        vec!["command", "new_profile"],
        vec!["root_envelope", "declaration"],
        vec!["root_envelope", "declaration", "source_context"],
        vec!["root_envelope", "declaration", "governor_profile"],
        vec!["root_envelope", "declaration", "delegated_keys"],
    ] {
        let mut copy = r.clone();
        let fields = at(&mut copy, &path).as_object().unwrap().clone();
        for (field, value) in fields {
            let mut c = r.clone();
            at(&mut c, &path)[&field] = if value.is_u64() {
                json!(value.as_u64().unwrap() + 1)
            } else {
                json!("ee".repeat(32))
            };
            assert!(verify(&c).is_err(), "unbound {path:?}/{field}");
        }
    }
}
#[test]
fn source_admin_exact_fields_types_and_privilege_extras_refuse() {
    let r = primary();
    for path in [
        vec![],
        vec!["command"],
        vec!["command", "source_context"],
        vec!["command", "old_profile"],
        vec!["command", "new_profile"],
        vec!["root_envelope"],
        vec!["root_envelope", "declaration"],
        vec!["root_envelope", "declaration", "source_context"],
        vec!["root_envelope", "declaration", "governor_profile"],
        vec!["root_envelope", "declaration", "delegated_keys"],
    ] {
        let mut copy = r.clone();
        let fields = at(&mut copy, &path).as_object().unwrap().clone();
        for field in fields.keys() {
            let mut c = r.clone();
            at(&mut c, &path).as_object_mut().unwrap().remove(field);
            assert!(verify(&c).is_err());
            let mut c = r.clone();
            at(&mut c, &path)[field] = json!(null);
            assert!(verify(&c).is_err());
        }
        let mut c = r.clone();
        at(&mut c, &path)["authorized"] = json!(true);
        assert!(verify(&c).is_err());
    }
}
#[test]
fn source_admin_each_role_wrong_domain_and_both_signature_byte_arrays_refuse() {
    let f = fixture();
    let r = primary();
    let mut bad: Vec<Value> = f["wrong_role_signatures"]
        .as_object()
        .unwrap()
        .values()
        .cloned()
        .collect();
    bad.push(f["wrong_domain_admin_signature_hex"].clone());
    for sig in bad {
        let mut c = r.clone();
        c["admin_signature_hex"] = sig;
        assert!(verify(&c).is_err());
    }
    for path in [
        vec!["admin_signature_hex"],
        vec!["root_envelope", "root_signature_hex"],
    ] {
        let mut c = r.clone();
        let original = decode_hex(at(&mut c, &path));
        for i in 0..64 {
            let mut s = original.clone();
            s[i] ^= 1;
            let mut c = r.clone();
            *at(&mut c, &path) = json!(hex(&s));
            assert!(verify(&c).is_err());
        }
        for sig in [
            "00".repeat(64),
            "ff".repeat(64),
            "ff".repeat(32) + &"00".repeat(32),
            "00".repeat(32) + &"ff".repeat(32),
            "AB".repeat(64),
            "00".repeat(63),
        ] {
            let mut c = r.clone();
            *at(&mut c, &path) = json!(sig);
            assert!(verify(&c).is_err());
        }
    }
}
#[test]
fn source_admin_signature_variants_bind_each_complete_request() {
    let f = fixture();
    let r = primary();
    for path in [
        vec!["admin_signature_hex"],
        vec!["root_envelope", "root_signature_hex"],
    ] {
        let mut c = r.clone();
        *at(&mut c, &path) = if path.len() == 1 {
            f["alternate_admin_signature_hex"].clone()
        } else {
            f["alternate_root_signature_hex"].clone()
        };
        assert_eq!(verify(&c), Ok(result(&c).to_string()));
        assert_ne!(result(&c), result(&r));
    }
}
#[test]
fn source_admin_revision_boolean_limits_and_canonical_aliases_refuse() {
    let r = primary();
    for value in [
        json!(true),
        json!(-1),
        json!(0.0),
        json!("0"),
        json!((1_u64 << 53) - 1),
    ] {
        let mut c = r.clone();
        c["command"]["expected_policy_revision"] = value;
        assert!(verify(&c).is_err());
    }
    let wire = r.to_string();
    for bad in [
        String::new(),
        " ".repeat(8193),
        wire.clone() + "\n\n",
        wire.clone() + " ",
        wire.replace("\"command\":", "\"\\u0063ommand\":"),
        wire.replace(
            "\"expected_policy_revision\":0",
            "\"expected_policy_revision\":0,\"expected_policy_revision\":0",
        ),
        wire.replace(
            "\"expected_policy_revision\":0",
            "\"expected_policy_revision\":0.0",
        ),
        wire.replace(
            "\"expected_policy_revision\":0",
            "\"expected_policy_revision\":0e0",
        ),
        wire.replace("source-policy-command", "source-policy-c\u{e9}mmand"),
    ] {
        assert!(verifier::verify_request(bad.as_bytes()).is_err());
    }
    assert!(verifier::verify_request((wire + "\n").as_bytes()).is_ok());
}
#[test]
fn source_admin_old_commands_cannot_follow_signed_new_expected_revision() {
    let f = fixture();
    let old = primary();
    for v in f["positive_vectors"].as_object().unwrap().values() {
        if v["command"] == old["command"] {
            continue;
        }
        let mut c = v["request"].clone();
        c["admin_signature_hex"] = old["admin_signature_hex"].clone();
        assert!(verify(&c).is_err());
    }
}
#[test]
fn source_admin_self_selected_and_restored_replay_remain_historical_math() {
    let f = fixture();
    let old = primary();
    for name in [
        "alternate_root",
        "alternate_admin",
        "new_incarnation",
        "new_root_revision",
        "new_policy_revision",
        "revoke",
    ] {
        assert!(verify(&f["positive_vectors"][name]["request"]).is_ok());
        assert!(verify(&old).is_ok());
        assert!(verify(&old.clone()).is_ok());
    }
    assert_eq!(result(&old).as_object().unwrap().len(), 4);
}
