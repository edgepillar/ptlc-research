//! Original synthetic public vectors. Deliberately known tags sign only tests.
//! Distinct public roles do not establish independent operational custody.
#[allow(dead_code)]
#[path = "../examples/verify_original_read_response.rs"]
mod verifier;
use bitcoin::secp256k1::{
    Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey, schnorr::Signature,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
const TAG: &[u8] = b"PTLC/observation-original-read-response/v1";
const REQUEST: &[u8] = b"PTLC/observation-original-read-response-request/v1\0";
const DECLARATION: &[u8] = b"PTLC/observation-source-root-declaration/v1\0";
const QUERY: &[u8] = b"PTLC/observation-original-read-query/v1\0";
const CLAIM: &[u8] = b"PTLC/observation-original-read-claim/v1\0";
const SOURCE: &[u8] = b"PTLC/observation-policy-source-context/v1\0";
fn hex(b: &[u8]) -> String {
    b.iter().map(|v| format!("{v:02x}")).collect()
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
    h.update(value.to_string().as_bytes());
    h.finalize().into()
}
fn message(r: &Value) -> [u8; 32] {
    let tag = Sha256::digest(TAG);
    let mut h = Sha256::new();
    h.update(tag);
    h.update(tag);
    h.update(r.to_string().as_bytes());
    h.finalize().into()
}
fn sign(digest: [u8; 32], tag: u8, aux: Option<[u8; 32]>) -> Value {
    let m = Message::from_digest(digest);
    let secp = Secp256k1::new();
    let s = match aux {
        Some(a) => secp.sign_schnorr_with_aux_rand(&m, &key(tag), &a),
        None => secp.sign_schnorr_no_aux_rand(&m, &key(tag)),
    };
    json!(hex(s.as_ref()))
}
fn decode(v: &Value) -> Vec<u8> {
    v.as_str()
        .unwrap()
        .as_bytes()
        .chunks_exact(2)
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
        .collect()
}
fn math(k: &Value, m: [u8; 32], sig: &Value) -> bool {
    Secp256k1::verification_only()
        .verify_schnorr(
            &Signature::from_slice(&decode(sig)).unwrap(),
            &Message::from_digest(m),
            &XOnlyPublicKey::from_slice(&decode(k)).unwrap(),
        )
        .is_ok()
}
fn result(p: &Value) -> Value {
    json!({"schema":"ptlc-observation-original-read-response-result-v1", "request_digest_hex":hex(&hash(REQUEST,p)),"root_signature_valid":true,"response_signature_valid":true})
}
fn response(s: &Value, q: Value, observation: &str, active: bool) -> Value {
    let unavailable = observation == "unavailable";
    let c = json!({"schema":"ptlc-observation-original-read-claim-v1","query_digest_hex":hex(&hash(QUERY,&q)),"root_declaration_digest_hex":q["root_declaration_digest_hex"],"source_context_digest_hex":hex(&hash(SOURCE,&q["source_context"])),"challenge_hex":q["challenge_hex"],"observation":observation,"claimed_checkpoint":if unavailable {Value::Null} else {q["expected_checkpoint"].clone()},"claimed_record_checkpoint":if unavailable {Value::Null} else {q["expected_record_checkpoint"].clone()},"head_policy":if unavailable {Value::Null} else {json!({"governor_profile":s["declaration"]["governor_profile"],"active":active})},"original_record":if unavailable || observation == "absent" {Value::Null} else {json!({"original_operation":q["original_operation"],"charge_sequence":2,"effect_sequence":if observation == "completed" {json!(6)} else {Value::Null}})}});
    json!({"schema":"ptlc-observation-original-read-response-v1","purpose":"original-checkpoint-response","algorithm":"BIP340-SHA256","read_rule":"historical-original-checkpoint-read-v1","root_declaration_digest_hex":hex(&hash(DECLARATION,&s["declaration"])),"source_response_role":"historical-original-responder","source_response_key_hex":s["declaration"]["delegated_keys"]["source_response_key_hex"],"source_context":s["declaration"]["source_context"],"query":q,"claim_digest_hex":hex(&hash(CLAIM,&c)),"claim":c})
}
fn vector(s: &Value, mut r: Value, tag: u8) -> Value {
    r["claim_digest_hex"] = json!(hex(&hash(CLAIM, &r["claim"])));
    let p = json!({"schema":"ptlc-observation-original-read-response-request-v1","root_envelope":s,"response":r,"response_signature_hex":sign(message(&r),tag,None)});
    let mut e = p.clone();
    e["schema"] = json!("ptlc-observation-original-read-response-envelope-v1");
    json!({"response":r,"message_digest_hex":hex(&message(&r)),"request":p,"envelope":e,"result":result(&p)})
}
fn rebind_root(s: &mut Value, q: &mut Value) {
    s["root_signature_hex"] = sign(hash(DECLARATION, &s["declaration"]), 96, None);
    q["root_declaration_digest_hex"] = json!(hex(&hash(DECLARATION, &s["declaration"])));
    q["source_context"] = s["declaration"]["source_context"].clone();
}
fn refresh_query(r: &mut Value) {
    r["claim"]["query_digest_hex"] = json!(hex(&hash(QUERY, &r["query"])));
    r["claim"]["source_context_digest_hex"] =
        json!(hex(&hash(SOURCE, &r["query"]["source_context"])));
    r["claim"]["root_declaration_digest_hex"] = r["query"]["root_declaration_digest_hex"].clone();
    r["claim"]["challenge_hex"] = r["query"]["challenge_hex"].clone();
    r["claim"]["original_record"]["original_operation"] = r["query"]["original_operation"].clone();
}
fn set(v: &mut Value, path: &[&str], value: Value) {
    let mut v = v;
    for f in &path[..path.len() - 1] {
        v = &mut v[*f];
    }
    v[path[path.len() - 1]] = value;
}
pub fn generated_fixture() -> Value {
    let unsigned: Value =
        serde_json::from_str(include_str!("../fixtures/original_read_contract.json")).unwrap();
    let legacy: Value =
        serde_json::from_str(include_str!("../fixtures/source_response.json")).unwrap();
    let s = legacy["positive_vectors"]["primary"]["envelope"]["root_envelope"].clone();
    let q = unsigned["query"].clone();
    let primary = response(&s, q.clone(), "pending", true);
    let mut positive = serde_json::Map::new();
    positive.insert("primary".into(), vector(&s, primary.clone(), 98));
    for state in ["absent", "completed", "unavailable"] {
        positive.insert(
            state.into(),
            vector(&s, response(&s, q.clone(), state, true), 98),
        );
    }
    for state in ["absent", "pending", "completed"] {
        positive.insert(
            format!("inactive_{state}"),
            vector(&s, response(&s, q.clone(), state, false), 98),
        );
    }
    for (name, path, v) in [
        (
            "new_challenge",
            vec!["challenge_hex"],
            json!("06".repeat(32)),
        ),
        (
            "same_id_changed_proposal",
            vec!["original_operation", "proposal_digest_hex"],
            json!("07".repeat(32)),
        ),
        (
            "same_id_changed_revision",
            vec!["original_operation", "expected_revision"],
            json!(3),
        ),
        (
            "different_id_same_proposal",
            vec!["original_operation", "operation_id_hex"],
            json!("08".repeat(32)),
        ),
        (
            "zero_original_revision",
            vec!["original_operation", "expected_revision"],
            json!(0),
        ),
        (
            "same_revision",
            vec!["original_operation", "expected_revision"],
            json!(7),
        ),
        (
            "new_policy_checkpoint",
            vec!["expected_checkpoint", "revision"],
            json!(9),
        ),
        (
            "new_record_checkpoint",
            vec!["expected_record_checkpoint", "event_sequence"],
            json!(11),
        ),
        (
            "zero_record_absence",
            vec!["expected_record_checkpoint", "event_sequence"],
            json!(0),
        ),
    ] {
        let mut c = q.clone();
        set(&mut c, &path, v);
        positive.insert(
            name.into(),
            vector(
                &s,
                response(
                    &s,
                    c,
                    if name == "zero_record_absence" {
                        "absent"
                    } else {
                        "pending"
                    },
                    true,
                ),
                98,
            ),
        );
    }
    let mut c = q.clone();
    c["original_operation"]["governor_profile"]["owner_auth_key_hex"] = public(85);
    for f in [
        "authority_profile_digest_hex",
        "verifier_profile_digest_hex",
        "pool_profile_digest_hex",
        "resource_profile_digest_hex",
    ] {
        c["original_operation"]["governor_profile"][f] = json!("09".repeat(32));
    }
    c["original_operation"]["governor_profile"]["authority_epoch"] = json!(2);
    c["original_operation"]["governor_profile"]["max_attempt_limit"] = json!(64);
    c["original_operation"]["governor_profile"]["max_target_limit"] = json!(1);
    positive.insert(
        "historical_different_profile".into(),
        vector(&s, response(&s, c, "completed", true), 98),
    );
    for name in [
        "new_root_revision",
        "new_incarnation",
        "new_head_profile",
        "alternate_response",
    ] {
        let mut rs = s.clone();
        let mut c = q.clone();
        let mut tag = 98;
        match name {
            "new_root_revision" => rs["declaration"]["declaration_revision"] = json!(2),
            "new_incarnation" => {
                rs["declaration"]["source_context"]["source_incarnation_hex"] =
                    json!("0a".repeat(32))
            }
            "new_head_profile" => {
                rs["declaration"]["governor_profile"]["owner_auth_key_hex"] = public(85);
                rs["declaration"]["governor_profile"]["max_attempt_limit"] = json!(1);
            }
            "alternate_response" => {
                rs["declaration"]["delegated_keys"]["source_response_key_hex"] = public(101);
                tag = 101;
            }
            _ => unreachable!(),
        }
        rebind_root(&mut rs, &mut c);
        positive.insert(
            name.into(),
            vector(&rs, response(&rs, c, "pending", true), tag),
        );
    }
    let mut rs = s.clone();
    rs["declaration"]["source_context"]["provisioning_root_key_hex"] = public(99);
    rs["root_signature_hex"] = sign(hash(DECLARATION, &rs["declaration"]), 99, None);
    let mut c = q.clone();
    c["root_declaration_digest_hex"] = json!(hex(&hash(DECLARATION, &rs["declaration"])));
    c["source_context"] = rs["declaration"]["source_context"].clone();
    positive.insert(
        "alternate_root".into(),
        vector(&rs, response(&rs, c, "pending", true), 98),
    );
    let mut refused = serde_json::Map::new();
    for (name, path, v) in [
        ("response_schema", vec!["schema"], json!("unsupported")),
        ("response_purpose", vec!["purpose"], json!("mutation")),
        (
            "response_algorithm",
            vec!["algorithm"],
            json!("unsupported"),
        ),
        (
            "response_rule",
            vec!["read_rule"],
            json!("exact-profile-checkpoint-read-v1"),
        ),
        (
            "response_role",
            vec!["source_response_role"],
            json!("checkpoint-responder"),
        ),
        (
            "response_root_digest",
            vec!["root_declaration_digest_hex"],
            json!("ee".repeat(32)),
        ),
        (
            "response_source",
            vec!["source_context", "source_id_hex"],
            json!("ee".repeat(32)),
        ),
        (
            "claim_schema",
            vec!["claim", "schema"],
            json!("unsupported"),
        ),
        (
            "claim_query_digest",
            vec!["claim", "query_digest_hex"],
            json!("ee".repeat(32)),
        ),
        (
            "claim_root_digest",
            vec!["claim", "root_declaration_digest_hex"],
            json!("ee".repeat(32)),
        ),
        (
            "claim_source_digest",
            vec!["claim", "source_context_digest_hex"],
            json!("ee".repeat(32)),
        ),
        (
            "claim_challenge",
            vec!["claim", "challenge_hex"],
            json!("ee".repeat(32)),
        ),
        ("claim_state", vec!["claim", "observation"], json!("active")),
        (
            "claim_policy_checkpoint",
            vec!["claim", "claimed_checkpoint", "revision"],
            json!(8),
        ),
        (
            "claim_record_checkpoint",
            vec!["claim", "claimed_record_checkpoint", "event_sequence"],
            json!(10),
        ),
        (
            "claim_active_alias",
            vec!["claim", "head_policy", "active"],
            json!(1),
        ),
        (
            "claim_head_profile",
            vec![
                "claim",
                "head_policy",
                "governor_profile",
                "max_attempt_limit",
            ],
            json!(64),
        ),
        (
            "record_original_proposal",
            vec![
                "claim",
                "original_record",
                "original_operation",
                "proposal_digest_hex",
            ],
            json!("ee".repeat(32)),
        ),
        (
            "record_charge_zero",
            vec!["claim", "original_record", "charge_sequence"],
            json!(0),
        ),
        (
            "record_charge_beyond",
            vec!["claim", "original_record", "charge_sequence"],
            json!(10),
        ),
        (
            "pending_effect",
            vec!["claim", "original_record", "effect_sequence"],
            json!(6),
        ),
        (
            "completed_without_effect",
            vec!["claim", "observation"],
            json!("completed"),
        ),
        (
            "absent_cached_record",
            vec!["claim", "observation"],
            json!("absent"),
        ),
        (
            "unavailable_cached_state",
            vec!["claim", "observation"],
            json!("unavailable"),
        ),
    ] {
        let mut r = primary.clone();
        set(&mut r, &path, v);
        refused.insert(name.into(), vector(&s, r, 98));
    }
    for (name, path, v) in [
        ("query_schema", vec!["schema"], json!("unsupported")),
        (
            "query_operation",
            vec!["operation"],
            json!("read-assignment-at-checkpoint"),
        ),
        ("query_rule", vec!["read_rule"], json!("unsupported")),
        (
            "query_root_digest",
            vec!["root_declaration_digest_hex"],
            json!("ee".repeat(32)),
        ),
        (
            "query_source",
            vec!["source_context", "source_incarnation_hex"],
            json!("ee".repeat(32)),
        ),
        (
            "query_retention",
            vec!["expected_record_checkpoint", "retention_rule"],
            json!("pruned-originals"),
        ),
        (
            "original_schema",
            vec!["original_operation", "schema"],
            json!("unsupported"),
        ),
        (
            "original_future_revision",
            vec!["original_operation", "expected_revision"],
            json!(8),
        ),
        (
            "original_namespace",
            vec!["original_operation", "governor_profile", "authority_id_hex"],
            json!("ee".repeat(32)),
        ),
        (
            "original_noncurve_owner",
            vec![
                "original_operation",
                "governor_profile",
                "owner_auth_key_hex",
            ],
            json!("ff".repeat(32)),
        ),
        (
            "original_cap_zero",
            vec![
                "original_operation",
                "governor_profile",
                "max_attempt_limit",
            ],
            json!(0),
        ),
    ] {
        let mut r = primary.clone();
        set(&mut r["query"], &path, v);
        refresh_query(&mut r);
        refused.insert(name.into(), vector(&s, r, 98));
    }
    let mut r = primary.clone();
    r["query"]["original_operation"]["expected_revision"] = json!(7);
    r["query"]["original_operation"]["governor_profile"]["max_attempt_limit"] = json!(64);
    refresh_query(&mut r);
    refused.insert("same_revision_changed_profile".into(), vector(&s, r, 98));
    for (name, value) in [
        ("effect_not_after_charge", 2),
        ("effect_beyond_checkpoint", 10),
    ] {
        let mut r = response(&s, q.clone(), "completed", true);
        r["claim"]["original_record"]["effect_sequence"] = json!(value);
        refused.insert(name.into(), vector(&s, r, 98));
    }
    let mut r = primary.clone();
    r["claim"]["authorized"] = json!(true);
    refused.insert("extra_claim_permission".into(), vector(&s, r, 98));
    for (name, tag) in [
        ("root_role", 96),
        ("admin_role", 97),
        ("issuer_role", 84),
        ("owner_role", 83),
    ] {
        let mut r = primary.clone();
        r["source_response_key_hex"] = public(tag);
        refused.insert(name.into(), vector(&s, r, tag));
    }
    let alternate_root = sign(hash(DECLARATION, &s["declaration"]), 96, Some([12; 32]));
    let alternate_response = sign(message(&primary), 98, Some([13; 32]));
    let wrong_plain = sign(
        hash(b"PTLC/observation-original-read-response/v1\0", &primary),
        98,
        None,
    );
    let wrong_legacy = sign(
        hash(b"PTLC/observation-source-response/v1\0", &primary),
        98,
        None,
    );
    json!({"schema":"ptlc-original-read-response-public-vectors-v1","purpose":"synthetic-historical-mathematics-only","positive_vectors":positive,"signed_refusal_vectors":refused,"alternate_root_signature_hex":alternate_root,"alternate_response_signature_hex":alternate_response,"wrong_plain_prefix_signature_hex":wrong_plain,"wrong_legacy_domain_signature_hex":wrong_legacy})
}
fn fixture() -> Value {
    serde_json::from_str(include_str!("../fixtures/original_read_response.json")).unwrap()
}
fn verify(v: &Value) -> Result<String, ()> {
    verifier::verify_request(v.to_string().as_bytes()).map(|s| s.trim_end_matches('\n').to_owned())
}
fn primary() -> Value {
    fixture()["positive_vectors"]["primary"]["request"].clone()
}
fn objects(v: &Value, path: Vec<String>, out: &mut Vec<Vec<String>>) {
    if let Some(o) = v.as_object() {
        out.push(path.clone());
        for (f, c) in o {
            let mut p = path.clone();
            p.push(f.clone());
            objects(c, p, out);
        }
    }
}
fn target<'a>(v: &'a mut Value, path: &[String]) -> &'a mut Value {
    let mut v = v;
    for f in path {
        v = &mut v[f];
    }
    v
}
#[test]
fn original_response_test_only_generator_checks_public_roles_and_emits_no_signer_material() {
    let f = generated_fixture();
    for v in f["positive_vectors"].as_object().unwrap().values() {
        assert_eq!(verify(&v["request"]), Ok(v["result"].to_string()));
    }
    let wire = f.to_string();
    for bad in [
        "secret_key",
        "private_key",
        "mnemonic",
        "permit",
        "current_authority",
    ] {
        assert!(!wire.contains(bad));
    }
    if std::env::var("PTLC_PUBLIC_ORIGINAL_RESPONSE_VECTOR_OUTPUT").as_deref() == Ok("1") {
        println!("PUBLIC_ORIGINAL_RESPONSE_VECTORS:{wire}");
    }
}
#[test]
fn original_response_fixture_reproduces_exact_tagged_messages_and_two_flag_results() {
    let f = fixture();
    assert_eq!(generated_fixture(), f);
    assert_eq!(f["positive_vectors"].as_object().unwrap().len(), 22);
    for v in f["positive_vectors"].as_object().unwrap().values() {
        assert_eq!(v["message_digest_hex"], hex(&message(&v["response"])));
        assert_eq!(verify(&v["request"]), Ok(v["result"].to_string()));
        assert_eq!(v["result"].as_object().unwrap().len(), 4);
    }
}
#[test]
fn original_response_valid_signatures_cannot_expand_historical_read_rules() {
    let f = fixture();
    assert_eq!(f["signed_refusal_vectors"].as_object().unwrap().len(), 43);
    for v in f["signed_refusal_vectors"].as_object().unwrap().values() {
        let p = &v["request"];
        let s = &p["root_envelope"];
        let r = &p["response"];
        assert!(math(
            &s["declaration"]["source_context"]["provisioning_root_key_hex"],
            hash(DECLARATION, &s["declaration"]),
            &s["root_signature_hex"]
        ));
        assert!(math(
            &r["source_response_key_hex"],
            message(r),
            &p["response_signature_hex"]
        ));
        assert!(verify(p).is_err());
    }
}
#[test]
fn original_response_every_field_missing_extra_and_typed_mutation_refuses() {
    let p = primary();
    let mut paths = Vec::new();
    objects(&p, Vec::new(), &mut paths);
    for path in paths {
        let keys = target(&mut p.clone(), &path)
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        for f in keys {
            let mut changed = p.clone();
            target(&mut changed, &path)
                .as_object_mut()
                .unwrap()
                .remove(&f);
            assert!(verify(&changed).is_err());
            let mut changed = p.clone();
            target(&mut changed, &path)[&f] = json!([]);
            assert!(verify(&changed).is_err());
        }
        let mut changed = p.clone();
        target(&mut changed, &path)["authorized"] = json!(true);
        assert!(verify(&changed).is_err());
    }
}
#[test]
fn original_response_signature_bytes_curve_and_scalar_bounds_refuse() {
    for path in [
        vec!["root_envelope", "root_signature_hex"],
        vec!["response_signature_hex"],
    ] {
        let mut original = primary();
        let mut sig = &mut original;
        for f in &path {
            sig = &mut sig[*f];
        }
        let b = decode(sig);
        for i in 0..64 {
            let mut changed = b.clone();
            changed[i] ^= 1;
            let mut p = primary();
            set(&mut p, &path, json!(hex(&changed)));
            assert!(verify(&p).is_err());
        }
        for text in [
            "00".repeat(64),
            "ff".repeat(64),
            "00".repeat(63),
            "AB".repeat(64),
        ] {
            let mut p = primary();
            set(&mut p, &path, json!(text));
            assert!(verify(&p).is_err());
        }
    }
}
#[test]
fn original_response_tagged_prehash_refuses_legacy_and_plain_prefix_signatures() {
    let f = fixture();
    for field in [
        "wrong_plain_prefix_signature_hex",
        "wrong_legacy_domain_signature_hex",
    ] {
        let mut p = primary();
        p["response_signature_hex"] = f[field].clone();
        assert!(verify(&p).is_err());
    }
    let legacy: Value =
        serde_json::from_str(include_str!("../fixtures/source_response.json")).unwrap();
    assert!(verify(&legacy["positive_vectors"]["primary"]["request"]).is_err());
}
#[test]
fn original_response_alternate_valid_signatures_change_complete_request_binding() {
    let f = fixture();
    for field in [
        "alternate_root_signature_hex",
        "alternate_response_signature_hex",
    ] {
        let mut p = primary();
        if field == "alternate_root_signature_hex" {
            p["root_envelope"]["root_signature_hex"] = f[field].clone();
        } else {
            p["response_signature_hex"] = f[field].clone();
        }
        assert_eq!(verify(&p), Ok(result(&p).to_string()));
        assert_ne!(result(&p), result(&primary()));
    }
}
#[test]
fn original_response_wire_aliases_duplicates_numbers_depth_and_bounds_refuse() {
    let wire = primary().to_string();
    assert!(verifier::verify_request((wire.clone() + "\n").as_bytes()).is_ok());
    for bad in [
        format!(" {wire}"),
        format!("{wire}\n\n"),
        wire.replace("\"response\":", "\"\\u0072esponse\":"),
        wire.replacen("\"revision\":7", "\"revision\":7,\"revision\":7", 1),
        wire.replacen("\"revision\":7", "\"revision\":7.0", 1),
        wire.replacen("\"revision\":7", "\"revision\":7e0", 1),
        wire.replacen("\"expected_revision\":4", "\"expected_revision\":true", 1),
        "[".repeat(512) + &"]".repeat(512),
        " ".repeat(16385),
    ] {
        assert!(verifier::verify_request(bad.as_bytes()).is_err());
    }
    assert!(verifier::verify_request(&[255]).is_err());
    assert!(verifier::verify_request(b"").is_err());
}
#[test]
fn original_response_fresh_challenge_old_state_and_self_selected_collisions_still_verify() {
    let f = fixture();
    let old = primary();
    for name in [
        "new_challenge",
        "same_id_changed_proposal",
        "same_id_changed_revision",
        "different_id_same_proposal",
        "historical_different_profile",
        "new_head_profile",
        "new_incarnation",
        "alternate_root",
    ] {
        assert!(verify(&f["positive_vectors"][name]["request"]).is_ok());
        assert!(verify(&old).is_ok());
        assert!(verify(&old.clone()).is_ok());
    }
}
