//! Original public response vectors, using deliberately known synthetic tags.
//! All signing stays in tests; these roles do not establish operational custody.
#[allow(dead_code)]
#[path = "../examples/verify_source_response.rs"]
mod verifier;
use bitcoin::secp256k1::{
    Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey, schnorr::Signature,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
const RESPONSE: &[u8] = b"PTLC/observation-source-response/v1\0";
const REQUEST: &[u8] = b"PTLC/observation-source-response-request/v1\0";
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
const QUERY: &[u8] = b"PTLC/observation-policy-read-query/v1\0";
const SOURCE: &[u8] = b"PTLC/observation-policy-source-context/v1\0";
const CLAIM: &[u8] = b"PTLC/observation-policy-read-claim/v1\0";
fn result(r: &Value) -> Value {
    json!({"schema":"ptlc-observation-source-response-result-v1","request_digest_hex":hex(&hash(REQUEST,r)),"root_signature_valid":true,"issuer_signature_valid":true,"owner_signature_valid":true,"response_signature_valid":true})
}
fn refresh_claim(r: &mut Value) {
    let q = &r["query"];
    let observation = r["claim"]["observation"].as_str().unwrap_or("active");
    r["claim"] = json!({"schema":"ptlc-observation-policy-read-claim-v1","query_digest_hex":hex(&hash(QUERY,q)),"source_context_digest_hex":hex(&hash(SOURCE,&q["source_context"])),"challenge_hex":q["challenge_hex"],"observation":observation,"claimed_checkpoint":if observation == "unavailable" {Value::Null} else {q["expected_checkpoint"].clone()},"assignment_digest_hex":if observation == "absent" || observation == "unavailable" {Value::Null} else {q["governor_signature_request"]["bound_intent"]["governor_assignment_digest_hex"].clone()}});
    refresh_claim_digest(r);
}
fn refresh_claim_digest(r: &mut Value) {
    r["claim_digest_hex"] = json!(hex(&hash(CLAIM, &r["claim"])));
}
fn response(s: &Value, g: &Value, observation: &str) -> Value {
    let current: Value =
        serde_json::from_str(include_str!("../fixtures/current_authority_contract.json")).unwrap();
    let mut query = current["query"].clone();
    query["source_context"] = s["declaration"]["source_context"].clone();
    query["governor_signature_request"] = g.clone();
    query["decoded_scope"]["authority_epoch"] =
        s["declaration"]["governor_profile"]["authority_epoch"].clone();
    let mut r = json!({"schema":"ptlc-observation-source-response-v1","purpose":"source-checkpoint-response","algorithm":"BIP340-SHA256","read_rule":"exact-profile-checkpoint-read-v1","root_declaration_digest_hex":hex(&hash(DECLARATION,&s["declaration"])),"source_response_role":"checkpoint-responder","source_response_key_hex":s["declaration"]["delegated_keys"]["source_response_key_hex"],"source_context":s["declaration"]["source_context"],"query":query,"claim":{"observation":observation},"claim_digest_hex":""});
    refresh_claim(&mut r);
    r
}
fn vector(s: &Value, r: Value, tag: u8) -> Value {
    let request = json!({"schema":"ptlc-observation-source-response-request-v1","root_envelope":s,"response":r,"response_signature_hex":sign(RESPONSE,&r,tag,None)});
    let mut envelope = request.clone();
    envelope["schema"] = json!("ptlc-observation-source-response-envelope-v1");
    json!({"response":r,"message_digest_hex":hex(&hash(RESPONSE,&r)),"request":request,"envelope":envelope,"result":result(&request)})
}
pub fn generated_fixture() -> Value {
    let roots: Value =
        serde_json::from_str(include_str!("../fixtures/source_root_roles.json")).unwrap();
    let governors: Value =
        serde_json::from_str(include_str!("../fixtures/governor_signature.json")).unwrap();
    let s = &roots["positive_vectors"]["primary"]["envelope"];
    let g = &governors["primary"]["request"];
    let d = &s["declaration"];
    for (actual, tag) in [
        (&d["source_context"]["provisioning_root_key_hex"], 96),
        (&d["delegated_keys"]["policy_admin_key_hex"], 97),
        (&d["delegated_keys"]["source_response_key_hex"], 98),
        (&d["delegated_keys"]["governor_issuer_key_hex"], 84),
        (&d["governor_profile"]["owner_auth_key_hex"], 83),
    ] {
        assert_eq!(*actual, public(tag));
    }
    let base = response(s, g, "active");
    let mut positives = serde_json::Map::new();
    positives.insert("primary".into(), vector(s, base.clone(), 98));
    for o in ["revoked", "absent", "unavailable"] {
        positives.insert(o.into(), vector(s, response(s, g, o), 98));
    }
    let mut r = base.clone();
    r["query"]["challenge_hex"] = json!("b5".repeat(32));
    refresh_claim(&mut r);
    positives.insert("new_challenge".into(), vector(s, r, 98));
    for (name, revision) in [("new_checkpoint", 1), ("max_checkpoint", (1_u64 << 53) - 1)] {
        let mut r = base.clone();
        r["query"]["expected_checkpoint"]["revision"] = json!(revision);
        refresh_claim(&mut r);
        positives.insert(name.into(), vector(s, r, 98));
    }
    let mut r = base.clone();
    r["query"]["expected_checkpoint"]["policy_state_digest_hex"] = json!("b4".repeat(32));
    refresh_claim(&mut r);
    positives.insert("new_state_digest".into(), vector(s, r, 98));
    for (name, root_name, governor_name, tag) in [
        ("alternate_root", "alternate_root", "primary", 98),
        ("alternate_admin", "alternate_admin", "primary", 98),
        ("alternate_response", "alternate_response", "primary", 101),
        ("new_incarnation", "new_incarnation", "primary", 98),
        ("new_root_revision", "new_revision", "primary", 98),
        ("alternate_owner", "alternate_owner", "alternate_owner", 98),
        (
            "alternate_issuer",
            "alternate_issuer",
            "alternate_issuer",
            98,
        ),
        ("broader_profile", "broader_caps", "broader_caps", 98),
        ("new_epoch", "new_epoch", "new_epoch", 98),
    ] {
        let s = &roots["positive_vectors"][root_name]["envelope"];
        let g = &governors[governor_name]["request"];
        positives.insert(name.into(), vector(s, response(s, g, "active"), tag));
    }
    let mut refused = serde_json::Map::new();
    let mut add = |name: &str, r: Value, tag: u8| {
        refused.insert(name.into(), vector(s, r, tag));
    };
    for (name, path, value) in [
        (
            "different_root_digest",
            vec!["root_declaration_digest_hex"],
            json!("ee".repeat(32)),
        ),
        (
            "different_source",
            vec!["source_context", "source_incarnation_hex"],
            json!("ee".repeat(32)),
        ),
        (
            "rule_expansion",
            vec!["read_rule"],
            json!("latest-and-allow-all"),
        ),
        (
            "role_expansion",
            vec!["source_response_role"],
            json!("policy-administrator"),
        ),
        (
            "different_query_source",
            vec!["query", "source_context", "source_incarnation_hex"],
            json!("ee".repeat(32)),
        ),
        (
            "different_query_checkpoint",
            vec!["claim", "claimed_checkpoint", "revision"],
            json!(1),
        ),
        (
            "different_query_digest",
            vec!["claim", "query_digest_hex"],
            json!("ee".repeat(32)),
        ),
        (
            "different_claim_source",
            vec!["claim", "source_context_digest_hex"],
            json!("ee".repeat(32)),
        ),
        (
            "different_claim_challenge",
            vec!["claim", "challenge_hex"],
            json!("ee".repeat(32)),
        ),
        (
            "different_assignment",
            vec!["claim", "assignment_digest_hex"],
            json!("ee".repeat(32)),
        ),
        (
            "unknown_observation",
            vec!["claim", "observation"],
            json!("authorized"),
        ),
        (
            "different_claim_digest",
            vec!["claim_digest_hex"],
            json!("ee".repeat(32)),
        ),
        (
            "changed_decoded_scope",
            vec!["query", "decoded_scope", "enrollment_id_hex"],
            json!("ee".repeat(32)),
        ),
        (
            "changed_retained_resource",
            vec!["query", "retained_resource", "session_id"],
            json!("ee".repeat(32)),
        ),
        (
            "scope_exceeds_caps",
            vec!["query", "decoded_scope", "attempt_limit"],
            json!(3),
        ),
    ] {
        let mut r = base.clone();
        *at(&mut r, &path) = value;
        if path[0] == "query" {
            refresh_claim(&mut r);
        } else if path[0] == "claim" {
            refresh_claim_digest(&mut r);
        }
        add(name, r, 98);
    }
    for (name, gname) in [
        ("unselected_issuer", "alternate_issuer"),
        ("unselected_profile", "broader_caps"),
    ] {
        let mut r = base.clone();
        r["query"]["governor_signature_request"] = governors[gname]["request"].clone();
        refresh_claim(&mut r);
        add(name, r, 98);
    }
    for (name, observation) in [
        ("unavailable_asserts_state", "unavailable"),
        ("absent_asserts_assignment", "absent"),
    ] {
        let mut r = base.clone();
        r["claim"]["observation"] = json!(observation);
        refresh_claim_digest(&mut r);
        add(name, r, 98);
    }
    for (name, tag) in [
        ("root_key_claim", 96),
        ("admin_key_claim", 97),
        ("issuer_key_claim", 84),
        ("owner_key_claim", 83),
    ] {
        let mut r = base.clone();
        r["source_response_key_hex"] = public(tag);
        add(name, r, tag);
    }
    let mut zero = base.clone();
    zero["query"]["governor_signature_request"]["issuer_signature_hex"] = json!("00".repeat(64));
    refresh_claim(&mut zero);
    add("zero_issuer_signature", zero, 98);
    let mut zero = base.clone();
    zero["query"]["governor_signature_request"]["owner_signature_hex"] = json!("00".repeat(64));
    refresh_claim(&mut zero);
    add("zero_owner_signature", zero, 98);
    let wrong: serde_json::Map<String, Value> = [
        ("root", 96),
        ("admin", 97),
        ("issuer", 84),
        ("owner", 83),
        ("other", 99),
    ]
    .into_iter()
    .map(|(n, t)| (n.into(), sign(RESPONSE, &base, t, None)))
    .collect();
    json!({"schema":"ptlc-source-response-public-vectors-v1","positive_vectors":positives,"signed_refusal_vectors":refused,"alternate_response_signature_hex":sign(RESPONSE,&base,98,Some([33;32])),"alternate_root_signature_hex":roots["alternate_root_signature_hex"],"wrong_domain_response_signature_hex":sign(DECLARATION,&base,98,None),"wrong_role_signatures":wrong})
}
fn fixture() -> Value {
    serde_json::from_str(include_str!("../fixtures/source_response.json")).unwrap()
}
fn primary() -> Value {
    fixture()["positive_vectors"]["primary"]["request"].clone()
}
fn verify(v: &Value) -> Result<String, ()> {
    verifier::verify_request(&serde_json::to_vec(v).unwrap())
}
fn at<'a>(value: &'a mut Value, path: &[&str]) -> &'a mut Value {
    let mut v = value;
    for p in path {
        v = &mut v[*p];
    }
    v
}
fn decode_hex(v: &Value) -> Vec<u8> {
    v.as_str()
        .unwrap()
        .as_bytes()
        .chunks_exact(2)
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
        .collect()
}
#[test]
fn source_response_public_generator_is_test_only_and_checks_all_primary_roles() {
    let generated = generated_fixture();
    for v in generated["positive_vectors"].as_object().unwrap().values() {
        assert_eq!(verify(&v["request"]), Ok(v["result"].to_string()));
    }
    let wire = generated.to_string();
    for forbidden in [
        "secret_key",
        "private_key",
        "mnemonic",
        "permit",
        "current_authority",
    ] {
        assert!(!wire.contains(forbidden));
    }
    if std::env::var("PTLC_PUBLIC_RESPONSE_VECTOR_OUTPUT").as_deref() == Ok("1") {
        println!("PUBLIC_RESPONSE_VECTORS:{wire}");
    }
}
#[test]
fn source_response_fixture_reproduces_all_four_observations_and_complete_results() {
    let f = fixture();
    assert_eq!(generated_fixture(), f);
    assert_eq!(f["positive_vectors"].as_object().unwrap().len(), 17);
    for v in f["positive_vectors"].as_object().unwrap().values() {
        assert_eq!(verify(&v["request"]), Ok(v["result"].to_string()));
    }
}
#[test]
fn source_response_valid_signatures_do_not_expand_selected_read_bindings() {
    let f = fixture();
    assert_eq!(f["signed_refusal_vectors"].as_object().unwrap().len(), 25);
    for (name, v) in f["signed_refusal_vectors"].as_object().unwrap() {
        let r = &v["request"];
        let k = XOnlyPublicKey::from_slice(&decode_hex(&r["response"]["source_response_key_hex"]))
            .unwrap();
        let s = Signature::from_slice(&decode_hex(&r["response_signature_hex"])).unwrap();
        assert!(
            Secp256k1::verification_only()
                .verify_schnorr(
                    &s,
                    &Message::from_digest(hash(RESPONSE, &r["response"])),
                    &k
                )
                .is_ok()
        );
        assert!(verify(r).is_err(), "accepted signed forbidden {name}");
    }
}
#[test]
fn source_response_all_response_profiles_context_and_root_fields_are_bound() {
    let r = primary();
    for path in [
        vec!["response"],
        vec!["response", "source_context"],
        vec!["response", "query"],
        vec!["response", "query", "source_context"],
        vec!["response", "query", "expected_checkpoint"],
        vec!["response", "query", "governor_signature_request"],
        vec![
            "response",
            "query",
            "governor_signature_request",
            "assignment",
        ],
        vec![
            "response",
            "query",
            "governor_signature_request",
            "assignment",
            "governor_profile",
        ],
        vec![
            "response",
            "query",
            "governor_signature_request",
            "bound_intent",
        ],
        vec!["response", "query", "decoded_scope"],
        vec!["response", "query", "retained_resource"],
        vec!["response", "claim"],
        vec!["response", "claim", "claimed_checkpoint"],
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
fn source_response_exact_fields_types_and_privilege_extras_refuse() {
    let r = primary();
    for path in [
        vec![],
        vec!["response"],
        vec!["response", "source_context"],
        vec!["response", "query"],
        vec!["response", "query", "source_context"],
        vec!["response", "query", "expected_checkpoint"],
        vec!["response", "query", "governor_signature_request"],
        vec![
            "response",
            "query",
            "governor_signature_request",
            "assignment",
        ],
        vec![
            "response",
            "query",
            "governor_signature_request",
            "assignment",
            "governor_profile",
        ],
        vec![
            "response",
            "query",
            "governor_signature_request",
            "bound_intent",
        ],
        vec!["response", "query", "decoded_scope"],
        vec!["response", "query", "retained_resource"],
        vec!["response", "claim"],
        vec!["response", "claim", "claimed_checkpoint"],
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
fn source_response_each_role_wrong_domain_and_all_four_signature_byte_arrays_refuse() {
    let f = fixture();
    let r = primary();
    let mut bad: Vec<Value> = f["wrong_role_signatures"]
        .as_object()
        .unwrap()
        .values()
        .cloned()
        .collect();
    bad.push(f["wrong_domain_response_signature_hex"].clone());
    for sig in bad {
        let mut c = r.clone();
        c["response_signature_hex"] = sig;
        assert!(verify(&c).is_err());
    }
    for path in [
        vec!["response_signature_hex"],
        vec!["root_envelope", "root_signature_hex"],
        vec![
            "response",
            "query",
            "governor_signature_request",
            "issuer_signature_hex",
        ],
        vec![
            "response",
            "query",
            "governor_signature_request",
            "owner_signature_hex",
        ],
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
fn source_response_signature_variants_bind_each_complete_request() {
    let f = fixture();
    let r = primary();
    for path in [
        vec!["response_signature_hex"],
        vec!["root_envelope", "root_signature_hex"],
    ] {
        let mut c = r.clone();
        *at(&mut c, &path) = if path.len() == 1 {
            f["alternate_response_signature_hex"].clone()
        } else {
            f["alternate_root_signature_hex"].clone()
        };
        assert_eq!(verify(&c), Ok(result(&c).to_string()));
        assert_ne!(result(&c), result(&r));
    }
}
#[test]
fn source_response_checkpoint_aliases_canonical_wire_and_bounds_refuse() {
    let r = primary();
    for value in [
        json!(true),
        json!(-1),
        json!(0.0),
        json!("0"),
        json!(1_u64 << 53),
    ] {
        let mut c = r.clone();
        c["response"]["query"]["expected_checkpoint"]["revision"] = value;
        assert!(verify(&c).is_err());
    }
    let wire = r.to_string();
    for bad in [
        String::new(),
        " ".repeat(16385),
        wire.clone() + "\n\n",
        wire.clone() + " ",
        wire.replace("\"response\":", "\"\\u0072esponse\":"),
        wire.replace("\"revision\":0", "\"revision\":0,\"revision\":0"),
        wire.replace("\"revision\":0", "\"revision\":0.0"),
        wire.replace("\"revision\":0", "\"revision\":0e0"),
    ] {
        assert!(verifier::verify_request(bad.as_bytes()).is_err());
    }
    assert!(verifier::verify_request((wire + "\n").as_bytes()).is_ok());
}
#[test]
fn source_response_old_responses_cannot_follow_changed_complete_selections() {
    let f = fixture();
    let old = primary();
    for v in f["positive_vectors"].as_object().unwrap().values() {
        if v["response"] == old["response"] {
            continue;
        }
        let mut c = v["request"].clone();
        c["response_signature_hex"] = old["response_signature_hex"].clone();
        assert!(verify(&c).is_err());
    }
}
#[test]
fn source_response_self_selected_and_restored_replay_remain_historical_math() {
    let f = fixture();
    let old = primary();
    for name in [
        "alternate_root",
        "alternate_admin",
        "new_incarnation",
        "new_root_revision",
        "new_checkpoint",
        "revoked",
    ] {
        assert!(verify(&f["positive_vectors"][name]["request"]).is_ok());
        assert!(verify(&old).is_ok());
        assert!(verify(&old.clone()).is_ok());
    }
    assert_eq!(result(&old).as_object().unwrap().len(), 6);
}
