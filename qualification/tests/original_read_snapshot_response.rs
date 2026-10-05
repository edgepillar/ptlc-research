//! Synthetic fixtures over owned-store samples. No application signing API.
#[allow(dead_code)]
#[path = "../examples/verify_original_read_response.rs"]
mod verifier;
use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const DECLARATION: &[u8] = b"PTLC/observation-source-root-declaration/v1\0";
const REQUEST: &[u8] = b"PTLC/observation-original-read-response-request/v1\0";
const ROWS: &[u8] = b"PTLC/offline-local-original-record-lineage/v1\0";
const STATE: &[u8] = b"PTLC/offline-local-policy-read-state/v1\0";
const TAG: &[u8] = b"PTLC/observation-original-read-response/v1";

fn hex(b: &[u8]) -> String {
    b.iter().map(|v| format!("{v:02x}")).collect()
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
fn sign(digest: [u8; 32], tag: u8) -> Value {
    // These known synthetic test values are never emitted as signer material.
    let secp = Secp256k1::new();
    let key = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[tag; 32]).unwrap());
    json!(hex(secp
        .sign_schnorr_no_aux_rand(&Message::from_digest(digest), &key)
        .as_ref()))
}
fn inputs() -> Value {
    serde_json::from_str(include_str!(
        "../fixtures/original_read_snapshot_inputs.json"
    ))
    .unwrap()
}
fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../fixtures/original_read_snapshot_response.json"
    ))
    .unwrap()
}
fn verify(v: &Value) -> Result<String, ()> {
    verifier::verify_request(v.to_string().as_bytes())
}
fn generated() -> Value {
    let mut f = inputs();
    f["schema"] = json!("ptlc-original-read-snapshot-response-public-vectors-v1");
    for group in ["positive_vectors", "counterclaim_vectors"] {
        for v in f[group].as_object_mut().unwrap().values_mut() {
            v.as_object_mut().unwrap().remove("record_material");
            let root = &v["root_declaration"];
            let response = &v["response"];
            let root_envelope = json!({"schema":"ptlc-observation-source-root-envelope-v1",
                "declaration":root,"root_signature_hex":sign(hash(DECLARATION,root),96)});
            let p = json!({"schema":"ptlc-observation-original-read-response-request-v1",
                "root_envelope":root_envelope,"response":response,"response_signature_hex":sign(message(response),98)});
            let result = json!({"schema":"ptlc-observation-original-read-response-result-v1",
                "request_digest_hex":hex(&hash(REQUEST,&p)),"root_signature_valid":true,"response_signature_valid":true});
            let mut envelope = p.clone();
            envelope["schema"] = json!("ptlc-observation-original-read-response-envelope-v1");
            v["request"] = p;
            v["envelope"] = envelope;
            v["result"] = result;
        }
    }
    f
}

#[test]
fn snapshot_response_generator_is_test_only_and_emits_public_material() {
    let f = generated();
    for group in ["positive_vectors", "counterclaim_vectors"] {
        for v in f[group].as_object().unwrap().values() {
            assert_eq!(verify(&v["request"]), Ok(v["result"].to_string() + "\n"));
        }
    }
    let wire = f.to_string();
    for forbidden in [
        "secret_key",
        "private_key",
        "mnemonic",
        "permit",
        "current_authority",
    ] {
        assert!(!wire.contains(forbidden));
    }
    if std::env::var("PTLC_PUBLIC_SNAPSHOT_RESPONSE_VECTOR_OUTPUT").as_deref() == Ok("1") {
        println!("PUBLIC_SNAPSHOT_RESPONSE_VECTORS:{wire}");
    }
}

#[test]
fn snapshot_response_fixture_reproduces_ten_samples_and_six_counterclaims() {
    let f = fixture();
    assert_eq!(generated(), f);
    assert_eq!(f["positive_vectors"].as_object().unwrap().len(), 10);
    assert_eq!(f["counterclaim_vectors"].as_object().unwrap().len(), 6);
    for group in ["positive_vectors", "counterclaim_vectors"] {
        for v in f[group].as_object().unwrap().values() {
            assert_eq!(v["message_digest_hex"], hex(&message(&v["response"])));
            assert!(v["request"].to_string().len() <= 16384);
            assert_eq!(v["result"].as_object().unwrap().len(), 4);
            assert_eq!(verify(&v["request"]), Ok(v["result"].to_string() + "\n"));
        }
    }
}

#[test]
fn snapshot_response_retained_rows_commit_to_both_selected_heads() {
    let f = inputs();
    for v in f["positive_vectors"].as_object().unwrap().values() {
        let rows = &v["record_material"];
        let q = &v["response"]["query"];
        assert_eq!(
            q["expected_record_checkpoint"]["record_lineage_digest_hex"],
            hex(&hash(ROWS, rows))
        );
        assert_eq!(
            q["expected_record_checkpoint"]["event_sequence"],
            rows["events"].as_array().unwrap().len()
        );
        let source = &rows["source"];
        let state = json!({"root_declaration":rows["root_declaration"],"revision":source["revision"],
            "profile_hex":source["profile_hex"],"active":source["active"],"mode":source["mode"]});
        assert_eq!(
            q["expected_checkpoint"]["policy_state_digest_hex"],
            hex(&hash(STATE, &state))
        );
        assert_eq!(q["expected_checkpoint"]["revision"], source["revision"]);
    }
}

#[test]
fn snapshot_response_old_signatures_bind_actual_record_fields_and_both_heads() {
    let f = fixture();
    for v in f["positive_vectors"].as_object().unwrap().values() {
        let paths = [
            vec!["response", "claim", "observation"],
            vec![
                "response",
                "query",
                "original_operation",
                "proposal_digest_hex",
            ],
            vec![
                "response",
                "query",
                "original_operation",
                "governor_profile",
                "authority_epoch",
            ],
            vec![
                "response",
                "query",
                "expected_checkpoint",
                "policy_state_digest_hex",
            ],
            vec![
                "response",
                "query",
                "expected_record_checkpoint",
                "record_lineage_digest_hex",
            ],
            vec!["response", "query", "challenge_hex"],
            vec!["root_envelope", "declaration", "declaration_revision"],
        ];
        for path in paths {
            let mut p = v["request"].clone();
            let mut target = &mut p;
            for field in path {
                target = &mut target[field];
            }
            *target = match target {
                Value::Number(n) => json!(n.as_u64().unwrap() + 1),
                _ => json!("08".repeat(32)),
            };
            assert!(verify(&p).is_err());
        }
    }
}

#[test]
fn snapshot_response_all_signature_bytes_refuse_for_samples_and_counterclaims() {
    let f = fixture();
    for group in ["positive_vectors", "counterclaim_vectors"] {
        for v in f[group].as_object().unwrap().values() {
            for root in [false, true] {
                for byte in 0..64 {
                    let mut p = v["request"].clone();
                    let field = if root {
                        &mut p["root_envelope"]["root_signature_hex"]
                    } else {
                        &mut p["response_signature_hex"]
                    };
                    let mut s = field.as_str().unwrap().to_owned().into_bytes();
                    s[byte * 2] = if s[byte * 2] == b'0' { b'1' } else { b'0' };
                    *field = json!(String::from_utf8(s).unwrap());
                    assert!(verify(&p).is_err());
                }
            }
        }
    }
}

#[test]
fn snapshot_response_valid_counterclaims_do_not_prove_store_truth() {
    let f = fixture();
    for v in f["counterclaim_vectors"].as_object().unwrap().values() {
        let actual = &f["positive_vectors"][v["actual_scenario"].as_str().unwrap()];
        assert_ne!(v["response"], actual["response"]);
        assert_ne!(
            v["result"]["request_digest_hex"],
            actual["result"]["request_digest_hex"]
        );
        assert_eq!(verify(&v["request"]), Ok(v["result"].to_string() + "\n"));
    }
}
