//! Normal verdict and unavailable-shape partition on public synthetic fixtures.

#[allow(dead_code)]
#[path = "../examples/complete_exchange.rs"]
mod legacy;
#[allow(dead_code)]
#[path = "../examples/verify_observation.rs"]
mod observation;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn request() -> Value {
    let terms: Value =
        serde_json::from_str(include_str!("../../tests/fixtures/session_terms.json")).unwrap();
    let rounds: Value =
        serde_json::from_str(include_str!("../fixtures/nonce_rounds.json")).unwrap();
    let vector = &rounds["vectors"][1];
    json!({
        "schema": "ptlc-completion-request-v1", "kind": "verify-zenon-completion",
        "bitcoin": null, "zenon_signature_hex": vector["signature_hex"],
        "zenon": {
            "schema": "ptlc-artifact-verification-v1", "kind": "bundle", "leg": "zenon",
            "context_digest_hex": vector["round_digest_hex"],
            "signer_keys_sec1_hex": terms["terms"]["zenon"]["signer_keys_sec1_hex"],
            "aggregate_key_xonly_hex": vector["public_key_hex"], "taproot_merkle_root_hex": "",
            "message_hex": vector["message_hex"],
            "adaptor_point_sec1_hex": terms["terms"]["adaptor_point_sec1_hex"],
            "public_nonces_hex": vector["public_nonces_hex"],
            "partial_signatures_hex": vector["partial_signatures_hex"],
            "adaptor_presignature_hex": vector["adaptor_presignature_hex"]
        }
    })
}

fn verdict(value: &Value) -> Value {
    serde_json::from_str(&observation::verify_request(&serde_json::to_vec(value).unwrap()).unwrap())
        .unwrap()
}

fn unavailable(value: &Value) {
    assert!(observation::verify_request(&serde_json::to_vec(value).unwrap()).is_err());
}

#[test]
fn normal_positive_is_exactly_bound_and_never_exports_a_witness_or_bitcoin_signature() {
    let input = request();
    let wire = serde_json::to_vec(&input).unwrap();
    let result = verdict(&input);
    let mut hash = Sha256::new();
    hash.update(b"PTLC/completion/v1\0");
    hash.update(&wire);
    let digest: String = hash
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(
        result,
        json!({"schema": "ptlc-observation-verifier-result-v1", "predicate": "zenon-completion-v1",
               "request_digest_hex": digest, "outcome": "verified"})
    );
    assert_eq!(
        observation::verify_request(&[wire, b"\n".to_vec()].concat()).unwrap(),
        result.to_string()
    );
}

#[test]
fn fixed_width_invalid_final_signatures_are_normal_negatives_while_legacy_fails() {
    let rounds: Value =
        serde_json::from_str(include_str!("../fixtures/nonce_rounds.json")).unwrap();
    for signature in [
        json!("00".repeat(64)),
        json!("ff".repeat(64)),
        rounds["vectors"][0]["signature_hex"].clone(),
    ] {
        let mut input = request();
        input["zenon_signature_hex"] = signature;
        assert!(legacy::verify_request(&serde_json::to_vec(&input).unwrap()).is_err());
        assert_eq!(verdict(&input)["outcome"], "rejected");
    }
}

#[test]
fn fixed_width_invalid_bundle_values_are_normal_negatives() {
    for (field, width) in [
        ("aggregate_key_xonly_hex", 32),
        ("message_hex", 32),
        ("adaptor_point_sec1_hex", 33),
        ("adaptor_presignature_hex", 65),
    ] {
        let mut input = request();
        input["zenon"][field] = json!("00".repeat(width));
        assert_eq!(verdict(&input)["outcome"], "rejected", "{field}");
    }
    for (field, width) in [
        ("signer_keys_sec1_hex", 33),
        ("public_nonces_hex", 66),
        ("partial_signatures_hex", 32),
    ] {
        for role in 0..2 {
            let mut input = request();
            input["zenon"][field][role] = json!("ff".repeat(width));
            assert_eq!(verdict(&input)["outcome"], "rejected", "{field} {role}");
        }
    }
}

#[test]
fn duplicate_or_reordered_signers_nonces_and_partials_are_mathematical_failures() {
    for field in [
        "signer_keys_sec1_hex",
        "public_nonces_hex",
        "partial_signatures_hex",
    ] {
        for duplicate in [false, true] {
            let mut input = request();
            let items = input["zenon"][field].as_array_mut().unwrap();
            if duplicate {
                items[1] = items[0].clone();
            } else {
                items.swap(0, 1);
            }
            assert_eq!(
                verdict(&input)["outcome"],
                "rejected",
                "{field} {duplicate}"
            );
        }
    }
}

#[test]
fn unsupported_modes_schemas_fields_and_types_do_not_emit_negative_verdicts() {
    for (field, value) in [
        ("schema", json!("other-v1")),
        ("kind", json!("recover-bitcoin")),
        ("bitcoin", json!({})),
        ("zenon", Value::Null),
    ] {
        let mut input = request();
        input[field] = value;
        unavailable(&input);
    }
    for field in ["schema", "kind", "zenon", "bitcoin", "zenon_signature_hex"] {
        let mut input = request();
        input.as_object_mut().unwrap().remove(field);
        unavailable(&input);
    }
    let mut input = request();
    input["source"] = json!("synthetic");
    unavailable(&input);
    for (field, value) in [
        ("schema", json!("other-v1")),
        ("kind", json!("alice-partial")),
        ("leg", json!("bitcoin")),
        ("taproot_merkle_root_hex", json!("00".repeat(32))),
    ] {
        let mut input = request();
        input["zenon"][field] = value;
        unavailable(&input);
    }
    let mut input = request();
    input["zenon"]["extra"] = json!(true);
    unavailable(&input);
}

#[test]
fn malformed_hex_widths_and_array_shapes_are_unavailable() {
    for value in [
        Value::Null,
        json!(true),
        json!("ff".repeat(63)),
        json!("GG".repeat(64)),
        json!("FF".repeat(64)),
    ] {
        let mut input = request();
        input["zenon_signature_hex"] = value;
        unavailable(&input);
    }
    for field in [
        "context_digest_hex",
        "aggregate_key_xonly_hex",
        "message_hex",
        "adaptor_point_sec1_hex",
        "adaptor_presignature_hex",
    ] {
        let mut input = request();
        input["zenon"][field] = json!("");
        unavailable(&input);
    }
    for field in [
        "signer_keys_sec1_hex",
        "public_nonces_hex",
        "partial_signatures_hex",
    ] {
        for value in [json!([]), json!(["00"]), json!([null, null]), json!(false)] {
            let mut input = request();
            input["zenon"][field] = value;
            unavailable(&input);
        }
    }
}

#[test]
fn noncanonical_duplicate_oversized_and_nonascii_input_is_unavailable() {
    let wire = serde_json::to_vec(&request()).unwrap();
    for bad in [
        b"".to_vec(),
        b"null".to_vec(),
        vec![0xff],
        [wire.clone(), b"\n\n".to_vec()].concat(),
        [b" ".to_vec(), wire.clone()].concat(),
        vec![b' '; observation::MAX_REQUEST_BYTES + 1],
        serde_json::to_vec_pretty(&request()).unwrap(),
    ] {
        assert!(observation::verify_request(&bad).is_err());
    }
    let duplicate = [
        wire[..wire.len() - 1].to_vec(),
        b",\"kind\":\"verify-zenon-completion\"}".to_vec(),
    ]
    .concat();
    assert!(observation::verify_request(&duplicate).is_err());
    let nested = String::from_utf8(wire)
        .unwrap()
        .replace("\"leg\":\"zenon\"", "\"leg\":\"zenon\",\"leg\":\"zenon\"");
    assert!(observation::verify_request(nested.as_bytes()).is_err());
}

#[test]
fn opaque_context_rebinding_changes_request_digest_without_claiming_source_authentication() {
    let input = request();
    let original = verdict(&input);
    let mut rebound = input.clone();
    rebound["zenon"]["context_digest_hex"] = json!("99".repeat(32));
    let changed = verdict(&rebound);
    assert_eq!(changed["outcome"], "verified");
    assert_ne!(
        changed["request_digest_hex"],
        original["request_digest_hex"]
    );
}
