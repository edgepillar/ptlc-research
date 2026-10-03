//! Public fixture conformance and adversarial request-boundary checks.

#[allow(dead_code)]
#[path = "../examples/verify_exchange.rs"]
mod verifier;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn request(leg: usize, bundle: bool) -> Value {
    let terms: Value =
        serde_json::from_str(include_str!("../../tests/fixtures/session_terms.json")).unwrap();
    let rounds: Value =
        serde_json::from_str(include_str!("../fixtures/nonce_rounds.json")).unwrap();
    let vector = &rounds["vectors"][leg];
    let name = vector["leg"].as_str().unwrap();
    let partials = vector["partial_signatures_hex"].as_array().unwrap();
    json!({
        "schema": "ptlc-artifact-verification-v1",
        "kind": if bundle { "bundle" } else { "alice-partial" },
        "context_digest_hex": vector["round_digest_hex"],
        "leg": name,
        "signer_keys_sec1_hex": terms["terms"][name]["signer_keys_sec1_hex"],
        "aggregate_key_xonly_hex": vector["public_key_hex"],
        "taproot_merkle_root_hex": if leg == 0 { terms["terms"]["bitcoin"]["tapleaf_hash_hex"].clone() } else { json!("") },
        "message_hex": vector["message_hex"],
        "adaptor_point_sec1_hex": terms["terms"]["adaptor_point_sec1_hex"],
        "public_nonces_hex": vector["public_nonces_hex"],
        "partial_signatures_hex": if bundle { partials.clone() } else { partials[..1].to_vec() },
        "adaptor_presignature_hex": if bundle { vector["adaptor_presignature_hex"].clone() } else { json!("") }
    })
}

fn verify(value: &Value) -> Result<String, ()> {
    verifier::verify_request(&serde_json::to_vec(value).unwrap())
}

fn changed(value: &Value, field: &str, replacement: Value) {
    let mut mutation = value.clone();
    mutation[field] = replacement;
    assert!(verify(&mutation).is_err(), "accepted mutation of {field}");
}

#[test]
fn verifies_both_legs_and_both_artifact_kinds_with_exact_response_binding() {
    for leg in 0..2 {
        for bundle in [false, true] {
            let input = request(leg, bundle);
            let wire = serde_json::to_vec(&input).unwrap();
            let mut hash = Sha256::new();
            hash.update(b"PTLC/artifact-verification/v1\0");
            hash.update(&wire);
            let digest: String = hash
                .finalize()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            let expected = json!({
                "schema": "ptlc-artifact-verification-result-v1",
                "request_digest_hex": digest,
                "valid": true
            })
            .to_string();
            assert_eq!(verifier::verify_request(&wire), Ok(expected.clone()));
            let mut with_lf = wire;
            with_lf.push(b'\n');
            assert_eq!(verifier::verify_request(&with_lf), Ok(expected));
        }
    }
}

#[test]
fn rejects_noncanonical_duplicate_trailing_and_oversized_json() {
    let input = request(0, true);
    let wire = serde_json::to_string(&input).unwrap();
    let duplicate = format!("{{\"kind\":\"bundle\",{}", &wire[1..]);
    let escaped_duplicate = format!("{{\"k\\u0069nd\":\"bundle\",{}", &wire[1..]);
    for malformed in [
        duplicate,
        escaped_duplicate,
        format!(" {wire}"),
        format!("{wire} "),
        format!("{wire}\n\n"),
        format!("{wire}{{}}"),
        serde_json::to_string_pretty(&input).unwrap(),
        "[".repeat(200) + &"]".repeat(200),
        " ".repeat(verifier::MAX_REQUEST_BYTES + 1),
        "{\"unknown\":\"\u{00e9}\"}".to_owned(),
    ] {
        assert!(verifier::verify_request(malformed.as_bytes()).is_err());
    }
    assert!(verifier::verify_request(&[0xff]).is_err());
}

#[test]
fn rejects_missing_unknown_wrong_type_and_array_shape_fields() {
    for leg in 0..2 {
        for bundle in [false, true] {
            let input = request(leg, bundle);
            for key in input.as_object().unwrap().keys() {
                let mut missing = input.clone();
                missing.as_object_mut().unwrap().remove(key);
                assert!(verify(&missing).is_err());
                for wrong_type in [Value::Null, json!(true), json!(17), json!({})] {
                    changed(&input, key, wrong_type);
                }
            }
            changed(&input, "unknown", json!("synthetic"));
            changed(&input, "schema", json!("wrong-schema"));
            changed(&input, "kind", json!("bob-partial"));
            changed(&input, "leg", json!("unknown-chain"));
            for key in [
                "signer_keys_sec1_hex",
                "public_nonces_hex",
                "partial_signatures_hex",
            ] {
                changed(&input, key, json!([]));
                let mut too_long = input[key].as_array().unwrap().clone();
                too_long.push(too_long[0].clone());
                changed(&input, key, json!(too_long));
                let mut wrong_item = input[key].clone();
                wrong_item[0] = json!(true);
                changed(&input, key, wrong_item);
            }
        }
    }
}

#[test]
fn rejects_noncanonical_hex_and_invalid_curve_or_scalar_encodings() {
    for leg in 0..2 {
        let input = request(leg, true);
        for key in [
            "context_digest_hex",
            "aggregate_key_xonly_hex",
            "message_hex",
            "adaptor_point_sec1_hex",
            "adaptor_presignature_hex",
        ] {
            let original = input[key].as_str().unwrap();
            for replacement in [
                original[2..].to_owned(),
                format!("{original}00"),
                original.to_uppercase(),
                "gg".repeat(original.len() / 2),
            ] {
                changed(&input, key, json!(replacement));
            }
        }
        for key in [
            "signer_keys_sec1_hex",
            "public_nonces_hex",
            "partial_signatures_hex",
        ] {
            for index in 0..2 {
                let mut value = input[key].clone();
                let original = value[index].as_str().unwrap().to_owned();
                value[index] = json!(original.to_uppercase());
                changed(&input, key, value.clone());
                value[index] = json!(original[2..].to_owned());
                changed(&input, key, value.clone());
                value[index] = json!("ff".repeat(original.len() / 2));
                changed(&input, key, value);
            }
        }
        let mut keys = input["signer_keys_sec1_hex"].clone();
        keys[0] = json!(format!("02{}", "ff".repeat(32)));
        changed(&input, "signer_keys_sec1_hex", keys);
        changed(
            &input,
            "adaptor_point_sec1_hex",
            json!(format!("02{}", "ff".repeat(32))),
        );
        let mut nonces = input["public_nonces_hex"].clone();
        nonces[0] = json!(format!(
            "{}{}",
            "00".repeat(33),
            &nonces[0].as_str().unwrap()[66..]
        ));
        changed(&input, "public_nonces_hex", nonces);
    }
}

#[test]
fn rejects_cryptographic_context_partial_and_presignature_mutations() {
    for leg in 0..2 {
        for bundle in [false, true] {
            let input = request(leg, bundle);
            changed(&input, "message_hex", json!("00".repeat(32)));
            changed(&input, "aggregate_key_xonly_hex", json!("00".repeat(32)));
            changed(
                &input,
                "adaptor_point_sec1_hex",
                input["signer_keys_sec1_hex"][0].clone(),
            );
            for key in ["signer_keys_sec1_hex", "public_nonces_hex"] {
                let mut reversed = input[key].as_array().unwrap().clone();
                reversed.reverse();
                changed(&input, key, json!(reversed));
                changed(
                    &input,
                    key,
                    json!([input[key][0].clone(), input[key][0].clone()]),
                );
            }
            let mut partials = input["partial_signatures_hex"].clone();
            partials[0] = json!("00".repeat(32));
            changed(&input, "partial_signatures_hex", partials);
            if bundle {
                let mut partials = input["partial_signatures_hex"].clone();
                partials[1] = json!("00".repeat(32));
                changed(&input, "partial_signatures_hex", partials);
                let mut reversed = input["partial_signatures_hex"].as_array().unwrap().clone();
                reversed.reverse();
                changed(&input, "partial_signatures_hex", json!(reversed));
                changed(
                    &input,
                    "adaptor_presignature_hex",
                    request(1 - leg, true)["adaptor_presignature_hex"].clone(),
                );
                changed(&input, "adaptor_presignature_hex", json!("00".repeat(65)));
                changed(&input, "adaptor_presignature_hex", json!(""));
            } else {
                changed(
                    &input,
                    "adaptor_presignature_hex",
                    request(leg, true)["adaptor_presignature_hex"].clone(),
                );
                changed(
                    &input,
                    "partial_signatures_hex",
                    json!([request(leg, true)["partial_signatures_hex"][1].clone()]),
                );
            }
            changed(&input, "taproot_merkle_root_hex", json!("00".repeat(32)));
            if leg == 0 {
                changed(&input, "taproot_merkle_root_hex", json!(""));
            }
        }
    }
}

#[test]
fn binds_but_does_not_authenticate_the_callers_context_digest() {
    let original = request(0, true);
    let mut rebound = original.clone();
    rebound["context_digest_hex"] = json!("00".repeat(32));
    let first: Value = serde_json::from_str(&verify(&original).unwrap()).unwrap();
    let second: Value = serde_json::from_str(&verify(&rebound).unwrap()).unwrap();
    assert_ne!(first["request_digest_hex"], second["request_digest_hex"]);
}
