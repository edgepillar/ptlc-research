//! Public-fixture completion checks. Synthetic signing below creates adversarial
//! test vectors only; the completion executable has no signing-key input.

#[allow(dead_code)]
#[path = "../examples/verify_exchange.rs"]
mod artifact;
#[allow(dead_code)]
#[path = "../examples/complete_exchange.rs"]
mod completion;

use musig2::{
    AdaptorSignature, AggNonce, BinaryEncoding, KeyAggContext, LiftedSignature, PartialSignature,
    SecNonce, adaptor,
    secp::{MaybeScalar, Point, Scalar},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn bytes(value: &Value) -> Vec<u8> {
    value
        .as_str()
        .unwrap()
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn fixtures() -> (Value, Value) {
    (
        serde_json::from_str(include_str!("../../tests/fixtures/session_terms.json")).unwrap(),
        serde_json::from_str(include_str!("../fixtures/nonce_rounds.json")).unwrap(),
    )
}

fn bundle(leg: usize) -> Value {
    let (terms, rounds) = fixtures();
    let vector = &rounds["vectors"][leg];
    let name = vector["leg"].as_str().unwrap();
    json!({
        "schema": "ptlc-artifact-verification-v1", "kind": "bundle",
        "context_digest_hex": vector["round_digest_hex"], "leg": name,
        "signer_keys_sec1_hex": terms["terms"][name]["signer_keys_sec1_hex"],
        "aggregate_key_xonly_hex": vector["public_key_hex"],
        "taproot_merkle_root_hex": if leg == 0 { terms["terms"]["bitcoin"]["tapleaf_hash_hex"].clone() } else { json!("") },
        "message_hex": vector["message_hex"],
        "adaptor_point_sec1_hex": terms["terms"]["adaptor_point_sec1_hex"],
        "public_nonces_hex": vector["public_nonces_hex"],
        "partial_signatures_hex": vector["partial_signatures_hex"],
        "adaptor_presignature_hex": vector["adaptor_presignature_hex"]
    })
}

fn request(recover: bool) -> Value {
    let (_, rounds) = fixtures();
    json!({
        "schema": "ptlc-completion-request-v1",
        "kind": if recover { "recover-bitcoin" } else { "verify-zenon-completion" },
        "zenon": bundle(1), "bitcoin": if recover { bundle(0) } else { Value::Null },
        "zenon_signature_hex": rounds["vectors"][1]["signature_hex"]
    })
}

fn verify(value: &Value) -> Result<String, ()> {
    completion::verify_request(&serde_json::to_vec(value).unwrap())
}

fn valid_bundle(value: &Value) {
    artifact::verify_request(&serde_json::to_vec(value).unwrap()).unwrap();
}

fn ordinary_verify(bundle: &Value, signature: &Value) {
    let key = Point::lift_x(
        bytes(&bundle["aggregate_key_xonly_hex"])
            .try_into()
            .unwrap(),
    )
    .unwrap();
    let final_signature = LiftedSignature::from_bytes(&bytes(signature)).unwrap();
    musig2::verify_single(key, final_signature, bytes(&bundle["message_hex"])).unwrap();
}

// Public fixed scalars/seeds are test inputs, never keys or entropy for funds.
fn alternate_bundle(leg: usize, witness_tag: u8) -> (Value, Value) {
    let scalar = |tag| Scalar::from_slice(&[tag; 32]).unwrap();
    let signing_keys = [scalar(1 + leg as u8 * 2), scalar(2 + leg as u8 * 2)];
    let mut result = bundle(leg);
    let mut context = KeyAggContext::new(signing_keys.map(|key| key.base_point_mul())).unwrap();
    if leg == 0 {
        let root: [u8; 32] = bytes(&result["taproot_merkle_root_hex"])
            .try_into()
            .unwrap();
        context = context.with_taproot_tweak(&root).unwrap();
    }
    let key: Point = context.aggregated_pubkey();
    let message = bytes(&result["message_hex"]);
    let witness = scalar(witness_tag);
    let adaptor_point = witness.base_point_mul();
    let nonces = signing_keys
        .iter()
        .enumerate()
        .map(|(role, signing_key)| {
            SecNonce::generate(
                [91 + role as u8; 32],
                *signing_key,
                key,
                &message,
                b"completion-test-only",
            )
        })
        .collect::<Vec<_>>();
    let public = nonces
        .iter()
        .map(SecNonce::public_nonce)
        .collect::<Vec<_>>();
    let aggregate = AggNonce::sum(&public);
    let partials: Vec<PartialSignature> = nonces
        .into_iter()
        .enumerate()
        .map(|(role, nonce)| {
            adaptor::sign_partial(
                &context,
                signing_keys[role],
                nonce,
                &aggregate,
                adaptor_point,
                &message,
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let pre = adaptor::aggregate_partial_signatures(
        &context,
        &aggregate,
        adaptor_point,
        partials.clone(),
        &message,
    )
    .unwrap();
    let final_signature: LiftedSignature = pre.adapt(witness).unwrap();
    result["public_nonces_hex"] = json!(
        public
            .iter()
            .map(|nonce| hex(&nonce.to_bytes()))
            .collect::<Vec<_>>()
    );
    result["partial_signatures_hex"] = json!(
        partials
            .iter()
            .map(|partial| hex(&partial.serialize()))
            .collect::<Vec<_>>()
    );
    result["adaptor_point_sec1_hex"] = json!(hex(&adaptor_point.serialize()));
    result["adaptor_presignature_hex"] = json!(hex(&pre.to_bytes()));
    let final_value = json!(hex(&final_signature.to_bytes()));
    valid_bundle(&result);
    ordinary_verify(&result, &final_value);
    (result, final_value)
}

#[test]
fn verifies_public_zenon_completion_and_recovers_exact_public_bitcoin_fixture() {
    for recover in [false, true] {
        let input = request(recover);
        let canonical = serde_json::to_vec(&input).unwrap();
        let mut hash = Sha256::new();
        hash.update(b"PTLC/completion/v1\0");
        hash.update(&canonical);
        let (_, rounds) = fixtures();
        let expected = json!({
            "schema": "ptlc-completion-result-v1", "request_digest_hex": hex(&hash.finalize()),
            "valid": true,
            "bitcoin_signature_hex": if recover { rounds["vectors"][0]["signature_hex"].clone() } else { json!("") }
        });
        let response = verify(&input).unwrap();
        assert_eq!(response, expected.to_string());
        let parsed: Value = serde_json::from_str(&response).unwrap();
        assert_eq!(parsed.as_object().unwrap().len(), 4);
        if recover {
            ordinary_verify(&input["bitcoin"], &parsed["bitcoin_signature_hex"]);
        }
        let mut with_lf = canonical;
        with_lf.push(b'\n');
        assert_eq!(completion::verify_request(&with_lf), Ok(response));
    }
}

#[test]
fn rejects_invalid_or_unrelated_final_signatures_before_authorizing_completion() {
    for recover in [false, true] {
        let original = request(recover);
        let original_hex = original["zenon_signature_hex"].as_str().unwrap();
        for replacement in [
            "00".repeat(64),
            "ff".repeat(64),
            original_hex[..126].to_owned(),
            format!("{original_hex}00"),
            original_hex.to_uppercase(),
            format!("{}{}", &original_hex[..64], "00".repeat(32)),
            format!("{}{}", "ff".repeat(32), &original_hex[64..]),
        ] {
            let mut changed = original.clone();
            changed["zenon_signature_hex"] = json!(replacement);
            assert!(verify(&changed).is_err());
        }
        let (unrelated_bundle, unrelated_final) = alternate_bundle(1, 7);
        // It is an ordinary valid signature under the same key and message.
        ordinary_verify(&original["zenon"], &unrelated_final);
        let mut changed = original.clone();
        changed["zenon_signature_hex"] = unrelated_final;
        assert!(verify(&changed).is_err());
        let mut changed = original;
        changed["zenon"] = unrelated_bundle;
        assert!(verify(&changed).is_err());
    }
}

#[test]
fn extraction_alone_is_not_authorization_for_an_invalid_final_signature() {
    let mut input = request(true);
    let pre =
        AdaptorSignature::from_bytes(&bytes(&input["zenon"]["adaptor_presignature_hex"])).unwrap();
    let wrong_witness = Scalar::from_slice(&[8; 32]).unwrap();
    let invalid_final: LiftedSignature = pre.adapt(wrong_witness).unwrap();
    let extracted: MaybeScalar = pre.reveal_secret(&invalid_final).unwrap();
    assert_eq!(extracted, wrong_witness.into());
    let expected_point =
        Point::from_slice(&bytes(&input["zenon"]["adaptor_point_sec1_hex"])).unwrap();
    assert_ne!(extracted.base_point_mul(), expected_point.into());
    let key = Point::lift_x(
        bytes(&input["zenon"]["aggregate_key_xonly_hex"])
            .try_into()
            .unwrap(),
    )
    .unwrap();
    assert!(
        musig2::verify_single(key, invalid_final, bytes(&input["zenon"]["message_hex"])).is_err()
    );
    input["zenon_signature_hex"] = json!(hex(&invalid_final.to_bytes()));
    assert!(verify(&input).is_err());
}

#[test]
fn rejects_valid_bundles_with_different_cross_leg_adaptor_points() {
    let mut input = request(true);
    let (different_bitcoin, _) = alternate_bundle(0, 8);
    valid_bundle(&input["zenon"]);
    valid_bundle(&different_bitcoin);
    input["bitcoin"] = different_bitcoin;
    assert!(verify(&input).is_err());
    // New valid rounds remain usable when both legs really share the same T.
    let (new_bitcoin, _) = alternate_bundle(0, 7);
    input["bitcoin"] = new_bitcoin;
    assert!(verify(&input).is_ok());
}

#[test]
fn rejects_mutated_retained_bundles_and_wrong_roles_or_legs() {
    let original = request(true);
    for leg in ["zenon", "bitcoin"] {
        for field in [
            "message_hex",
            "aggregate_key_xonly_hex",
            "adaptor_point_sec1_hex",
            "adaptor_presignature_hex",
        ] {
            let mut changed = original.clone();
            let width = changed[leg][field].as_str().unwrap().len() / 2;
            changed[leg][field] = json!("00".repeat(width));
            assert!(verify(&changed).is_err());
        }
        for field in [
            "public_nonces_hex",
            "partial_signatures_hex",
            "signer_keys_sec1_hex",
        ] {
            let mut changed = original.clone();
            changed[leg][field].as_array_mut().unwrap().reverse();
            assert!(verify(&changed).is_err());
            let mut changed = original.clone();
            let width = changed[leg][field][0].as_str().unwrap().len() / 2;
            changed[leg][field][0] = json!("00".repeat(width));
            assert!(verify(&changed).is_err());
        }
        for (field, value) in [
            ("kind", json!("alice-partial")),
            (
                "leg",
                json!(if leg == "zenon" { "bitcoin" } else { "zenon" }),
            ),
            ("unknown", json!("synthetic")),
            ("schema", json!("wrong")),
        ] {
            let mut changed = original.clone();
            changed[leg][field] = value;
            assert!(verify(&changed).is_err());
        }
    }
    let mut changed = original;
    changed["bitcoin"]["taproot_merkle_root_hex"] = json!("00".repeat(32));
    assert!(verify(&changed).is_err());
}

#[test]
fn rejects_schema_type_mode_duplicate_and_wire_boundary_errors() {
    for recover in [false, true] {
        let original = request(recover);
        for key in original.as_object().unwrap().keys() {
            let mut missing = original.clone();
            missing.as_object_mut().unwrap().remove(key);
            assert!(verify(&missing).is_err());
            for wrong_type in [json!(true), json!(17), json!([])] {
                let mut changed = original.clone();
                changed[key] = wrong_type;
                assert!(verify(&changed).is_err());
            }
        }
        for (key, value) in [
            ("schema", json!("wrong")),
            ("kind", json!("complete-alice")),
            ("unknown", json!("synthetic")),
            ("bitcoin", if recover { Value::Null } else { bundle(0) }),
            ("zenon", Value::Null),
            ("zenon_signature_hex", Value::Null),
        ] {
            let mut changed = original.clone();
            changed[key] = value;
            assert!(verify(&changed).is_err());
        }
        let wire = original.to_string();
        let duplicate = format!("{{\"kind\":\"recover-bitcoin\",{}", &wire[1..]);
        let nested_duplicate = wire.replacen("\"zenon\":{", "\"zenon\":{\"kind\":\"bundle\",", 1);
        for malformed in [
            duplicate,
            nested_duplicate,
            format!(" {wire}"),
            format!("{wire}\n\n"),
            format!("{wire}{{}}"),
            serde_json::to_string_pretty(&original).unwrap(),
            " ".repeat(completion::MAX_REQUEST_BYTES + 1),
            "[".repeat(200) + &"]".repeat(200),
        ] {
            assert!(completion::verify_request(malformed.as_bytes()).is_err());
        }
    }
    assert!(completion::verify_request(&[0xff]).is_err());
}

#[test]
fn request_digest_binds_all_public_context_without_authenticating_it() {
    let original = request(true);
    let first: Value = serde_json::from_str(&verify(&original).unwrap()).unwrap();
    for leg in ["bitcoin", "zenon"] {
        let mut rebound = original.clone();
        rebound[leg]["context_digest_hex"] = json!("00".repeat(32));
        let second: Value = serde_json::from_str(&verify(&rebound).unwrap()).unwrap();
        assert_ne!(first["request_digest_hex"], second["request_digest_hex"]);
        assert_eq!(
            first["bitcoin_signature_hex"],
            second["bitcoin_signature_hex"]
        );
    }
}
