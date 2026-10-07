//! Public-only parser and aggregate boundary controls. No signing or nonce generation.
//! Transcript shape, partial validity, participant identity and custody are separate.

use musig2::{
    AggNonce, BinaryEncoding, KeyAggContext, PartialSignature, PubNonce, adaptor,
    secp::{MaybePoint, MaybeScalar, Point},
};
use serde_json::Value;

fn decode(encoded: &str) -> Vec<u8> {
    assert!(encoded.len().is_multiple_of(2));
    assert!(
        encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
    encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn corpus() -> Value {
    let value: Value =
        serde_json::from_str(include_str!("../fixtures/public_nonce_edges.json")).unwrap();
    assert_eq!(value["schema"], "ptlc-public-nonce-edge-corpus-v1");
    assert_eq!(value["legs"].as_array().unwrap().len(), 2);
    value
}

fn case(leg: usize, name: &str) -> Value {
    let value = corpus();
    assert_eq!(value["legs"][leg]["leg"], ["bitcoin", "zenon"][leg]);
    let cases = value["legs"][leg]["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 8);
    let selected: Vec<_> = cases.iter().filter(|row| row["name"] == name).collect();
    assert_eq!(selected.len(), 1);
    selected[0].clone()
}

fn parse_pair(value: &Value) -> [PubNonce; 2] {
    std::array::from_fn(|role| {
        PubNonce::from_bytes(&decode(value["public_nonces_hex"][role].as_str().unwrap())).unwrap()
    })
}

fn original_inputs(leg: usize) -> Value {
    let value: Value =
        serde_json::from_str(include_str!("../fixtures/public_nonce_intents.json")).unwrap();
    value["vectors"][leg * 2]["public_inputs"].clone()
}

fn original_keys(inputs: &Value, leg: usize) -> KeyAggContext {
    let declared = &inputs["key_aggregation"];
    let ordered = declared["ordered_signer_keys_sec1_hex"].as_array().unwrap();
    assert_eq!(ordered.len(), 2);
    let points: Vec<_> = ordered
        .iter()
        .map(|value| Point::from_slice(&decode(value.as_str().unwrap())).unwrap())
        .collect();
    let mut keys = KeyAggContext::new(points).unwrap();
    let base: Point = keys.aggregated_pubkey();
    assert_eq!(
        base.serialize_xonly().as_slice(),
        decode(declared["declared_base_key_xonly_hex"].as_str().unwrap())
    );
    if leg == 0 {
        assert_eq!(declared["tweak"]["kind"], "taproot-xonly");
        let root: [u8; 32] = decode(declared["tweak"]["merkle_root_hex"].as_str().unwrap())
            .try_into()
            .unwrap();
        keys = keys.with_taproot_tweak(&root).unwrap();
    } else {
        assert_eq!(declared["tweak"], serde_json::json!({"kind": "none"}));
    }
    let signing: Point = keys.aggregated_pubkey();
    assert_eq!(
        signing.serialize_xonly().as_slice(),
        decode(declared["declared_signing_key_xonly_hex"].as_str().unwrap())
    );
    keys
}

fn verify_original_partials(leg: usize, pair: &[PubNonce; 2], expected: bool) {
    let inputs = original_inputs(leg);
    let keys = original_keys(&inputs, leg);
    let rounds: Value =
        serde_json::from_str(include_str!("../fixtures/nonce_rounds.json")).unwrap();
    let message = decode(inputs["message_hex"].as_str().unwrap());
    let adaptor =
        Point::from_slice(&decode(inputs["adaptor_point_sec1_hex"].as_str().unwrap())).unwrap();
    let aggregate = AggNonce::sum(pair);
    for role in 0..2 {
        let partial = PartialSignature::from_slice(&decode(
            rounds["vectors"][leg]["partial_signatures_hex"][role]
                .as_str()
                .unwrap(),
        ))
        .unwrap();
        let signer: Point = keys.get_pubkey(role).unwrap();
        assert_eq!(
            adaptor::verify_partial(
                &keys,
                partial,
                &aggregate,
                adaptor,
                signer,
                &pair[role],
                &message
            )
            .is_ok(),
            expected
        );
    }
}

fn checked_case(leg: usize, name: &str) -> [PubNonce; 2] {
    let value = case(leg, name);
    let pair = parse_pair(&value);
    let aggregate = AggNonce::sum(&pair);
    assert_eq!(
        aggregate.R1 == MaybePoint::Infinity,
        value["aggregate_components_infinity"][0].as_bool().unwrap()
    );
    assert_eq!(
        aggregate.R2 == MaybePoint::Infinity,
        value["aggregate_components_infinity"][1].as_bool().unwrap()
    );
    assert_eq!(
        AggNonce::from_bytes(&aggregate.to_bytes()).unwrap(),
        aggregate
    );
    verify_original_partials(leg, &pair, name == "baseline");
    pair
}

fn noncurve_x() -> Vec<u8> {
    // Reuse the existing public BIP340 row under its recorded CC0-1.0 license.
    let value: Value = serde_json::from_str(include_str!(
        "../../tests/fixtures/bip340_public_vectors.json"
    ))
    .unwrap();
    let selected: Vec<_> = value["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["index"] == 5)
        .collect();
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0]["valid"], false);
    let x = decode(selected[0]["public_key_hex"].as_str().unwrap());
    let field = decode("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");
    assert_eq!(x.len(), 32);
    assert!(x.iter().any(|byte| *byte != 0) && x < field);
    x
}

#[test]
fn baseline_pairs_parse_and_verify_original_partial_fixtures() {
    for leg in 0..2 {
        let pair = checked_case(leg, "baseline");
        let inputs = original_inputs(leg);
        for role in 0..2 {
            assert_eq!(
                pair[role].to_bytes().as_slice(),
                decode(inputs["public_nonces_hex"][role].as_str().unwrap())
            );
        }
    }
}

#[test]
fn equal_full_public_nonces_parse_without_protocol_reflection_policy() {
    for leg in 0..2 {
        let pair = checked_case(leg, "equal_full");
        assert_eq!(pair[0], pair[1]);
        assert_eq!(case(leg, "equal_full")["python_round_accepts"], false);
    }
}

#[test]
fn shared_first_components_parse_but_reject_original_partials() {
    for leg in 0..2 {
        let pair = checked_case(leg, "shared_first_component");
        assert_ne!(pair[0], pair[1]);
        assert_eq!(pair[0].R1, pair[1].R1);
        assert_ne!(pair[0].R2, pair[1].R2);
    }
}

#[test]
fn shared_second_components_parse_but_reject_original_partials() {
    for leg in 0..2 {
        let pair = checked_case(leg, "shared_second_component");
        assert_ne!(pair[0], pair[1]);
        assert_ne!(pair[0].R1, pair[1].R1);
        assert_eq!(pair[0].R2, pair[1].R2);
    }
}

#[test]
fn repeated_components_in_one_public_nonce_parse_but_reject_original_partials() {
    for leg in 0..2 {
        let pair = checked_case(leg, "repeated_components_in_alice_nonce");
        assert_eq!(pair[0].R1, pair[0].R2);
        assert_ne!(pair[0], pair[1]);
    }
}

#[test]
fn first_component_cancellation_preserves_valid_public_nonce_parsing() {
    for leg in 0..2 {
        let pair = checked_case(leg, "first_component_cancellation");
        assert_eq!(pair[1].R1, -pair[0].R1);
        assert_eq!(&AggNonce::sum(&pair).to_bytes()[..33], &[0; 33]);
    }
}

#[test]
fn second_component_cancellation_preserves_valid_public_nonce_parsing() {
    for leg in 0..2 {
        let pair = checked_case(leg, "second_component_cancellation");
        assert_eq!(pair[1].R2, -pair[0].R2);
        assert_eq!(&AggNonce::sum(&pair).to_bytes()[33..], &[0; 33]);
    }
}

#[test]
fn both_component_cancellation_uses_generator_fallback_without_individual_infinity() {
    for leg in 0..2 {
        let pair = checked_case(leg, "both_components_cancellation");
        assert_eq!(pair[1].R1, -pair[0].R1);
        assert_eq!(pair[1].R2, -pair[0].R2);
        let aggregate = AggNonce::sum(&pair);
        assert_eq!(aggregate.to_bytes(), [0; 66]);
        assert!(PubNonce::from_bytes(&aggregate.to_bytes()).is_err());
        let inputs = original_inputs(leg);
        let keys = original_keys(&inputs, leg);
        let message = decode(inputs["message_hex"].as_str().unwrap());
        let key: Point = keys.aggregated_pubkey();
        let coefficient: MaybeScalar = aggregate.nonce_coefficient(key, message);
        let final_nonce: Point = aggregate.final_nonce(coefficient);
        assert_eq!(final_nonce, Point::generator());
    }
}

#[test]
fn in_field_noncurve_public_nonce_components_refuse_backend_parsing() {
    let x = noncurve_x();
    for leg in 0..2 {
        for prefix in [2, 3] {
            for role in 0..2 {
                for component in 0..2 {
                    let baseline = parse_pair(&case(leg, "baseline"));
                    let mut nonce = baseline[role].to_bytes();
                    let at = component * 33;
                    nonce[at] = prefix;
                    nonce[at + 1..at + 33].copy_from_slice(&x);
                    assert!(PubNonce::from_bytes(&nonce).is_err());
                }
            }
        }
    }
}

#[test]
fn in_field_noncurve_signer_and_adaptor_points_refuse_backend_parsing() {
    let x = noncurve_x();
    for leg in 0..2 {
        for prefix in [2, 3] {
            let mut invalid = vec![prefix];
            invalid.extend_from_slice(&x);
            let mut inputs = original_inputs(leg);
            for role in 0..2 {
                inputs["key_aggregation"]["ordered_signer_keys_sec1_hex"][role] = serde_json::json!(
                    invalid
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<String>()
                );
                let ordered = inputs["key_aggregation"]["ordered_signer_keys_sec1_hex"]
                    .as_array()
                    .unwrap();
                assert!(
                    ordered
                        .iter()
                        .map(|value| Point::from_slice(&decode(value.as_str().unwrap())))
                        .collect::<Result<Vec<_>, _>>()
                        .is_err()
                );
                inputs = original_inputs(leg);
            }
            assert!(Point::from_slice(&invalid).is_err());
        }
    }
}

#[test]
fn individual_infinity_encoding_is_not_aggregate_infinity() {
    for leg in 0..2 {
        for role in 0..2 {
            for component in 0..2 {
                let baseline = parse_pair(&case(leg, "baseline"));
                let mut nonce = baseline[role].to_bytes();
                let at = component * 33;
                nonce[at..at + 33].fill(0);
                assert!(PubNonce::from_bytes(&nonce).is_err());
                assert!(AggNonce::from_bytes(&nonce).is_ok());
            }
        }
    }
}
