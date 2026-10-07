//! Public fixture conformance only. No private keys, secret nonces or signing.
//! The helper reads the declared projection; Python checks the complete corpus.
//! Partial verification is not participant authentication or nonce custody.

use musig2::{
    AggNonce, BinaryEncoding, KeyAggContext, PartialSignature, PubNonce, adaptor, secp::Point,
};
use serde_json::{Value, json};

#[derive(Debug, PartialEq)]
enum Refusal {
    Shape,
    Point,
    BaseKey,
    SigningKey,
    Tweak,
    Partial,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn bytes(value: &Value, width: usize) -> Result<Vec<u8>, Refusal> {
    let text = value.as_str().ok_or(Refusal::Shape)?;
    if text.len() != width * 2
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Refusal::Shape);
    }
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).map_err(|_| Refusal::Shape)
        })
        .collect()
}

fn point(value: &Value) -> Result<Point, Refusal> {
    let encoded = bytes(value, 33)?;
    if !matches!(encoded[0], 2 | 3) {
        return Err(Refusal::Point);
    }
    Point::from_slice(&encoded).map_err(|_| Refusal::Point)
}

// Private to this test binary. This is not an arbitrary peer-wire validator.
struct PublicContext {
    keys: KeyAggContext,
    message: [u8; 32],
    adaptor: Point,
    public: Vec<PubNonce>,
    index: usize,
}

fn public_context(inputs: &Value, selected_leg: &str) -> Result<PublicContext, Refusal> {
    if inputs["operation"] != "musig2-adaptor-partial" {
        return Err(Refusal::Shape);
    }
    let declared = &inputs["key_aggregation"];
    let ordered = declared["ordered_signer_keys_sec1_hex"]
        .as_array()
        .filter(|keys| keys.len() == 2)
        .ok_or(Refusal::Shape)?;
    let parsed = ordered.iter().map(point).collect::<Result<Vec<_>, _>>()?;
    let mut keys = KeyAggContext::new(parsed).map_err(|_| Refusal::Point)?;
    let base: Point = keys.aggregated_pubkey();
    if base.serialize_xonly().as_slice() != bytes(&declared["declared_base_key_xonly_hex"], 32)? {
        return Err(Refusal::BaseKey);
    }
    let tweak = &declared["tweak"];
    match selected_leg {
        "bitcoin" if tweak["kind"] == "taproot-xonly" => {
            let root: [u8; 32] = bytes(&tweak["merkle_root_hex"], 32)?.try_into().unwrap();
            keys = keys.with_taproot_tweak(&root).map_err(|_| Refusal::Tweak)?;
        }
        "zenon" if tweak == &json!({"kind": "none"}) => {}
        _ => return Err(Refusal::Tweak),
    }
    let signing: Point = keys.aggregated_pubkey();
    if signing.serialize_xonly().as_slice()
        != bytes(&declared["declared_signing_key_xonly_hex"], 32)?
    {
        return Err(Refusal::SigningKey);
    }
    let index = inputs["signer_index"]
        .as_u64()
        .filter(|index| *index < 2)
        .ok_or(Refusal::Shape)? as usize;
    let message = bytes(&inputs["message_hex"], 32)?.try_into().unwrap();
    let adaptor = point(&inputs["adaptor_point_sec1_hex"])?;
    let nonces = inputs["public_nonces_hex"]
        .as_array()
        .filter(|nonces| nonces.len() == 2)
        .ok_or(Refusal::Shape)?;
    let public = nonces
        .iter()
        .map(|nonce| PubNonce::from_bytes(&bytes(nonce, 66)?).map_err(|_| Refusal::Point))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(PublicContext {
        keys,
        message,
        adaptor,
        public,
        index,
    })
}

fn verify(context: &PublicContext, supplied: &Value) -> Result<(), Refusal> {
    let partial =
        PartialSignature::from_slice(&bytes(supplied, 32)?).map_err(|_| Refusal::Partial)?;
    let signer: Point = context.keys.get_pubkey(context.index).unwrap();
    adaptor::verify_partial(
        &context.keys,
        partial,
        &AggNonce::sum(&context.public),
        context.adaptor,
        signer,
        &context.public[context.index],
        context.message,
    )
    .map_err(|_| Refusal::Partial)
}

fn packets() -> Vec<Value> {
    let corpus: Value =
        serde_json::from_str(include_str!("../fixtures/public_nonce_intents.json")).unwrap();
    assert_eq!(corpus["schema"], "ptlc-public-nonce-intent-corpus-v1");
    let vectors = corpus["vectors"].as_array().unwrap().clone();
    assert_eq!(vectors.len(), 4);
    vectors
}

fn partial(leg: usize, role: usize) -> Value {
    let corpus: Value =
        serde_json::from_str(include_str!("../fixtures/nonce_rounds.json")).unwrap();
    corpus["vectors"][leg]["partial_signatures_hex"][role].clone()
}

fn input(leg: usize, role: usize) -> Value {
    packets()[leg * 2 + role]["public_inputs"].clone()
}

#[test]
fn four_factory_packets_match_actual_public_backend_and_existing_partials() {
    for (index, packet) in packets().iter().enumerate() {
        let leg = ["bitcoin", "zenon"][index / 2];
        let role = ["alice", "bob"][index % 2];
        assert_eq!(packet["signing_context"]["leg"], leg);
        assert_eq!(packet["signing_context"]["role"], role);
        let context = public_context(&packet["public_inputs"], leg).unwrap();
        assert_eq!(context.index, index % 2);
        assert_eq!(verify(&context, &partial(index / 2, index % 2)), Ok(()));
    }
}

#[test]
fn different_declared_base_key_is_rejected_after_actual_aggregation() {
    for leg in 0..2 {
        let mut inputs = input(leg, 0);
        inputs["key_aggregation"]["declared_base_key_xonly_hex"] = json!("00".repeat(32));
        assert!(matches!(
            public_context(&inputs, ["bitcoin", "zenon"][leg]),
            Err(Refusal::BaseKey)
        ));
    }
}

#[test]
fn different_declared_signing_key_is_rejected_after_selected_tweak() {
    for leg in 0..2 {
        let mut inputs = input(leg, 0);
        inputs["key_aggregation"]["declared_signing_key_xonly_hex"] = json!("00".repeat(32));
        assert!(matches!(
            public_context(&inputs, ["bitcoin", "zenon"][leg]),
            Err(Refusal::SigningKey)
        ));
    }
}

#[test]
fn reversing_ordered_keys_rejects_the_original_declared_base() {
    for leg in 0..2 {
        let mut inputs = input(leg, 0);
        inputs["key_aggregation"]["ordered_signer_keys_sec1_hex"]
            .as_array_mut()
            .unwrap()
            .reverse();
        assert!(matches!(
            public_context(&inputs, ["bitcoin", "zenon"][leg]),
            Err(Refusal::BaseKey)
        ));
    }
}

#[test]
fn changed_taproot_root_rejects_the_original_declared_output() {
    let mut inputs = input(0, 0);
    inputs["key_aggregation"]["tweak"]["merkle_root_hex"] = json!("88".repeat(32));
    assert!(matches!(
        public_context(&inputs, "bitcoin"),
        Err(Refusal::SigningKey)
    ));
}

#[test]
fn each_leg_requires_its_separately_selected_tweak_profile() {
    let mut bitcoin = input(0, 0);
    bitcoin["key_aggregation"]["tweak"] = json!({"kind": "none"});
    assert!(matches!(
        public_context(&bitcoin, "bitcoin"),
        Err(Refusal::Tweak)
    ));
    let mut zenon = input(1, 0);
    zenon["key_aggregation"]["tweak"] = input(0, 0)["key_aggregation"]["tweak"].clone();
    assert!(matches!(
        public_context(&zenon, "zenon"),
        Err(Refusal::Tweak)
    ));
}

#[test]
fn malformed_signer_points_refuse_before_aggregation() {
    for encoded in [
        "02".to_owned() + &"ff".repeat(32),
        "04".to_owned() + &"11".repeat(32),
        "00".repeat(33),
        "02".to_owned() + &"11".repeat(31),
    ] {
        for role in 0..2 {
            let mut inputs = input(0, 0);
            inputs["key_aggregation"]["ordered_signer_keys_sec1_hex"][role] = json!(encoded);
            assert!(public_context(&inputs, "bitcoin").is_err());
        }
    }
}

#[test]
fn malformed_adaptor_points_refuse_public_context_construction() {
    for encoded in [
        "02".to_owned() + &"ff".repeat(32),
        "04".to_owned() + &"11".repeat(32),
        "00".repeat(33),
    ] {
        let mut inputs = input(1, 0);
        inputs["adaptor_point_sec1_hex"] = json!(encoded);
        assert!(matches!(
            public_context(&inputs, "zenon"),
            Err(Refusal::Point)
        ));
    }
}

#[test]
fn malformed_either_full_nonce_component_is_rejected_by_backend_parser() {
    for role in 0..2 {
        for component in 0..2 {
            let original = bytes(&input(0, 0)["public_nonces_hex"][role], 66).unwrap();
            for fault in 0..3 {
                let mut encoded = original.clone();
                let start = component * 33;
                match fault {
                    0 => encoded[start] = 4,
                    1 => encoded[start..start + 33].fill(0),
                    _ => encoded[start + 1..start + 33].fill(255),
                }
                let mut inputs = input(0, 0);
                inputs["public_nonces_hex"][role] = json!(hex(&encoded));
                assert!(matches!(
                    public_context(&inputs, "bitcoin"),
                    Err(Refusal::Point)
                ));
            }
        }
        for width in [65, 67] {
            let mut inputs = input(0, 0);
            inputs["public_nonces_hex"][role] = json!("11".repeat(width));
            assert!(matches!(
                public_context(&inputs, "bitcoin"),
                Err(Refusal::Shape)
            ));
        }
    }
}

#[test]
fn participant_index_requires_an_integer_in_the_fixed_two_party_range() {
    for index in [
        json!(true),
        json!(false),
        json!(-1),
        json!(2),
        json!(0.0),
        json!("0"),
        Value::Null,
    ] {
        let mut inputs = input(0, 0);
        inputs["signer_index"] = index;
        assert!(matches!(
            public_context(&inputs, "bitcoin"),
            Err(Refusal::Shape)
        ));
    }
}

#[test]
fn another_valid_adaptor_passes_point_checks_but_rejects_existing_partial() {
    for leg in 0..2 {
        let mut inputs = input(leg, 0);
        inputs["adaptor_point_sec1_hex"] =
            inputs["key_aggregation"]["ordered_signer_keys_sec1_hex"][0].clone();
        let context = public_context(&inputs, ["bitcoin", "zenon"][leg]).unwrap();
        assert_eq!(verify(&context, &partial(leg, 0)), Err(Refusal::Partial));
    }
}

#[test]
fn changed_supplied_message_passes_shape_but_rejects_existing_partial() {
    for leg in 0..2 {
        let mut inputs = input(leg, 0);
        inputs["message_hex"] = json!("89".repeat(32));
        let context = public_context(&inputs, ["bitcoin", "zenon"][leg]).unwrap();
        assert_eq!(verify(&context, &partial(leg, 0)), Err(Refusal::Partial));
    }
}

#[test]
fn swapping_valid_full_nonces_preserves_sum_but_rejects_each_partial() {
    for leg in 0..2 {
        for role in 0..2 {
            let mut inputs = input(leg, role);
            let original = public_context(&inputs, ["bitcoin", "zenon"][leg]).unwrap();
            inputs["public_nonces_hex"]
                .as_array_mut()
                .unwrap()
                .reverse();
            let changed = public_context(&inputs, ["bitcoin", "zenon"][leg]).unwrap();
            assert_eq!(
                AggNonce::sum(&original.public).to_bytes(),
                AggNonce::sum(&changed.public).to_bytes()
            );
            assert_eq!(verify(&changed, &partial(leg, role)), Err(Refusal::Partial));
        }
    }
}

#[test]
fn another_participant_index_rejects_the_original_participant_partial() {
    for leg in 0..2 {
        for role in 0..2 {
            let mut inputs = input(leg, role);
            inputs["signer_index"] = json!(1 - role);
            let context = public_context(&inputs, ["bitcoin", "zenon"][leg]).unwrap();
            assert_eq!(verify(&context, &partial(leg, role)), Err(Refusal::Partial));
        }
    }
}

#[test]
fn changed_partial_scalar_is_rejected_in_the_original_context() {
    for leg in 0..2 {
        for role in 0..2 {
            let context = public_context(&input(leg, role), ["bitcoin", "zenon"][leg]).unwrap();
            let mut changed = bytes(&partial(leg, role), 32).unwrap();
            changed[31] ^= 1;
            assert_eq!(
                verify(&context, &json!(hex(&changed))),
                Err(Refusal::Partial)
            );
        }
    }
}

#[test]
fn another_self_consistent_key_order_supplies_no_original_participant_approval() {
    for leg in 0..2 {
        let mut inputs = input(leg, 0);
        let declared = &mut inputs["key_aggregation"];
        declared["ordered_signer_keys_sec1_hex"]
            .as_array_mut()
            .unwrap()
            .reverse();
        let ordered = declared["ordered_signer_keys_sec1_hex"]
            .as_array()
            .unwrap()
            .iter()
            .map(|key| point(key).unwrap());
        let mut keys = KeyAggContext::new(ordered).unwrap();
        let base: Point = keys.aggregated_pubkey();
        declared["declared_base_key_xonly_hex"] = json!(hex(&base.serialize_xonly()));
        if leg == 0 {
            keys = keys
                .with_taproot_tweak(
                    &bytes(&declared["tweak"]["merkle_root_hex"], 32)
                        .unwrap()
                        .try_into()
                        .unwrap(),
                )
                .unwrap();
        }
        let signing: Point = keys.aggregated_pubkey();
        declared["declared_signing_key_xonly_hex"] = json!(hex(&signing.serialize_xonly()));
        let context = public_context(&inputs, ["bitcoin", "zenon"][leg]).unwrap();
        assert_eq!(verify(&context, &partial(leg, 0)), Err(Refusal::Partial));
    }
}

#[test]
fn altered_context_with_identical_projection_is_not_revalidated_or_fresh() {
    let mut packet = packets()[0].clone();
    let original = packet["public_inputs"].clone();
    packet["signing_context"]["nonce_round"]["round_id"] = json!("8b".repeat(32));
    assert_eq!(packet["public_inputs"], original);
    // Deliberately no transcript rebuild: this helper establishes public math only.
    let context = public_context(&packet["public_inputs"], "bitcoin").unwrap();
    assert_eq!(verify(&context, &partial(0, 0)), Ok(()));
}
