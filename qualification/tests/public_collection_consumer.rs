//! Existing public consumer conformance only. No signing or private inputs.
//! Test requests select the fixed complete factory corpus before scalar mutation.

use musig2::{
    AdaptorSignature, AggNonce, BinaryEncoding, KeyAggContext, PartialSignature, PubNonce, adaptor,
    secp::{MaybeScalar, Point},
};
#[allow(dead_code)]
#[path = "../examples/verify_exchange.rs"]
mod verifier;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

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

// Private to this test binary; it is not a peer-wire or application interface.
struct PublicSession {
    keys: KeyAggContext,
    public: [PubNonce; 2],
    aggregate: AggNonce,
    adaptor: Point,
    message: Vec<u8>,
    partials: [PartialSignature; 2],
    pre: AdaptorSignature,
}

fn original(leg: usize) -> PublicSession {
    let intents: Value =
        serde_json::from_str(include_str!("../fixtures/public_nonce_intents.json")).unwrap();
    let rounds: Value =
        serde_json::from_str(include_str!("../fixtures/nonce_rounds.json")).unwrap();
    let inputs = &intents["vectors"][leg * 2]["public_inputs"];
    let row = &rounds["vectors"][leg];
    assert_eq!(row["leg"], ["bitcoin", "zenon"][leg]);
    for role in 0..2 {
        let selected = &intents["vectors"][leg * 2 + role]["public_inputs"];
        assert_eq!(selected["signer_index"], role);
        assert_eq!(selected["operation"], "musig2-adaptor-partial");
        for name in [
            "key_aggregation",
            "public_nonces_hex",
            "adaptor_point_sec1_hex",
            "message_hex",
        ] {
            assert_eq!(selected[name], inputs[name]);
        }
    }
    let declared = &inputs["key_aggregation"];
    let points: Vec<_> = declared["ordered_signer_keys_sec1_hex"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| Point::from_slice(&decode(value.as_str().unwrap())).unwrap())
        .collect();
    assert_eq!(points.len(), 2);
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
    assert!(keys.get_pubkey::<Point>(2).is_none());
    let signing: Point = keys.aggregated_pubkey();
    assert_eq!(
        signing.serialize_xonly().as_slice(),
        decode(declared["declared_signing_key_xonly_hex"].as_str().unwrap())
    );
    assert_eq!(
        row["public_key_hex"],
        declared["declared_signing_key_xonly_hex"]
    );
    assert_eq!(row["message_hex"], inputs["message_hex"]);
    assert_eq!(row["public_nonces_hex"], inputs["public_nonces_hex"]);
    let public = std::array::from_fn(|role| {
        PubNonce::from_bytes(&decode(row["public_nonces_hex"][role].as_str().unwrap())).unwrap()
    });
    let partials = std::array::from_fn(|role| {
        PartialSignature::from_slice(&decode(
            row["partial_signatures_hex"][role].as_str().unwrap(),
        ))
        .unwrap()
    });
    let session = PublicSession {
        keys,
        aggregate: AggNonce::sum(&public),
        public,
        adaptor: Point::from_slice(&decode(inputs["adaptor_point_sec1_hex"].as_str().unwrap()))
            .unwrap(),
        message: decode(inputs["message_hex"].as_str().unwrap()),
        partials,
        pre: AdaptorSignature::from_bytes(&decode(
            row["adaptor_presignature_hex"].as_str().unwrap(),
        ))
        .unwrap(),
    };
    for role in 0..2 {
        assert!(verifies(&session, role, session.partials[role]));
    }
    same_aggregate(&session, &session.partials);
    session
}

fn verifies(session: &PublicSession, role: usize, partial: PartialSignature) -> bool {
    let signer: Point = session.keys.get_pubkey(role).unwrap();
    adaptor::verify_partial(
        &session.keys,
        partial,
        &session.aggregate,
        session.adaptor,
        signer,
        &session.public[role],
        &session.message,
    )
    .is_ok()
}

fn aggregate(
    session: &PublicSession,
    parts: &[PartialSignature],
) -> Result<AdaptorSignature, musig2::errors::VerifyError> {
    adaptor::aggregate_partial_signatures(
        &session.keys,
        &session.aggregate,
        session.adaptor,
        parts.iter().copied(),
        &session.message,
    )
}

fn same_aggregate(session: &PublicSession, parts: &[PartialSignature]) {
    let supplied: PartialSignature = parts.iter().copied().sum();
    assert_eq!(supplied, session.partials[0] + session.partials[1]);
    let pre = aggregate(session, parts).unwrap();
    assert_eq!(pre.to_bytes(), session.pre.to_bytes());
    let key: Point = session.keys.aggregated_pubkey();
    adaptor::verify_single(key, &pre, &session.message, session.adaptor).unwrap();
}

fn order_minus_one() -> PartialSignature {
    PartialSignature::from_slice(&decode(
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
    ))
    .unwrap()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

// A selected local fixture projection, not a new consumer or context validator.
// Python retains complete staged reconstruction; the verifier binds an opaque digest.
fn request(leg: usize, bundle: bool) -> Value {
    let intents: Value =
        serde_json::from_str(include_str!("../fixtures/public_nonce_intents.json")).unwrap();
    let rounds: Value =
        serde_json::from_str(include_str!("../fixtures/nonce_rounds.json")).unwrap();
    let selected = &intents["vectors"][leg * 2 + 1];
    let context = &selected["signing_context"];
    let inputs = &selected["public_inputs"];
    let declared = &inputs["key_aggregation"];
    let name = ["bitcoin", "zenon"][leg];
    assert_eq!(context["leg"], name);
    assert_eq!(context["role"], "bob");
    assert_eq!(context["purpose"], format!("{name}-claim-partial"));
    assert_eq!(context["stage"], "signing-context");
    assert_eq!(inputs["signer_index"], 1);
    assert_eq!(
        inputs["public_nonces_hex"],
        json!([
            context["nonce_round"]["public_nonces"]["alice"],
            context["nonce_round"]["public_nonces"]["bob"]
        ])
    );
    let terms = if leg == 0 {
        &context["binding"]["terms"]
    } else {
        &context["binding"]["bitcoin"]["terms"]
    };
    assert_eq!(
        declared["ordered_signer_keys_sec1_hex"],
        terms[name]["signer_keys_sec1_hex"]
    );
    assert_eq!(
        inputs["adaptor_point_sec1_hex"],
        terms["adaptor_point_sec1_hex"]
    );
    assert_eq!(
        inputs["message_hex"],
        context["binding"]["binding"][if leg == 0 {
            "claim_sighash_hex"
        } else {
            "message_hex"
        }]
    );
    assert_eq!(
        declared["declared_signing_key_xonly_hex"],
        terms[name][if leg == 0 {
            "output_key_xonly_hex"
        } else {
            "aggregate_key_xonly_hex"
        }]
    );
    let root = if leg == 0 {
        terms[name]["tapleaf_hash_hex"].clone()
    } else {
        json!("")
    };
    if leg == 0 {
        assert_eq!(declared["tweak"]["merkle_root_hex"], root);
    }
    let mut digest = Sha256::new();
    digest.update(b"PTLC/offline-transcript/v1\0signing-context\0");
    digest.update(serde_json::to_vec(context).unwrap());
    let row = &rounds["vectors"][leg];
    let original = row["partial_signatures_hex"].as_array().unwrap();
    json!({
        "schema": "ptlc-artifact-verification-v1",
        "kind": if bundle { "bundle" } else { "alice-partial" },
        "context_digest_hex": hex(&digest.finalize()),
        "leg": name,
        "signer_keys_sec1_hex": declared["ordered_signer_keys_sec1_hex"],
        "aggregate_key_xonly_hex": declared["declared_signing_key_xonly_hex"],
        "taproot_merkle_root_hex": root,
        "message_hex": inputs["message_hex"],
        "adaptor_point_sec1_hex": inputs["adaptor_point_sec1_hex"],
        "public_nonces_hex": inputs["public_nonces_hex"],
        "partial_signatures_hex": if bundle { original.clone() } else { original[..1].to_vec() },
        "adaptor_presignature_hex": if bundle { row["adaptor_presignature_hex"].clone() } else { json!("") }
    })
}

fn verify(input: &Value) -> Result<String, ()> {
    verifier::verify_request(&serde_json::to_vec(input).unwrap())
}

fn refuse(leg: usize, bundle: bool, parts: &[PartialSignature]) {
    let mut input = request(leg, bundle);
    assert!(verify(&input).is_ok());
    input["partial_signatures_hex"] = json!(
        parts
            .iter()
            .map(|part| hex(&part.serialize()))
            .collect::<Vec<_>>()
    );
    assert!(verify(&input).is_err());
}

#[test]
fn collection_consumer_original_selected_requests_bind_exact_receipts() {
    for leg in 0..2 {
        original(leg);
        for bundle in [false, true] {
            let input = request(leg, bundle);
            let mut digest = Sha256::new();
            digest.update(b"PTLC/artifact-verification/v1\0");
            digest.update(serde_json::to_vec(&input).unwrap());
            let expected = json!({
                "schema": "ptlc-artifact-verification-result-v1",
                "request_digest_hex": hex(&digest.finalize()),
                "valid": true
            })
            .to_string();
            assert_eq!(verify(&input), Ok(expected));
        }
    }
}

#[test]
fn collection_consumer_combined_singleton_refuses_bundle_and_alice_only() {
    for leg in 0..2 {
        let session = original(leg);
        let combined = session.partials[0] + session.partials[1];
        same_aggregate(&session, &[combined]);
        for role in 0..2 {
            assert!(!verifies(&session, role, combined));
        }
        for bundle in [false, true] {
            refuse(leg, bundle, &[combined]);
        }
    }
}

#[test]
fn collection_consumer_split_three_items_refuse_unchanged_bundle() {
    for leg in 0..2 {
        let session = original(leg);
        for role in 0..2 {
            for piece in [PartialSignature::one(), order_minus_one()] {
                let remainder = session.partials[role] - piece;
                let parts = [piece, remainder, session.partials[1 - role]];
                assert!(!verifies(&session, role, piece));
                assert!(!verifies(&session, role, remainder));
                same_aggregate(&session, &parts);
                refuse(leg, true, &parts);
            }
        }
    }
}

#[test]
fn collection_consumer_zero_padding_refuses_unchanged_bundle() {
    for leg in 0..2 {
        let session = original(leg);
        let parts = [session.partials[0], session.partials[1], MaybeScalar::Zero];
        same_aggregate(&session, &parts);
        refuse(leg, true, &parts);
    }
}

#[test]
fn collection_consumer_cancelling_pair_refuses_unchanged_bundle() {
    for leg in 0..2 {
        let session = original(leg);
        let parts = [
            session.partials[0],
            session.partials[1],
            PartialSignature::one(),
            order_minus_one(),
        ];
        same_aggregate(&session, &parts);
        refuse(leg, true, &parts);
    }
}

#[test]
fn collection_consumer_two_compensated_items_refuse_original_role_equations() {
    for leg in 0..2 {
        let session = original(leg);
        for offset in [PartialSignature::one(), order_minus_one()] {
            let parts = [session.partials[0] + offset, session.partials[1] - offset];
            for role in 0..2 {
                assert!(!verifies(&session, role, parts[role]));
            }
            same_aggregate(&session, &parts);
            refuse(leg, true, &parts);
        }
    }
}

#[test]
fn collection_consumer_combined_and_zero_refuse_in_both_original_orders() {
    for leg in 0..2 {
        let session = original(leg);
        let combined = session.partials[0] + session.partials[1];
        for parts in [[combined, MaybeScalar::Zero], [MaybeScalar::Zero, combined]] {
            for role in 0..2 {
                assert!(!verifies(&session, role, parts[role]));
            }
            same_aggregate(&session, &parts);
            refuse(leg, true, &parts);
        }
    }
}
