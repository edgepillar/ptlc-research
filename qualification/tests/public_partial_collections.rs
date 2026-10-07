//! Public scalar collection conformance only. No private keys, nonces or signing.
//! The aggregate equation supplies no collection arity or role association proof.

use musig2::{
    AdaptorSignature, AggNonce, BinaryEncoding, KeyAggContext, PartialSignature, PubNonce, adaptor,
    secp::{MaybeScalar, Point},
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

#[test]
fn combined_singleton_preserves_aggregate_but_fails_each_original_role() {
    for leg in 0..2 {
        let session = original(leg);
        let combined = session.partials[0] + session.partials[1];
        for role in 0..2 {
            assert_ne!(combined, session.partials[role]);
            assert!(!verifies(&session, role, combined));
        }
        same_aggregate(&session, &[combined]);
    }
}

#[test]
fn split_original_partial_preserves_three_item_aggregate_without_role_validity() {
    for leg in 0..2 {
        let session = original(leg);
        for role in 0..2 {
            for piece in [PartialSignature::one(), order_minus_one()] {
                let remainder = session.partials[role] - piece;
                assert!(!verifies(&session, role, piece));
                assert!(!verifies(&session, role, remainder));
                assert!(verifies(&session, 1 - role, session.partials[1 - role]));
                same_aggregate(&session, &[piece, remainder, session.partials[1 - role]]);
            }
        }
    }
}

#[test]
fn zero_padding_preserves_original_role_partials_and_three_item_aggregate() {
    for leg in 0..2 {
        let session = original(leg);
        for role in 0..2 {
            assert!(verifies(&session, role, session.partials[role]));
            assert!(!verifies(&session, role, MaybeScalar::Zero));
        }
        same_aggregate(
            &session,
            &[session.partials[0], session.partials[1], MaybeScalar::Zero],
        );
    }
}

#[test]
fn cancelling_pair_preserves_four_item_aggregate_without_extra_role_validity() {
    for leg in 0..2 {
        let session = original(leg);
        let one = PartialSignature::one();
        let opposite = order_minus_one();
        assert_eq!(one + opposite, MaybeScalar::Zero);
        for role in 0..2 {
            assert!(verifies(&session, role, session.partials[role]));
            assert!(!verifies(&session, role, one));
            assert!(!verifies(&session, role, opposite));
        }
        same_aggregate(
            &session,
            &[session.partials[0], session.partials[1], one, opposite],
        );
    }
}

#[test]
fn changed_totals_refuse_selected_one_three_and_four_item_collections() {
    for leg in 0..2 {
        let session = original(leg);
        let one = PartialSignature::one();
        let total = session.partials[0] + session.partials[1];
        let collections = [
            vec![total + one],
            vec![session.partials[0], session.partials[1], one],
            vec![session.partials[0], session.partials[1], one, one],
        ];
        for collection in collections {
            let supplied: PartialSignature = collection.iter().copied().sum();
            assert_ne!(supplied, total);
            assert!(aggregate(&session, &collection).is_err());
        }
    }
}
