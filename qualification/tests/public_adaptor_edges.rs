//! Public partials and adaptor boundaries only. No signing or private nonce inputs.
//! A valid aggregate does not authenticate roles or prove each partial is valid.

use musig2::{
    AdaptorSignature, AggNonce, BinaryEncoding, KeyAggContext, PartialSignature, PubNonce, adaptor,
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

// Private to this public test binary. No application verifier interface is added.
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
    let aggregate = AggNonce::sum(&public);
    let partials = std::array::from_fn(|role| {
        PartialSignature::from_slice(&decode(
            row["partial_signatures_hex"][role].as_str().unwrap(),
        ))
        .unwrap()
    });
    PublicSession {
        keys,
        public,
        aggregate,
        adaptor: Point::from_slice(&decode(inputs["adaptor_point_sec1_hex"].as_str().unwrap()))
            .unwrap(),
        message: decode(inputs["message_hex"].as_str().unwrap()),
        partials,
        pre: AdaptorSignature::from_bytes(&decode(
            row["adaptor_presignature_hex"].as_str().unwrap(),
        ))
        .unwrap(),
    }
}

fn verifies(session: &PublicSession, role: usize, partial: PartialSignature, point: Point) -> bool {
    let signer: Point = session.keys.get_pubkey(role).unwrap();
    adaptor::verify_partial(
        &session.keys,
        partial,
        &session.aggregate,
        point,
        signer,
        &session.public[role],
        &session.message,
    )
    .is_ok()
}

fn aggregate(
    session: &PublicSession,
    parts: impl IntoIterator<Item = PartialSignature>,
    point: Point,
) -> Result<AdaptorSignature, musig2::errors::VerifyError> {
    adaptor::aggregate_partial_signatures(
        &session.keys,
        &session.aggregate,
        point,
        parts,
        &session.message,
    )
}

fn final_nonce(session: &PublicSession) -> Point {
    let key: Point = session.keys.aggregated_pubkey();
    let coefficient: MaybeScalar = session.aggregate.nonce_coefficient(key, &session.message);
    session.aggregate.final_nonce(coefficient)
}

fn order() -> Vec<u8> {
    decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
}

fn order_minus_one() -> PartialSignature {
    PartialSignature::from_slice(&decode(
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
    ))
    .unwrap()
}

#[test]
fn original_partials_verify_individually_and_aggregate_to_preserved_public_fixture() {
    for leg in 0..2 {
        let session = original(leg);
        for role in 0..2 {
            assert!(verifies(
                &session,
                role,
                session.partials[role],
                session.adaptor
            ));
        }
        let pre = aggregate(&session, session.partials, session.adaptor).unwrap();
        assert_eq!(pre.to_bytes(), session.pre.to_bytes());
        let key: Point = session.keys.aggregated_pubkey();
        adaptor::verify_single(key, &pre, &session.message, session.adaptor).unwrap();
        let (nonce, _): (MaybePoint, MaybeScalar) = pre.unzip();
        assert_eq!(nonce, MaybePoint::Valid(final_nonce(&session)));
    }
}

#[test]
fn partial_scalar_parser_separates_zero_in_range_order_and_exact_length() {
    let zero = [0; 32];
    assert_eq!(
        PartialSignature::from_slice(&zero).unwrap(),
        MaybeScalar::Zero
    );
    assert_eq!(
        order_minus_one().serialize().as_slice(),
        decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140")
    );
    let one = PartialSignature::one();
    assert_eq!(PartialSignature::from_slice(&one.serialize()).unwrap(), one);
    for invalid in [
        order(),
        decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142"),
        vec![0xff; 32],
    ] {
        assert!(PartialSignature::from_slice(&invalid).is_err());
    }
    for length in [0, 1, 31, 33, 64, 65] {
        assert!(PartialSignature::from_slice(&vec![0; length]).is_err());
    }
}

#[test]
fn decodable_scalar_boundaries_refuse_original_partial_equations() {
    for leg in 0..2 {
        let session = original(leg);
        for role in 0..2 {
            for partial in [
                MaybeScalar::Zero,
                PartialSignature::one(),
                order_minus_one(),
            ] {
                assert_ne!(partial, session.partials[role]);
                assert!(!verifies(&session, role, partial, session.adaptor));
            }
        }
    }
}

#[test]
fn single_changed_missing_and_duplicated_shares_refuse_original_aggregation() {
    for leg in 0..2 {
        let session = original(leg);
        assert!(aggregate(&session, [], session.adaptor).is_err());
        for role in 0..2 {
            assert!(aggregate(&session, [session.partials[role]], session.adaptor).is_err());
            assert!(aggregate(&session, [session.partials[role]; 2], session.adaptor).is_err());
            let mut changed = session.partials;
            changed[role] += PartialSignature::one();
            assert!(!verifies(&session, role, changed[role], session.adaptor));
            assert!(aggregate(&session, changed, session.adaptor).is_err());
        }
    }
}

#[test]
fn reordered_share_collection_preserves_aggregate_but_refuses_wrong_role_equations() {
    for leg in 0..2 {
        let session = original(leg);
        assert_ne!(session.partials[0], session.partials[1]);
        let reversed = [session.partials[1], session.partials[0]];
        for role in 0..2 {
            assert!(!verifies(&session, role, reversed[role], session.adaptor));
        }
        assert_eq!(
            aggregate(&session, reversed, session.adaptor)
                .unwrap()
                .to_bytes(),
            session.pre.to_bytes()
        );
    }
}

#[test]
fn compensated_public_share_changes_preserve_aggregate_but_fail_each_partial() {
    for leg in 0..2 {
        let session = original(leg);
        // Public scalar arithmetic through the pinned backend; no share is signed.
        for delta in [PartialSignature::one(), order_minus_one()] {
            let changed = [session.partials[0] + delta, session.partials[1] - delta];
            assert_eq!(
                changed[0] + changed[1],
                session.partials[0] + session.partials[1]
            );
            for role in 0..2 {
                assert_ne!(changed[role], session.partials[role]);
                assert!(!verifies(&session, role, changed[role], session.adaptor));
            }
            let pre = aggregate(&session, changed, session.adaptor).unwrap();
            assert_eq!(pre.to_bytes(), session.pre.to_bytes());
            let key: Point = session.keys.aggregated_pubkey();
            adaptor::verify_single(key, &pre, &session.message, session.adaptor).unwrap();
        }
    }
}

#[test]
fn valid_cancelling_adaptor_yields_infinity_without_preserving_old_partials() {
    for leg in 0..2 {
        let session = original(leg);
        let nonce = final_nonce(&session);
        let point = Point::from_slice(&(-nonce).serialize()).unwrap();
        let adapted = nonce + point;
        assert_eq!(adapted, MaybePoint::Infinity);
        assert_eq!(adapted.serialize_xonly(), [0; 32]);
        assert!(adapted.has_even_y() && !adapted.has_odd_y());
        for role in 0..2 {
            assert!(!verifies(&session, role, session.partials[role], point));
        }
        assert!(aggregate(&session, session.partials, point).is_err());
        let key: Point = session.keys.aggregated_pubkey();
        assert!(adaptor::verify_single(key, &session.pre, &session.message, point).is_err());
    }
}

#[test]
fn generator_fallback_also_cancels_with_a_valid_adaptor_point() {
    let corpus: Value =
        serde_json::from_str(include_str!("../fixtures/public_nonce_edges.json")).unwrap();
    for leg in 0..2 {
        let mut session = original(leg);
        let cases = corpus["legs"][leg]["cases"].as_array().unwrap();
        let selected: Vec<_> = cases
            .iter()
            .filter(|row| row["name"] == "both_components_cancellation")
            .collect();
        assert_eq!(selected.len(), 1);
        session.public = std::array::from_fn(|role| {
            PubNonce::from_bytes(&decode(
                selected[0]["public_nonces_hex"][role].as_str().unwrap(),
            ))
            .unwrap()
        });
        session.aggregate = AggNonce::sum(&session.public);
        assert_eq!(session.aggregate.R1, MaybePoint::Infinity);
        assert_eq!(session.aggregate.R2, MaybePoint::Infinity);
        let nonce = final_nonce(&session);
        assert_eq!(nonce, Point::generator());
        let point = -Point::generator();
        assert_eq!(nonce + point, MaybePoint::Infinity);
        for role in 0..2 {
            assert!(!verifies(&session, role, session.partials[role], point));
        }
        assert!(aggregate(&session, session.partials, point).is_err());
    }
}

#[test]
fn adaptor_presignature_decoding_does_not_supply_public_verification() {
    for leg in 0..2 {
        let session = original(leg);
        let encoded = session.pre.to_bytes();
        assert_eq!(
            AdaptorSignature::from_bytes(&encoded).unwrap().to_bytes(),
            encoded
        );
        let key: Point = session.keys.aggregated_pubkey();
        let mut infinity = encoded;
        infinity[..33].fill(0);
        let parsed = AdaptorSignature::from_bytes(&infinity).unwrap();
        let (nonce, _): (MaybePoint, MaybeScalar) = parsed.unzip();
        assert_eq!(nonce, MaybePoint::Infinity);
        assert!(adaptor::verify_single(key, &parsed, &session.message, session.adaptor).is_err());
        let mut zero_scalar = encoded;
        zero_scalar[33..].fill(0);
        let parsed = AdaptorSignature::from_bytes(&zero_scalar).unwrap();
        assert!(adaptor::verify_single(key, &parsed, &session.message, session.adaptor).is_err());
        for scalar in [order(), vec![0xff; 32]] {
            let mut invalid = encoded;
            invalid[33..].copy_from_slice(&scalar);
            assert!(AdaptorSignature::from_bytes(&invalid).is_err());
        }
    }
    for length in [0, 1, 32, 64, 66] {
        assert!(AdaptorSignature::from_bytes(&vec![0; length]).is_err());
    }
}
