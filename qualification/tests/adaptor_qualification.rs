//! Public fixed inputs are deliberate test vectors, never wallet material.
//! Existing candidate APIs perform all scalar and point operations.

use musig2::{
    AdaptorSignature, AggNonce, BinaryEncoding, KeyAggContext, LiftedSignature, PartialSignature,
    SecNonce, adaptor,
    secp::{MaybePoint, MaybeScalar, Point, Scalar},
    secp256k1::{Secp256k1, XOnlyPublicKey, schnorr::Signature as IndependentSignature},
};
use schnorr_fun::{
    Message, Signature as FunSignature,
    adaptor::{Adaptor, EncryptedSign},
    fun::{Point as FunPoint, Scalar as FunScalar, marker::EvenY},
};
use sha2::Sha256;

fn scalar(tag: u8) -> Scalar {
    Scalar::from_slice(&[tag; 32]).expect("fixed nonzero in-range synthetic scalar")
}

fn fun_scalar(tag: u8) -> FunScalar {
    FunScalar::from_bytes([tag; 32]).expect("fixed nonzero in-range synthetic scalar")
}

fn final_verifiers(public_key: [u8; 32], message: &[u8], signature: &[u8]) -> [bool; 3] {
    let Some(bytes) = <[u8; 64]>::try_from(signature).ok() else {
        return [false; 3];
    };
    let native_sig = IndependentSignature::from_byte_array(bytes);
    let native = XOnlyPublicKey::from_byte_array(public_key).is_ok_and(|key| {
        Secp256k1::verification_only()
            .verify_schnorr(&native_sig, message, &key)
            .is_ok()
    });
    let musig = Point::lift_x(public_key)
        .ok()
        .zip(LiftedSignature::from_bytes(&bytes).ok())
        .is_some_and(|(key, sig)| musig2::verify_single(key, sig, message).is_ok());
    let schnorr = schnorr_fun::Schnorr::<Sha256>::verify_only();
    let fun = FunPoint::<EvenY>::from_xonly_bytes(public_key)
        .zip(FunSignature::from_bytes(bytes))
        .is_some_and(|(key, sig)| schnorr.verify(&key, Message::raw(message), &sig));
    [native, musig, fun]
}

fn decode_hex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0);
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn public_fixture_vector(
    id: &str,
    key: [u8; 32],
    message: [u8; 32],
    signature: [u8; 64],
) -> serde_json::Value {
    assert_eq!(final_verifiers(key, &message, &signature), [true; 3]);
    serde_json::json!({
        "id": id,
        "public_key_hex": encode_hex(&key),
        "message_hex": encode_hex(&message),
        "signature_hex": encode_hex(&signature),
        "valid": true
    })
}

#[test]
fn completed_public_signature_fixture_matches_pinned_candidates() {
    let key = scalar(1);
    let witness = scalar(2);
    let message = [3; 32];
    let pre = adaptor::sign_solo(key, message, [4; 32], witness.base_point_mul());
    let complete: LiftedSignature = pre.adapt(witness).unwrap();
    let musig_vector = public_fixture_vector(
        "musig2-single",
        key.base_point_mul().serialize_xonly(),
        message,
        complete.to_bytes(),
    );

    let schnorr = schnorr_fun::new_with_deterministic_nonces::<Sha256>();
    let keypair = schnorr.new_keypair(fun_scalar(1));
    let witness = fun_scalar(2);
    let pre = schnorr.encrypted_sign(
        &keypair,
        &schnorr.encryption_key_for(&witness),
        Message::raw(&message),
    );
    let complete = schnorr.decrypt_signature(witness, pre);
    let fun_vector = public_fixture_vector(
        "schnorr-fun-single",
        keypair.public_key().to_xonly_bytes(),
        message,
        complete.to_bytes(),
    );

    let witness = scalar(7);
    let point = witness.base_point_mul();
    let btc_message = [0x42; 32];
    let znn_message: [u8; 32] =
        decode_hex("e357d6597d0149f0adb2ab0f0d7dff932412e2f55fd9b94bb9301c8ccf9df974")
            .try_into()
            .unwrap();
    let (btc_key, btc_pre) = two_party_pre_signature([1, 2], [11, 12], btc_message, point);
    let (znn_key, znn_pre) = two_party_pre_signature([3, 4], [13, 14], znn_message, point);
    let znn_complete: LiftedSignature = znn_pre.adapt(witness).unwrap();
    let extracted = znn_pre.reveal_secret::<MaybeScalar>(&znn_complete).unwrap();
    let btc_complete: LiftedSignature = btc_pre.adapt(extracted).unwrap();
    let corpus = serde_json::json!({
        "schema": "ptlc-bip340-completed-signatures-v1",
        "note": "Public verification fields only. Synthetic offline qualification; no Bitcoin transaction or live-chain claim.",
        "vectors": [
            musig_vector,
            fun_vector,
            public_fixture_vector("musig2-aggregate-btc-synthetic", btc_key.serialize_xonly(), btc_message, btc_complete.to_bytes()),
            public_fixture_vector("musig2-aggregate-znn-contract-digest", znn_key.serialize_xonly(), znn_message, znn_complete.to_bytes())
        ]
    });
    let expected: serde_json::Value =
        serde_json::from_str(include_str!("../fixtures/completed_signatures.json")).unwrap();
    assert_eq!(corpus, expected, "pinned public signature fixture changed");
}

#[test]
fn all_public_official_bip340_vectors_match_all_three_verifiers() {
    let corpus: serde_json::Value = serde_json::from_str(include_str!(
        "../../tests/fixtures/bip340_public_vectors.json"
    ))
    .unwrap();
    let vectors = corpus["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 19);
    let mut lengths = std::collections::BTreeSet::new();
    for vector in vectors {
        let public_key: [u8; 32] = decode_hex(vector["public_key_hex"].as_str().unwrap())
            .try_into()
            .unwrap();
        let message = decode_hex(vector["message_hex"].as_str().unwrap());
        let signature = decode_hex(vector["signature_hex"].as_str().unwrap());
        let expected = vector["valid"].as_bool().unwrap();
        lengths.insert(message.len());
        assert_eq!(
            final_verifiers(public_key, &message, &signature),
            [expected; 3],
            "official vector {}: {}",
            vector["index"],
            vector["comment"]
        );
    }
    assert_eq!(lengths, [0, 1, 17, 32, 100].into());
}

#[test]
fn musig_single_signer_round_trips_cover_signer_and_adapted_nonce_parities() {
    let mut coverage = [[false; 2]; 2];
    for case in 1..=32_u8 {
        let key = scalar(case);
        let witness = scalar(case + 64);
        let point = witness.base_point_mul();
        let message = [case + 32; 32];
        let pre = adaptor::sign_solo(key, message, [case + 128; 32], point);
        let (pre_nonce, _): (MaybePoint, MaybeScalar) = pre.unzip();
        let adapted_nonce = (pre_nonce + point).into_option().unwrap();
        coverage[usize::from(!key.base_point_mul().has_even_y())]
            [usize::from(!adapted_nonce.has_even_y())] = true;
        adaptor::verify_single(key.base_point_mul(), &pre, message, point).unwrap();
        let complete: LiftedSignature = pre.adapt(witness).unwrap();
        assert_eq!(
            final_verifiers(
                key.base_point_mul().serialize_xonly(),
                &message,
                &complete.to_bytes()
            ),
            [true; 3]
        );
        assert_eq!(
            pre.reveal_secret::<MaybeScalar>(&complete),
            Some(witness.into())
        );
        assert_eq!(AdaptorSignature::from_bytes(&pre.to_bytes()).unwrap(), pre);
    }
    assert_eq!(
        coverage, [[true; 2]; 2],
        "all four parity combinations must execute"
    );
}

#[test]
fn schnorr_fun_round_trips_cover_signer_and_nonce_negation_parities() {
    let schnorr = schnorr_fun::new_with_deterministic_nonces::<Sha256>();
    let mut coverage = [[false; 2]; 2];
    for case in 1..=32_u8 {
        let keypair = schnorr.new_keypair(fun_scalar(case));
        let witness = fun_scalar(case + 64);
        let point = schnorr.encryption_key_for(&witness);
        let message = [case + 32; 32];
        let pre = schnorr.encrypted_sign(&keypair, &point, Message::raw(&message));
        coverage[usize::from(!scalar(case).base_point_mul().has_even_y())]
            [usize::from(pre.needs_negation)] = true;
        assert!(schnorr.verify_encrypted_signature(
            &keypair.public_key(),
            &point,
            Message::raw(&message),
            &pre
        ));
        let complete = schnorr.decrypt_signature(witness, pre.clone());
        assert_eq!(
            final_verifiers(
                keypair.public_key().to_xonly_bytes(),
                &message,
                &complete.to_bytes()
            ),
            [true; 3]
        );
        let extracted = schnorr
            .recover_decryption_key(&point, &pre, &complete)
            .unwrap();
        assert_eq!(extracted.to_bytes(), witness.to_bytes());
    }
    assert_eq!(
        coverage, [[true; 2]; 2],
        "all four parity combinations must execute"
    );
}

#[test]
fn musig_pre_signature_rejects_wrong_message_key_and_adaptor() {
    let key = scalar(1);
    let point = scalar(2).base_point_mul();
    let pre = adaptor::sign_solo(key, [3; 32], [4; 32], point);
    assert!(adaptor::verify_single(key.base_point_mul(), &pre, [5; 32], point).is_err());
    assert!(adaptor::verify_single(scalar(6).base_point_mul(), &pre, [3; 32], point).is_err());
    assert!(
        adaptor::verify_single(
            key.base_point_mul(),
            &pre,
            [3; 32],
            scalar(7).base_point_mul()
        )
        .is_err()
    );
}

#[test]
fn schnorr_fun_pre_signature_rejects_wrong_message_key_adaptor_and_parity() {
    let schnorr = schnorr_fun::new_with_deterministic_nonces::<Sha256>();
    let keypair = schnorr.new_keypair(fun_scalar(1));
    let point = schnorr.encryption_key_for(&fun_scalar(2));
    let pre = schnorr.encrypted_sign(&keypair, &point, Message::raw(&[3; 32]));
    assert!(!schnorr.verify_encrypted_signature(
        &keypair.public_key(),
        &point,
        Message::raw(&[5; 32]),
        &pre
    ));
    assert!(!schnorr.verify_encrypted_signature(
        &schnorr.new_keypair(fun_scalar(6)).public_key(),
        &point,
        Message::raw(&[3; 32]),
        &pre
    ));
    assert!(!schnorr.verify_encrypted_signature(
        &keypair.public_key(),
        &schnorr.encryption_key_for(&fun_scalar(7)),
        Message::raw(&[3; 32]),
        &pre
    ));
    let mut wrong_parity = pre;
    wrong_parity.needs_negation = !wrong_parity.needs_negation;
    assert!(!schnorr.verify_encrypted_signature(
        &keypair.public_key(),
        &point,
        Message::raw(&[3; 32]),
        &wrong_parity
    ));
}

#[test]
fn wrong_witness_completion_fails_final_verification_for_both_candidates() {
    let key = scalar(1);
    let point = scalar(2).base_point_mul();
    let pre = adaptor::sign_solo(key, [3; 32], [4; 32], point);
    let wrong: LiftedSignature = pre.adapt(scalar(5)).unwrap();
    assert_eq!(
        final_verifiers(
            key.base_point_mul().serialize_xonly(),
            &[3; 32],
            &wrong.to_bytes()
        ),
        [false; 3]
    );
    // This API checks the pair's algebra, not the expected adaptor point/message.
    // An extracted value is therefore not sufficient authorization to proceed.
    let extracted_from_invalid = pre.reveal_secret::<MaybeScalar>(&wrong).unwrap();
    assert_eq!(extracted_from_invalid, scalar(5).into());
    assert_ne!(extracted_from_invalid.base_point_mul(), point.into());

    let schnorr = schnorr_fun::new_with_deterministic_nonces::<Sha256>();
    let keypair = schnorr.new_keypair(fun_scalar(1));
    let point = schnorr.encryption_key_for(&fun_scalar(2));
    let pre = schnorr.encrypted_sign(&keypair, &point, Message::raw(&[3; 32]));
    let wrong = schnorr.decrypt_signature(fun_scalar(5), pre.clone());
    assert_eq!(
        final_verifiers(
            keypair.public_key().to_xonly_bytes(),
            &[3; 32],
            &wrong.to_bytes()
        ),
        [false; 3]
    );
    assert!(
        schnorr
            .recover_decryption_key(&point, &pre, &wrong)
            .is_none()
    );
}

#[test]
fn unrelated_final_signatures_do_not_reveal_the_committed_witness() {
    let key = scalar(1);
    let point = scalar(2).base_point_mul();
    let pre = adaptor::sign_solo(key, [3; 32], [4; 32], point);
    let unrelated: LiftedSignature = musig2::sign_solo(key, [5; 32], [6; 32]);
    assert!(pre.reveal_secret::<MaybeScalar>(&unrelated).is_none());

    let schnorr = schnorr_fun::new_with_deterministic_nonces::<Sha256>();
    let keypair = schnorr.new_keypair(fun_scalar(1));
    let point = schnorr.encryption_key_for(&fun_scalar(2));
    let pre = schnorr.encrypted_sign(&keypair, &point, Message::raw(&[3; 32]));
    let unrelated = schnorr.sign(&keypair, Message::raw(&[5; 32]));
    assert!(
        schnorr
            .recover_decryption_key(&point, &pre, &unrelated)
            .is_none()
    );
}

#[test]
fn uncompleted_pre_signatures_fail_consensus_signature_verification() {
    let key = scalar(1);
    let pre = adaptor::sign_solo(key, [3; 32], [4; 32], scalar(2).base_point_mul());
    let pre_bytes = pre.to_bytes();
    assert_eq!(
        final_verifiers(
            key.base_point_mul().serialize_xonly(),
            &[3; 32],
            &pre_bytes[1..]
        ),
        [false; 3]
    );
    let schnorr = schnorr_fun::new_with_deterministic_nonces::<Sha256>();
    let keypair = schnorr.new_keypair(fun_scalar(1));
    let point = schnorr.encryption_key_for(&fun_scalar(2));
    let pre = schnorr.encrypted_sign(&keypair, &point, Message::raw(&[3; 32]));
    let incomplete = FunSignature {
        R: pre.R,
        s: pre.s_hat,
    };
    assert_eq!(
        final_verifiers(
            keypair.public_key().to_xonly_bytes(),
            &[3; 32],
            &incomplete.to_bytes()
        ),
        [false; 3]
    );
}

#[test]
fn final_signature_boundaries_reject_malformed_lengths_and_out_of_range_values() {
    let key = scalar(1).base_point_mul().serialize_xonly();
    for bad in [vec![0xff; 64], vec![0; 63], vec![0; 65], vec![]] {
        assert_eq!(final_verifiers(key, &[3; 32], &bad), [false; 3]);
    }
    assert!(LiftedSignature::from_bytes(&[0xff; 64]).is_err());
    assert!(FunSignature::from_bytes([0xff; 64]).is_none());
    assert!(AdaptorSignature::from_bytes(&[0xff; 65]).is_err());
    assert!(AdaptorSignature::from_bytes(&[0; 64]).is_err());
    assert!(FunPoint::<EvenY>::from_xonly_bytes([0xff; 32]).is_none());
    let invalid_scalar: Option<FunScalar> = FunScalar::from_bytes([0xff; 32]);
    assert!(invalid_scalar.is_none());
}

#[test]
fn changed_final_signature_byte_is_rejected_by_all_verifiers() {
    let key = scalar(1);
    let pre = adaptor::sign_solo(key, [3; 32], [4; 32], scalar(2).base_point_mul());
    let complete: LiftedSignature = pre.adapt(scalar(2)).unwrap();
    let mut bytes = complete.to_bytes();
    bytes[63] ^= 1;
    assert_eq!(
        final_verifiers(key.base_point_mul().serialize_xonly(), &[3; 32], &bytes),
        [false; 3]
    );
}

#[test]
fn musig_nonce_seed_reuse_constraint_is_observable_without_secret_recovery() {
    // Deliberately unsafe caller inputs in a regression-only test.
    // Reusing this tuple under different adaptor points preserves the pre-nonce.
    let a = adaptor::sign_solo(scalar(1), [3; 32], [4; 32], scalar(2).base_point_mul());
    let b = adaptor::sign_solo(scalar(1), [3; 32], [4; 32], scalar(5).base_point_mul());
    assert_eq!(&a.to_bytes()[..33], &b.to_bytes()[..33]);
    let fresh = adaptor::sign_solo(scalar(1), [3; 32], [6; 32], scalar(5).base_point_mul());
    assert_ne!(&a.to_bytes()[..33], &fresh.to_bytes()[..33]);
}

fn two_party_pre_signature(
    key_tags: [u8; 2],
    nonce_tags: [u8; 2],
    message: [u8; 32],
    adaptor_point: Point,
) -> (Point, AdaptorSignature) {
    let keys = key_tags.map(scalar);
    let public_keys = keys.map(|key| key.base_point_mul());
    let context = KeyAggContext::new(public_keys).unwrap();
    let aggregate_key: Point = context.aggregated_pubkey();
    let secret_nonces = [0, 1].map(|i| {
        SecNonce::generate(
            [nonce_tags[i]; 32],
            keys[i],
            aggregate_key,
            message,
            adaptor_point.serialize(),
        )
    });
    let public_nonces = secret_nonces.each_ref().map(SecNonce::public_nonce);
    let aggregate_nonce = AggNonce::sum(&public_nonces);
    let partials: Vec<PartialSignature> = secret_nonces
        .into_iter()
        .enumerate()
        .map(|(i, nonce)| {
            let partial = adaptor::sign_partial(
                &context,
                keys[i],
                nonce,
                &aggregate_nonce,
                adaptor_point,
                message,
            )
            .unwrap();
            adaptor::verify_partial(
                &context,
                partial,
                &aggregate_nonce,
                adaptor_point,
                public_keys[i],
                &public_nonces[i],
                message,
            )
            .unwrap();
            assert!(
                adaptor::verify_partial(
                    &context,
                    partial,
                    &aggregate_nonce,
                    adaptor_point,
                    public_keys[i],
                    &public_nonces[i],
                    [0xff; 32]
                )
                .is_err()
            );
            assert!(
                adaptor::verify_partial(
                    &context,
                    MaybeScalar::Zero,
                    &aggregate_nonce,
                    adaptor_point,
                    public_keys[i],
                    &public_nonces[i],
                    message
                )
                .is_err()
            );
            partial
        })
        .collect();
    let pre = adaptor::aggregate_partial_signatures(
        &context,
        &aggregate_nonce,
        adaptor_point,
        partials,
        message,
    )
    .unwrap();
    adaptor::verify_single(aggregate_key, &pre, message, adaptor_point).unwrap();
    (aggregate_key, pre)
}

#[test]
fn two_distinct_aggregate_keys_link_two_messages_through_one_witness() {
    // Cryptographic linkage only: no transaction, funding, clock, or chain model.
    let witness = scalar(7);
    let point = witness.base_point_mul();
    let btc_message = [0x42; 32];
    // SHA3-256(id32 || destination20), independently checked by the parent harness.
    // This checks a concrete contract digest, not full account-block serialization.
    let znn_message: [u8; 32] =
        decode_hex("e357d6597d0149f0adb2ab0f0d7dff932412e2f55fd9b94bb9301c8ccf9df974")
            .try_into()
            .unwrap();
    let (btc_key, btc_pre) = two_party_pre_signature([1, 2], [11, 12], btc_message, point);
    let (znn_key, znn_pre) = two_party_pre_signature([3, 4], [13, 14], znn_message, point);
    assert_ne!(btc_key, znn_key);
    // Both verified pre-signatures exist before the first completed signature.
    let znn_complete: LiftedSignature = znn_pre.adapt(witness).unwrap();
    assert_eq!(
        final_verifiers(
            znn_key.serialize_xonly(),
            &znn_message,
            &znn_complete.to_bytes()
        ),
        [true; 3]
    );
    let recovered = znn_pre.reveal_secret::<MaybeScalar>(&znn_complete).unwrap();
    assert_eq!(recovered.base_point_mul(), point.into());
    assert!(
        btc_pre
            .reveal_secret::<MaybeScalar>(&znn_complete)
            .is_none()
    );
    let btc_complete: LiftedSignature = btc_pre.adapt(recovered).unwrap();
    assert_eq!(
        final_verifiers(
            btc_key.serialize_xonly(),
            &btc_message,
            &btc_complete.to_bytes()
        ),
        [true; 3]
    );
    assert_eq!(
        final_verifiers(
            btc_key.serialize_xonly(),
            &znn_message,
            &btc_complete.to_bytes()
        ),
        [false; 3]
    );
}
