//! Candidate-only deterministic adaptor exercise with public synthetic constants.
//! No application signer, wallet input, durable custody, transport, or node access.

use musig2::{
    secp::{MaybePoint, Point, Scalar},
    secp256k1::{Secp256k1, XOnlyPublicKey, schnorr::Signature},
};
use schnorr_fun::{
    Message,
    adaptor::{Adaptor, EncryptedSign, EncryptedSignature},
    fun::Scalar as FunScalar,
};
use sha2::Sha256;

fn fun_scalar(tag: u8) -> FunScalar {
    FunScalar::from_bytes([tag; 32]).expect("public nonzero synthetic scalar")
}

fn public_point(tag: u8) -> Point {
    Scalar::from_slice(&[tag; 32])
        .expect("public nonzero synthetic scalar")
        .base_point_mul()
}

fn comparison_bytes(pre: &EncryptedSignature) -> [u8; 65] {
    // Fixture comparison only: R_x || s_hat || canonical negation flag.
    // This is neither musig2::AdaptorSignature encoding nor a client wire format.
    let mut bytes = [0; 65];
    bytes[..32].copy_from_slice(&pre.R.to_xonly_bytes());
    bytes[32..64].copy_from_slice(&pre.s_hat.to_bytes());
    bytes[64] = u8::from(pre.needs_negation);
    bytes
}

fn public_pre_nonce_x(pre: &EncryptedSignature, adaptor: Point) -> [u8; 32] {
    // Recover the public pre-nonce up to sign, using an independent group API.
    // Comparing adapted R alone would miss reuse when a changed T changes R.
    let nonce = Point::lift_x(pre.R.to_xonly_bytes()).expect("valid even-Y nonce");
    let correction = if pre.needs_negation {
        adaptor
    } else {
        -adaptor
    };
    match nonce + correction {
        MaybePoint::Valid(point) => point.serialize_xonly(),
        MaybePoint::Infinity => panic!("valid pre-signature must have a nonzero pre-nonce"),
    }
}

fn independent_verify(key: [u8; 32], message: &[u8; 32], signature: [u8; 64]) -> bool {
    let key = XOnlyPublicKey::from_byte_array(key).expect("valid synthetic key");
    Secp256k1::verification_only()
        .verify_schnorr(&Signature::from_byte_array(signature), message, &key)
        .is_ok()
}

#[test]
fn same_inputs_and_reconstructed_synthetic_owners_have_identical_outputs() {
    let schnorr = schnorr_fun::new_with_deterministic_nonces::<Sha256>();
    let key = schnorr.new_keypair(fun_scalar(1));
    let witness = fun_scalar(2);
    let point = schnorr.encryption_key_for(&witness);
    let message = [3; 32];
    let first = schnorr.encrypted_sign(&key, &point, Message::raw(&message));
    let repeated = schnorr.encrypted_sign(&key, &point, Message::raw(&message));

    // Reconstruct only public test constants, without claiming a storage restore.
    let reconstructed = schnorr_fun::new_with_deterministic_nonces::<Sha256>();
    let restored_key = reconstructed.new_keypair(fun_scalar(1));
    let restored_point = reconstructed.encryption_key_for(&fun_scalar(2));
    let replay =
        reconstructed.encrypted_sign(&restored_key, &restored_point, Message::raw(&message));
    assert_eq!(comparison_bytes(&first), comparison_bytes(&repeated));
    assert_eq!(comparison_bytes(&first), comparison_bytes(&replay));
    assert!(schnorr.verify_encrypted_signature(
        &key.public_key(),
        &point,
        Message::raw(&message),
        &first,
    ));
    let completed = schnorr.decrypt_signature(witness, first.clone());
    let replayed = reconstructed.decrypt_signature(fun_scalar(2), replay);
    assert_eq!(completed.to_bytes(), replayed.to_bytes());
    assert!(independent_verify(
        key.public_key().to_xonly_bytes(),
        &message,
        completed.to_bytes(),
    ));
    let recovered = schnorr
        .recover_decryption_key(&point, &first, &completed)
        .expect("matching completion must reveal the committed witness");
    assert_eq!(recovered.to_bytes(), fun_scalar(2).to_bytes());
    assert_eq!(schnorr.encryption_key_for(&recovered), point);
}

#[test]
fn public_pre_nonce_binds_message_and_full_adaptor_point_in_selected_cases() {
    let schnorr = schnorr_fun::new_with_deterministic_nonces::<Sha256>();
    let key = schnorr.new_keypair(fun_scalar(1));
    let point = schnorr.encryption_key_for(&fun_scalar(2));
    let changed_point = schnorr.encryption_key_for(&fun_scalar(5));
    let mut negated_witness = fun_scalar(2);
    negated_witness.conditional_negate(true);
    let negated_point = schnorr.encryption_key_for(&negated_witness);
    let message = [3; 32];
    let changed_message = [4; 32];
    let base = schnorr.encrypted_sign(&key, &point, Message::raw(&message));
    let changed_t = schnorr.encrypted_sign(&key, &changed_point, Message::raw(&message));
    let negated_t = schnorr.encrypted_sign(&key, &negated_point, Message::raw(&message));
    let changed_m = schnorr.encrypted_sign(&key, &point, Message::raw(&changed_message));
    let base_nonce = public_pre_nonce_x(&base, public_point(2));
    assert_ne!(base_nonce, public_pre_nonce_x(&changed_t, public_point(5)));
    assert_ne!(base_nonce, public_pre_nonce_x(&negated_t, -public_point(2)));
    assert_ne!(base_nonce, public_pre_nonce_x(&changed_m, public_point(2)));

    for (pre, adaptor, msg) in [
        (&base, &point, &message),
        (&changed_t, &changed_point, &message),
        (&negated_t, &negated_point, &message),
        (&changed_m, &point, &changed_message),
    ] {
        assert!(schnorr.verify_encrypted_signature(
            &key.public_key(),
            adaptor,
            Message::raw(msg),
            pre,
        ));
    }
    assert!(!schnorr.verify_encrypted_signature(
        &key.public_key(),
        &changed_point,
        Message::raw(&message),
        &base,
    ));
    assert!(!schnorr.verify_encrypted_signature(
        &key.public_key(),
        &point,
        Message::raw(&changed_message),
        &base,
    ));
}

#[test]
fn synthetic_parity_cases_complete_verify_and_extract_only_the_bound_witness() {
    let schnorr = schnorr_fun::new_with_deterministic_nonces::<Sha256>();
    let mut coverage = [[false; 2]; 2];
    for tag in 1..=32_u8 {
        let key = schnorr.new_keypair(fun_scalar(tag));
        let witness = fun_scalar(tag + 64);
        let point = schnorr.encryption_key_for(&witness);
        let message = [tag + 32; 32];
        let pre = schnorr.encrypted_sign(&key, &point, Message::raw(&message));
        coverage[usize::from(!public_point(tag).has_even_y())][usize::from(pre.needs_negation)] =
            true;
        assert!(schnorr.verify_encrypted_signature(
            &key.public_key(),
            &point,
            Message::raw(&message),
            &pre,
        ));
        let completed = schnorr.decrypt_signature(witness, pre.clone());
        assert!(independent_verify(
            key.public_key().to_xonly_bytes(),
            &message,
            completed.to_bytes(),
        ));
        let recovered = schnorr
            .recover_decryption_key(&point, &pre, &completed)
            .expect("matching completion must reveal the committed witness");
        assert_eq!(recovered.to_bytes(), witness.to_bytes());
        assert_eq!(schnorr.encryption_key_for(&recovered), point);

        let wrong = schnorr.decrypt_signature(fun_scalar(tag + 65), pre.clone());
        assert!(!independent_verify(
            key.public_key().to_xonly_bytes(),
            &message,
            wrong.to_bytes(),
        ));
        assert!(
            schnorr
                .recover_decryption_key(&point, &pre, &wrong)
                .is_none()
        );
    }
    assert_eq!(
        coverage, [[true; 2]; 2],
        "all four parity pairs must execute"
    );
}
