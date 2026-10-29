//! Unqualified candidate source for one public adaptor relation.
//! Public API has no private input or signing; tests use fixed public scalars.

use schnorr_fun::{
    Message,
    adaptor::{Adaptor, EncryptedSignature},
    fun::{
        Point, Scalar,
        marker::{EvenY, NonZero, Normal, Public, Zero},
    },
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub const BACKEND: &str = "schnorr_fun-encrypted-v1";
pub const BACKEND_COMMIT: &str = "74d18bbf864f98e5cf7c18dcfb74ba1ecfe837ce";
pub const MAX_REQUEST: usize = 8192;

fn fields(value: &Value, expected: &[&str]) -> Result<(), ()> {
    let object = value.as_object().ok_or(())?;
    if object.len() != expected.len() || expected.iter().any(|key| !object.contains_key(*key)) {
        return Err(());
    }
    Ok(())
}

fn bytes<const N: usize>(value: &Value) -> Result<[u8; N], ()> {
    let text = value.as_str().ok_or(())?;
    if text.len() != N * 2
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(());
    }
    let mut result = [0; N];
    for (index, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        result[index] =
            u8::from_str_radix(std::str::from_utf8(pair).map_err(|_| ())?, 16).map_err(|_| ())?;
    }
    Ok(result)
}

fn hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn verify_request(input: &[u8]) -> Result<Vec<u8>, ()> {
    if input.is_empty() || input.len() > MAX_REQUEST || !input.is_ascii() {
        return Err(());
    }
    let request: Value = serde_json::from_slice(input).map_err(|_| ())?;
    if serde_json::to_vec(&request).map_err(|_| ())? != input {
        return Err(());
    }
    fields(
        &request,
        &[
            "schema",
            "backend",
            "backend_commit",
            "context_digest_hex",
            "key_xonly_hex",
            "message_hex",
            "adaptor_point_sec1_hex",
            "presignature",
        ],
    )?;
    if request["schema"] != "ptlc-nom-client-presignature-check-v1"
        || request["backend"] != BACKEND
        || request["backend_commit"] != BACKEND_COMMIT
    {
        return Err(());
    }
    bytes::<32>(&request["context_digest_hex"])?;
    let key =
        Point::<EvenY, Public, NonZero>::from_xonly_bytes(bytes::<32>(&request["key_xonly_hex"])?)
            .ok_or(())?;
    let message = bytes::<32>(&request["message_hex"])?;
    let point_bytes = bytes::<33>(&request["adaptor_point_sec1_hex"])?;
    let point = Point::<Normal, Public, NonZero>::from_bytes(point_bytes).ok_or(())?;
    if point.to_bytes() != point_bytes {
        return Err(());
    }
    let supplied = &request["presignature"];
    fields(supplied, &["r_x_hex", "s_hat_hex", "needs_negation"])?;
    let pre = EncryptedSignature {
        R: Point::<EvenY, Public, NonZero>::from_xonly_bytes(bytes::<32>(&supplied["r_x_hex"])?)
            .ok_or(())?,
        s_hat: Scalar::<Public, Zero>::from_bytes(bytes::<32>(&supplied["s_hat_hex"])?).ok_or(())?,
        needs_negation: supplied["needs_negation"].as_bool().ok_or(())?,
    };
    // The nonce generator is not invoked by public verification.
    let schnorr = schnorr_fun::new_with_deterministic_nonces::<Sha256>();
    if !schnorr.verify_encrypted_signature(&key, &point, Message::raw(&message), &pre) {
        return Err(());
    }
    // The context digest is caller supplied. Echoing it authenticates no terms,
    // genesis, actor, funding, currentness, timing or signing owner.
    serde_json::to_vec(&json!({
        "schema": "ptlc-nom-client-presignature-result-v1",
        "request_digest_hex": hex(&Sha256::digest(input)),
        "context_digest_hex": request["context_digest_hex"],
        "presignature_valid": true,
        "scope": "PUBLIC_MATHEMATICS_ONLY",
        "action_permission": "NONE",
        "application": "NO-GO",
        "core": "NO-GO",
        "independent_assessment": "UNFILLED",
        "context_authentication": "NOT_VERIFIED",
        "chain_state": "NOT_VERIFIED",
        "signer_safety": "NOT_ASSESSED",
    }))
    .map_err(|_| ())
}

/// Run the bounded public JSON interface; no caller input is echoed on failure.
pub fn run_cli() -> i32 {
    use std::io::{self, Read, Write};
    if std::env::args_os().len() != 1 {
        return 2;
    }
    let mut input = Vec::new();
    if io::stdin()
        .take((MAX_REQUEST + 2) as u64)
        .read_to_end(&mut input)
        .is_err()
    {
        return 2;
    }
    // Admit one CLI framing LF; the library hashes canonical JSON without it.
    let request = input.strip_suffix(b"\n").unwrap_or(&input);
    match verify_request(request) {
        Ok(result) => {
            let stdout = io::stdout();
            let mut output = stdout.lock();
            if output.write_all(&result).is_ok() && output.flush().is_ok() {
                0
            } else {
                2
            }
        }
        Err(()) => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use schnorr_fun::{adaptor::EncryptedSign, fun::Scalar as TestScalar};

    fn public_request() -> Value {
        let schnorr = schnorr_fun::new_with_deterministic_nonces::<Sha256>();
        let key = schnorr.new_keypair(TestScalar::from_bytes([1; 32]).unwrap());
        let point = schnorr.encryption_key_for(&TestScalar::from_bytes([2; 32]).unwrap());
        let pre = schnorr.encrypted_sign(&key, &point, Message::raw(&[3; 32]));
        json!({
            "schema": "ptlc-nom-client-presignature-check-v1",
            "backend": BACKEND, "backend_commit": BACKEND_COMMIT,
            "context_digest_hex": "04".repeat(32),
            "key_xonly_hex": hex(&key.public_key().to_xonly_bytes()),
            "message_hex": "03".repeat(32),
            "adaptor_point_sec1_hex": hex(&point.to_bytes()),
            "presignature": {
                "r_x_hex": hex(&pre.R.to_xonly_bytes()),
                "s_hat_hex": hex(&pre.s_hat.to_bytes()), "needs_negation": pre.needs_negation,
            },
        })
    }

    #[test]
    fn a_single_public_leg_needs_no_invented_other_entry() {
        let input = serde_json::to_vec(&public_request()).unwrap();
        let reply: Value = serde_json::from_slice(&verify_request(&input).unwrap()).unwrap();
        assert_eq!(reply["request_digest_hex"], hex(&Sha256::digest(&input)));
        assert_eq!(reply["presignature_valid"], true);
        assert_eq!(reply["action_permission"], "NONE");
        assert_eq!(reply["scope"], "PUBLIC_MATHEMATICS_ONLY");
        assert_eq!(reply["application"], "NO-GO");
        assert_eq!(reply["core"], "NO-GO");
        assert_eq!(reply["context_authentication"], "NOT_VERIFIED");
    }

    #[test]
    fn mathematical_validity_does_not_authenticate_a_caller_context() {
        let first = public_request();
        let mut second = first.clone();
        second["context_digest_hex"] = json!("05".repeat(32));
        let left: Value =
            serde_json::from_slice(&verify_request(&serde_json::to_vec(&first).unwrap()).unwrap())
                .unwrap();
        let right: Value =
            serde_json::from_slice(&verify_request(&serde_json::to_vec(&second).unwrap()).unwrap())
                .unwrap();
        assert_eq!(left["presignature_valid"], right["presignature_valid"]);
        assert_ne!(left["request_digest_hex"], right["request_digest_hex"]);
        assert_ne!(left["context_digest_hex"], right["context_digest_hex"]);
    }

    #[test]
    fn historical_public_completion_supplies_a_single_leg_byte_oracle() {
        // This fixture was derived from an already public signature and the
        // deliberately public witness 3. It is not an operational signing API.
        let mut request: Value =
            serde_json::from_slice(include_bytes!("../synthetic_long_request.json")).unwrap();
        let historical: Value = serde_json::from_slice(include_bytes!(
            "../../compatibility/fixtures/nom_bilateral_completions_v1.json"
        ))
        .unwrap();
        assert_eq!(request["message_hex"], historical["long_message_hex"]);
        assert_eq!(
            request["presignature"]["r_x_hex"],
            &historical["long_signature_hex"].as_str().unwrap()[..64]
        );
        let result: Value = serde_json::from_slice(
            &verify_request(&serde_json::to_vec(&request).unwrap()).unwrap(),
        )
        .unwrap();
        assert_eq!(result["presignature_valid"], true);
        assert_eq!(result["action_permission"], "NONE");
        request["message_hex"] = historical["short_message_hex"].clone();
        assert!(verify_request(&serde_json::to_vec(&request).unwrap()).is_err());
    }

    #[test]
    fn changed_message_point_scalar_and_parity_are_not_validated() {
        let original = public_request();
        let mut changed = original.clone();
        changed["message_hex"] = json!("07".repeat(32));
        assert!(verify_request(&serde_json::to_vec(&changed).unwrap()).is_err());
        let schnorr = schnorr_fun::new_with_deterministic_nonces::<Sha256>();
        let other_key = schnorr.new_keypair(TestScalar::from_bytes([7; 32]).unwrap());
        let mut changed = original.clone();
        changed["key_xonly_hex"] = json!(hex(&other_key.public_key().to_xonly_bytes()));
        assert!(verify_request(&serde_json::to_vec(&changed).unwrap()).is_err());
        let mut changed = original.clone();
        let point = changed["adaptor_point_sec1_hex"].as_str().unwrap();
        changed["adaptor_point_sec1_hex"] = json!(format!(
            "{}{}",
            if &point[..2] == "02" { "03" } else { "02" },
            &point[2..]
        ));
        assert!(verify_request(&serde_json::to_vec(&changed).unwrap()).is_err());
        let mut changed = original.clone();
        changed["presignature"]["s_hat_hex"] = json!("ff".repeat(32));
        assert!(verify_request(&serde_json::to_vec(&changed).unwrap()).is_err());
        let mut changed = original.clone();
        changed["presignature"]["needs_negation"] = json!(
            !original["presignature"]["needs_negation"]
                .as_bool()
                .unwrap()
        );
        assert!(verify_request(&serde_json::to_vec(&changed).unwrap()).is_err());
    }

    #[test]
    fn foreign_encodings_noncanonical_objects_and_unbounded_inputs_refuse() {
        let original = public_request();
        let input = serde_json::to_vec(&original).unwrap();
        assert!(verify_request(&[input.as_slice(), b"\n"].concat()).is_err());
        assert!(verify_request(&vec![b'x'; MAX_REQUEST + 1]).is_err());
        for changed in [
            {
                let mut value = original.clone();
                value["backend"] = json!("musig2-adaptor-v1");
                value
            },
            {
                let mut value = original.clone();
                value["presignature"]["needs_negation"] = json!(1);
                value
            },
            {
                let mut value = original.clone();
                value["key_xonly_hex"] = json!("ff".repeat(32));
                value
            },
            {
                let mut value = original.clone();
                value["unexpected"] = json!(true);
                value
            },
        ] {
            assert!(verify_request(&serde_json::to_vec(&changed).unwrap()).is_err());
        }
    }
}
