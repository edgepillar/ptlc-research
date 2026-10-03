//! Public completion verification and cross-leg adaptation. No signing keys,
//! secret nonce generation, wallet, transport, or chain observation is present.
//! The extracted witness is used in memory and never returned or serialized.

#[allow(dead_code)]
#[path = "verify_exchange.rs"]
mod artifact_verifier;

use std::io::{self, Read, Write};

use musig2::{
    AdaptorSignature, BinaryEncoding, LiftedSignature,
    secp::{MaybeScalar, Point},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub const MAX_REQUEST_BYTES: usize = 65_536;

const FIELDS: [&str; 5] = ["schema", "kind", "zenon", "bitcoin", "zenon_signature_hex"];

fn text(value: &Value) -> Result<&str, ()> {
    value.as_str().ok_or(())
}

fn bytes(value: &Value, length: usize) -> Result<Vec<u8>, ()> {
    let value = text(value)?;
    if value.len() != length * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |byte: u8| match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                _ => unreachable!(),
            };
            Ok(digit(pair[0]) * 16 + digit(pair[1]))
        })
        .collect()
}

fn hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

struct Bundle {
    key: Point,
    message: Vec<u8>,
    adaptor: Point,
    presignature: AdaptorSignature,
}

fn verified_bundle(value: &Value, leg: &str) -> Result<Bundle, ()> {
    if text(&value["kind"])? != "bundle" || text(&value["leg"])? != leg {
        return Err(());
    }
    // Reuse the complete ordered-key/tweak/partial/aggregation verification.
    artifact_verifier::verify_request(&serde_json::to_vec(value).map_err(|_| ())?)?;
    let key_bytes = bytes(&value["aggregate_key_xonly_hex"], 32)?
        .try_into()
        .map_err(|_| ())?;
    Ok(Bundle {
        key: Point::lift_x(key_bytes).map_err(|_| ())?,
        message: bytes(&value["message_hex"], 32)?,
        adaptor: Point::from_slice(&bytes(&value["adaptor_point_sec1_hex"], 33)?)
            .map_err(|_| ())?,
        presignature: AdaptorSignature::from_bytes(&bytes(&value["adaptor_presignature_hex"], 65)?)
            .map_err(|_| ())?,
    })
}

/// Accept compact sorted-key ASCII JSON, optionally followed by one LF.
/// Canonical equality rejects duplicate keys, including nested duplicates.
/// Context digests and chain facts remain caller supplied and unauthenticated.
pub fn verify_request(input: &[u8]) -> Result<String, ()> {
    if input.len() > MAX_REQUEST_BYTES || !input.is_ascii() {
        return Err(());
    }
    let wire = input.strip_suffix(b"\n").unwrap_or(input);
    let request: Value = serde_json::from_slice(wire).map_err(|_| ())?;
    let canonical = serde_json::to_vec(&request).map_err(|_| ())?;
    if canonical != wire {
        return Err(());
    }
    let object = request.as_object().ok_or(())?;
    if object.len() != FIELDS.len() || !FIELDS.iter().all(|key| object.contains_key(*key)) {
        return Err(());
    }
    if text(&request["schema"])? != "ptlc-completion-request-v1" {
        return Err(());
    }
    let recover = match text(&request["kind"])? {
        "verify-zenon-completion" if request["bitcoin"].is_null() => false,
        "recover-bitcoin" if request["bitcoin"].is_object() => true,
        _ => return Err(()),
    };
    let zenon = verified_bundle(&request["zenon"], "zenon")?;
    let final_zenon = LiftedSignature::from_bytes(&bytes(&request["zenon_signature_hex"], 64)?)
        .map_err(|_| ())?;

    // Extraction alone does not establish final signature validity or T binding.
    // Verification of the exact retained key/message must happen first.
    musig2::verify_single(zenon.key, final_zenon, &zenon.message).map_err(|_| ())?;
    let witness: MaybeScalar = zenon.presignature.reveal_secret(&final_zenon).ok_or(())?;
    if witness == MaybeScalar::Zero || witness.base_point_mul() != zenon.adaptor.into() {
        return Err(());
    }

    let bitcoin_signature_hex = if recover {
        let bitcoin = verified_bundle(&request["bitcoin"], "bitcoin")?;
        if bitcoin.adaptor != zenon.adaptor {
            return Err(());
        }
        let final_bitcoin: LiftedSignature = bitcoin.presignature.adapt(witness).ok_or(())?;
        musig2::verify_single(bitcoin.key, final_bitcoin, &bitcoin.message).map_err(|_| ())?;
        hex(&final_bitcoin.to_bytes())
    } else {
        String::new()
    };
    let mut hash = Sha256::new();
    hash.update(b"PTLC/completion/v1\0");
    hash.update(canonical);
    Ok(json!({
        "schema": "ptlc-completion-result-v1",
        "request_digest_hex": hex(&hash.finalize()),
        "valid": true,
        "bitcoin_signature_hex": bitcoin_signature_hex
    })
    .to_string())
}

fn run() -> Result<(), ()> {
    let mut input = Vec::new();
    io::stdin()
        .lock()
        .take(MAX_REQUEST_BYTES as u64 + 1)
        .read_to_end(&mut input)
        .map_err(|_| ())?;
    let response = verify_request(&input)?;
    let mut output = io::stdout().lock();
    output.write_all(response.as_bytes()).map_err(|_| ())?;
    output.write_all(b"\n").map_err(|_| ())?;
    output.flush().map_err(|_| ())
}

fn main() {
    // Suppress all request values, panic internals, and environment details.
    std::panic::set_hook(Box::new(|_| {}));
    if !matches!(std::panic::catch_unwind(run), Ok(Ok(()))) {
        let _ = io::stderr().write_all(b"completion rejected\n");
        std::process::exit(1);
    }
}
