//! Offline public-artifact verification only. This executable has no signing,
//! secret storage, chain observation, or participant authentication capability.

use std::io::{self, Read, Write};

use musig2::{
    AdaptorSignature, AggNonce, BinaryEncoding, KeyAggContext, PartialSignature, PubNonce, adaptor,
    secp::Point,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub const MAX_REQUEST_BYTES: usize = 32_768;

const FIELDS: [&str; 12] = [
    "schema",
    "kind",
    "context_digest_hex",
    "leg",
    "signer_keys_sec1_hex",
    "aggregate_key_xonly_hex",
    "taproot_merkle_root_hex",
    "message_hex",
    "adaptor_point_sec1_hex",
    "public_nonces_hex",
    "partial_signatures_hex",
    "adaptor_presignature_hex",
];

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

fn array(value: &Value, count: usize, width: usize) -> Result<Vec<Vec<u8>>, ()> {
    let values = value.as_array().ok_or(())?;
    if values.len() != count {
        return Err(());
    }
    values.iter().map(|value| bytes(value, width)).collect()
}

fn point(value: &[u8]) -> Result<Point, ()> {
    if value.len() != 33 || !matches!(value[0], 2 | 3) {
        return Err(());
    }
    Point::from_slice(value).map_err(|_| ())
}

/// Accept compact sorted-key ASCII JSON, optionally followed by one LF.
/// Canonical input equality rejects duplicate keys before they can be trusted,
/// even though serde_json::Value itself retains only the last duplicate value.
/// The context digest is an opaque caller binding, not independently rederived.
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
    if text(&request["schema"])? != "ptlc-artifact-verification-v1" {
        return Err(());
    }
    let count = match text(&request["kind"])? {
        "alice-partial" => 1,
        "bundle" => 2,
        _ => return Err(()),
    };
    bytes(&request["context_digest_hex"], 32)?;
    let signer_bytes = array(&request["signer_keys_sec1_hex"], 2, 33)?;
    if signer_bytes[0] == signer_bytes[1] {
        return Err(());
    }
    let signers = [point(&signer_bytes[0])?, point(&signer_bytes[1])?];
    let mut keys = KeyAggContext::new(signers).map_err(|_| ())?;
    match text(&request["leg"])? {
        "bitcoin" => {
            let root: [u8; 32] = bytes(&request["taproot_merkle_root_hex"], 32)?
                .try_into()
                .map_err(|_| ())?;
            keys = keys.with_taproot_tweak(&root).map_err(|_| ())?;
        }
        "zenon" if text(&request["taproot_merkle_root_hex"])? == "" => {}
        _ => return Err(()),
    }
    let aggregate: Point = keys.aggregated_pubkey();
    if aggregate.serialize_xonly().as_slice() != bytes(&request["aggregate_key_xonly_hex"], 32)? {
        return Err(());
    }
    let message = bytes(&request["message_hex"], 32)?;
    let adaptor_point = point(&bytes(&request["adaptor_point_sec1_hex"], 33)?)?;
    let public_bytes = array(&request["public_nonces_hex"], 2, 66)?;
    if public_bytes[0] == public_bytes[1] {
        return Err(());
    }
    // Explicit compressed-point checks reject infinity and alternate encodings.
    for nonce in &public_bytes {
        point(&nonce[..33])?;
        point(&nonce[33..])?;
    }
    let nonces = public_bytes
        .iter()
        .map(|nonce| PubNonce::from_bytes(nonce).map_err(|_| ()))
        .collect::<Result<Vec<_>, _>>()?;
    let aggregate_nonce = AggNonce::sum(&nonces);
    let partials = array(&request["partial_signatures_hex"], count, 32)?
        .iter()
        .map(|partial| PartialSignature::from_slice(partial).map_err(|_| ()))
        .collect::<Result<Vec<_>, _>>()?;
    for role in 0..count {
        adaptor::verify_partial(
            &keys,
            partials[role],
            &aggregate_nonce,
            adaptor_point,
            signers[role],
            &nonces[role],
            &message,
        )
        .map_err(|_| ())?;
    }
    if count == 1 {
        if text(&request["adaptor_presignature_hex"])? != "" {
            return Err(());
        }
    } else {
        let supplied_bytes = bytes(&request["adaptor_presignature_hex"], 65)?;
        let supplied = AdaptorSignature::from_bytes(&supplied_bytes).map_err(|_| ())?;
        let computed = adaptor::aggregate_partial_signatures(
            &keys,
            &aggregate_nonce,
            adaptor_point,
            partials,
            &message,
        )
        .map_err(|_| ())?;
        if computed.to_bytes().as_slice() != supplied_bytes {
            return Err(());
        }
        adaptor::verify_single(aggregate, &supplied, &message, adaptor_point).map_err(|_| ())?;
    }
    let mut hash = Sha256::new();
    hash.update(b"PTLC/artifact-verification/v1\0");
    hash.update(canonical);
    Ok(json!({
        "schema": "ptlc-artifact-verification-result-v1",
        "request_digest_hex": hex(&hash.finalize()),
        "valid": true
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
    // Never expose request values, library panic details, or environment paths.
    std::panic::set_hook(Box::new(|_| {}));
    if !matches!(std::panic::catch_unwind(run), Ok(Ok(()))) {
        let _ = io::stderr().write_all(b"artifact verification rejected\n");
        std::process::exit(1);
    }
}
