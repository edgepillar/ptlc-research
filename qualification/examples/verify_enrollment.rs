//! Public-only BIP340 verification of the exact Stage 32 candidate owner intent.
//! Supplied key/digests establish no owner role, source truth, freshness, registry
//! admission, quota or idempotency. No signing or persistence is implemented.

use std::io::{self, Read, Write};

use bitcoin::secp256k1::{Message, Secp256k1, XOnlyPublicKey, schnorr::Signature};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub const MAX_REQUEST_BYTES: usize = 8192;
const REQUEST_FIELDS: [&str; 3] = ["schema", "intent", "signature_hex"];
const INTENT_FIELDS: [&str; 8] = [
    "schema",
    "purpose",
    "role",
    "algorithm",
    "resource_digest_hex",
    "scope_digest_hex",
    "owner_auth_key_hex",
    "request_id_hex",
];

fn fields(value: &Value, expected: &[&str]) -> Result<(), ()> {
    let object = value.as_object().ok_or(())?;
    if object.len() != expected.len() || !expected.iter().all(|key| object.contains_key(*key)) {
        return Err(());
    }
    Ok(())
}

fn text(value: &Value) -> Result<&str, ()> {
    value.as_str().ok_or(())
}

fn bytes(value: &Value, size: usize) -> Result<Vec<u8>, ()> {
    let encoded = text(value)?;
    if encoded.len() != size * 2
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(());
    }
    encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).map_err(|_| ())?, 16).map_err(|_| ())
        })
        .collect()
}

fn hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn owner_key(intent: &Value) -> Result<XOnlyPublicKey, ()> {
    fields(intent, &INTENT_FIELDS)?;
    for field in INTENT_FIELDS {
        text(&intent[field])?;
    }
    for (field, expected) in [
        ("schema", "ptlc-observation-enrollment-intent-v1"),
        ("purpose", "observation-enrollment"),
        ("role", "enrollment-governor"),
        ("algorithm", "BIP340-SHA256"),
    ] {
        if text(&intent[field])? != expected {
            return Err(());
        }
    }
    for field in ["resource_digest_hex", "scope_digest_hex", "request_id_hex"] {
        bytes(&intent[field], 32)?;
    }
    XOnlyPublicKey::from_slice(&bytes(&intent["owner_auth_key_hex"], 32)?).map_err(|_| ())
}

/// Require sorted-key compact ASCII JSON, with at most one trailing LF.
/// Re-encoding rejects duplicate keys, escaped aliases and whitespace variants.
pub fn verify_request(input: &[u8]) -> Result<String, ()> {
    if input.is_empty() || input.len() > MAX_REQUEST_BYTES || !input.is_ascii() {
        return Err(());
    }
    let wire = input.strip_suffix(b"\n").unwrap_or(input);
    let request: Value = serde_json::from_slice(wire).map_err(|_| ())?;
    let canonical = serde_json::to_vec(&request).map_err(|_| ())?;
    if canonical != wire {
        return Err(());
    }
    fields(&request, &REQUEST_FIELDS)?;
    if text(&request["schema"])? != "ptlc-observation-enrollment-signature-request-v1" {
        return Err(());
    }
    let intent = &request["intent"];
    let key = owner_key(intent)?;
    let signature =
        Signature::from_slice(&bytes(&request["signature_hex"], 64)?).map_err(|_| ())?;
    let mut message_hash = Sha256::new();
    message_hash.update(b"PTLC/observation-enrollment-owner-intent/v1\0");
    message_hash.update(serde_json::to_vec(intent).map_err(|_| ())?);
    Secp256k1::verification_only()
        .verify_schnorr(
            &signature,
            &Message::from_digest(message_hash.finalize().into()),
            &key,
        )
        .map_err(|_| ())?;
    let mut request_hash = Sha256::new();
    request_hash.update(b"PTLC/observation-enrollment-signature-request/v1\0");
    request_hash.update(canonical);
    Ok(
        json!({"schema": "ptlc-observation-enrollment-signature-result-v1",
        "request_digest_hex": hex(&request_hash.finalize()), "signature_valid": true})
        .to_string(),
    )
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
    // No untrusted request bytes, library panic details or paths escape on error.
    std::panic::set_hook(Box::new(|_| {}));
    if !matches!(std::panic::catch_unwind(run), Ok(Ok(()))) {
        std::process::exit(1);
    }
}
