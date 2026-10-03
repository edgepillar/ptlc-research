//! Public-only qualification of a signature over an exact completion envelope.
//! Supplied keys and terms digests do not establish local pin provenance, peer
//! identity, payload semantics, channel confidentiality, or chain observation.

use std::io::{self, Read, Write};

use bitcoin::secp256k1::{Message, Secp256k1, XOnlyPublicKey, schnorr::Signature};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub const MAX_REQUEST_BYTES: usize = 65_536;
pub const MAX_PAYLOAD_BYTES: usize = 32_000;

const REQUEST_FIELDS: [&str; 4] = ["schema", "context", "payload_hex", "signature_hex"];
const CONTEXT_FIELDS: [&str; 11] = [
    "schema",
    "algorithm",
    "purpose",
    "sender",
    "recipient",
    "session_id",
    "terms_digest_hex",
    "alice_id_hex",
    "bob_id_hex",
    "alice_auth_key_hex",
    "bob_auth_key_hex",
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

fn bytes(value: &Value, minimum: usize, maximum: usize) -> Result<Vec<u8>, ()> {
    let encoded = text(value)?;
    if encoded.len() % 2 != 0
        || encoded.len() < minimum * 2
        || encoded.len() > maximum * 2
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

fn context_key(context: &Value) -> Result<XOnlyPublicKey, ()> {
    fields(context, &CONTEXT_FIELDS)?;
    for field in CONTEXT_FIELDS {
        text(&context[field])?;
    }
    for (field, expected) in [
        ("schema", "ptlc-completion-auth-context-v1"),
        ("algorithm", "BIP340-SHA256"),
        ("purpose", "zenon-completion"),
        ("sender", "alice"),
        ("recipient", "bob"),
    ] {
        if text(&context[field])? != expected {
            return Err(());
        }
    }
    for field in [
        "session_id",
        "terms_digest_hex",
        "alice_id_hex",
        "bob_id_hex",
    ] {
        bytes(&context[field], 32, 32)?;
    }
    if context["alice_id_hex"] == context["bob_id_hex"] {
        return Err(());
    }
    let alice_bytes = bytes(&context["alice_auth_key_hex"], 32, 32)?;
    let bob_bytes = bytes(&context["bob_auth_key_hex"], 32, 32)?;
    if alice_bytes == bob_bytes {
        return Err(());
    }
    let alice = XOnlyPublicKey::from_slice(&alice_bytes).map_err(|_| ())?;
    XOnlyPublicKey::from_slice(&bob_bytes).map_err(|_| ())?;
    Ok(alice)
}

/// Verify compact sorted-key ASCII JSON, optionally followed by exactly one LF.
/// Exact re-encoding rejects duplicate keys, escaped aliases and noncanonical
/// whitespace before any decoded field is trusted as an authenticated binding.
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
    fields(&request, &REQUEST_FIELDS)?;
    if text(&request["schema"])? != "ptlc-completion-auth-request-v1" {
        return Err(());
    }
    let context = &request["context"];
    let alice_key = context_key(context)?;
    let payload = bytes(&request["payload_hex"], 1, MAX_PAYLOAD_BYTES)?;
    let signature =
        Signature::from_slice(&bytes(&request["signature_hex"], 64, 64)?).map_err(|_| ())?;
    let mut message_hash = Sha256::new();
    message_hash.update(b"PTLC/completion-auth/signature/v1\0");
    message_hash.update(serde_json::to_vec(context).map_err(|_| ())?);
    message_hash.update(b"\0");
    message_hash.update((payload.len() as u32).to_be_bytes());
    message_hash.update(&payload);
    let message = Message::from_digest(message_hash.finalize().into());
    Secp256k1::verification_only()
        .verify_schnorr(&signature, &message, &alice_key)
        .map_err(|_| ())?;
    let mut request_hash = Sha256::new();
    request_hash.update(b"PTLC/completion-auth/request/v1\0");
    request_hash.update(canonical);
    Ok(json!({
        "schema": "ptlc-completion-auth-result-v1",
        "request_digest_hex": hex(&request_hash.finalize()),
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
    // Reject silently: no request values, library panic details or paths escape.
    std::panic::set_hook(Box::new(|_| {}));
    if !matches!(std::panic::catch_unwind(run), Ok(Ok(()))) {
        std::process::exit(1);
    }
}
