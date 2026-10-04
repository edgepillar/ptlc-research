//! Explicit normal verdicts for a public, fixed-shape Zenon completion request.
//! Shape, I/O and panic failures are not mathematical negatives. No Bitcoin
//! adaptation, signing, source authentication or journal admission is performed.

#[allow(dead_code)]
#[path = "complete_exchange.rs"]
mod completion;

use std::io::{self, Read, Write};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub const MAX_REQUEST_BYTES: usize = completion::MAX_REQUEST_BYTES;
pub const RESULT_SCHEMA: &str = "ptlc-observation-verifier-result-v1";
pub const PREDICATE: &str = "zenon-completion-v1";

fn exact_fields(value: &Value, fields: &[&str]) -> Result<(), ()> {
    let object = value.as_object().ok_or(())?;
    if object.len() != fields.len() || !fields.iter().all(|key| object.contains_key(*key)) {
        return Err(());
    }
    Ok(())
}

fn fixed_hex(value: &Value, width: usize) -> Result<(), ()> {
    let text = value.as_str().ok_or(())?;
    if text.len() != width * 2
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(());
    }
    Ok(())
}

fn pair(value: &Value, width: usize) -> Result<(), ()> {
    let items = value.as_array().ok_or(())?;
    if items.len() != 2 {
        return Err(());
    }
    for item in items {
        fixed_hex(item, width)?;
    }
    Ok(())
}

fn shape(request: &Value) -> Result<(), ()> {
    exact_fields(
        request,
        &["schema", "kind", "zenon", "bitcoin", "zenon_signature_hex"],
    )?;
    if request["schema"] != "ptlc-completion-request-v1"
        || request["kind"] != "verify-zenon-completion"
        || !request["bitcoin"].is_null()
    {
        return Err(());
    }
    fixed_hex(&request["zenon_signature_hex"], 64)?;
    let bundle = &request["zenon"];
    exact_fields(
        bundle,
        &[
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
        ],
    )?;
    if bundle["schema"] != "ptlc-artifact-verification-v1"
        || bundle["kind"] != "bundle"
        || bundle["leg"] != "zenon"
        || bundle["taproot_merkle_root_hex"] != ""
    {
        return Err(());
    }
    for field in [
        "context_digest_hex",
        "aggregate_key_xonly_hex",
        "message_hex",
    ] {
        fixed_hex(&bundle[field], 32)?;
    }
    fixed_hex(&bundle["adaptor_point_sec1_hex"], 33)?;
    fixed_hex(&bundle["adaptor_presignature_hex"], 65)?;
    pair(&bundle["signer_keys_sec1_hex"], 33)?;
    pair(&bundle["public_nonces_hex"], 66)?;
    pair(&bundle["partial_signatures_hex"], 32)
}

/// A completed shape check precedes reuse of the unchanged, pure predicate.
/// On this fixed domain its Err paths express invalid mathematical inputs;
/// panics propagate to the process boundary and never become normal rejection.
/// Context digests are opaque bindings, not authenticated chain or source facts.
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
    shape(&request)?;
    // This function has no I/O. Do not use the legacy executable exit status.
    let outcome = if completion::verify_request(&canonical).is_ok() {
        "verified"
    } else {
        "rejected"
    };
    let mut hash = Sha256::new();
    hash.update(b"PTLC/completion/v1\0");
    hash.update(canonical);
    let digest: String = hash
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Ok(json!({
        "schema": RESULT_SCHEMA,
        "predicate": PREDICATE,
        "request_digest_hex": digest,
        "outcome": outcome
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
    std::panic::set_hook(Box::new(|_| {}));
    if !matches!(std::panic::catch_unwind(run), Ok(Ok(()))) {
        let _ = io::stderr().write_all(b"observation verdict unavailable\n");
        std::process::exit(2);
    }
}
