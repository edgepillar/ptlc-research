//! Public-only BIP340 issuer assignment and separate v2 owner-intent checks.
//! Key selection, scope truth, current authority and permission remain external.
//! No signing, root provisioning, state, enrollment or quota is implemented.

use std::io::{self, Read, Write};

use bitcoin::secp256k1::{Message, Secp256k1, XOnlyPublicKey, schnorr::Signature};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub const MAX_REQUEST_BYTES: usize = 8192;
const PROFILE_FIELDS: [&str; 14] = [
    "schema",
    "purpose",
    "role",
    "algorithm",
    "owner_auth_key_hex",
    "resource_digest_hex",
    "authority_id_hex",
    "authority_epoch",
    "authority_profile_digest_hex",
    "verifier_profile_digest_hex",
    "pool_profile_digest_hex",
    "resource_profile_digest_hex",
    "max_attempt_limit",
    "max_target_limit",
];
const INTENT_FIELDS: [&str; 9] = [
    "schema",
    "purpose",
    "role",
    "algorithm",
    "resource_digest_hex",
    "scope_digest_hex",
    "owner_auth_key_hex",
    "request_id_hex",
    "governor_assignment_digest_hex",
];

fn fields(value: &Value, expected: &[&str]) -> Result<(), ()> {
    let object = value.as_object().ok_or(())?;
    if object.len() != expected.len() || !expected.iter().all(|key| object.contains_key(*key)) {
        return Err(());
    }
    Ok(())
}

fn fixed(value: &Value, expected: &[(&str, &str)]) -> Result<(), ()> {
    for (field, text) in expected {
        if value[*field].as_str().ok_or(())? != *text {
            return Err(());
        }
    }
    Ok(())
}

fn bytes(value: &Value, size: usize) -> Result<Vec<u8>, ()> {
    let encoded = value.as_str().ok_or(())?;
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

fn digest(domain: &[u8], value: &Value) -> Result<[u8; 32], ()> {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(serde_json::to_vec(value).map_err(|_| ())?);
    Ok(hash.finalize().into())
}

fn messages(request: &Value) -> Result<(XOnlyPublicKey, XOnlyPublicKey, [u8; 32], [u8; 32]), ()> {
    fields(
        request,
        &[
            "schema",
            "assignment",
            "bound_intent",
            "issuer_signature_hex",
            "owner_signature_hex",
        ],
    )?;
    fixed(
        request,
        &[("schema", "ptlc-observation-governor-signature-request-v1")],
    )?;
    let assignment = &request["assignment"];
    fields(
        assignment,
        &[
            "schema",
            "purpose",
            "algorithm",
            "issuer_auth_key_hex",
            "governor_profile",
        ],
    )?;
    fixed(
        assignment,
        &[
            ("schema", "ptlc-observation-governor-assignment-v1"),
            ("purpose", "observation-governor-assignment"),
            ("algorithm", "BIP340-SHA256"),
        ],
    )?;
    let profile = &assignment["governor_profile"];
    fields(profile, &PROFILE_FIELDS)?;
    fixed(
        profile,
        &[
            ("schema", "ptlc-observation-governor-profile-v1"),
            ("purpose", "observation-enrollment"),
            ("role", "enrollment-governor"),
            ("algorithm", "BIP340-SHA256"),
        ],
    )?;
    for field in [
        "owner_auth_key_hex",
        "resource_digest_hex",
        "authority_id_hex",
        "authority_profile_digest_hex",
        "verifier_profile_digest_hex",
        "pool_profile_digest_hex",
        "resource_profile_digest_hex",
    ] {
        bytes(&profile[field], 32)?;
    }
    for (field, maximum) in [
        ("authority_epoch", (1_u64 << 53) - 1),
        ("max_attempt_limit", 64),
        ("max_target_limit", 64),
    ] {
        let value = profile[field].as_u64().ok_or(())?;
        if value == 0 || value > maximum {
            return Err(());
        }
    }
    let intent = &request["bound_intent"];
    fields(intent, &INTENT_FIELDS)?;
    fixed(
        intent,
        &[
            ("schema", "ptlc-observation-enrollment-intent-v2"),
            ("purpose", "observation-enrollment"),
            ("role", "enrollment-governor"),
            ("algorithm", "BIP340-SHA256"),
        ],
    )?;
    for field in [
        "resource_digest_hex",
        "scope_digest_hex",
        "owner_auth_key_hex",
        "request_id_hex",
        "governor_assignment_digest_hex",
    ] {
        bytes(&intent[field], 32)?;
    }
    let issuer_message = digest(b"PTLC/observation-governor-assignment/v1\0", assignment)?;
    if intent["governor_assignment_digest_hex"]
        .as_str()
        .ok_or(())?
        != hex(&issuer_message)
        || intent["owner_auth_key_hex"] != profile["owner_auth_key_hex"]
        || intent["resource_digest_hex"] != profile["resource_digest_hex"]
    {
        return Err(());
    }
    // The opaque scope hash does not decode pins, caps or source evidence.
    let issuer = XOnlyPublicKey::from_slice(&bytes(&assignment["issuer_auth_key_hex"], 32)?)
        .map_err(|_| ())?;
    let owner =
        XOnlyPublicKey::from_slice(&bytes(&intent["owner_auth_key_hex"], 32)?).map_err(|_| ())?;
    Ok((
        issuer,
        owner,
        issuer_message,
        digest(b"PTLC/observation-enrollment-owner-intent/v2\0", intent)?,
    ))
}

/// Exact compact sorted-key ASCII JSON, with at most one trailing LF.
/// Re-encoding rejects duplicate keys, aliases and noncanonical numbers.
pub fn verify_request(input: &[u8]) -> Result<String, ()> {
    if input.is_empty() || input.len() > MAX_REQUEST_BYTES || !input.is_ascii() {
        return Err(());
    }
    let wire = input.strip_suffix(b"\n").unwrap_or(input);
    let request: Value = serde_json::from_slice(wire).map_err(|_| ())?;
    if serde_json::to_vec(&request).map_err(|_| ())? != wire {
        return Err(());
    }
    let (issuer, owner, issuer_message, owner_message) = messages(&request)?;
    let secp = Secp256k1::verification_only();
    for (field, key, message) in [
        ("issuer_signature_hex", issuer, issuer_message),
        ("owner_signature_hex", owner, owner_message),
    ] {
        let signature = Signature::from_slice(&bytes(&request[field], 64)?).map_err(|_| ())?;
        secp.verify_schnorr(&signature, &Message::from_digest(message), &key)
            .map_err(|_| ())?;
    }
    Ok(json!({"schema": "ptlc-observation-governor-signature-result-v1",
        "request_digest_hex": hex(&digest(b"PTLC/observation-governor-signature-request/v1\0", &request)?),
        "issuer_signature_valid": true, "owner_signature_valid": true}).to_string())
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
        std::process::exit(1);
    }
}
