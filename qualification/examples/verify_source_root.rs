//! Public-only root signature over one exact historical source-role declaration.
//! A root supplied by the packet is not trusted provisioning or current policy.
//! No source command, SQLite operation, application gate or signer is connected.
use bitcoin::secp256k1::{Message, Secp256k1, XOnlyPublicKey, schnorr::Signature};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::io::{self, Read, Write};

pub const MAX_REQUEST_BYTES: usize = 8192;
const DECLARATION: &[u8] = b"PTLC/observation-source-root-declaration/v1\0";
const REQUEST: &[u8] = b"PTLC/observation-source-root-request/v1\0";

fn fields(value: &Value, expected: &[&str]) -> Result<(), ()> {
    let object = value.as_object().ok_or(())?;
    if object.len() != expected.len() || !expected.iter().all(|field| object.contains_key(*field)) {
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
    let text = value.as_str().ok_or(())?;
    if text.len() != size * 2
        || !text
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(());
    }
    text.as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).map_err(|_| ())?, 16).map_err(|_| ()))
        .collect()
}
fn number(value: &Value, max: u64) -> Result<(), ()> {
    let number = value.as_u64().ok_or(())?;
    if number == 0 || number > max {
        return Err(());
    }
    Ok(())
}
fn hash(domain: &[u8], value: &Value) -> Result<[u8; 32], ()> {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(serde_json::to_vec(value).map_err(|_| ())?);
    Ok(hash.finalize().into())
}
fn hex(value: &[u8]) -> String {
    value.iter().map(|b| format!("{b:02x}")).collect()
}
fn selected_root(declaration: &Value) -> Result<XOnlyPublicKey, ()> {
    fields(
        declaration,
        &[
            "schema",
            "purpose",
            "algorithm",
            "declaration_revision",
            "source_context",
            "governor_profile",
            "delegated_keys",
            "root_transition",
        ],
    )?;
    fixed(
        declaration,
        &[
            ("schema", "ptlc-observation-source-root-declaration-v1"),
            ("purpose", "source-role-declaration"),
            ("algorithm", "BIP340-SHA256"),
            ("root_transition", "independent-reprovisioning"),
        ],
    )?;
    number(&declaration["declaration_revision"], (1_u64 << 53) - 1)?;
    let source = &declaration["source_context"];
    fields(
        source,
        &[
            "schema",
            "source_id_hex",
            "source_profile_digest_hex",
            "source_incarnation_hex",
            "provisioning_root_key_hex",
            "resource_digest_hex",
            "authority_id_hex",
            "role",
        ],
    )?;
    fixed(
        source,
        &[
            ("schema", "ptlc-observation-policy-source-context-v1"),
            ("role", "enrollment-governor"),
        ],
    )?;
    for field in [
        "source_id_hex",
        "source_profile_digest_hex",
        "source_incarnation_hex",
        "provisioning_root_key_hex",
        "resource_digest_hex",
        "authority_id_hex",
    ] {
        bytes(&source[field], 32)?;
    }
    let profile = &declaration["governor_profile"];
    fields(
        profile,
        &[
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
        ],
    )?;
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
    for (field, max) in [
        ("authority_epoch", (1_u64 << 53) - 1),
        ("max_attempt_limit", 64),
        ("max_target_limit", 64),
    ] {
        number(&profile[field], max)?;
    }
    for field in ["authority_id_hex", "resource_digest_hex", "role"] {
        if source[field] != profile[field] {
            return Err(());
        }
    }
    let roles = &declaration["delegated_keys"];
    fields(
        roles,
        &[
            "policy_admin_key_hex",
            "source_response_key_hex",
            "governor_issuer_key_hex",
        ],
    )?;
    let keys = [
        &source["provisioning_root_key_hex"],
        &profile["owner_auth_key_hex"],
        &roles["policy_admin_key_hex"],
        &roles["source_response_key_hex"],
        &roles["governor_issuer_key_hex"],
    ];
    for (i, key) in keys.iter().enumerate() {
        if keys[..i].contains(key) {
            return Err(());
        }
        XOnlyPublicKey::from_slice(&bytes(key, 32)?).map_err(|_| ())?;
    }
    XOnlyPublicKey::from_slice(&bytes(keys[0], 32)?).map_err(|_| ())
}

/// Exact canonical ASCII request, with at most one trailing LF.
/// Verifies mathematics under the packet root, not that root's governance role.
pub fn verify_request(input: &[u8]) -> Result<String, ()> {
    if input.is_empty() || input.len() > MAX_REQUEST_BYTES || !input.is_ascii() {
        return Err(());
    }
    let wire = input.strip_suffix(b"\n").unwrap_or(input);
    let request: Value = serde_json::from_slice(wire).map_err(|_| ())?;
    if serde_json::to_vec(&request).map_err(|_| ())? != wire {
        return Err(());
    }
    fields(&request, &["schema", "declaration", "root_signature_hex"])?;
    fixed(
        &request,
        &[("schema", "ptlc-observation-source-root-request-v1")],
    )?;
    let root = selected_root(&request["declaration"])?;
    let signature =
        Signature::from_slice(&bytes(&request["root_signature_hex"], 64)?).map_err(|_| ())?;
    Secp256k1::verification_only()
        .verify_schnorr(
            &signature,
            &Message::from_digest(hash(DECLARATION, &request["declaration"])?),
            &root,
        )
        .map_err(|_| ())?;
    Ok(json!({"schema":"ptlc-observation-source-root-result-v1","request_digest_hex":hex(&hash(REQUEST,&request)?),"root_signature_valid":true}).to_string())
}
fn run() -> Result<(), ()> {
    let mut input = Vec::new();
    io::stdin()
        .lock()
        .take(MAX_REQUEST_BYTES as u64 + 1)
        .read_to_end(&mut input)
        .map_err(|_| ())?;
    let result = verify_request(&input)?;
    let mut out = io::stdout().lock();
    out.write_all(result.as_bytes()).map_err(|_| ())?;
    out.write_all(b"\n").map_err(|_| ())?;
    out.flush().map_err(|_| ())
}
fn main() {
    std::panic::set_hook(Box::new(|_| {}));
    if !matches!(std::panic::catch_unwind(run), Ok(Ok(()))) {
        std::process::exit(1);
    }
}
