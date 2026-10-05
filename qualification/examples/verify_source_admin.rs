//! Public-only historical attenuation/revocation mathematics under packet roles.
//! No trusted provisioning, current revision, source mutation or signer exists.
#[allow(dead_code)]
#[path = "verify_source_root.rs"]
mod root;
use bitcoin::secp256k1::{Message, Secp256k1, XOnlyPublicKey, schnorr::Signature};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::io::{self, Read, Write};

pub const MAX_REQUEST_BYTES: usize = 8192;
const COMMAND: &[u8] = b"PTLC/observation-source-admin-command/v1\0";
const REQUEST: &[u8] = b"PTLC/observation-source-admin-request/v1\0";
const DECLARATION: &[u8] = b"PTLC/observation-source-root-declaration/v1\0";

fn fields(value: &Value, expected: &[&str]) -> Result<(), ()> {
    let object = value.as_object().ok_or(())?;
    if object.len() != expected.len() || !expected.iter().all(|f| object.contains_key(*f)) {
        return Err(());
    }
    Ok(())
}
fn bytes(value: &Value, size: usize) -> Result<Vec<u8>, ()> {
    let text = value.as_str().ok_or(())?;
    if text.len() != size * 2
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(());
    }
    text.as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).map_err(|_| ())?, 16).map_err(|_| ()))
        .collect()
}
fn hash(domain: &[u8], value: &Value) -> Result<[u8; 32], ()> {
    let mut h = Sha256::new();
    h.update(domain);
    h.update(serde_json::to_vec(value).map_err(|_| ())?);
    Ok(h.finalize().into())
}
fn hex(value: &[u8]) -> String {
    value.iter().map(|b| format!("{b:02x}")).collect()
}
fn profile(value: &Value, anchor: &Value) -> Result<(), ()> {
    fields(
        value,
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
    for (field, original) in anchor.as_object().ok_or(())? {
        if field == "max_attempt_limit" || field == "max_target_limit" {
            let n = value[field].as_u64().ok_or(())?;
            if n == 0 || n > original.as_u64().ok_or(())? {
                return Err(());
            }
        } else if value[field] != *original {
            return Err(());
        }
    }
    Ok(())
}
fn command(value: &Value, declaration: &Value) -> Result<XOnlyPublicKey, ()> {
    fields(
        value,
        &[
            "schema",
            "purpose",
            "algorithm",
            "administration_rule",
            "source_context",
            "root_declaration_digest_hex",
            "administrator_role",
            "administrator_key_hex",
            "original_command_id_hex",
            "expected_policy_revision",
            "old_profile",
            "new_profile",
            "old_active",
            "new_active",
            "operation",
        ],
    )?;
    for (field, text) in [
        ("schema", "ptlc-observation-source-admin-command-v1"),
        ("purpose", "source-policy-command"),
        ("algorithm", "BIP340-SHA256"),
        ("administration_rule", "attenuate-or-revoke-v1"),
        ("administrator_role", "policy-administrator"),
    ] {
        if value[field].as_str().ok_or(())? != text {
            return Err(());
        }
    }
    if value["source_context"] != declaration["source_context"]
        || value["administrator_key_hex"] != declaration["delegated_keys"]["policy_admin_key_hex"]
        || value["root_declaration_digest_hex"].as_str().ok_or(())?
            != hex(&hash(DECLARATION, declaration)?)
    {
        return Err(());
    }
    bytes(&value["original_command_id_hex"], 32)?;
    let revision = value["expected_policy_revision"].as_u64().ok_or(())?;
    if revision > (1_u64 << 53) - 2 {
        return Err(());
    }
    let old = &value["old_profile"];
    let new = &value["new_profile"];
    profile(old, &declaration["governor_profile"])?;
    profile(new, &declaration["governor_profile"])?;
    if value["old_active"].as_bool().ok_or(())? != true {
        return Err(());
    }
    let active = value["new_active"].as_bool().ok_or(())?;
    match value["operation"].as_str().ok_or(())? {
        "reduce-limits" => {
            let mut reduced = false;
            for field in ["max_attempt_limit", "max_target_limit"] {
                let (a, b) = (
                    old[field].as_u64().ok_or(())?,
                    new[field].as_u64().ok_or(())?,
                );
                if b > a {
                    return Err(());
                }
                reduced |= b < a;
            }
            if !active || !reduced {
                return Err(());
            }
        }
        "revoke" => {
            if active || old != new {
                return Err(());
            }
        }
        _ => return Err(()),
    }
    XOnlyPublicKey::from_slice(&bytes(&value["administrator_key_hex"], 32)?).map_err(|_| ())
}

/// Verify exact historical packet mathematics; no independent selection is made.
pub fn verify_request(input: &[u8]) -> Result<String, ()> {
    if input.is_empty() || input.len() > MAX_REQUEST_BYTES || !input.is_ascii() {
        return Err(());
    }
    let wire = input.strip_suffix(b"\n").unwrap_or(input);
    let request: Value = serde_json::from_slice(wire).map_err(|_| ())?;
    if serde_json::to_vec(&request).map_err(|_| ())? != wire {
        return Err(());
    }
    fields(
        &request,
        &["schema", "root_envelope", "command", "admin_signature_hex"],
    )?;
    if request["schema"].as_str().ok_or(())? != "ptlc-observation-source-admin-request-v1" {
        return Err(());
    }
    let mut statement = request["root_envelope"].clone();
    fields(&statement, &["schema", "declaration", "root_signature_hex"])?;
    if statement["schema"].as_str().ok_or(())? != "ptlc-observation-source-root-envelope-v1" {
        return Err(());
    }
    statement["schema"] = json!("ptlc-observation-source-root-request-v1");
    // Reuse the retained exact declaration and all five curve checks unchanged.
    root::verify_request(&serde_json::to_vec(&statement).map_err(|_| ())?)?;
    let key = command(&request["command"], &statement["declaration"])?;
    let signature =
        Signature::from_slice(&bytes(&request["admin_signature_hex"], 64)?).map_err(|_| ())?;
    Secp256k1::verification_only()
        .verify_schnorr(
            &signature,
            &Message::from_digest(hash(COMMAND, &request["command"])?),
            &key,
        )
        .map_err(|_| ())?;
    Ok(json!({"schema":"ptlc-observation-source-admin-result-v1","request_digest_hex":hex(&hash(REQUEST,&request)?),"root_signature_valid":true,"administrator_signature_valid":true}).to_string())
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
