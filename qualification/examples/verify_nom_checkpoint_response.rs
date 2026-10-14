//! Public root-grant and checkpoint-response mathematics only.
//! Packet roots, digest fields and signatures establish no provisioned authority,
//! actual evidence opening, current read, protected store or work permission.
use bitcoin::secp256k1::{Message, Secp256k1, XOnlyPublicKey, schnorr::Signature};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::io::{self, Read, Write};

pub const MAX_REQUEST_BYTES: usize = 8192;
pub const DECLARATION_DOMAIN: &[u8] = b"ptlc-nom-checkpoint-response-authority-message-v1\0";
pub const MESSAGE_DOMAIN: &[u8] = b"ptlc-nom-checkpoint-response-signed-message-v1\0";
pub const REQUEST_DOMAIN: &[u8] = b"ptlc-nom-checkpoint-response-request-v1\0";
const POLICY_DOMAIN: &[u8] = b"ptlc-nom-checkpoint-service-selection-v1\0";
const MAX_NUMBER: u64 = (1_u64 << 53) - 1;

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
fn number(value: &Value) -> Result<u64, ()> {
    let n = value.as_u64().ok_or(())?;
    if n == 0 || n > MAX_NUMBER {
        return Err(());
    }
    Ok(n)
}
fn hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}
pub fn message_digest(domain: &[u8], value: &Value) -> Result<[u8; 32], ()> {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(serde_json::to_vec(value).map_err(|_| ())?);
    Ok(hash.finalize().into())
}
fn policy(value: &Value) -> Result<XOnlyPublicKey, ()> {
    fields(
        value,
        &[
            "schema",
            "purpose",
            "service_id_hex",
            "service_epoch",
            "checkpoint_key_hex",
            "realm",
            "max_snapshots",
        ],
    )?;
    fixed(
        value,
        &[
            ("schema", "ptlc-nom-checkpoint-service-selection-v1"),
            ("purpose", "external-reference-retention-only"),
        ],
    )?;
    bytes(&value["service_id_hex"], 32)?;
    number(&value["service_epoch"])?;
    let count = number(&value["max_snapshots"])?;
    if count > 16 {
        return Err(());
    }
    let realm = &value["realm"];
    fields(
        realm,
        &[
            "core_commit",
            "chain_id",
            "genesis_hash_hex",
            "binary_digest_hex",
            "spork_state_digest_hex",
            "canonicality_policy_digest_hex",
            "finality_policy_digest_hex",
            "freshness_policy_digest_hex",
            "restore_policy_digest_hex",
        ],
    )?;
    fixed(
        realm,
        &[("core_commit", "45e1bbb48ce6fc19d44c5fbf59ccf5784981fced")],
    )?;
    let chain = realm["chain_id"].as_str().ok_or(())?;
    if chain.is_empty() || !chain.bytes().all(|c| c.is_ascii_digit()) {
        return Err(());
    }
    let id = chain.parse::<u64>().map_err(|_| ())?;
    if id == 0 || id.to_string() != chain {
        return Err(());
    }
    for field in [
        "genesis_hash_hex",
        "binary_digest_hex",
        "spork_state_digest_hex",
        "canonicality_policy_digest_hex",
        "finality_policy_digest_hex",
        "freshness_policy_digest_hex",
        "restore_policy_digest_hex",
    ] {
        bytes(&realm[field], 32)?;
    }
    XOnlyPublicKey::from_slice(&bytes(&value["checkpoint_key_hex"], 32)?).map_err(|_| ())
}
fn declaration(value: &Value) -> Result<[XOnlyPublicKey; 2], ()> {
    fields(
        value,
        &[
            "schema",
            "purpose",
            "algorithm",
            "authority_epoch",
            "root_key_hex",
            "service_selection",
            "service_selection_digest_hex",
            "work_scope_digest_hex",
            "root_transition",
        ],
    )?;
    fixed(
        value,
        &[
            ("schema", "ptlc-nom-checkpoint-response-authority-v1"),
            ("purpose", "checkpoint-candidate-response-role"),
            ("algorithm", "BIP340-SHA256"),
            ("root_transition", "independent-reprovisioning"),
        ],
    )?;
    number(&value["authority_epoch"])?;
    bytes(&value["work_scope_digest_hex"], 32)?;
    let signer = policy(&value["service_selection"])?;
    let root = XOnlyPublicKey::from_slice(&bytes(&value["root_key_hex"], 32)?).map_err(|_| ())?;
    if root == signer
        || value["service_selection_digest_hex"]
            != hex(&message_digest(POLICY_DOMAIN, &value["service_selection"])?)
    {
        return Err(());
    }
    Ok([root, signer])
}
pub fn signed_message(request: &Value) -> Value {
    json!({"schema":"ptlc-nom-checkpoint-response-signed-message-v1",
        "purpose":"checkpoint-candidate-or-outage-math-only", "declaration":request["declaration"],
        "query_digest_hex":request["query_digest_hex"],"discovery_message_digest_hex":request["discovery_message_digest_hex"]})
}
fn depth_bound(wire: &[u8]) -> Result<(), ()> {
    let (mut depth, mut quoted, mut escaped) = (0_u32, false, false);
    for byte in wire {
        if quoted {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                quoted = false;
            }
        } else if *byte == b'"' {
            quoted = true;
        } else if *byte == b'[' || *byte == b'{' {
            depth += 1;
            if depth > 12 {
                return Err(());
            }
        } else if *byte == b']' || *byte == b'}' {
            depth = depth.checked_sub(1).ok_or(())?;
        }
    }
    if depth != 0 || quoted {
        return Err(());
    }
    Ok(())
}
/// Exact mathematics under packet keys; Python selects its role and actual openings.
pub fn verify_request(input: &[u8]) -> Result<String, ()> {
    if input.is_empty() || input.len() > MAX_REQUEST_BYTES || !input.is_ascii() {
        return Err(());
    }
    let wire = input.strip_suffix(b"\n").unwrap_or(input);
    depth_bound(wire)?;
    let request: Value = serde_json::from_slice(wire).map_err(|_| ())?;
    if serde_json::to_vec(&request).map_err(|_| ())? != wire {
        return Err(());
    }
    fields(
        &request,
        &[
            "schema",
            "declaration",
            "query_digest_hex",
            "discovery_message_digest_hex",
            "root_signature_hex",
            "response_signature_hex",
        ],
    )?;
    fixed(
        &request,
        &[("schema", "ptlc-nom-checkpoint-response-request-v1")],
    )?;
    bytes(&request["query_digest_hex"], 32)?;
    bytes(&request["discovery_message_digest_hex"], 32)?;
    let keys = declaration(&request["declaration"])?;
    for (key, domain, payload, field) in [
        (
            &keys[0],
            DECLARATION_DOMAIN,
            request["declaration"].clone(),
            "root_signature_hex",
        ),
        (
            &keys[1],
            MESSAGE_DOMAIN,
            signed_message(&request),
            "response_signature_hex",
        ),
    ] {
        let signature = Signature::from_slice(&bytes(&request[field], 64)?).map_err(|_| ())?;
        Secp256k1::verification_only()
            .verify_schnorr(
                &signature,
                &Message::from_digest(message_digest(domain, &payload)?),
                key,
            )
            .map_err(|_| ())?;
    }
    Ok(json!({"schema":"ptlc-nom-checkpoint-response-result-v1",
        "request_digest_hex":hex(&message_digest(REQUEST_DOMAIN,&request)?),
        "root_signature_valid":true,"response_signature_valid":true})
    .to_string())
}
fn run() -> Result<(), ()> {
    let mut input = Vec::new();
    io::stdin()
        .lock()
        .take((MAX_REQUEST_BYTES + 1) as u64)
        .read_to_end(&mut input)
        .map_err(|_| ())?;
    let output = verify_request(&input)?;
    let mut writer = io::stdout().lock();
    writer.write_all(output.as_bytes()).map_err(|_| ())?;
    writer.write_all(b"\n").map_err(|_| ())?;
    writer.flush().map_err(|_| ())
}
fn main() {
    if run().is_err() {
        eprintln!("selected public checkpoint signature check refused");
        std::process::exit(1);
    }
}
