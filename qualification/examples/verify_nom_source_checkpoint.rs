//! Three public historical signatures under independently selected NoM roles.
//! This worker does not provision its packet root, open commitments, authenticate
//! chain facts, retain a nonrollback checkpoint, or admit application work.
use bitcoin::secp256k1::{Message, Secp256k1, XOnlyPublicKey, schnorr::Signature};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::io::{self, Read, Write};

pub const MAX_REQUEST_BYTES: usize = 8192;
const MAX_NUMBER: u64 = (1_u64 << 53) - 1;
const ROOT_KEY: &[u8] = b"ptlc-nom-selected-root-key-v1\0";
const DECLARATION: &[u8] = b"ptlc-nom-source-checkpoint-declaration-message-v1\0";
const SOURCE: &[u8] = b"ptlc-nom-historical-source-message-v1\0";
const CHECKPOINT: &[u8] = b"ptlc-nom-historical-custody-message-v1\0";
const REQUEST: &[u8] = b"ptlc-nom-source-checkpoint-request-v1\0";

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
fn number(value: &Value) -> Result<(), ()> {
    let number = value.as_u64().ok_or(())?;
    if number == 0 || number > MAX_NUMBER {
        return Err(());
    }
    Ok(())
}
fn hex(value: &[u8]) -> String {
    value.iter().map(|b| format!("{b:02x}")).collect()
}
fn hash_bytes(domain: &[u8], value: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(value);
    hash.finalize().into()
}
fn hash(domain: &[u8], value: &Value) -> Result<[u8; 32], ()> {
    Ok(hash_bytes(
        domain,
        &serde_json::to_vec(value).map_err(|_| ())?,
    ))
}
fn network(value: &Value, root: &[u8]) -> Result<(), ()> {
    fields(
        value,
        &[
            "schema",
            "core_commit",
            "chain_id",
            "genesis_hash_hex",
            "binary_digest_hex",
            "spork_state_digest_hex",
            "authority_id_hex",
            "authority_profile_digest_hex",
            "authority_incarnation_hex",
            "provisioning_root_digest_hex",
            "canonicality_policy_digest_hex",
            "finality_policy_digest_hex",
            "freshness_policy_digest_hex",
            "restore_policy_digest_hex",
        ],
    )?;
    fixed(
        value,
        &[
            ("schema", "ptlc-nom-network-selection-v1"),
            ("core_commit", "45e1bbb48ce6fc19d44c5fbf59ccf5784981fced"),
        ],
    )?;
    let chain = value["chain_id"].as_str().ok_or(())?;
    if chain.is_empty() || !chain.bytes().all(|c| c.is_ascii_digit()) {
        return Err(());
    }
    let parsed = chain.parse::<u64>().map_err(|_| ())?;
    if parsed == 0 || parsed.to_string() != chain {
        return Err(());
    }
    for field in [
        "genesis_hash_hex",
        "binary_digest_hex",
        "spork_state_digest_hex",
        "authority_id_hex",
        "authority_profile_digest_hex",
        "authority_incarnation_hex",
        "provisioning_root_digest_hex",
        "canonicality_policy_digest_hex",
        "finality_policy_digest_hex",
        "freshness_policy_digest_hex",
        "restore_policy_digest_hex",
    ] {
        bytes(&value[field], 32)?;
    }
    if value["provisioning_root_digest_hex"] != hex(&hash_bytes(ROOT_KEY, root)) {
        return Err(());
    }
    Ok(())
}
fn declaration(value: &Value) -> Result<[XOnlyPublicKey; 3], ()> {
    fields(
        value,
        &[
            "schema",
            "purpose",
            "algorithm",
            "declaration_epoch",
            "network_selection",
            "root_key_hex",
            "source_response_key_hex",
            "consumer_checkpoint_key_hex",
            "root_transition",
        ],
    )?;
    fixed(
        value,
        &[
            ("schema", "ptlc-nom-source-checkpoint-declaration-v1"),
            ("purpose", "historical-nom-source-and-custody-roles"),
            ("algorithm", "BIP340-SHA256"),
            ("root_transition", "independent-reprovisioning"),
        ],
    )?;
    number(&value["declaration_epoch"])?;
    let encodings = [
        &value["root_key_hex"],
        &value["source_response_key_hex"],
        &value["consumer_checkpoint_key_hex"],
    ];
    let mut keys = Vec::new();
    for (i, key) in encodings.iter().enumerate() {
        if encodings[..i].contains(key) {
            return Err(());
        }
        keys.push(XOnlyPublicKey::from_slice(&bytes(key, 32)?).map_err(|_| ())?);
    }
    network(&value["network_selection"], &bytes(encodings[0], 32)?)?;
    Ok([keys[0], keys[1], keys[2]])
}
fn statements(request: &Value) -> Result<(), ()> {
    let source = &request["source_statement"];
    fields(
        source,
        &[
            "schema",
            "purpose",
            "declaration_digest_hex",
            "binding_digest_hex",
            "query_digest_hex",
            "work_scope_digest_hex",
            "source_claim_digest_hex",
            "claim_coverage",
        ],
    )?;
    fixed(
        source,
        &[
            ("schema", "ptlc-nom-historical-source-statement-v1"),
            ("purpose", "historical-selected-capsule-source-claim"),
        ],
    )?;
    for field in [
        "declaration_digest_hex",
        "binding_digest_hex",
        "query_digest_hex",
        "work_scope_digest_hex",
        "source_claim_digest_hex",
    ] {
        bytes(&source[field], 32)?;
    }
    if ![
        "COMPLETE_CLAIM",
        "INCOMPLETE_CLAIM",
        "CONTRADICTED_CLAIM",
        "UNAVAILABLE_CLAIM",
    ]
    .contains(&source["claim_coverage"].as_str().ok_or(())?)
    {
        return Err(());
    }
    let checkpoint = &request["checkpoint_statement"];
    fields(
        checkpoint,
        &[
            "schema",
            "purpose",
            "declaration_digest_hex",
            "capsule_sha256",
            "journal_sha256",
            "journal_head_hex",
            "journal_sequence",
            "work_scope_digest_hex",
            "charged_work_digest_hex",
            "charged_work_count",
            "consumer_incarnation_hex",
            "observer_retention_selection_digest_hex",
            "observer_retention_head_digest_hex",
            "observer_retention_sequence",
            "external_checkpoint_digest_hex",
            "disclosure_possible",
            "work_outcome",
        ],
    )?;
    fixed(
        checkpoint,
        &[
            ("schema", "ptlc-nom-historical-custody-checkpoint-v1"),
            ("purpose", "historical-held-capsule-and-unknown-work"),
            ("work_outcome", "UNKNOWN"),
        ],
    )?;
    for field in [
        "declaration_digest_hex",
        "capsule_sha256",
        "journal_sha256",
        "journal_head_hex",
        "work_scope_digest_hex",
        "charged_work_digest_hex",
        "consumer_incarnation_hex",
        "observer_retention_selection_digest_hex",
        "observer_retention_head_digest_hex",
        "external_checkpoint_digest_hex",
    ] {
        bytes(&checkpoint[field], 32)?;
    }
    for field in [
        "journal_sequence",
        "charged_work_count",
        "observer_retention_sequence",
    ] {
        number(&checkpoint[field])?;
    }
    if checkpoint["disclosure_possible"] != true {
        return Err(());
    }
    let digest = hex(&hash(DECLARATION, &request["declaration"])?);
    if source["declaration_digest_hex"] != digest
        || checkpoint["declaration_digest_hex"] != digest
        || source["work_scope_digest_hex"] != checkpoint["work_scope_digest_hex"]
    {
        return Err(());
    }
    Ok(())
}
fn depth_bound(input: &[u8]) -> Result<(), ()> {
    let (mut depth, mut quoted, mut escaped) = (0_u8, false, false);
    for byte in input {
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

/// Exact public mathematics under packet keys, with no source or custody truth.
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
            "source_statement",
            "checkpoint_statement",
            "root_signature_hex",
            "source_signature_hex",
            "checkpoint_signature_hex",
        ],
    )?;
    fixed(
        &request,
        &[("schema", "ptlc-nom-source-checkpoint-request-v1")],
    )?;
    let keys = declaration(&request["declaration"])?;
    statements(&request)?;
    for (key, domain, payload, field) in [
        (&keys[0], DECLARATION, "declaration", "root_signature_hex"),
        (&keys[1], SOURCE, "source_statement", "source_signature_hex"),
        (
            &keys[2],
            CHECKPOINT,
            "checkpoint_statement",
            "checkpoint_signature_hex",
        ),
    ] {
        let signature = Signature::from_slice(&bytes(&request[field], 64)?).map_err(|_| ())?;
        Secp256k1::verification_only()
            .verify_schnorr(
                &signature,
                &Message::from_digest(hash(domain, &request[payload])?),
                key,
            )
            .map_err(|_| ())?;
    }
    Ok(json!({"schema":"ptlc-nom-source-checkpoint-result-v1", "request_digest_hex":hex(&hash(REQUEST, &request)?),
        "root_signature_valid":true, "source_signature_valid":true, "checkpoint_signature_valid":true}).to_string())
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
    if run().is_err() {
        std::process::exit(1);
    }
}
