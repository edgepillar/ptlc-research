//! Public-only historical original-read mathematics under an exact root role.
//! No caller authentication, old-profile provenance, live source or use exists.
#[allow(dead_code)]
#[path = "verify_source_root.rs"]
mod root;
use bitcoin::secp256k1::{Message, Secp256k1, XOnlyPublicKey, schnorr::Signature};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::io::{self, Read, Write};

pub const MAX_REQUEST_BYTES: usize = 16384;
const MAX_NUMBER: u64 = (1_u64 << 53) - 1;
const TAG: &[u8] = b"PTLC/observation-original-read-response/v1";
const REQUEST: &[u8] = b"PTLC/observation-original-read-response-request/v1\0";
const DECLARATION: &[u8] = b"PTLC/observation-source-root-declaration/v1\0";
const QUERY: &[u8] = b"PTLC/observation-original-read-query/v1\0";
const CLAIM: &[u8] = b"PTLC/observation-original-read-claim/v1\0";
const SOURCE: &[u8] = b"PTLC/observation-policy-source-context/v1\0";

fn fields(v: &Value, expected: &[&str]) -> Result<(), ()> {
    let o = v.as_object().ok_or(())?;
    if o.len() != expected.len() || !expected.iter().all(|f| o.contains_key(*f)) {
        return Err(());
    }
    Ok(())
}
fn fixed(v: &Value, expected: &[(&str, &str)]) -> Result<(), ()> {
    for (f, text) in expected {
        if v[*f].as_str().ok_or(())? != *text {
            return Err(());
        }
    }
    Ok(())
}
fn bytes(v: &Value, size: usize) -> Result<Vec<u8>, ()> {
    let s = v.as_str().ok_or(())?;
    if s.len() != 2 * size
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(());
    }
    s.as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).map_err(|_| ())?, 16).map_err(|_| ()))
        .collect()
}
fn number(v: &Value, min: u64, max: u64) -> Result<u64, ()> {
    let n = v.as_u64().ok_or(())?;
    if n < min || n > max {
        return Err(());
    }
    Ok(n)
}
fn hash(domain: &[u8], v: &Value) -> Result<[u8; 32], ()> {
    let mut h = Sha256::new();
    h.update(domain);
    h.update(serde_json::to_vec(v).map_err(|_| ())?);
    Ok(h.finalize().into())
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|v| format!("{v:02x}")).collect()
}
fn matching_hash(value: &Value, domain: &[u8], body: &Value) -> Result<(), ()> {
    if bytes(value, 32)?.as_slice() != hash(domain, body)? {
        return Err(());
    }
    Ok(())
}
fn message(v: &Value) -> Result<[u8; 32], ()> {
    let tag = Sha256::digest(TAG);
    let mut h = Sha256::new();
    h.update(tag);
    h.update(tag);
    h.update(serde_json::to_vec(v).map_err(|_| ())?);
    Ok(h.finalize().into())
}
fn profile(v: &Value) -> Result<(), ()> {
    fields(
        v,
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
        v,
        &[
            ("schema", "ptlc-observation-governor-profile-v1"),
            ("purpose", "observation-enrollment"),
            ("role", "enrollment-governor"),
            ("algorithm", "BIP340-SHA256"),
        ],
    )?;
    for f in [
        "owner_auth_key_hex",
        "resource_digest_hex",
        "authority_id_hex",
        "authority_profile_digest_hex",
        "verifier_profile_digest_hex",
        "pool_profile_digest_hex",
        "resource_profile_digest_hex",
    ] {
        bytes(&v[f], 32)?;
    }
    number(&v["authority_epoch"], 1, MAX_NUMBER)?;
    number(&v["max_attempt_limit"], 1, 64)?;
    number(&v["max_target_limit"], 1, 64)?;
    // Public curve membership is not an owner signature or possession proof.
    XOnlyPublicKey::from_slice(&bytes(&v["owner_auth_key_hex"], 32)?).map_err(|_| ())?;
    Ok(())
}
fn checkpoint(v: &Value) -> Result<u64, ()> {
    fields(v, &["revision", "policy_state_digest_hex"])?;
    bytes(&v["policy_state_digest_hex"], 32)?;
    number(&v["revision"], 0, MAX_NUMBER)
}
fn record_checkpoint(v: &Value) -> Result<u64, ()> {
    fields(
        v,
        &[
            "retention_rule",
            "event_sequence",
            "record_lineage_digest_hex",
        ],
    )?;
    fixed(
        v,
        &[("retention_rule", "retained-all-originals-in-incarnation-v1")],
    )?;
    bytes(&v["record_lineage_digest_hex"], 32)?;
    number(&v["event_sequence"], 0, MAX_NUMBER)
}
fn query(q: &Value, d: &Value) -> Result<(), ()> {
    fields(
        q,
        &[
            "schema",
            "operation",
            "read_rule",
            "root_declaration_digest_hex",
            "source_context",
            "expected_checkpoint",
            "expected_record_checkpoint",
            "challenge_hex",
            "original_operation",
        ],
    )?;
    fixed(
        q,
        &[
            ("schema", "ptlc-observation-original-read-query-v1"),
            ("operation", "read-original-at-checkpoint"),
            ("read_rule", "same-incarnation-original-lookup-v1"),
        ],
    )?;
    matching_hash(&q["root_declaration_digest_hex"], DECLARATION, d)?;
    if q["source_context"] != d["source_context"] {
        return Err(());
    }
    bytes(&q["challenge_hex"], 32)?;
    let revision = checkpoint(&q["expected_checkpoint"])?;
    record_checkpoint(&q["expected_record_checkpoint"])?;
    let o = &q["original_operation"];
    fields(
        o,
        &[
            "schema",
            "operation_id_hex",
            "expected_revision",
            "governor_profile",
            "proposal_digest_hex",
        ],
    )?;
    fixed(o, &[("schema", "ptlc-observation-original-operation-v1")])?;
    bytes(&o["operation_id_hex"], 32)?;
    bytes(&o["proposal_digest_hex"], 32)?;
    let old_revision = number(&o["expected_revision"], 0, MAX_NUMBER)?;
    profile(&o["governor_profile"])?;
    for f in ["authority_id_hex", "resource_digest_hex", "role"] {
        if o["governor_profile"][f] != d["source_context"][f] {
            return Err(());
        }
    }
    if old_revision > revision
        || (old_revision == revision && o["governor_profile"] != d["governor_profile"])
    {
        return Err(());
    }
    Ok(())
}
fn claim(c: &Value, q: &Value, d: &Value) -> Result<(), ()> {
    fields(
        c,
        &[
            "schema",
            "query_digest_hex",
            "root_declaration_digest_hex",
            "source_context_digest_hex",
            "challenge_hex",
            "observation",
            "claimed_checkpoint",
            "claimed_record_checkpoint",
            "head_policy",
            "original_record",
        ],
    )?;
    fixed(c, &[("schema", "ptlc-observation-original-read-claim-v1")])?;
    matching_hash(&c["query_digest_hex"], QUERY, q)?;
    matching_hash(
        &c["source_context_digest_hex"],
        SOURCE,
        &q["source_context"],
    )?;
    if c["root_declaration_digest_hex"] != q["root_declaration_digest_hex"]
        || c["challenge_hex"] != q["challenge_hex"]
    {
        return Err(());
    }
    let state = c["observation"].as_str().ok_or(())?;
    if state == "unavailable" {
        if [
            "claimed_checkpoint",
            "claimed_record_checkpoint",
            "head_policy",
            "original_record",
        ]
        .iter()
        .any(|f| !c[*f].is_null())
        {
            return Err(());
        }
        return Ok(());
    }
    checkpoint(&c["claimed_checkpoint"])?;
    let sequence = record_checkpoint(&c["claimed_record_checkpoint"])?;
    if c["claimed_checkpoint"] != q["expected_checkpoint"]
        || c["claimed_record_checkpoint"] != q["expected_record_checkpoint"]
    {
        return Err(());
    }
    fields(&c["head_policy"], &["governor_profile", "active"])?;
    c["head_policy"]["active"].as_bool().ok_or(())?;
    if c["head_policy"]["governor_profile"] != d["governor_profile"] {
        return Err(());
    }
    if state == "absent" {
        return if c["original_record"].is_null() {
            Ok(())
        } else {
            Err(())
        };
    }
    let r = &c["original_record"];
    fields(
        r,
        &["original_operation", "charge_sequence", "effect_sequence"],
    )?;
    if r["original_operation"] != q["original_operation"] {
        return Err(());
    }
    let charge = number(&r["charge_sequence"], 1, sequence)?;
    match state {
        "pending" if r["effect_sequence"].is_null() => Ok(()),
        "completed" => {
            number(&r["effect_sequence"], charge + 1, sequence)?;
            Ok(())
        }
        _ => Err(()),
    }
}

pub fn verify_request(input: &[u8]) -> Result<String, ()> {
    if input.is_empty() || input.len() > MAX_REQUEST_BYTES || !input.is_ascii() {
        return Err(());
    }
    let input = input.strip_suffix(b"\n").unwrap_or(input);
    let packet: Value = serde_json::from_slice(input).map_err(|_| ())?;
    if serde_json::to_vec(&packet).map_err(|_| ())? != input {
        return Err(());
    }
    fields(
        &packet,
        &[
            "schema",
            "root_envelope",
            "response",
            "response_signature_hex",
        ],
    )?;
    fixed(
        &packet,
        &[(
            "schema",
            "ptlc-observation-original-read-response-request-v1",
        )],
    )?;
    let envelope = &packet["root_envelope"];
    fields(envelope, &["schema", "declaration", "root_signature_hex"])?;
    fixed(
        envelope,
        &[("schema", "ptlc-observation-source-root-envelope-v1")],
    )?;
    let mut root_request = envelope.clone();
    root_request["schema"] = json!("ptlc-observation-source-root-request-v1");
    root::verify_request(&serde_json::to_vec(&root_request).map_err(|_| ())?)?;
    let d = &envelope["declaration"];
    let r = &packet["response"];
    fields(
        r,
        &[
            "schema",
            "purpose",
            "algorithm",
            "read_rule",
            "root_declaration_digest_hex",
            "source_response_role",
            "source_response_key_hex",
            "source_context",
            "query",
            "claim",
            "claim_digest_hex",
        ],
    )?;
    fixed(
        r,
        &[
            ("schema", "ptlc-observation-original-read-response-v1"),
            ("purpose", "original-checkpoint-response"),
            ("algorithm", "BIP340-SHA256"),
            ("read_rule", "historical-original-checkpoint-read-v1"),
            ("source_response_role", "historical-original-responder"),
        ],
    )?;
    matching_hash(&r["root_declaration_digest_hex"], DECLARATION, d)?;
    if r["source_response_key_hex"] != d["delegated_keys"]["source_response_key_hex"]
        || r["source_context"] != d["source_context"]
    {
        return Err(());
    }
    query(&r["query"], d)?;
    claim(&r["claim"], &r["query"], d)?;
    matching_hash(&r["claim_digest_hex"], CLAIM, &r["claim"])?;
    let key =
        XOnlyPublicKey::from_slice(&bytes(&r["source_response_key_hex"], 32)?).map_err(|_| ())?;
    let signature =
        Signature::from_slice(&bytes(&packet["response_signature_hex"], 64)?).map_err(|_| ())?;
    Secp256k1::verification_only()
        .verify_schnorr(&signature, &Message::from_digest(message(r)?), &key)
        .map_err(|_| ())?;
    let result = json!({"schema":"ptlc-observation-original-read-response-result-v1", "request_digest_hex":hex(&hash(REQUEST, &packet)?), "root_signature_valid":true,"response_signature_valid":true});
    Ok(serde_json::to_string(&result).map_err(|_| ())? + "\n")
}
fn run() -> Result<(), ()> {
    let mut input = Vec::new();
    io::stdin()
        .take((MAX_REQUEST_BYTES + 1) as u64)
        .read_to_end(&mut input)
        .map_err(|_| ())?;
    io::stdout()
        .write_all(verify_request(&input)?.as_bytes())
        .map_err(|_| ())
}
fn main() {
    std::panic::set_hook(Box::new(|_| {}));
    if run().is_err() {
        std::process::exit(1);
    }
}
