//! Public checkpoint-response mathematics; no source service or current oracle.
#[allow(dead_code)]
#[path = "verify_governor.rs"]
mod governor;
#[allow(dead_code)]
#[path = "verify_source_root.rs"]
mod root;
use bitcoin::secp256k1::{Message, Secp256k1, XOnlyPublicKey, schnorr::Signature};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::io::{self, Read, Write};

pub const MAX_REQUEST_BYTES: usize = 16384;
const RESPONSE: &[u8] = b"PTLC/observation-source-response/v1\0";
const REQUEST: &[u8] = b"PTLC/observation-source-response-request/v1\0";
const SOURCE: &[u8] = b"PTLC/observation-policy-source-context/v1\0";
const QUERY: &[u8] = b"PTLC/observation-policy-read-query/v1\0";
const CLAIM: &[u8] = b"PTLC/observation-policy-read-claim/v1\0";
const DECLARATION: &[u8] = b"PTLC/observation-source-root-declaration/v1\0";
const BINDING: [&str; 7] = [
    "session_id",
    "terms_digest_hex",
    "bitcoin_context_digest_hex",
    "zenon_context_digest_hex",
    "bitcoin_bundle_digest_hex",
    "zenon_bundle_digest_hex",
    "release_digest_hex",
];
const PINS: [&str; 6] = [
    "authority_id_hex",
    "authority_epoch",
    "authority_profile_digest_hex",
    "verifier_profile_digest_hex",
    "pool_profile_digest_hex",
    "resource_profile_digest_hex",
];
fn fields(v: &Value, expected: &[&str]) -> Result<(), ()> {
    let o = v.as_object().ok_or(())?;
    if o.len() != expected.len() || !expected.iter().all(|f| o.contains_key(*f)) {
        return Err(());
    }
    Ok(())
}
fn fixed(v: &Value, expected: &[(&str, &str)]) -> Result<(), ()> {
    for (f, t) in expected {
        if v[*f].as_str().ok_or(())? != *t {
            return Err(());
        }
    }
    Ok(())
}
fn bytes(v: &Value, size: usize) -> Result<Vec<u8>, ()> {
    let s = v.as_str().ok_or(())?;
    if s.len() != size * 2
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
fn hash(domain: &[u8], v: &Value) -> Result<[u8; 32], ()> {
    let mut h = Sha256::new();
    h.update(domain);
    h.update(serde_json::to_vec(v).map_err(|_| ())?);
    Ok(h.finalize().into())
}
fn hex(v: &[u8]) -> String {
    v.iter().map(|b| format!("{b:02x}")).collect()
}
fn matches_hash(v: &Value, domain: &[u8], body: &Value) -> Result<(), ()> {
    if bytes(v, 32)? != hash(domain, body)? {
        return Err(());
    }
    Ok(())
}
fn number(v: &Value, min: u64, max: u64) -> Result<u64, ()> {
    let n = v.as_u64().ok_or(())?;
    if n < min || n > max {
        return Err(());
    }
    Ok(n)
}
fn checkpoint(v: &Value) -> Result<(), ()> {
    fields(v, &["revision", "policy_state_digest_hex"])?;
    number(&v["revision"], 0, (1_u64 << 53) - 1)?;
    bytes(&v["policy_state_digest_hex"], 32)?;
    Ok(())
}
fn query(v: &Value, d: &Value) -> Result<(), ()> {
    fields(
        v,
        &[
            "schema",
            "operation",
            "source_context",
            "expected_checkpoint",
            "challenge_hex",
            "governor_signature_request",
            "decoded_scope",
            "retained_resource",
        ],
    )?;
    fixed(
        v,
        &[
            ("schema", "ptlc-observation-policy-read-query-v1"),
            ("operation", "read-assignment-at-checkpoint"),
        ],
    )?;
    if v["source_context"] != d["source_context"] {
        return Err(());
    }
    checkpoint(&v["expected_checkpoint"])?;
    bytes(&v["challenge_hex"], 32)?;
    let g = &v["governor_signature_request"];
    // Reuse the retained full issuer and v2 owner checks, without provisioning.
    governor::verify_request(&serde_json::to_vec(g).map_err(|_| ())?)?;
    let p = &d["governor_profile"];
    let a = &g["assignment"];
    let i = &g["bound_intent"];
    if a["governor_profile"] != *p
        || a["issuer_auth_key_hex"] != d["delegated_keys"]["governor_issuer_key_hex"]
    {
        return Err(());
    }
    let s = &v["decoded_scope"];
    let r = &v["retained_resource"];
    let mut sf = vec![
        "schema",
        "predicate",
        "authority_id_hex",
        "enrollment_id_hex",
        "authority_epoch",
        "authority_profile_digest_hex",
        "verifier_profile_digest_hex",
        "pool_profile_digest_hex",
        "resource_profile_digest_hex",
        "attempt_limit",
        "target_limit",
    ];
    sf.extend(BINDING);
    fields(s, &sf)?;
    fixed(
        s,
        &[
            ("schema", "ptlc-observation-authority-scope-v1"),
            ("predicate", "zenon-completion-v1"),
        ],
    )?;
    for f in sf.iter().skip(2) {
        if *f != "authority_epoch" && *f != "attempt_limit" && *f != "target_limit" {
            bytes(&s[*f], 32)?;
        }
    }
    number(&s["authority_epoch"], 1, (1_u64 << 53) - 1)?;
    for (f, cap) in [
        ("attempt_limit", "max_attempt_limit"),
        ("target_limit", "max_target_limit"),
    ] {
        number(&s[f], 1, p[cap].as_u64().ok_or(())?)?;
    }
    for f in PINS {
        if s[f] != p[f] {
            return Err(());
        }
    }
    let mut rf = vec!["schema", "predicate", "resource_kind"];
    rf.extend(BINDING);
    fields(r, &rf)?;
    fixed(
        r,
        &[
            ("schema", "ptlc-observation-retained-resource-v1"),
            ("predicate", "zenon-completion-v1"),
            ("resource_kind", "exact-paired-release-v1"),
        ],
    )?;
    for f in BINDING {
        bytes(&r[f], 32)?;
        if r[f] != s[f] {
            return Err(());
        }
    }
    matches_hash(
        &i["scope_digest_hex"],
        b"PTLC/observation-authority-scope/v1\0",
        s,
    )?;
    matches_hash(
        &i["resource_digest_hex"],
        b"PTLC/observation-retained-resource/v1\0",
        r,
    )?;
    Ok(())
}
fn claim(v: &Value, q: &Value) -> Result<(), ()> {
    fields(
        v,
        &[
            "schema",
            "query_digest_hex",
            "source_context_digest_hex",
            "challenge_hex",
            "observation",
            "claimed_checkpoint",
            "assignment_digest_hex",
        ],
    )?;
    fixed(v, &[("schema", "ptlc-observation-policy-read-claim-v1")])?;
    matches_hash(&v["query_digest_hex"], QUERY, q)?;
    matches_hash(
        &v["source_context_digest_hex"],
        SOURCE,
        &q["source_context"],
    )?;
    if v["challenge_hex"] != q["challenge_hex"] {
        return Err(());
    }
    let head = &v["claimed_checkpoint"];
    let assignment = &v["assignment_digest_hex"];
    match v["observation"].as_str().ok_or(())? {
        "unavailable" => {
            if !head.is_null() || !assignment.is_null() {
                return Err(());
            }
        }
        observation @ ("active" | "revoked" | "absent") => {
            checkpoint(head)?;
            if *head != q["expected_checkpoint"] {
                return Err(());
            }
            if observation == "absent" {
                if !assignment.is_null() {
                    return Err(());
                }
            } else {
                bytes(assignment, 32)?;
                if *assignment
                    != q["governor_signature_request"]["bound_intent"]["governor_assignment_digest_hex"]
                {
                    return Err(());
                }
            }
        }
        _ => return Err(()),
    }
    Ok(())
}
fn response(v: &Value, d: &Value) -> Result<XOnlyPublicKey, ()> {
    fields(
        v,
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
        v,
        &[
            ("schema", "ptlc-observation-source-response-v1"),
            ("purpose", "source-checkpoint-response"),
            ("algorithm", "BIP340-SHA256"),
            ("read_rule", "exact-profile-checkpoint-read-v1"),
            ("source_response_role", "checkpoint-responder"),
        ],
    )?;
    matches_hash(&v["root_declaration_digest_hex"], DECLARATION, d)?;
    if v["source_response_key_hex"] != d["delegated_keys"]["source_response_key_hex"]
        || v["source_context"] != d["source_context"]
    {
        return Err(());
    }
    query(&v["query"], d)?;
    claim(&v["claim"], &v["query"])?;
    matches_hash(&v["claim_digest_hex"], CLAIM, &v["claim"])?;
    XOnlyPublicKey::from_slice(&bytes(&v["source_response_key_hex"], 32)?).map_err(|_| ())
}
/// Check packet mathematics only; root, history and claims can be self-selected.
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
        &[
            "schema",
            "root_envelope",
            "response",
            "response_signature_hex",
        ],
    )?;
    fixed(
        &request,
        &[("schema", "ptlc-observation-source-response-request-v1")],
    )?;
    let mut s = request["root_envelope"].clone();
    fields(&s, &["schema", "declaration", "root_signature_hex"])?;
    fixed(
        &s,
        &[("schema", "ptlc-observation-source-root-envelope-v1")],
    )?;
    s["schema"] = json!("ptlc-observation-source-root-request-v1");
    root::verify_request(&serde_json::to_vec(&s).map_err(|_| ())?)?;
    let key = response(&request["response"], &s["declaration"])?;
    let signature =
        Signature::from_slice(&bytes(&request["response_signature_hex"], 64)?).map_err(|_| ())?;
    Secp256k1::verification_only()
        .verify_schnorr(
            &signature,
            &Message::from_digest(hash(RESPONSE, &request["response"])?),
            &key,
        )
        .map_err(|_| ())?;
    Ok(json!({"schema":"ptlc-observation-source-response-result-v1","request_digest_hex":hex(&hash(REQUEST,&request)?),"root_signature_valid":true,"issuer_signature_valid":true,"owner_signature_valid":true,"response_signature_valid":true}).to_string())
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
