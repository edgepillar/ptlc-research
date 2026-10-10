//! Public-only fixed-recipient qualification. No private signing input or scalar output.
//! Locally selected messages, keys and terms provenance are the caller's obligation.

use musig2::{
    AdaptorSignature, BinaryEncoding, LiftedSignature, adaptor,
    secp::{MaybeScalar, Point},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::io::{self, Read, Write};

fn fields(value: &Value, expected: &[&str]) -> Result<(), ()> {
    let object = value.as_object().ok_or(())?;
    if object.len() != expected.len() || expected.iter().any(|key| !object.contains_key(*key)) {
        return Err(());
    }
    Ok(())
}
fn bytes(value: &Value, size: usize) -> Result<Vec<u8>, ()> {
    let text = value.as_str().ok_or(())?;
    if text.len() != 2 * size
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
fn hex(value: &[u8]) -> String {
    value.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn verify_request(input: &[u8]) -> Result<String, ()> {
    if input.len() > 8192 || !input.is_ascii() {
        return Err(());
    }
    let request: Value = serde_json::from_slice(input).map_err(|_| ())?;
    if serde_json::to_vec(&request).map_err(|_| ())? != input {
        return Err(());
    }
    fields(
        &request,
        &[
            "schema",
            "profile",
            "context_digest_hex",
            "mode",
            "adaptor_point_sec1_hex",
            "long",
            "short",
            "completion_hex",
        ],
    )?;
    if request["schema"] != "ptlc-nom-public-verification-v1"
        || request["profile"] != "zenon-ptlc-unlock:v1"
    {
        return Err(());
    }
    bytes(&request["context_digest_hex"], 32)?;
    let point_bytes = bytes(&request["adaptor_point_sec1_hex"], 33)?;
    let point = Point::from_slice(&point_bytes).map_err(|_| ())?;
    if point.serialize().as_slice() != point_bytes {
        return Err(());
    }
    let mut pairs = Vec::new();
    for leg in ["long", "short"] {
        let value = &request[leg];
        fields(value, &["key_xonly_hex", "message_hex", "presignature_hex"])?;
        let key = Point::lift_x(
            <[u8; 32]>::try_from(bytes(&value["key_xonly_hex"], 32)?).map_err(|_| ())?,
        )
        .map_err(|_| ())?;
        let message = bytes(&value["message_hex"], 32)?;
        let pre = AdaptorSignature::from_bytes(&bytes(&value["presignature_hex"], 65)?)
            .map_err(|_| ())?;
        adaptor::verify_single(key, &pre, &message, point).map_err(|_| ())?;
        pairs.push((key, message, pre));
    }
    if pairs[0].0 == pairs[1].0 || pairs[0].1 == pairs[1].1 {
        return Err(());
    }
    let mode = request["mode"].as_str().ok_or(())?;
    let mut result = String::new();
    if mode == "verify-pair" {
        if request["completion_hex"] != "" {
            return Err(());
        }
    } else {
        let index = match mode {
            "verify-long" => 0,
            "verify-short" | "recover-long" => 1,
            _ => return Err(()),
        };
        let completed =
            LiftedSignature::from_bytes(&bytes(&request["completion_hex"], 64)?).map_err(|_| ())?;
        let (key, message, pre) = &pairs[index];
        musig2::verify_single(*key, completed, message).map_err(|_| ())?;
        let witness = pre.reveal_secret::<MaybeScalar>(&completed).ok_or(())?;
        if witness.base_point_mul() != point.into() {
            return Err(());
        }
        if mode == "recover-long" {
            let long: LiftedSignature = pairs[0].2.adapt(witness).ok_or(())?;
            musig2::verify_single(pairs[0].0, long, &pairs[0].1).map_err(|_| ())?;
            result = hex(&long.to_bytes());
        }
    }
    let reply = json!({"schema":"ptlc-nom-public-verification-result-v1","request_digest_hex":hex(&Sha256::digest(input)),"valid":true,"completed_long_hex":result});
    serde_json::to_string(&reply).map_err(|_| ())
}

fn main() {
    let mut input = Vec::new();
    if io::stdin().take(8193).read_to_end(&mut input).is_err() {
        std::process::exit(2);
    }
    match verify_request(&input) {
        Ok(result) => {
            if io::stdout().write_all(result.as_bytes()).is_err() {
                std::process::exit(2);
            }
        }
        Err(()) => std::process::exit(2),
    }
}
