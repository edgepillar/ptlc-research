//! Public toy witnesses for send-derived entry ids; no application signer.

#[allow(dead_code)]
#[path = "../examples/verify_nom_swap.rs"]
mod worker;
mod support {
    pub mod pr138;
}
use musig2::{
    BinaryEncoding, LiftedSignature, adaptor,
    secp::{MaybeScalar, Scalar},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use support::pr138::{bytes, hex, sha3};

fn corpus() -> Value {
    serde_json::from_str(include_str!(
        "../../compatibility/fixtures/nom_created_funding_v1.json"
    ))
    .unwrap()
}
fn toy(n: u8) -> Scalar {
    let mut public_constant = [0; 32];
    public_constant[31] = n;
    Scalar::from_slice(&public_constant).unwrap()
}
fn message(terms: &Value, leg: &str) -> [u8; 32] {
    let mut input = b"zenon-ptlc-unlock:v1".to_vec();
    input.extend(
        terms["chain_id"]
            .as_str()
            .unwrap()
            .parse::<u64>()
            .unwrap()
            .to_be_bytes(),
    );
    input.extend(bytes("01b3b6e5adcb4c15ff06318c6318c6318c6318c6"));
    input.push(1);
    input.extend(bytes(terms[leg]["entry_id_hex"].as_str().unwrap()));
    let role = terms[leg]["recipient"].as_str().unwrap();
    input.extend(bytes(
        terms[format!("{role}_address_hex")].as_str().unwrap(),
    ));
    sha3(&input)
}
fn completions() -> Value {
    let source = corpus();
    let terms = &source["terms"];
    let point = toy(3).base_point_mul();
    let messages = [message(terms, "long"), message(terms, "short")];
    let pres = [
        adaptor::sign_solo(toy(1), messages[0], [61; 32], point),
        adaptor::sign_solo(toy(2), messages[1], [62; 32], point),
    ];
    let short: LiftedSignature = pres[1].adapt(toy(3)).unwrap();
    let extracted = pres[1].reveal_secret::<MaybeScalar>(&short).unwrap();
    assert_eq!(extracted, toy(3).into());
    let long: LiftedSignature = pres[0].adapt(extracted).unwrap();
    for (index, leg) in ["long", "short"].iter().enumerate() {
        let key = toy(index as u8 + 1).base_point_mul();
        assert_eq!(
            hex(&key.serialize_xonly()),
            terms[*leg]["funder_key_xonly_hex"]
        );
        assert_eq!(
            terms[*leg]["entry_id_hex"],
            source["fundings"][*leg]["hash_hex"]
        );
        assert_ne!(
            terms[*leg]["entry_id_hex"],
            source["old_entry_ids_hex"][*leg]
        );
        adaptor::verify_single(key, &pres[index], messages[index], point).unwrap();
        musig2::verify_single(key, if index == 0 { long } else { short }, messages[index]).unwrap();
    }
    assert_eq!(hex(&point.serialize()), terms["adaptor_point_sec1_hex"]);
    json!({"schema":"ptlc-nom-created-public-completions-v1", "pair":{"schema":"ptlc-nom-public-pair-v1",
        "long_presignature_hex":hex(&pres[0].to_bytes()), "short_presignature_hex":hex(&pres[1].to_bytes())},
        "long_message_hex":hex(&messages[0]), "short_message_hex":hex(&messages[1]),
        "long_signature_hex":hex(&long.to_bytes()), "short_signature_hex":hex(&short.to_bytes())})
}
fn request(mode: &str, completion: &str) -> Value {
    let f = completions();
    let terms = corpus()["terms"].clone();
    let mut hash = Sha256::new();
    hash.update(b"ptlc-nom-verification-context-v1\0");
    hash.update(serde_json::to_vec(&json!({"terms":terms,"pair":f["pair"]})).unwrap());
    let mut result = json!({"schema":"ptlc-nom-public-verification-v1", "profile":"zenon-ptlc-unlock:v1",
        "context_digest_hex":hex(&hash.finalize()), "mode":mode, "completion_hex":completion,
        "adaptor_point_sec1_hex":terms["adaptor_point_sec1_hex"]});
    for leg in ["long", "short"] {
        result[leg] = json!({"key_xonly_hex":terms[leg]["funder_key_xonly_hex"],
            "message_hex":f[format!("{leg}_message_hex")], "presignature_hex":f["pair"][format!("{leg}_presignature_hex")]});
    }
    result
}
fn verify(input: &Value) -> Result<Value, ()> {
    serde_json::from_str(&worker::verify_request(
        &serde_json::to_vec(input).unwrap(),
    )?)
    .map_err(|_| ())
}

#[test]
fn created_funding_public_witnesses_are_reproducible_and_recover_the_exact_long_completion() {
    let f = completions();
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../compatibility/fixtures/nom_created_completions_v1.json");
    if std::env::var("PTLC_REGENERATE_CREATED_PUBLIC_V1") == Ok("1".to_string()) {
        std::fs::write(
            &path,
            format!("{}\n", serde_json::to_string_pretty(&f).unwrap()),
        )
        .unwrap();
    }
    let retained: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(retained, f);
    verify(&request("verify-pair", "")).unwrap();
    for leg in ["long", "short"] {
        verify(&request(
            &format!("verify-{leg}"),
            f[format!("{leg}_signature_hex")].as_str().unwrap(),
        ))
        .unwrap();
    }
    let result = verify(&request(
        "recover-long",
        f["short_signature_hex"].as_str().unwrap(),
    ))
    .unwrap();
    assert_eq!(result["completed_long_hex"], f["long_signature_hex"]);
    assert_eq!(result.as_object().unwrap().len(), 4); // no scalar returned
}

#[test]
fn created_funding_refuses_old_ids_cross_leg_witnesses_and_unrelated_valid_completions() {
    let f = completions();
    let old: Value = serde_json::from_str(include_str!(
        "../../compatibility/fixtures/nom_completions_v1.json"
    ))
    .unwrap();
    for leg in ["long", "short"] {
        let selected = request(
            &format!("verify-{leg}"),
            f[format!("{leg}_signature_hex")].as_str().unwrap(),
        );
        for replacement in [
            old[format!("{leg}_signature_hex")].clone(),
            f[format!(
                "{}_signature_hex",
                if leg == "long" { "short" } else { "long" }
            )]
            .clone(),
        ] {
            let mut changed = selected.clone();
            changed["completion_hex"] = replacement;
            assert!(verify(&changed).is_err());
        }
    }
    let message = message(&corpus()["terms"], "short");
    let unrelated = adaptor::sign_solo(toy(2), message, [99; 32], toy(3).base_point_mul());
    let completed: LiftedSignature = unrelated.adapt(toy(3)).unwrap();
    musig2::verify_single(toy(2).base_point_mul(), completed, message).unwrap();
    assert!(verify(&request("recover-long", &hex(&completed.to_bytes()))).is_err());
}

#[test]
fn created_funding_mutated_contexts_refuse_the_selected_public_witness() {
    let f = completions();
    for leg in ["long", "short"] {
        for field in ["chain_id", "entry_id_hex", "destination"] {
            let mut terms = corpus()["terms"].clone();
            match field {
                "chain_id" => terms[field] = json!("70"),
                "entry_id_hex" => terms[leg][field] = corpus()["old_entry_ids_hex"][leg].clone(),
                _ => {
                    let role = terms[leg]["recipient"].as_str().unwrap().to_string();
                    terms[format!("{role}_address_hex")] =
                        json!("0033333333333333333333333333333333333333");
                }
            }
            let key = toy(if leg == "long" { 1 } else { 2 }).base_point_mul();
            let signature = LiftedSignature::from_bytes(&bytes(
                f[format!("{leg}_signature_hex")].as_str().unwrap(),
            ))
            .unwrap();
            assert!(
                musig2::verify_single(key, signature, message(&terms, leg)).is_err(),
                "{field}"
            );
        }
    }
}
