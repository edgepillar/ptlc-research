//! Synthetic two-funder adaptor qualification; no private application signer.

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

fn terms() -> Value {
    serde_json::from_str(include_str!(
        "../../compatibility/fixtures/nom_terms_v1.json"
    ))
    .unwrap()
}
fn message(terms: &Value, leg: &str) -> [u8; 32] {
    let mut wire = b"zenon-ptlc-unlock:v1".to_vec();
    wire.extend(
        terms["chain_id"]
            .as_str()
            .unwrap()
            .parse::<u64>()
            .unwrap()
            .to_be_bytes(),
    );
    wire.extend(bytes("01b3b6e5adcb4c15ff06318c6318c6318c6318c6"));
    wire.push(1);
    wire.extend(bytes(terms[leg]["entry_id_hex"].as_str().unwrap()));
    let recipient = terms[leg]["recipient"].as_str().unwrap();
    wire.extend(bytes(
        terms[format!("{recipient}_address_hex")].as_str().unwrap(),
    ));
    sha3(&wire)
}
fn scalar(n: u8) -> Scalar {
    let mut b = [0; 32];
    b[31] = n;
    Scalar::from_slice(&b).unwrap()
}
fn fixture() -> Value {
    let terms = terms();
    let witness = scalar(3);
    let point = witness.base_point_mul();
    let messages = [message(&terms, "long"), message(&terms, "short")];
    let pres = [
        adaptor::sign_solo(scalar(1), messages[0], [31; 32], point),
        adaptor::sign_solo(scalar(2), messages[1], [32; 32], point),
    ];
    let short: LiftedSignature = pres[1].adapt(witness).unwrap();
    let extracted = pres[1].reveal_secret::<MaybeScalar>(&short).unwrap();
    assert_eq!(extracted, witness.into());
    let long: LiftedSignature = pres[0].adapt(extracted).unwrap();
    for (i, leg) in ["long", "short"].iter().enumerate() {
        let key = scalar(i as u8 + 1).base_point_mul();
        assert_eq!(
            hex(&key.serialize_xonly()),
            terms[*leg]["funder_key_xonly_hex"]
        );
        adaptor::verify_single(key, &pres[i], messages[i], point).unwrap();
        musig2::verify_single(key, if i == 0 { long } else { short }, messages[i]).unwrap();
    }
    assert_eq!(hex(&point.serialize()), terms["adaptor_point_sec1_hex"]);
    json!({"schema":"ptlc-nom-public-completions-v1","pair":{"schema":"ptlc-nom-public-pair-v1","long_presignature_hex":hex(&pres[0].to_bytes()),"short_presignature_hex":hex(&pres[1].to_bytes())},"long_message_hex":hex(&messages[0]),"short_message_hex":hex(&messages[1]),"long_signature_hex":hex(&long.to_bytes()),"short_signature_hex":hex(&short.to_bytes())})
}
fn request(mode: &str, completion: &str) -> Value {
    let f = fixture();
    let terms = terms();
    let selection = json!({"terms":terms,"pair":f["pair"]});
    let mut h = Sha256::new();
    h.update(b"ptlc-nom-verification-context-v1\0");
    h.update(serde_json::to_vec(&selection).unwrap());
    let mut r = json!({"schema":"ptlc-nom-public-verification-v1","profile":"zenon-ptlc-unlock:v1","context_digest_hex":hex(&h.finalize()),"mode":mode,"completion_hex":completion,"adaptor_point_sec1_hex":terms["adaptor_point_sec1_hex"]});
    for leg in ["long", "short"] {
        r[leg] = json!({"key_xonly_hex":terms[leg]["funder_key_xonly_hex"],"message_hex":f[format!("{leg}_message_hex")],"presignature_hex":f["pair"][format!("{leg}_presignature_hex")]});
    }
    r
}
fn verify(r: &Value) -> Result<Value, ()> {
    serde_json::from_str(&worker::verify_request(&serde_json::to_vec(r).unwrap())?).map_err(|_| ())
}

#[test]
fn synthetic_fixed_recipient_fixture_and_public_recovery_are_reproducible() {
    let f = fixture();
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../compatibility/fixtures/nom_completions_v1.json");
    if std::env::var("PTLC_REGENERATE_PUBLIC_NOM_V1") == Ok("1".to_string()) {
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
    assert_eq!(result.as_object().unwrap().len(), 4); // no extracted scalar field
}

#[test]
fn public_worker_refuses_cross_leg_replays_wrong_points_and_unrelated_valid_signatures() {
    let f = fixture();
    let valid = request("recover-long", f["short_signature_hex"].as_str().unwrap());
    for (field, value) in [
        ("profile", json!("zenon-ptlc-unlock:v2")),
        ("mode", json!("sign")),
        (
            "adaptor_point_sec1_hex",
            json!(hex(&scalar(4).base_point_mul().serialize())),
        ),
        ("completion_hex", f["long_signature_hex"].clone()),
    ] {
        let mut changed = valid.clone();
        changed[field] = value;
        assert!(verify(&changed).is_err(), "{field}");
    }
    for field in ["key_xonly_hex", "message_hex", "presignature_hex"] {
        let mut changed = valid.clone();
        changed["short"][field] = changed["long"][field].clone();
        assert!(verify(&changed).is_err(), "{field}");
    }
    let msg = message(&terms(), "short");
    let other = adaptor::sign_solo(scalar(2), msg, [99; 32], scalar(3).base_point_mul());
    let unrelated: LiftedSignature = other.adapt(scalar(3)).unwrap();
    musig2::verify_single(scalar(2).base_point_mul(), unrelated, msg).unwrap();
    let mut changed = valid.clone();
    changed["completion_hex"] = json!(hex(&unrelated.to_bytes()));
    assert!(
        verify(&changed).is_err(),
        "ordinary validity is insufficient for extraction from a different pre-signature"
    );
    let mut unknown = valid.clone();
    unknown["extra"] = json!(true);
    assert!(verify(&unknown).is_err());
    let canonical = serde_json::to_vec(&valid).unwrap();
    let mut whitespace = b" ".to_vec();
    whitespace.extend(canonical);
    assert!(worker::verify_request(&whitespace).is_err());
    assert!(worker::verify_request(&vec![b' '; 8193]).is_err());
}
