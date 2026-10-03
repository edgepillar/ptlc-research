//! Test-only ephemeral ownership. Public fixed seeds are deliberately unsafe for funds.
//! No secret serialization, production API, journal bridge, or zeroization claim.

use std::thread::{self, ThreadId};

use musig2::{
    AggNonce, BinaryEncoding, KeyAggContext, LiftedSignature, PartialSignature, PubNonce, SecNonce,
    adaptor,
    secp::{MaybeScalar, Point, Scalar},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn bytes(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn scalar(tag: u8) -> Scalar {
    Scalar::from_slice(&[tag; 32]).unwrap()
}

fn digest(payload: &Value) -> String {
    let stage = payload["stage"].as_str().unwrap();
    let mut hash = Sha256::new();
    hash.update(b"PTLC/offline-transcript/v1\0");
    hash.update(stage.as_bytes());
    hash.update(b"\0");
    hash.update(serde_json::to_vec(payload).unwrap());
    hex(&hash.finalize())
}

fn bindings() -> [Value; 2] {
    let data: Value =
        serde_json::from_str(include_str!("../../tests/fixtures/session_terms.json")).unwrap();
    let base = |stage: &str| {
        json!({
            "schema": "ptlc-offline-transcript-v1", "stage": stage,
            "session_id": data["terms"]["session_id"]
        })
    };
    let mut terms = base("terms");
    terms["terms"] = data["terms"].clone();
    let mut btc = base("bitcoin");
    btc["terms"] = data["terms"].clone();
    btc["terms_digest_hex"] = json!(digest(&terms));
    btc["binding"] = data["bitcoin_binding"].clone();
    let mut znn = base("zenon");
    znn["bitcoin"] = btc.clone();
    znn["bitcoin_digest_hex"] = json!(digest(&btc));
    znn["binding"] = data["zenon_binding"].clone();
    [btc, znn]
}

#[derive(Clone)]
struct Context {
    binding: Value,
    round_id: String,
    keys: KeyAggContext,
    message: [u8; 32],
    adaptor: Point,
}

impl Context {
    fn new(leg: usize) -> Self {
        let binding = bindings()[leg].clone();
        let mut keys = KeyAggContext::new([
            scalar(1 + leg as u8 * 2).base_point_mul(),
            scalar(2 + leg as u8 * 2).base_point_mul(),
        ])
        .unwrap();
        if leg == 0 {
            let root: [u8; 32] = bytes(
                binding["terms"]["bitcoin"]["tapleaf_hash_hex"]
                    .as_str()
                    .unwrap(),
            )
            .try_into()
            .unwrap();
            keys = keys.with_taproot_tweak(&root).unwrap();
        }
        let field = if leg == 0 {
            "claim_sighash_hex"
        } else {
            "message_hex"
        };
        let message = bytes(binding["binding"][field].as_str().unwrap())
            .try_into()
            .unwrap();
        let terms = if leg == 0 {
            &binding["terms"]
        } else {
            &binding["bitcoin"]["terms"]
        };
        let leg_name = if leg == 0 { "bitcoin" } else { "zenon" };
        let declared_keys = &terms[leg_name]["signer_keys_sec1_hex"];
        for role in 0..2 {
            assert_eq!(
                hex(&scalar(1 + (leg * 2 + role) as u8)
                    .base_point_mul()
                    .serialize()),
                declared_keys[role]
            );
        }
        assert_eq!(
            hex(&scalar(7).base_point_mul().serialize()),
            terms["adaptor_point_sec1_hex"]
        );
        Self {
            binding,
            round_id: hex(&[61 + leg as u8; 32]),
            keys,
            message,
            adaptor: scalar(7).base_point_mul(),
        }
    }

    fn extra(&self, role: usize) -> Vec<u8> {
        let mut extra = b"PTLC/test-only-nonce-owner/v1\0".to_vec();
        extra.extend(bytes(&digest(&self.binding)));
        extra.extend(bytes(&self.round_id));
        extra.push(role as u8);
        extra.extend(self.adaptor.serialize());
        extra
    }
}

fn round(context: &Context, public: &[Vec<u8>; 2]) -> Value {
    let opening = |role: &str, nonce: &[u8]| {
        json!({
            "schema": "ptlc-offline-transcript-v1", "stage": "nonce-opening",
            "session_id": context.binding["session_id"], "leg": context.binding["stage"],
            "binding_digest_hex": digest(&context.binding), "round_id": context.round_id,
            "role": role, "public_nonce_hex": hex(nonce)
        })
    };
    let commitments = json!({
        "schema": "ptlc-offline-transcript-v1", "stage": "nonce-commitments",
        "session_id": context.binding["session_id"], "leg": context.binding["stage"],
        "round_id": context.round_id, "binding_digest_hex": digest(&context.binding),
        "binding": context.binding,
        "commitments": {"alice": digest(&opening("alice", &public[0])), "bob": digest(&opening("bob", &public[1]))}
    });
    json!({
        "schema": "ptlc-offline-transcript-v1", "stage": "nonce-round",
        "session_id": context.binding["session_id"], "leg": context.binding["stage"],
        "round_id": context.round_id, "binding_digest_hex": digest(&context.binding),
        "commitments_digest_hex": digest(&commitments), "commitments": commitments,
        "public_nonces": {"alice": hex(&public[0]), "bob": hex(&public[1])}
    })
}

#[derive(Debug, PartialEq)]
enum Refusal {
    Owner,
    Spent,
    Context,
    Nonce,
    Backend,
    Injected,
}

// Neither owner type exposes Clone, Debug, or any secret serialization method.
struct Generated {
    nonce: SecNonce,
    context: Context,
    role: usize,
    key: Scalar,
    pid: u32,
    thread: ThreadId,
}

impl Generated {
    fn new(context: Context, role: usize, tag: u8) -> Self {
        let leg = usize::from(context.binding["stage"] == "zenon");
        let key = scalar(1 + (leg * 2 + role) as u8);
        let aggregate: Point = context.keys.aggregated_pubkey();
        let nonce = SecNonce::generate(
            [tag; 32],
            key,
            aggregate,
            context.message,
            context.extra(role),
        );
        Self {
            nonce,
            context,
            role,
            key,
            pid: std::process::id(),
            thread: thread::current().id(),
        }
    }

    fn public(&self) -> Vec<u8> {
        self.nonce.public_nonce().to_bytes().to_vec()
    }

    // Moving self seals exactly one complete round. Any refusal drops this owner.
    fn seal(self, public: [Vec<u8>; 2]) -> Result<Ready, Refusal> {
        if self.pid != std::process::id() || self.thread != thread::current().id() {
            return Err(Refusal::Owner);
        }
        if public[self.role] != self.public() || public[0] == public[1] {
            return Err(Refusal::Nonce);
        }
        let parsed = public
            .iter()
            .map(|nonce| PubNonce::from_bytes(nonce).map_err(|_| Refusal::Nonce))
            .collect::<Result<Vec<_>, _>>()?;
        let transcript = round(&self.context, &public);
        Ok(Ready {
            nonce: Some(self.nonce),
            context: self.context,
            role: self.role,
            key: self.key,
            pid: self.pid,
            thread: self.thread,
            transcript,
            public: parsed,
            calls: 0,
        })
    }
}

struct Ready {
    nonce: Option<SecNonce>,
    context: Context,
    role: usize,
    key: Scalar,
    pid: u32,
    thread: ThreadId,
    transcript: Value,
    public: Vec<PubNonce>,
    calls: usize,
}

#[derive(Clone, Copy)]
enum Fault {
    None,
    BeforeBackend,
    Panic,
    WrongKey,
}

impl Ready {
    fn sign_once(
        &mut self,
        expected_round: &Value,
        fault: Fault,
    ) -> Result<PartialSignature, Refusal> {
        if self.pid != std::process::id() || self.thread != thread::current().id() {
            return Err(Refusal::Owner);
        }
        // Burn before all request checks and backend work, including unwinding.
        let nonce = self.nonce.take().ok_or(Refusal::Spent)?;
        if &self.transcript != expected_round {
            return Err(Refusal::Context);
        }
        match fault {
            Fault::BeforeBackend => return Err(Refusal::Injected),
            Fault::Panic => panic!("synthetic failure after consumption"),
            _ => {}
        }
        let key = if matches!(fault, Fault::WrongKey) {
            scalar(99)
        } else {
            self.key
        };
        self.calls += 1;
        let aggregate = AggNonce::sum(&self.public);
        let partial = adaptor::sign_partial(
            &self.context.keys,
            key,
            nonce,
            &aggregate,
            self.context.adaptor,
            self.context.message,
        )
        .map_err(|_| Refusal::Backend)?;
        adaptor::verify_partial(
            &self.context.keys,
            partial,
            &aggregate,
            self.context.adaptor,
            self.key.base_point_mul(),
            &self.public[self.role],
            self.context.message,
        )
        .map_err(|_| Refusal::Backend)?;
        Ok(partial)
    }
}

fn owners(leg: usize) -> [Ready; 2] {
    let context = Context::new(leg);
    let generated = [
        Generated::new(context.clone(), 0, 71 + leg as u8 * 2),
        Generated::new(context, 1, 72 + leg as u8 * 2),
    ];
    let public = generated.each_ref().map(Generated::public);
    generated.map(|owner| owner.seal(public.clone()).ok().unwrap())
}

fn public_vector(leg: usize) -> Value {
    let mut pair = owners(leg);
    let transcript = pair[0].transcript.clone();
    let partials = pair
        .each_mut()
        .map(|owner| owner.sign_once(&transcript, Fault::None).unwrap());
    let owner = &pair[0];
    let aggregate = AggNonce::sum(&owner.public);
    let key: Point = owner.context.keys.aggregated_pubkey();
    let pre = adaptor::aggregate_partial_signatures(
        &owner.context.keys,
        &aggregate,
        owner.context.adaptor,
        partials,
        owner.context.message,
    )
    .unwrap();
    adaptor::verify_single(key, &pre, owner.context.message, owner.context.adaptor).unwrap();
    let final_signature: LiftedSignature = pre.adapt(scalar(7)).unwrap();
    musig2::verify_single(key, final_signature, owner.context.message).unwrap();
    let witness: MaybeScalar = pre.reveal_secret(&final_signature).unwrap();
    assert_eq!(witness.base_point_mul(), owner.context.adaptor.into());
    let terms = if leg == 0 {
        &owner.context.binding["terms"]
    } else {
        &owner.context.binding["bitcoin"]["terms"]
    };
    let leg_name = if leg == 0 { "bitcoin" } else { "zenon" };
    let key_field = if leg == 0 {
        "output_key_xonly_hex"
    } else {
        "aggregate_key_xonly_hex"
    };
    assert_eq!(hex(&key.serialize_xonly()), terms[leg_name][key_field]);
    json!({
        "leg": leg_name, "round_id_hex": owner.context.round_id,
        "binding_digest_hex": digest(&owner.context.binding), "round_digest_hex": digest(&transcript),
        "nonce_commitments_hex": [transcript["commitments"]["commitments"]["alice"], transcript["commitments"]["commitments"]["bob"]],
        "public_nonces_hex": owner.public.iter().map(|nonce| hex(&nonce.to_bytes())).collect::<Vec<_>>(),
        "partial_signatures_hex": partials.iter().map(|partial| hex(&partial.serialize())).collect::<Vec<_>>(),
        "adaptor_presignature_hex": hex(&pre.to_bytes()),
        "public_key_hex": hex(&key.serialize_xonly()), "message_hex": hex(&owner.context.message),
        "signature_hex": hex(&final_signature.to_bytes()), "valid": true
    })
}

#[test]
fn public_nonce_fixture_matches_actual_pinned_signing() {
    let generated = json!({
        "schema": "ptlc-public-nonce-round-fixture-v1",
        "note": "Public synthetic nonce rounds and signatures only. Deterministic test seeds are not fresh entropy. No journal bridge, authentication, durable secret ownership, or live-chain claim.",
        "vectors": [public_vector(0), public_vector(1)]
    });
    let expected: Value =
        serde_json::from_str(include_str!("../fixtures/nonce_rounds.json")).unwrap();
    assert_eq!(generated, expected);
}

#[test]
fn successful_output_cannot_be_recomputed_by_the_same_owner() {
    for leg in 0..2 {
        let mut pair = owners(leg);
        for owner in &mut pair {
            let transcript = owner.transcript.clone();
            assert!(owner.sign_once(&transcript, Fault::None).is_ok());
            assert_eq!(
                owner.sign_once(&transcript, Fault::None),
                Err(Refusal::Spent)
            );
            assert_eq!(owner.calls, 1);
        }
    }
}

#[test]
fn any_changed_request_burns_the_local_owner_before_backend_work() {
    for field in [
        "round_id",
        "binding_digest_hex",
        "session_id",
        "leg",
        "public_nonces",
        "commitments",
        "unknown",
    ] {
        let mut owner = owners(0).into_iter().next().unwrap();
        let original = owner.transcript.clone();
        let mut changed = original.clone();
        changed[field] = json!("changed-public-context");
        assert_eq!(
            owner.sign_once(&changed, Fault::None),
            Err(Refusal::Context)
        );
        assert_eq!(owner.sign_once(&original, Fault::None), Err(Refusal::Spent));
        assert_eq!(owner.calls, 0);
    }
}

#[test]
fn injected_failures_and_backend_rejection_burn_the_local_owner() {
    for fault in [Fault::BeforeBackend, Fault::WrongKey, Fault::Panic] {
        let mut owner = owners(1).into_iter().next().unwrap();
        let original = owner.transcript.clone();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            owner.sign_once(&original, fault)
        }));
        match fault {
            Fault::Panic => assert!(result.is_err()),
            Fault::WrongKey => assert_eq!(result.unwrap(), Err(Refusal::Backend)),
            _ => assert_eq!(result.unwrap(), Err(Refusal::Injected)),
        }
        assert_eq!(owner.sign_once(&original, Fault::None), Err(Refusal::Spent));
        assert_eq!(owner.calls, usize::from(matches!(fault, Fault::WrongKey)));
    }
}

#[test]
fn malformed_public_nonces_are_rejected_by_the_actual_backend_parser() {
    let valid = Generated::new(Context::new(0), 1, 72).public();
    let mut cases = vec![
        valid[..65].to_vec(),
        [valid.clone(), vec![0]].concat(),
        vec![0; 66],
    ];
    let mut prefix = valid.clone();
    prefix[0] = 4;
    cases.push(prefix);
    let mut infinity = valid.clone();
    infinity[..33].fill(0);
    cases.push(infinity);
    let mut bad_x = valid.clone();
    bad_x[1..33].fill(255);
    cases.push(bad_x);
    for invalid in cases {
        assert!(PubNonce::from_bytes(&invalid).is_err());
        let owner = Generated::new(Context::new(0), 0, 71);
        let public = owner.public();
        assert!(matches!(owner.seal([public, invalid]), Err(Refusal::Nonce)));
    }
}

#[test]
fn another_thread_cannot_use_the_ephemeral_owner() {
    let owner = owners(0).into_iter().next().unwrap();
    let mut owner = thread::spawn(move || {
        let mut owner = owner;
        assert_eq!(
            owner.sign_once(&owner.transcript.clone(), Fault::None),
            Err(Refusal::Owner)
        );
        assert_eq!(owner.calls, 0);
        owner
    })
    .join()
    .unwrap();
    assert!(
        owner
            .sign_once(&owner.transcript.clone(), Fault::None)
            .is_ok()
    );
}

#[test]
fn contextual_derivation_is_not_freshness_or_restored_copy_protection() {
    let context = Context::new(0);
    let baseline = Generated::new(context.clone(), 0, 71).public();
    // Reconstructing all inputs repeats the nonce. This is an explicit limitation.
    assert_eq!(baseline, Generated::new(context.clone(), 0, 71).public());
    for field in 0..5 {
        let mut changed = context.clone();
        match field {
            0 => changed.round_id = hex(&[99; 32]),
            1 => changed.binding["session_id"] = json!(hex(&[99; 32])),
            2 => changed.message[0] ^= 1,
            3 => changed.adaptor = scalar(8).base_point_mul(),
            _ => {
                changed.keys =
                    KeyAggContext::new([scalar(2).base_point_mul(), scalar(1).base_point_mul()])
                        .unwrap()
            }
        }
        assert_ne!(baseline, Generated::new(changed, 0, 71).public());
    }
}
