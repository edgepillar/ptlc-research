// MIT-licensed test helpers adapted from accepted public-synthetic source
// 5c5fd7c771996a13df80da60256f7c31e81cb7cc. See the root LICENSE.
// This selected copy adds a noop wrapper and two acknowledged pause hooks.
// Unused imports and unselected fault variants remain outside this profile.
#![allow(dead_code, unused_imports)]

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
        self.sign_with_pauses(expected_round, fault, |_, _| {})
    }

    fn sign_with_pauses(
        &mut self,
        expected_round: &Value,
        fault: Fault,
        mut pause: impl FnMut(&Ready, &'static str),
    ) -> Result<PartialSignature, Refusal> {
        if self.pid != std::process::id() || self.thread != thread::current().id() {
            return Err(Refusal::Owner);
        }
        // Burn before all request checks and backend work, including unwinding.
        let nonce = self.nonce.take().ok_or(Refusal::Spent)?;
        pause(self, "nonce-removed");
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
        pause(self, "before-backend");
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

// Only fixed public synthetic inputs are accepted by this test child.

fn public_owner(leg: usize, role: usize) -> Ready {
    owners(leg).into_iter().nth(role).unwrap()
}

fn public_partial(leg: usize, role: usize) -> String {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../qualification/fixtures/nonce_rounds.json"
    ))
    .unwrap();
    fixture["vectors"][leg]["partial_signatures_hex"][role]
        .as_str()
        .unwrap()
        .to_owned()
}

fn owner_event(owner: &Ready, event: &str) -> Value {
    json!({
        "event": event,
        "leg": owner.context.binding["stage"],
        "role": if owner.role == 0 { "alice" } else { "bob" },
        "round_digest_hex": digest(&owner.transcript),
        "backend_entries": owner.calls,
        "nonce_present": owner.nonce.is_some()
    })
}

fn emit_owner(value: Value) {
    use std::io::Write;
    let wire = value.to_string();
    assert!(wire.len() <= 1000);
    // A leading newline separates libtest's display from the bounded frame.
    println!("\nPTLC_NONCE_BOUNDARY {wire}");
    std::io::stdout().flush().unwrap();
}

fn owner_command() -> String {
    use std::io::BufRead;
    let mut line = Vec::new();
    let input = std::io::stdin();
    let size = std::io::Read::take(input.lock(), 65)
        .read_until(b'\n', &mut line)
        .unwrap();
    assert!((1..=64).contains(&size) && line.last() == Some(&b'\n'));
    line.pop();
    let command = String::from_utf8(line).unwrap();
    assert!(command.is_ascii());
    command
}

fn assert_inline_profile() {
    for leg in 0..2 {
        for role in 0..2 {
            let mut owner = public_owner(leg, role);
            let transcript = owner.transcript.clone();
            let mut pauses = Vec::new();
            let partial = owner
                .sign_with_pauses(&transcript, Fault::None, |ready, cut| {
                    assert!(ready.nonce.is_none());
                    assert_eq!(ready.calls, 0);
                    pauses.push(cut);
                })
                .unwrap();
            assert_eq!(pauses, ["nonce-removed", "before-backend"]);
            assert_eq!(hex(&partial.serialize()), public_partial(leg, role));
            assert_eq!(owner.calls, 1);
            assert_eq!(
                owner.sign_with_pauses(&transcript, Fault::None, |_, _| {
                    panic!("spent owner reached a pause")
                }),
                Err(Refusal::Spent)
            );
            assert_eq!(owner.calls, 1);

            for fault in [Fault::None, Fault::BeforeBackend] {
                let mut refused = public_owner(leg, role);
                let mut expected = refused.transcript.clone();
                if matches!(fault, Fault::None) {
                    expected["round_id"] = json!(hex(&[99; 32]));
                }
                let mut refusals = Vec::new();
                let result = refused.sign_with_pauses(&expected, fault, |ready, cut| {
                    assert!(ready.nonce.is_none());
                    assert_eq!(ready.calls, 0);
                    refusals.push(cut);
                });
                assert_eq!(
                    result,
                    Err(if matches!(fault, Fault::None) {
                        Refusal::Context
                    } else {
                        Refusal::Injected
                    })
                );
                assert_eq!(refusals, ["nonce-removed"]);
                assert!(refused.nonce.is_none());
                assert_eq!(refused.calls, 0);
                assert_eq!(
                    refused.sign_with_pauses(&refused.transcript.clone(), Fault::None, |_, _| {
                        panic!("refused owner reached another pause")
                    }),
                    Err(Refusal::Spent)
                );
                assert_eq!(refused.calls, 0);
            }
        }
    }
}

#[test]
fn public_synthetic_nonce_boundary_child() {
    let selection = match std::env::var("PTLC_PUBLIC_SYNTHETIC_BOUNDARY_SCOPE") {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => None,
        Err(_) => panic!("invalid fixed public boundary scope encoding"),
    };
    let Some(selection) = selection else {
        // Four actual public positives and eight separate before-backend refusals.
        assert_inline_profile();
        return;
    };
    let (leg, role) = match selection.as_str() {
        "bitcoin-alice" => (0, 0),
        "bitcoin-bob" => (0, 1),
        "zenon-alice" => (1, 0),
        "zenon-bob" => (1, 1),
        _ => panic!("unknown fixed public boundary scope"),
    };
    let mut owner = public_owner(leg, role);
    emit_owner(owner_event(&owner, "prepared"));
    assert_eq!(owner_command(), "sign");
    let transcript = owner.transcript.clone();
    let partial = owner
        .sign_with_pauses(&transcript, Fault::None, |ready, cut| {
            assert!(ready.nonce.is_none());
            assert_eq!(ready.calls, 0);
            // The local call still owns SecNonce; Option removal is not erasure.
            emit_owner(owner_event(ready, cut));
            assert_eq!(owner_command(), "continue");
        })
        .unwrap();
    let encoded = hex(&partial.serialize());
    assert_eq!(encoded, public_partial(leg, role));
    assert_eq!(owner.calls, 1);
    assert_eq!(
        owner.sign_once(&transcript, Fault::None),
        Err(Refusal::Spent)
    );
    assert_eq!(owner.calls, 1);
    emit_owner(owner_event(&owner, "computed"));
    assert_eq!(owner_command(), "release");
    let mut delivered = owner_event(&owner, "partial");
    delivered["partial_hex"] = json!(encoded);
    emit_owner(delivered);
    assert_eq!(owner_command(), "finish");
}
struct BoundaryCoordinator {
    child: std::process::Child,
    event: std::sync::mpsc::Receiver<Result<Value, &'static str>>,
    reader: Option<thread::JoinHandle<()>>,
    root: std::path::PathBuf,
}

impl BoundaryCoordinator {
    fn new(leg: usize, role: usize, cut: &str) -> Self {
        use std::os::unix::fs::PermissionsExt;
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let serial = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "ptlc-nonce-boundary-{}-{serial}",
            std::process::id()
        ));
        std::fs::create_dir(&root).expect("private public-test directory creation failed");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let actor = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../tests/native_nonce_boundary_actor.py");
        let mut child = std::process::Command::new("python3")
            .arg("-B")
            .arg(actor)
            .arg(&root)
            .arg("--owner-test")
            .arg(std::env::current_exe().unwrap())
            .args(["--leg", if leg == 0 { "bitcoin" } else { "zenon" }])
            .args(["--role", if role == 0 { "alice" } else { "bob" }])
            .args(["--cut", cut])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("public death coordinator launch failed");
        let stdout = child.stdout.take().unwrap();
        let (send, event) = std::sync::mpsc::channel();
        let reader = thread::spawn(move || {
            use std::io::BufRead;
            let mut stream = std::io::BufReader::new(stdout);
            let mut line = Vec::new();
            let result = match std::io::Read::take(&mut stream, 2049).read_until(b'\n', &mut line) {
                Ok(size) if (1..=2048).contains(&size) && line.last() == Some(&b'\n') => {
                    serde_json::from_slice(&line).map_err(|_| "invalid public death event")
                }
                _ => Err("incomplete or oversized public death event"),
            };
            let _ = send.send(result);
        });
        Self {
            child,
            event,
            reader: Some(reader),
            root,
        }
    }

    fn expect(&self, expected: Value) {
        let value = self
            .event
            .recv_timeout(std::time::Duration::from_secs(15))
            .expect("public death coordinator event timed out")
            .expect("public death coordinator event refused");
        assert_eq!(value, expected);
    }

    fn finish(&mut self) {
        let end = std::time::Instant::now() + std::time::Duration::from_secs(15);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(
                    status.success(),
                    "public death coordinator exited unsuccessfully"
                );
                break;
            }
            assert!(
                std::time::Instant::now() < end,
                "public coordinator exit timed out"
            );
            thread::sleep(std::time::Duration::from_millis(10));
        }
        self.reader.take().unwrap().join().unwrap();
    }
}

impl Drop for BoundaryCoordinator {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn boundary_result(leg: usize, role: usize, cut: &str) -> Value {
    let owner = public_owner(leg, role);
    let continued = cut == "continued";
    let pauses = if cut == "nonce-removed" {
        vec!["nonce-removed"]
    } else {
        vec!["nonce-removed", "before-backend"]
    };
    json!({
        "event": "qualified",
        "leg": if leg == 0 { "bitcoin" } else { "zenon" },
        "role": if role == 0 { "alice" } else { "bob" },
        "cut": cut,
        "round_digest_hex": digest(&owner.transcript),
        "native_launches": 1,
        "native_sigkill": usize::from(!continued),
        "native_normal_exit": usize::from(continued),
        "native_exit_code": if continued { 0 } else { -9 },
        "acknowledged_pauses": pauses,
        "nonce_present_at_pauses": vec![false; pauses.len()],
        "native_backend_entries": usize::from(continued),
        "completed_partials": usize::from(continued),
        "delivered_partials": usize::from(continued),
        "callback_entries": 1,
        "reopen_status": if continued { "OUTPUT_RECORDED" } else { "OUTCOME_UNKNOWN" },
        "replays_after_reopen": if continued { 2 } else { 0 },
        "forbidden_calls": 0,
        "coordinator_survived": true,
        "output_hex": if continued { json!(public_partial(leg, role)) } else { Value::Null }
    })
}

#[test]
fn native_nonce_boundary_sigkill_refuses_consumed_reentry_after_reopen() {
    for leg in 0..2 {
        for role in 0..2 {
            for cut in ["nonce-removed", "before-backend"] {
                let mut peer = BoundaryCoordinator::new(leg, role, cut);
                peer.expect(boundary_result(leg, role, cut));
                peer.finish();
            }
        }
    }
}

#[test]
fn native_nonce_boundary_continuations_compute_and_replay_public_output() {
    for leg in 0..2 {
        for role in 0..2 {
            let mut peer = BoundaryCoordinator::new(leg, role, "continued");
            peer.expect(boundary_result(leg, role, "continued"));
            peer.finish();
        }
    }
}
