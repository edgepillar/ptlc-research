//! Separate public-synthetic test construction, unsafe for funds.
//! The private owner definitions below are copied from the accepted repository
//! source at b86af7abcf575ad900fa5bf7fb5b85788d181126 under the root MIT license.
//! No production signer API, custody, nonce freshness, or secure erasure claim.
// Copied helpers retain fault variants outside this selected handoff profile.
#![allow(dead_code)]

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

// This peer accepts only existing public fixtures. The nonce stays in this test
// thread; only a public partial scalar crosses the pipe. It is not a signer API.
struct JournalPeer {
    child: std::process::Child,
    input: Option<std::process::ChildStdin>,
    events: std::sync::mpsc::Receiver<Result<Value, &'static str>>,
    reader: Option<thread::JoinHandle<()>>,
    root: std::path::PathBuf,
}

impl JournalPeer {
    fn new(leg: usize, role: usize, scenario: &str) -> Self {
        use std::os::unix::fs::PermissionsExt;
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let serial = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "ptlc-native-partial-{}-{serial}",
            std::process::id()
        ));
        std::fs::create_dir(&root).expect("private test directory creation failed");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .expect("private test directory permissions failed");
        let actor = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../tests/native_partial_journal_actor.py");
        let mut child = std::process::Command::new("python3")
            .arg("-B")
            .arg(actor)
            .arg(&root)
            .args(["--leg", if leg == 0 { "bitcoin" } else { "zenon" }])
            .args(["--role", if role == 0 { "alice" } else { "bob" }])
            .args(["--scenario", scenario])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("public journal peer launch failed");
        let input = child.stdin.take();
        let stdout = child
            .stdout
            .take()
            .expect("public journal peer stdout absent");
        let (send, events) = std::sync::mpsc::channel();
        let reader = thread::spawn(move || {
            use std::io::BufRead;
            let mut stream = std::io::BufReader::new(stdout);
            loop {
                let mut line = Vec::new();
                let read = std::io::Read::take(&mut stream, 2049).read_until(b'\n', &mut line);
                let value = match read {
                    Ok(size) if (1..=2048).contains(&size) && line.last() == Some(&b'\n') => {
                        serde_json::from_slice(&line).map_err(|_| "invalid public peer event")
                    }
                    _ => Err("incomplete or oversized public peer event"),
                };
                let stop = value.is_err();
                if send.send(value).is_err() || stop {
                    break;
                }
            }
        });
        Self {
            child,
            input,
            events,
            reader: Some(reader),
            root,
        }
    }

    fn send(&mut self, value: &str) {
        use std::io::Write;
        assert!(value.is_ascii() && value.len() <= 255 && !value.contains('\n'));
        let input = self
            .input
            .as_mut()
            .expect("public journal peer input absent");
        writeln!(input, "{value}").expect("public journal peer command failed");
        input
            .flush()
            .expect("public journal peer command flush failed");
    }

    fn expect(&self, expected: Value) {
        let actual = self
            .events
            .recv_timeout(std::time::Duration::from_secs(15))
            .expect("public journal peer event timed out")
            .expect("public journal peer event refused");
        assert_eq!(actual, expected);
    }

    fn finish(&mut self) {
        self.input.take();
        let end = std::time::Instant::now() + std::time::Duration::from_secs(15);
        loop {
            if let Some(status) = self
                .child
                .try_wait()
                .expect("public journal peer wait failed")
            {
                assert!(
                    status.success(),
                    "public journal peer exited unsuccessfully"
                );
                break;
            }
            assert!(
                std::time::Instant::now() < end,
                "public journal peer exit timed out"
            );
            thread::sleep(std::time::Duration::from_millis(10));
        }
        self.reader.take().unwrap().join().unwrap();
    }
}

impl Drop for JournalPeer {
    fn drop(&mut self) {
        self.input.take();
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn selected_test_owner(leg: usize, role: usize) -> Ready {
    owners(leg).into_iter().nth(role).unwrap()
}

fn expected_test_partial(leg: usize, role: usize) -> String {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../qualification/fixtures/nonce_rounds.json"
    ))
    .unwrap();
    fixture["vectors"][leg]["partial_signatures_hex"][role]
        .as_str()
        .unwrap()
        .to_owned()
}

fn peer_event(owner: &Ready, event: &str, history: usize, status: &str) -> Value {
    json!({
        "event": event, "history": history, "status": status,
        "leg": owner.context.binding["stage"],
        "role": if owner.role == 0 { "alice" } else { "bob" },
        "round_digest_hex": digest(&owner.transcript)
    })
}

fn peer_result(
    owner: &Ready,
    event: &str,
    history: usize,
    recorded: bool,
    recovered: bool,
) -> Value {
    let status = if recorded {
        "OUTPUT_RECORDED"
    } else if recovered {
        "OUTCOME_UNKNOWN"
    } else {
        "CONSUMED"
    };
    let mut value = peer_event(owner, event, history, status);
    let leg = usize::from(owner.context.binding["stage"] == "zenon");
    value["output_hex"] = if recorded {
        json!(expected_test_partial(leg, owner.role))
    } else {
        Value::Null
    };
    value["replays"] = json!(if recorded { 2 } else { 0 });
    value["forbidden_calls"] = json!(0);
    value
}

fn native_attempt(
    peer: &mut JournalPeer,
    owner: &mut Ready,
    history: usize,
    fault: Fault,
    lost: bool,
) {
    assert!(owner.nonce.is_some());
    assert_eq!(owner.calls, 0);
    peer.expect(peer_event(owner, "reserved", history, "RESERVED"));
    peer.send("produce");
    peer.expect(peer_event(owner, "invoke", history, "CONSUMED"));
    // The journal admission precedes this actual nonce-dependent primitive call.
    let transcript = owner.transcript.clone();
    let result = owner.sign_once(&transcript, fault);
    let calls = usize::from(!matches!(fault, Fault::BeforeBackend));
    assert_eq!(owner.calls, calls);
    assert!(owner.nonce.is_none());
    let recorded = matches!(fault, Fault::None) && !lost;
    match fault {
        Fault::None => {
            let partial = result.unwrap();
            let leg = usize::from(owner.context.binding["stage"] == "zenon");
            let public = hex(&partial.serialize());
            assert_eq!(public, expected_test_partial(leg, owner.role));
            // Loss is selected before delivery. No secret material is serialized.
            peer.send(if lost { "lost" } else { &public });
        }
        Fault::BeforeBackend => {
            assert_eq!(result, Err(Refusal::Injected));
            peer.send("refused");
        }
        Fault::WrongKey => {
            assert_eq!(result, Err(Refusal::Backend));
            peer.send("refused");
        }
        Fault::Panic => panic!("panic injection is outside this selected handoff"),
    }
    peer.expect(peer_result(owner, "produced", history, recorded, false));
    assert_eq!(
        owner.sign_once(&transcript, Fault::None),
        Err(Refusal::Spent)
    );
    assert_eq!(owner.calls, calls);
}

#[test]
fn native_partial_journal_retains_and_replays_without_backend_reentry() {
    for leg in 0..2 {
        for role in 0..2 {
            let mut owner = selected_test_owner(leg, role);
            let mut peer = JournalPeer::new(leg, role, "recorded");
            native_attempt(&mut peer, &mut owner, 1, Fault::None, false);
            peer.expect(peer_result(&owner, "recovered", 1, true, true));
            peer.finish();
            assert_eq!(owner.calls, 1);
        }
    }
}

#[test]
fn native_partial_journal_lost_result_seals_admission_and_consumes_owner() {
    for leg in 0..2 {
        for role in 0..2 {
            let mut owner = selected_test_owner(leg, role);
            let mut peer = JournalPeer::new(leg, role, "lost");
            native_attempt(&mut peer, &mut owner, 1, Fault::None, true);
            peer.expect(peer_result(&owner, "recovered", 1, false, true));
            peer.finish();
            assert_eq!(owner.calls, 1);
        }
    }
}

#[test]
fn native_partial_journal_refused_native_attempts_cannot_retry() {
    for leg in 0..2 {
        for role in 0..2 {
            for fault in [Fault::BeforeBackend, Fault::WrongKey] {
                let mut owner = selected_test_owner(leg, role);
                let mut peer = JournalPeer::new(leg, role, "refused");
                native_attempt(&mut peer, &mut owner, 1, fault, false);
                peer.expect(peer_result(&owner, "recovered", 1, false, true));
                peer.finish();
                assert_eq!(owner.calls, usize::from(matches!(fault, Fault::WrongKey)));
            }
        }
    }
}

fn repeated_history_partials(scenario: &str) {
    for leg in 0..2 {
        for role in 0..2 {
            let mut first = selected_test_owner(leg, role);
            let mut second = selected_test_owner(leg, role);
            assert_eq!(first.transcript, second.transcript);
            assert_eq!(
                first.nonce.as_ref().unwrap().public_nonce(),
                second.nonce.as_ref().unwrap().public_nonce()
            );
            let mut peer = JournalPeer::new(leg, role, scenario);
            native_attempt(&mut peer, &mut first, 1, Fault::None, false);
            if scenario == "restore" {
                peer.expect(peer_result(&first, "recovered", 1, true, true));
            }
            native_attempt(&mut peer, &mut second, 2, Fault::None, false);
            if scenario == "copy" {
                peer.expect(peer_result(&first, "recovered", 1, true, true));
            }
            peer.expect(peer_result(&second, "recovered", 2, true, true));
            peer.finish();
            assert_eq!((first.calls, second.calls), (1, 1));
        }
    }
}

#[test]
fn copied_journals_and_reconstructed_test_owners_repeat_partial_math() {
    repeated_history_partials("copy");
}

#[test]
fn restored_journal_and_reconstructed_test_owner_repeat_partial_math() {
    repeated_history_partials("restore");
}
