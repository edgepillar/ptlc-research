//! Check the real public CLI and the independently selectable locked package.
//! No signing, node, secret input, activation, network fetch or funds.

use sha2::{Digest, Sha256};
use std::{
    io::Write,
    path::PathBuf,
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn public_cli_path() -> PathBuf {
    let current = std::env::current_exe().unwrap();
    let target = current.parent().unwrap().parent().unwrap();
    // Each context selects its own built executable from its target directory.
    if env!("CARGO_PKG_NAME") == "ptlc-nom-public-crypto" {
        let name = if cfg!(windows) {
            "ptlc-nom-public-crypto.exe"
        } else {
            "ptlc-nom-public-crypto"
        };
        return target.join(name);
    }
    let directory = target.join("examples");
    let name = if cfg!(windows) {
        "verify_client_presignature.exe"
    } else {
        "verify_client_presignature"
    };
    directory.join(name)
}

fn public_child(stdout: Stdio) -> Child {
    Command::new(public_cli_path())
        .stdin(Stdio::piped())
        .stdout(stdout)
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

fn bounded_output(mut child: Child) -> Output {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return child.wait_with_output().unwrap(),
            Ok(None) => {}
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait_with_output();
                panic!("owned public checker status could not be observed");
            }
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait_with_output();
            panic!("owned public checker exceeded its bounded wait");
        }
        thread::sleep(Duration::from_millis(5));
    }
}

fn run_public_cli(raw: &[u8]) -> Output {
    let mut child = public_child(Stdio::piped());
    child.stdin.take().unwrap().write_all(raw).unwrap();
    bounded_output(child)
}

fn canonical_request() -> Vec<u8> {
    let value: serde_json::Value = serde_json::from_slice(
        &std::fs::read(root().join("public_crypto/synthetic_long_request.json")).unwrap(),
    )
    .unwrap();
    serde_json::to_vec(&value).unwrap()
}

#[test]
fn the_built_public_cli_accepts_one_framing_lf_and_refuses_oversized_input() {
    let value: serde_json::Value = serde_json::from_slice(
        &std::fs::read(root().join("public_crypto/synthetic_long_request.json")).unwrap(),
    )
    .unwrap();
    let canonical = serde_json::to_vec(&value).unwrap();
    let mut framed = canonical.clone();
    framed.push(b'\n');
    let output = run_public_cli(&framed);
    assert!(output.status.success());
    assert!(output.stderr.is_empty() && output.stdout.len() <= 2048);
    let checked: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let digest: String = Sha256::digest(&canonical)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(checked["request_digest_hex"], digest);
    assert_eq!(checked["presignature_valid"], true);
    assert_eq!(checked["action_permission"], "NONE");
    assert_eq!(checked["application"], "NO-GO");
    assert_eq!(checked["core"], "NO-GO");
    let refused = run_public_cli(&vec![b'x'; 8193]);
    assert_eq!(refused.status.code(), Some(2));
    assert!(refused.stdout.is_empty() && refused.stderr.is_empty());
}

#[test]
fn the_small_package_has_its_own_consistent_offline_lock_and_public_targets() {
    let lock = root().join("public_crypto/Cargo.lock");
    let before = std::fs::read(&lock).unwrap();
    let output = Command::new(env!("CARGO"))
        .args([
            "metadata",
            "--format-version",
            "1",
            "--locked",
            "--offline",
            "--no-deps",
            "--manifest-path",
        ])
        .arg(root().join("public_crypto/Cargo.toml"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "locked offline package metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty() && output.stdout.len() <= 65536);
    let metadata: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let packages = metadata["packages"].as_array().unwrap();
    assert_eq!(packages.len(), 1);
    assert_eq!(packages[0]["name"], "ptlc-nom-public-crypto");
    assert_eq!(packages[0]["dependencies"].as_array().unwrap().len(), 3);
    let targets = packages[0]["targets"].as_array().unwrap();
    assert_eq!(targets.len(), 3);
    assert!(
        targets
            .iter()
            .any(|target| target["kind"] == serde_json::json!(["lib"]))
    );
    assert!(
        targets
            .iter()
            .any(|target| target["kind"] == serde_json::json!(["bin"]))
    );
    assert!(targets.iter().any(|target| {
        target["kind"] == serde_json::json!(["test"])
            && target["name"] == "client_public_crypto_process"
    }));
    assert_eq!(std::fs::read(lock).unwrap(), before);
}

#[test]
fn interrupted_partial_input_is_not_a_completed_public_check() {
    let canonical = canonical_request();
    let mut child = public_child(Stdio::piped());
    let mut input = child.stdin.take().unwrap();
    input.write_all(&canonical[..canonical.len() / 2]).unwrap();
    // Keep EOF withheld. This selects an incomplete-input window, not an
    // instruction-level cut or any signing-state restore boundary.
    assert!(child.try_wait().unwrap().is_none());
    child.kill().unwrap();
    drop(input);
    let interrupted = bounded_output(child);
    assert!(!interrupted.status.success());
    assert!(interrupted.stdout.is_empty() && interrupted.stderr.is_empty());

    let fresh = run_public_cli(&canonical);
    assert!(fresh.status.success() && fresh.stderr.is_empty());
    let checked: serde_json::Value = serde_json::from_slice(&fresh.stdout).unwrap();
    assert_eq!(checked["presignature_valid"], true);
    assert_eq!(
        checked["request_digest_hex"],
        "00a23ea5269a1f47ec336f4b6c08477a5f0a0b36f0fe9b90cac3888f556f4280"
    );
    assert_eq!(checked["action_permission"], "NONE");
    assert_eq!(checked["application"], "NO-GO");
    assert_eq!(checked["core"], "NO-GO");
}

#[test]
fn a_broken_output_pipe_refuses_public_result_delivery() {
    let mut child = public_child(Stdio::piped());
    // Close the only reader before completing the bounded public input.
    drop(child.stdout.take().unwrap());
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&canonical_request())
        .unwrap();
    let output = bounded_output(child);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty() && output.stderr.is_empty());
}

#[test]
fn a_zero_exit_without_captured_output_is_not_a_verification_receipt() {
    let mut child = public_child(Stdio::null());
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&canonical_request())
        .unwrap();
    let lost = bounded_output(child);
    assert!(lost.status.success());
    assert!(lost.stdout.is_empty() && lost.stderr.is_empty());
    // A deliberately discarded result supplies no JSON receipt. This is a
    // public-IO counterexample, not operational recovery or key-use evidence.
    assert!(serde_json::from_slice::<serde_json::Value>(&lost.stdout).is_err());
}
