//! Check the real public CLI and the independently selectable locked package.
//! No signing, node, secret input, activation, network fetch or funds.

use sha2::{Digest, Sha256};
use std::{
    io::Write,
    path::PathBuf,
    process::{Command, Stdio},
};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn example(raw: &[u8]) -> std::process::Output {
    // Cargo's default test selection also compiles the example targets. Resolve
    // the current build's sibling examples directory, including custom targets.
    let current = std::env::current_exe().unwrap();
    let directory = current.parent().unwrap().parent().unwrap().join("examples");
    let name = if cfg!(windows) {
        "verify_client_presignature.exe"
    } else {
        "verify_client_presignature"
    };
    let mut child = Command::new(directory.join(name))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(raw).unwrap();
    child.wait_with_output().unwrap()
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
    let output = example(&framed);
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
    let refused = example(&vec![b'x'; 8193]);
    assert_eq!(refused.status.code(), Some(2));
    assert!(refused.stdout.is_empty() && refused.stderr.is_empty());
}

#[test]
fn the_small_package_has_its_own_consistent_offline_lock_and_two_targets() {
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
    assert_eq!(targets.len(), 2);
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
    assert_eq!(std::fs::read(lock).unwrap(), before);
}
