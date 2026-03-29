use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::tempdir;

fn signet() -> Command {
    Command::cargo_bin("signet").unwrap()
}

// ─── identity generate ───────────────────────────────────────────────────────

#[test]
fn test_identity_generate_unencrypted() {
    let dir = tempdir().unwrap();
    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["identity", "generate", "--name", "agent1", "--unencrypted"])
        .assert()
        .success();

    let keys_dir = dir.path().join("keys");
    assert!(keys_dir.join("agent1.key").exists(), ".key file must exist");
    assert!(keys_dir.join("agent1.pub").exists(), ".pub file must exist");
}

#[test]
fn test_identity_generate_encrypted() {
    let dir = tempdir().unwrap();
    signet()
        .env("SIGNET_HOME", dir.path())
        .env("SIGNET_PASSPHRASE", "s3cr3t")
        .args(["identity", "generate", "--name", "agent2"])
        .assert()
        .success();

    let keys_dir = dir.path().join("keys");
    assert!(keys_dir.join("agent2.key").exists(), ".key file must exist");
    assert!(keys_dir.join("agent2.pub").exists(), ".pub file must exist");
}

// ─── identity list ───────────────────────────────────────────────────────────

#[test]
fn test_identity_list() {
    let dir = tempdir().unwrap();

    for name in ["alice", "bob"] {
        signet()
            .env("SIGNET_HOME", dir.path())
            .args(["identity", "generate", "--name", name, "--unencrypted"])
            .assert()
            .success();
    }

    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["identity", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("alice"))
        .stdout(predicate::str::contains("bob"));
}

#[test]
fn test_identity_list_empty() {
    let dir = tempdir().unwrap();
    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["identity", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("No keys found"));
}

// ─── identity export ─────────────────────────────────────────────────────────

#[test]
fn test_identity_export() {
    let dir = tempdir().unwrap();
    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["identity", "generate", "--name", "exporter", "--unencrypted"])
        .assert()
        .success();

    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["identity", "export", "--name", "exporter"])
        .assert()
        .success()
        .stdout(predicate::str::contains("ed25519"))
        .stdout(predicate::str::contains("exporter"));
}

// ─── sign ────────────────────────────────────────────────────────────────────

#[test]
fn test_sign_stdout() {
    let dir = tempdir().unwrap();
    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["identity", "generate", "--name", "signer", "--unencrypted"])
        .assert()
        .success();

    let out = signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "sign",
            "--key", "signer",
            "--tool", "bash",
            "--params", r#"{"cmd":"ls"}"#,
            "--target", "mcp://local",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let stdout = String::from_utf8(out).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("stdout must be valid JSON");
    assert!(v.get("sig").is_some(), "receipt must have 'sig' field");
    assert!(v.get("action").is_some(), "receipt must have 'action' field");
}

#[test]
fn test_sign_output_file() {
    let dir = tempdir().unwrap();
    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["identity", "generate", "--name", "filekey", "--unencrypted"])
        .assert()
        .success();

    let receipt_path = dir.path().join("receipt.json");
    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "sign",
            "--key", "filekey",
            "--tool", "bash",
            "--params", r#"{"cmd":"pwd"}"#,
            "--target", "mcp://local",
            "--output", receipt_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert!(receipt_path.exists(), "receipt file must exist");
    let content = fs::read_to_string(&receipt_path).unwrap();
    let v: serde_json::Value = serde_json::from_str(&content).expect("receipt file must be valid JSON");
    assert!(v.get("sig").is_some());
}

// ─── verify ──────────────────────────────────────────────────────────────────

#[test]
fn test_verify_valid() {
    let dir = tempdir().unwrap();
    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["identity", "generate", "--name", "verkey", "--unencrypted"])
        .assert()
        .success();

    let receipt_path = dir.path().join("receipt.json");
    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "sign",
            "--key", "verkey",
            "--tool", "read_file",
            "--params", r#"{"path":"/tmp/foo"}"#,
            "--target", "mcp://fs",
            "--output", receipt_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "verify",
            receipt_path.to_str().unwrap(),
            "--pubkey", "verkey",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Valid"));
}

#[test]
fn test_verify_invalid() {
    let dir = tempdir().unwrap();
    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["identity", "generate", "--name", "tampkey", "--unencrypted"])
        .assert()
        .success();

    let receipt_path = dir.path().join("receipt.json");
    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "sign",
            "--key", "tampkey",
            "--tool", "bash",
            "--params", r#"{"cmd":"echo hi"}"#,
            "--target", "mcp://local",
            "--output", receipt_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Tamper: change the tool name in the receipt
    let content = fs::read_to_string(&receipt_path).unwrap();
    let mut v: serde_json::Value = serde_json::from_str(&content).unwrap();
    v["action"]["tool"] = serde_json::Value::String("evil_tool".to_string());
    fs::write(&receipt_path, serde_json::to_string(&v).unwrap()).unwrap();

    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "verify",
            receipt_path.to_str().unwrap(),
            "--pubkey", "tampkey",
        ])
        .assert()
        .failure()
        .code(1);
}

#[test]
fn test_verify_pubkey_file() {
    let dir = tempdir().unwrap();
    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["identity", "generate", "--name", "pubfilekey", "--unencrypted"])
        .assert()
        .success();

    let receipt_path = dir.path().join("receipt.json");
    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "sign",
            "--key", "pubfilekey",
            "--tool", "list_dir",
            "--params", r#"{"path":"/tmp"}"#,
            "--target", "mcp://fs",
            "--output", receipt_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let pub_file_path = dir.path().join("keys").join("pubfilekey.pub");
    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "verify",
            receipt_path.to_str().unwrap(),
            "--pubkey", pub_file_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Valid"));
}

// ─── end-to-end ──────────────────────────────────────────────────────────────

#[test]
fn test_sign_verify_e2e() {
    let dir = tempdir().unwrap();
    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "identity", "generate",
            "--name", "e2eagent",
            "--owner", "ci-robot",
            "--unencrypted",
        ])
        .assert()
        .success();

    let receipt_path = dir.path().join("receipt.json");
    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "sign",
            "--key", "e2eagent",
            "--tool", "github_create_pr",
            "--params", r#"{"title":"fix bug"}"#,
            "--target", "mcp://github.local",
            "--output", receipt_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "verify",
            receipt_path.to_str().unwrap(),
            "--pubkey", "e2eagent",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Valid"))
        .stdout(predicate::str::contains("e2eagent"));
}

// ─── passphrase via env var ───────────────────────────────────────────────────

#[test]
fn test_passphrase_env_var() {
    let dir = tempdir().unwrap();
    // Generate encrypted key using SIGNET_PASSPHRASE
    signet()
        .env("SIGNET_HOME", dir.path())
        .env("SIGNET_PASSPHRASE", "mypassword")
        .args(["identity", "generate", "--name", "enckey"])
        .assert()
        .success();

    // Sign using the same SIGNET_PASSPHRASE to decrypt
    let receipt_path = dir.path().join("receipt.json");
    signet()
        .env("SIGNET_HOME", dir.path())
        .env("SIGNET_PASSPHRASE", "mypassword")
        .args([
            "sign",
            "--key", "enckey",
            "--tool", "bash",
            "--params", r#"{"cmd":"date"}"#,
            "--target", "mcp://local",
            "--output", receipt_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert!(receipt_path.exists());
}

// ─── @file params ────────────────────────────────────────────────────────────

#[test]
fn test_params_at_file() {
    let dir = tempdir().unwrap();
    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["identity", "generate", "--name", "atfilekey", "--unencrypted"])
        .assert()
        .success();

    let params_file = dir.path().join("params.json");
    fs::write(&params_file, r#"{"action":"deploy","env":"prod"}"#).unwrap();

    let at_arg = format!("@{}", params_file.to_str().unwrap());
    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "sign",
            "--key", "atfilekey",
            "--tool", "deploy",
            "--params", &at_arg,
            "--target", "mcp://deploy",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("sig"));
}

// ─── audit log ───────────────────────────────────────────────────────────────

#[test]
fn test_sign_creates_audit_log() {
    let dir = tempdir().unwrap();
    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["identity", "generate", "--name", "auditkey", "--unencrypted"])
        .assert()
        .success();

    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "sign",
            "--key", "auditkey",
            "--tool", "bash",
            "--params", r#"{"cmd":"ls"}"#,
            "--target", "mcp://local",
        ])
        .assert()
        .success();

    let audit_dir = dir.path().join("audit");
    assert!(audit_dir.exists(), "audit/ directory must exist");
    let entries: Vec<_> = fs::read_dir(&audit_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();
    assert_eq!(entries.len(), 1, "audit/ must have exactly 1 file");
}

#[test]
fn test_sign_no_log() {
    let dir = tempdir().unwrap();
    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["identity", "generate", "--name", "nologkey", "--unencrypted"])
        .assert()
        .success();

    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "sign",
            "--key", "nologkey",
            "--tool", "bash",
            "--params", r#"{"cmd":"ls"}"#,
            "--target", "mcp://local",
            "--no-log",
        ])
        .assert()
        .success();

    let audit_dir = dir.path().join("audit");
    assert!(!audit_dir.exists(), "audit/ directory must NOT exist when --no-log is used");
}

#[test]
fn test_audit_list() {
    let dir = tempdir().unwrap();
    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["identity", "generate", "--name", "listkey", "--unencrypted"])
        .assert()
        .success();

    for i in 0..3 {
        signet()
            .env("SIGNET_HOME", dir.path())
            .args([
                "sign",
                "--key", "listkey",
                "--tool", "bash",
                "--params", &format!(r#"{{"cmd":"cmd{i}"}}"#),
                "--target", "mcp://local",
            ])
            .assert()
            .success();
    }

    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["audit"])
        .assert()
        .success()
        .stdout(predicate::str::contains("3 records"));
}

#[test]
fn test_audit_since() {
    let dir = tempdir().unwrap();
    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["identity", "generate", "--name", "sincekey", "--unencrypted"])
        .assert()
        .success();

    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "sign",
            "--key", "sincekey",
            "--tool", "bash",
            "--params", r#"{"cmd":"date"}"#,
            "--target", "mcp://local",
        ])
        .assert()
        .success();

    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["audit", "--since", "1h"])
        .assert()
        .success()
        .stdout(predicate::str::contains("1 records"));
}

#[test]
fn test_audit_verify() {
    let dir = tempdir().unwrap();
    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["identity", "generate", "--name", "verifyauditkey", "--unencrypted"])
        .assert()
        .success();

    for i in 0..3 {
        signet()
            .env("SIGNET_HOME", dir.path())
            .args([
                "sign",
                "--key", "verifyauditkey",
                "--tool", "bash",
                "--params", &format!(r#"{{"cmd":"run{i}"}}"#),
                "--target", "mcp://local",
            ])
            .assert()
            .success();
    }

    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["audit", "--verify"])
        .assert()
        .success()
        .stdout(predicate::str::contains("3/3 signatures valid"));
}

#[test]
fn test_verify_chain() {
    let dir = tempdir().unwrap();
    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["identity", "generate", "--name", "chainkey", "--unencrypted"])
        .assert()
        .success();

    for i in 0..3 {
        signet()
            .env("SIGNET_HOME", dir.path())
            .args([
                "sign",
                "--key", "chainkey",
                "--tool", "bash",
                "--params", &format!(r#"{{"cmd":"step{i}"}}"#),
                "--target", "mcp://local",
            ])
            .assert()
            .success();
    }

    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["verify", "--chain"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Chain intact: 3 records verified"));
}

#[test]
fn test_params_at_nonexistent() {
    let dir = tempdir().unwrap();
    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["identity", "generate", "--name", "atmisskey", "--unencrypted"])
        .assert()
        .success();

    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "sign",
            "--key", "atmisskey",
            "--tool", "bash",
            "--params", "@/nonexistent/path/params.json",
            "--target", "mcp://local",
        ])
        .assert()
        .failure()
        .code(3)
        .stderr(predicate::str::contains("Error:"));
}
