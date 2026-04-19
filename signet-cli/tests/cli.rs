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
        .args([
            "identity",
            "generate",
            "--name",
            "exporter",
            "--unencrypted",
        ])
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
            "--key",
            "signer",
            "--tool",
            "bash",
            "--params",
            r#"{"cmd":"ls"}"#,
            "--target",
            "mcp://local",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let stdout = String::from_utf8(out).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("stdout must be valid JSON");
    assert!(v.get("sig").is_some(), "receipt must have 'sig' field");
    assert!(
        v.get("action").is_some(),
        "receipt must have 'action' field"
    );
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
            "--key",
            "filekey",
            "--tool",
            "bash",
            "--params",
            r#"{"cmd":"pwd"}"#,
            "--target",
            "mcp://local",
            "--output",
            receipt_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert!(receipt_path.exists(), "receipt file must exist");
    let content = fs::read_to_string(&receipt_path).unwrap();
    let v: serde_json::Value =
        serde_json::from_str(&content).expect("receipt file must be valid JSON");
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
            "--key",
            "verkey",
            "--tool",
            "read_file",
            "--params",
            r#"{"path":"/tmp/foo"}"#,
            "--target",
            "mcp://fs",
            "--output",
            receipt_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "verify",
            receipt_path.to_str().unwrap(),
            "--pubkey",
            "verkey",
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
            "--key",
            "tampkey",
            "--tool",
            "bash",
            "--params",
            r#"{"cmd":"echo hi"}"#,
            "--target",
            "mcp://local",
            "--output",
            receipt_path.to_str().unwrap(),
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
            "--pubkey",
            "tampkey",
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
        .args([
            "identity",
            "generate",
            "--name",
            "pubfilekey",
            "--unencrypted",
        ])
        .assert()
        .success();

    let receipt_path = dir.path().join("receipt.json");
    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "sign",
            "--key",
            "pubfilekey",
            "--tool",
            "list_dir",
            "--params",
            r#"{"path":"/tmp"}"#,
            "--target",
            "mcp://fs",
            "--output",
            receipt_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let pub_file_path = dir.path().join("keys").join("pubfilekey.pub");
    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "verify",
            receipt_path.to_str().unwrap(),
            "--pubkey",
            pub_file_path.to_str().unwrap(),
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
            "identity",
            "generate",
            "--name",
            "e2eagent",
            "--owner",
            "ci-robot",
            "--unencrypted",
        ])
        .assert()
        .success();

    let receipt_path = dir.path().join("receipt.json");
    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "sign",
            "--key",
            "e2eagent",
            "--tool",
            "github_create_pr",
            "--params",
            r#"{"title":"fix bug"}"#,
            "--target",
            "mcp://github.local",
            "--output",
            receipt_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "verify",
            receipt_path.to_str().unwrap(),
            "--pubkey",
            "e2eagent",
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
            "--key",
            "enckey",
            "--tool",
            "bash",
            "--params",
            r#"{"cmd":"date"}"#,
            "--target",
            "mcp://local",
            "--output",
            receipt_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert!(receipt_path.exists());
}

// ─── delegate create ────────────────────────────────────────────────────────

#[test]
fn test_delegate_create() {
    let dir = tempdir().unwrap();
    // Create delegator and delegate identities
    for name in ["owner", "agent"] {
        signet()
            .env("SIGNET_HOME", dir.path())
            .args(["identity", "generate", "--name", name, "--unencrypted"])
            .assert()
            .success();
    }

    let out = signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "delegate",
            "create",
            "--from",
            "owner",
            "--to",
            "agent",
            "--to-name",
            "my-agent",
            "--tools",
            "Bash,Read",
            "--targets",
            "mcp://github.local",
            "--max-depth",
            "1",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let stdout = String::from_utf8(out).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("must be valid JSON");
    assert_eq!(v["v"], 1);
    assert_eq!(v["delegator"]["name"], "owner");
    assert_eq!(v["delegate"]["name"], "my-agent");
    assert!(v["sig"].as_str().unwrap().starts_with("ed25519:"));
}

#[test]
fn test_delegate_create_output_file() {
    let dir = tempdir().unwrap();
    for name in ["alice", "bot"] {
        signet()
            .env("SIGNET_HOME", dir.path())
            .args(["identity", "generate", "--name", name, "--unencrypted"])
            .assert()
            .success();
    }

    let token_path = dir.path().join("token.json");
    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "delegate",
            "create",
            "--from",
            "alice",
            "--to",
            "bot",
            "--to-name",
            "bot",
            "--output",
            token_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert!(token_path.exists());
    let content = fs::read_to_string(&token_path).unwrap();
    let v: serde_json::Value = serde_json::from_str(&content).expect("must be valid JSON");
    assert!(v.get("sig").is_some());
}

// ─── delegate verify ────────────────────────────────────────────────────────

#[test]
fn test_delegate_verify_single_token() {
    let dir = tempdir().unwrap();
    for name in ["root", "agent"] {
        signet()
            .env("SIGNET_HOME", dir.path())
            .args(["identity", "generate", "--name", name, "--unencrypted"])
            .assert()
            .success();
    }

    let token_path = dir.path().join("token.json");
    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "delegate",
            "create",
            "--from",
            "root",
            "--to",
            "agent",
            "--to-name",
            "agent",
            "--output",
            token_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["delegate", "verify", token_path.to_str().unwrap()])
        .assert()
        .success()
        .stderr(predicate::str::contains("Token valid"));
}

// ─── delegate sign (v4 authorized receipt) ──────────────────────────────────

#[test]
fn test_delegate_sign_v4_receipt() {
    let dir = tempdir().unwrap();
    for name in ["owner", "bot"] {
        signet()
            .env("SIGNET_HOME", dir.path())
            .args(["identity", "generate", "--name", name, "--unencrypted"])
            .assert()
            .success();
    }

    // Create delegation token
    let token_path = dir.path().join("token.json");
    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "delegate",
            "create",
            "--from",
            "owner",
            "--to",
            "bot",
            "--to-name",
            "bot",
            "--tools",
            "*",
            "--targets",
            "*",
            "--output",
            token_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Wrap token in array for chain format
    let token_content = fs::read_to_string(&token_path).unwrap();
    let chain_path = dir.path().join("chain.json");
    fs::write(&chain_path, format!("[{token_content}]")).unwrap();

    // Sign an action with delegation chain
    let receipt_path = dir.path().join("v4_receipt.json");
    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "delegate",
            "sign",
            "--key",
            "bot",
            "--tool",
            "Bash",
            "--params",
            r#"{"command":"ls"}"#,
            "--target",
            "mcp://local",
            "--chain",
            chain_path.to_str().unwrap(),
            "--output",
            receipt_path.to_str().unwrap(),
            "--no-log",
        ])
        .assert()
        .success();

    let content = fs::read_to_string(&receipt_path).unwrap();
    let v: serde_json::Value = serde_json::from_str(&content).expect("must be valid JSON");
    assert_eq!(v["v"], 4);
    assert!(v.get("authorization").is_some());
}

// ─── delegate verify-auth (v4 receipt verification) ─────────────────────────

#[test]
fn test_delegate_verify_auth_e2e() {
    let dir = tempdir().unwrap();
    for name in ["root", "worker"] {
        signet()
            .env("SIGNET_HOME", dir.path())
            .args(["identity", "generate", "--name", name, "--unencrypted"])
            .assert()
            .success();
    }

    // Create delegation
    let token_path = dir.path().join("token.json");
    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "delegate",
            "create",
            "--from",
            "root",
            "--to",
            "worker",
            "--to-name",
            "worker",
            "--tools",
            "*",
            "--targets",
            "*",
            "--output",
            token_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let token_content = fs::read_to_string(&token_path).unwrap();
    let chain_path = dir.path().join("chain.json");
    fs::write(&chain_path, format!("[{token_content}]")).unwrap();

    // Sign action
    let receipt_path = dir.path().join("receipt.json");
    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "delegate",
            "sign",
            "--key",
            "worker",
            "--tool",
            "Read",
            "--params",
            r#"{"path":"/tmp/data"}"#,
            "--target",
            "mcp://fs",
            "--chain",
            chain_path.to_str().unwrap(),
            "--output",
            receipt_path.to_str().unwrap(),
            "--no-log",
        ])
        .assert()
        .success();

    // Verify against trusted root
    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "delegate",
            "verify-auth",
            receipt_path.to_str().unwrap(),
            "--trusted-roots",
            "root",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("Authorized receipt verified"));
}

#[test]
fn test_delegate_verify_auth_wrong_root() {
    let dir = tempdir().unwrap();
    for name in ["root", "worker", "stranger"] {
        signet()
            .env("SIGNET_HOME", dir.path())
            .args(["identity", "generate", "--name", name, "--unencrypted"])
            .assert()
            .success();
    }

    let token_path = dir.path().join("token.json");
    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "delegate",
            "create",
            "--from",
            "root",
            "--to",
            "worker",
            "--to-name",
            "worker",
            "--tools",
            "*",
            "--targets",
            "*",
            "--output",
            token_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let token_content = fs::read_to_string(&token_path).unwrap();
    let chain_path = dir.path().join("chain.json");
    fs::write(&chain_path, format!("[{token_content}]")).unwrap();

    let receipt_path = dir.path().join("receipt.json");
    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "delegate",
            "sign",
            "--key",
            "worker",
            "--tool",
            "Bash",
            "--params",
            "{}",
            "--target",
            "mcp://local",
            "--chain",
            chain_path.to_str().unwrap(),
            "--output",
            receipt_path.to_str().unwrap(),
            "--no-log",
        ])
        .assert()
        .success();

    // Verify with wrong root — should fail
    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "delegate",
            "verify-auth",
            receipt_path.to_str().unwrap(),
            "--trusted-roots",
            "stranger",
        ])
        .assert()
        .failure();
}

// ─── policy validate ────────────────────────────────────────────────────────

#[test]
fn test_policy_validate() {
    let dir = tempdir().unwrap();
    let policy_path = dir.path().join("policy.yaml");
    fs::write(
        &policy_path,
        "version: 1\nname: test-policy\nrules:\n  - id: deny-rm\n    match:\n      tool: Bash\n      params:\n        command:\n          contains: \"rm -rf\"\n    action: deny\n    reason: destructive command\n",
    )
    .unwrap();

    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["policy", "validate", policy_path.to_str().unwrap()])
        .assert()
        .success()
        .stderr(predicate::str::contains("test-policy"))
        .stderr(predicate::str::contains("valid"))
        .stderr(predicate::str::contains("1 rules"));
}

#[test]
fn test_policy_check_allowed() {
    let dir = tempdir().unwrap();
    let policy_path = dir.path().join("policy.yaml");
    fs::write(
        &policy_path,
        "version: 1\nname: check-policy\nrules:\n  - id: allow-read\n    match:\n      tool: Read\n    action: allow\n",
    )
    .unwrap();

    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "policy", "check",
            policy_path.to_str().unwrap(),
            "--tool", "Read",
            "--params", r#"{"path":"/tmp"}"#,
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("ALLOW"));
}

#[test]
fn test_policy_check_denied() {
    let dir = tempdir().unwrap();
    let policy_path = dir.path().join("policy.yaml");
    fs::write(
        &policy_path,
        "version: 1\nname: deny-policy\ndefault_action: deny\nrules: []\n",
    )
    .unwrap();

    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "policy", "check",
            policy_path.to_str().unwrap(),
            "--tool", "Bash",
        ])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("DENY"));
}

// ─── sign --policy ──────────────────────────────────────────────────────────

#[test]
fn test_sign_with_policy_cli_allowed() {
    let dir = tempdir().unwrap();
    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["identity", "generate", "--name", "polkey", "--unencrypted"])
        .assert()
        .success();

    let policy_path = dir.path().join("policy.yaml");
    fs::write(
        &policy_path,
        "version: 1\nname: allow-all\nrules: []\n",
    )
    .unwrap();

    let out = signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "sign",
            "--key", "polkey",
            "--tool", "Read",
            "--params", "{}",
            "--target", "mcp://local",
            "--policy", policy_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("allow-all"))
        .get_output()
        .stdout
        .clone();

    let stdout = String::from_utf8(out).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert!(v.get("policy").is_some(), "receipt must have policy attestation");
}

#[test]
fn test_sign_with_policy_cli_denied() {
    let dir = tempdir().unwrap();
    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["identity", "generate", "--name", "denkey", "--unencrypted"])
        .assert()
        .success();

    let policy_path = dir.path().join("policy.yaml");
    fs::write(
        &policy_path,
        "version: 1\nname: deny-all\ndefault_action: deny\nrules: []\n",
    )
    .unwrap();

    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "sign",
            "--key", "denkey",
            "--tool", "Bash",
            "--params", "{}",
            "--target", "mcp://local",
            "--policy", policy_path.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .code(1)  // exit_codes::VERIFICATION_FAILED
        .stderr(predicate::str::contains("policy violation"));
}

// ─── @file params ────────────────────────────────────────────────────────────

#[test]
fn test_params_at_file() {
    let dir = tempdir().unwrap();
    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "identity",
            "generate",
            "--name",
            "atfilekey",
            "--unencrypted",
        ])
        .assert()
        .success();

    let params_file = dir.path().join("params.json");
    fs::write(&params_file, r#"{"action":"deploy","env":"prod"}"#).unwrap();

    let at_arg = format!("@{}", params_file.to_str().unwrap());
    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "sign",
            "--key",
            "atfilekey",
            "--tool",
            "deploy",
            "--params",
            &at_arg,
            "--target",
            "mcp://deploy",
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
        .args([
            "identity",
            "generate",
            "--name",
            "auditkey",
            "--unencrypted",
        ])
        .assert()
        .success();

    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "sign",
            "--key",
            "auditkey",
            "--tool",
            "bash",
            "--params",
            r#"{"cmd":"ls"}"#,
            "--target",
            "mcp://local",
        ])
        .assert()
        .success();

    let audit_dir = dir.path().join("audit");
    assert!(audit_dir.exists(), "audit/ directory must exist");
    let jsonl_files: Vec<_> = fs::read_dir(&audit_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .map(|ext| ext == "jsonl")
                .unwrap_or(false)
        })
        .collect();
    assert_eq!(
        jsonl_files.len(),
        1,
        "audit/ must have exactly 1 .jsonl file"
    );
}

#[test]
fn test_sign_no_log() {
    let dir = tempdir().unwrap();
    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "identity",
            "generate",
            "--name",
            "nologkey",
            "--unencrypted",
        ])
        .assert()
        .success();

    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "sign",
            "--key",
            "nologkey",
            "--tool",
            "bash",
            "--params",
            r#"{"cmd":"ls"}"#,
            "--target",
            "mcp://local",
            "--no-log",
        ])
        .assert()
        .success();

    let audit_dir = dir.path().join("audit");
    assert!(
        !audit_dir.exists(),
        "audit/ directory must NOT exist when --no-log is used"
    );
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
                "--key",
                "listkey",
                "--tool",
                "bash",
                "--params",
                &format!(r#"{{"cmd":"cmd{i}"}}"#),
                "--target",
                "mcp://local",
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
        .args([
            "identity",
            "generate",
            "--name",
            "sincekey",
            "--unencrypted",
        ])
        .assert()
        .success();

    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "sign",
            "--key",
            "sincekey",
            "--tool",
            "bash",
            "--params",
            r#"{"cmd":"date"}"#,
            "--target",
            "mcp://local",
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
        .args([
            "identity",
            "generate",
            "--name",
            "verifyauditkey",
            "--unencrypted",
        ])
        .assert()
        .success();

    for i in 0..3 {
        signet()
            .env("SIGNET_HOME", dir.path())
            .args([
                "sign",
                "--key",
                "verifyauditkey",
                "--tool",
                "bash",
                "--params",
                &format!(r#"{{"cmd":"run{i}"}}"#),
                "--target",
                "mcp://local",
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
        .args([
            "identity",
            "generate",
            "--name",
            "chainkey",
            "--unencrypted",
        ])
        .assert()
        .success();

    for i in 0..3 {
        signet()
            .env("SIGNET_HOME", dir.path())
            .args([
                "sign",
                "--key",
                "chainkey",
                "--tool",
                "bash",
                "--params",
                &format!(r#"{{"cmd":"step{i}"}}"#),
                "--target",
                "mcp://local",
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
        .args([
            "identity",
            "generate",
            "--name",
            "atmisskey",
            "--unencrypted",
        ])
        .assert()
        .success();

    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "sign",
            "--key",
            "atmisskey",
            "--tool",
            "bash",
            "--params",
            "@/nonexistent/path/params.json",
            "--target",
            "mcp://local",
        ])
        .assert()
        .failure()
        .code(3)
        .stderr(predicate::str::contains("Error:"));
}

// ─── proxy ──────────────────────────────────────────────────────────────────

/// Helper: run proxy with input, return (stdout, stderr)
fn run_proxy(
    dir: &std::path::Path,
    target: &str,
    key: &str,
    input: &str,
    extra_args: &[&str],
) -> (String, String) {
    use std::io::Write;
    use std::process::{Command as StdCommand, Stdio};

    let bin = assert_cmd::cargo::cargo_bin("signet");

    let mut cmd = StdCommand::new(bin);
    cmd.env("SIGNET_HOME", dir)
        .args(["proxy", "--target", target, "--key", key])
        .args(extra_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("failed to spawn proxy");

    // Write input to stdin then close it
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(input.as_bytes()).expect("write stdin");
        // stdin drops here, closing pipe → proxy sees EOF → exits
    }

    let output = child
        .wait_with_output()
        .expect("wait for proxy");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (stdout, stderr)
}

fn mock_server_cmd() -> String {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    format!("python3 {}/tests/mock_mcp_server.py", manifest_dir)
}

#[test]
fn test_proxy_signs_tools_call() {
    let dir = tempdir().unwrap();
    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["identity", "generate", "--name", "proxykey", "--unencrypted"])
        .assert()
        .success();

    let input = concat!(
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"message":"hello"}}}"#,
        "\n",
    );

    let (stdout, stderr) = run_proxy(dir.path(), &mock_server_cmd(), "proxykey", input, &[]);

    // Proxy should have signed the call
    assert!(
        stderr.contains("[signet proxy] signed: echo"),
        "stderr should log signing: {stderr}",
    );

    // Server should have received the _signet receipt
    // The "signed" field is inside a nested JSON string, so it appears escaped
    assert!(
        stdout.contains(r#"\"signed\": \"yes\""#) || stdout.contains(r#""signed": "yes""#),
        "server should see _signet in params: {stdout}",
    );
}

#[test]
fn test_proxy_passthrough_non_tools_call() {
    let dir = tempdir().unwrap();
    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["identity", "generate", "--name", "passkey", "--unencrypted"])
        .assert()
        .success();

    let input = concat!(
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
        "\n",
    );

    let (stdout, stderr) = run_proxy(dir.path(), &mock_server_cmd(), "passkey", input, &[]);

    // Should NOT log signing for initialize
    assert!(
        !stderr.contains("[signet proxy] signed:"),
        "initialize should not be signed: {stderr}",
    );

    // Should pass through and get response
    assert!(
        stdout.contains("protocolVersion") || stdout.contains("mock"),
        "should get initialize response: {stdout}",
    );
}

#[test]
fn test_proxy_writes_audit_log() {
    let dir = tempdir().unwrap();
    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["identity", "generate", "--name", "auditkey", "--unencrypted"])
        .assert()
        .success();

    let input = concat!(
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"test_tool","arguments":{}}}"#,
        "\n",
    );

    let (_stdout, _stderr) = run_proxy(dir.path(), &mock_server_cmd(), "auditkey", input, &[]);

    // Audit log should exist
    let audit_dir = dir.path().join("audit");
    assert!(audit_dir.exists(), "audit/ should exist");
    let files: Vec<_> = fs::read_dir(&audit_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map(|ext| ext == "jsonl").unwrap_or(false))
        .collect();
    assert!(!files.is_empty(), "should have audit .jsonl file");

    // Read and verify audit content
    let content = fs::read_to_string(files[0].path()).unwrap();
    assert!(content.contains("test_tool"), "audit should contain tool name");
    assert!(content.contains("ed25519:"), "audit should contain signature");
}

#[test]
fn test_proxy_no_log_skips_audit() {
    let dir = tempdir().unwrap();
    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["identity", "generate", "--name", "nologkey", "--unencrypted"])
        .assert()
        .success();

    let input = concat!(
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{}}}"#,
        "\n",
    );

    let (_stdout, stderr) = run_proxy(
        dir.path(), &mock_server_cmd(), "nologkey", input, &["--no-log"],
    );

    // Should still sign
    assert!(stderr.contains("[signet proxy] signed:"));

    // But no audit directory
    let audit_dir = dir.path().join("audit");
    assert!(!audit_dir.exists(), "audit/ should NOT exist with --no-log");
}

#[test]
fn test_proxy_with_policy_allowed() {
    let dir = tempdir().unwrap();
    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["identity", "generate", "--name", "polkey", "--unencrypted"])
        .assert()
        .success();

    let policy_path = dir.path().join("policy.yaml");
    fs::write(
        &policy_path,
        "version: 1\nname: allow-all\nrules: []\n",
    )
    .unwrap();

    let input = concat!(
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{}}}"#,
        "\n",
    );

    let (_stdout, stderr) = run_proxy(
        dir.path(), &mock_server_cmd(), "polkey", input,
        &["--policy", policy_path.to_str().unwrap()],
    );

    assert!(stderr.contains("[signet proxy] signed:"), "should sign with policy: {stderr}");
}

#[test]
fn test_proxy_with_policy_denied() {
    let dir = tempdir().unwrap();
    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["identity", "generate", "--name", "denkey", "--unencrypted"])
        .assert()
        .success();

    let policy_path = dir.path().join("policy.yaml");
    fs::write(
        &policy_path,
        "version: 1\nname: deny-all\ndefault_action: deny\nrules: []\n",
    )
    .unwrap();

    let input = concat!(
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"Bash","arguments":{"cmd":"ls"}}}"#,
        "\n",
    );

    let (_stdout, stderr) = run_proxy(
        dir.path(), &mock_server_cmd(), "denkey", input,
        &["--policy", policy_path.to_str().unwrap()],
    );

    assert!(
        stderr.contains("DENIED") || stderr.contains("policy violation"),
        "should deny: {stderr}",
    );
}

#[test]
fn test_proxy_multiple_messages() {
    let dir = tempdir().unwrap();
    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["identity", "generate", "--name", "multikey", "--unencrypted"])
        .assert()
        .success();

    let input = concat!(
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#, "\n",
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read","arguments":{"path":"/tmp"}}}"#, "\n",
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"write","arguments":{"path":"a.txt"}}}"#, "\n",
    );

    let (stdout, stderr) = run_proxy(dir.path(), &mock_server_cmd(), "multikey", input, &[]);

    // Should sign exactly 2 tools/call, not initialize
    let sign_count = stderr.matches("[signet proxy] signed:").count();
    assert_eq!(sign_count, 2, "should sign 2 tools/call, got {sign_count}: {stderr}");

    // Should get 3 responses
    let response_count = stdout.matches("\"jsonrpc\"").count();
    assert_eq!(response_count, 3, "should get 3 responses, got {response_count}: {stdout}");
}

#[test]
fn test_proxy_bilateral_cosigning() {
    let dir = tempdir().unwrap();
    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["identity", "generate", "--name", "bilatkey", "--unencrypted"])
        .assert()
        .success();

    let input = concat!(
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"msg":"test"}}}"#, "\n",
    );

    let (_stdout, stderr) = run_proxy(dir.path(), &mock_server_cmd(), "bilatkey", input, &[]);

    // Should sign the request
    assert!(
        stderr.contains("[signet proxy] signed: echo"),
        "should sign request: {stderr}",
    );

    // Should bilateral co-sign the response
    assert!(
        stderr.contains("bilateral: echo") && stderr.contains("response co-signed"),
        "should bilateral co-sign: {stderr}",
    );

    // Should log "1 signed, 1 bilateral"
    assert!(
        stderr.contains("1 signed, 1 bilateral"),
        "should count bilateral: {stderr}",
    );

    // Audit should contain bilateral receipt (v3)
    let audit_dir = dir.path().join("audit");
    assert!(audit_dir.exists());
    let files: Vec<_> = fs::read_dir(&audit_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map(|ext| ext == "jsonl").unwrap_or(false))
        .collect();
    let content = fs::read_to_string(files[0].path()).unwrap();
    // Bilateral receipt has v:3 and agent_receipt embedded
    assert!(content.contains("\"v\":3") || content.contains("\"v\": 3"), "should have v3 bilateral receipt: {content}");
    assert!(content.contains("agent_receipt"), "should embed agent_receipt: {content}");
}

#[test]
fn test_proxy_bilateral_multiple_calls() {
    let dir = tempdir().unwrap();
    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["identity", "generate", "--name", "multibi", "--unencrypted"])
        .assert()
        .success();

    let input = concat!(
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read","arguments":{}}}"#, "\n",
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"write","arguments":{}}}"#, "\n",
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"bash","arguments":{}}}"#, "\n",
    );

    let (_stdout, stderr) = run_proxy(dir.path(), &mock_server_cmd(), "multibi", input, &[]);

    // Should sign 3 and bilateral 3
    assert!(
        stderr.contains("3 signed, 3 bilateral"),
        "should have 3 bilateral: {stderr}",
    );
}

// ─── explore ─────────────────────────────────────────────────────────────────

/// Helper: create a key and sign N receipts with different tools.
fn setup_explore_env(dir: &std::path::Path, key: &str, tools: &[&str]) {
    signet()
        .env("SIGNET_HOME", dir)
        .args(["identity", "generate", "--name", key, "--unencrypted"])
        .assert()
        .success();

    for tool in tools {
        signet()
            .env("SIGNET_HOME", dir)
            .args([
                "sign",
                "--key",
                key,
                "--tool",
                tool,
                "--params",
                &format!(r#"{{"tool":"{tool}"}}"#),
                "--target",
                "mcp://local",
            ])
            .assert()
            .success();
    }
}

#[test]
fn test_explore_default_table() {
    let dir = tempdir().unwrap();
    setup_explore_env(dir.path(), "exp1", &["bash", "read", "write"]);

    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["explore"])
        .assert()
        .success()
        .stdout(predicate::str::contains("3 receipts shown"))
        .stdout(predicate::str::contains("bash"))
        .stdout(predicate::str::contains("read"))
        .stdout(predicate::str::contains("write"));
}

#[test]
fn test_explore_empty() {
    let dir = tempdir().unwrap();
    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["explore"])
        .assert()
        .success()
        .stdout(predicate::str::contains("No receipts found"));
}

#[test]
fn test_explore_tool_filter() {
    let dir = tempdir().unwrap();
    setup_explore_env(dir.path(), "exp2", &["bash", "read", "bash", "write"]);

    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["explore", "--tool", "bash"])
        .assert()
        .success()
        .stdout(predicate::str::contains("2 receipts shown"));
}

#[test]
fn test_explore_signer_filter() {
    let dir = tempdir().unwrap();
    setup_explore_env(dir.path(), "exp3", &["bash", "read"]);

    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["explore", "--signer", "exp3"])
        .assert()
        .success()
        .stdout(predicate::str::contains("2 receipts shown"));

    // Non-existent signer
    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["explore", "--signer", "nonexistent"])
        .assert()
        .success()
        .stdout(predicate::str::contains("No receipts found"));
}

#[test]
fn test_explore_show_receipt() {
    let dir = tempdir().unwrap();
    setup_explore_env(dir.path(), "exp4", &["bash"]);

    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["explore", "--show", "1"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Receipt Details"))
        .stdout(predicate::str::contains("bash"))
        .stdout(predicate::str::contains("exp4"))
        .stdout(predicate::str::contains("ed25519:"));
}

#[test]
fn test_explore_show_full_json() {
    let dir = tempdir().unwrap();
    setup_explore_env(dir.path(), "exp5", &["read"]);

    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["explore", "--show", "1", "--full"])
        .assert()
        .success()
        .stdout(predicate::str::contains(r#""v": 1"#))
        .stdout(predicate::str::contains(r#""tool": "read""#));
}

#[test]
fn test_explore_show_out_of_range() {
    let dir = tempdir().unwrap();
    setup_explore_env(dir.path(), "exp6", &["bash"]);

    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["explore", "--show", "999"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("out of range"));
}

#[test]
fn test_explore_chain() {
    let dir = tempdir().unwrap();
    setup_explore_env(dir.path(), "exp7", &["bash", "read", "write"]);

    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["explore", "--chain"])
        .assert()
        .success()
        .stdout(predicate::str::contains("INTACT"))
        .stdout(predicate::str::contains("3/3 valid"));
}

#[test]
fn test_explore_stats() {
    let dir = tempdir().unwrap();
    setup_explore_env(dir.path(), "exp8", &["bash", "bash", "read", "write", "write", "write"]);

    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["explore", "--stats"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Total receipts: 6"))
        .stdout(predicate::str::contains("write"))
        .stdout(predicate::str::contains("v1 (unilateral)"));
}

#[test]
fn test_explore_tail() {
    let dir = tempdir().unwrap();
    setup_explore_env(dir.path(), "exp9", &["a", "b", "c", "d", "e"]);

    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["explore", "--tail", "2"])
        .assert()
        .success()
        .stdout(predicate::str::contains("2 receipts shown (of 5 total)"));
}

#[test]
fn test_explore_since() {
    let dir = tempdir().unwrap();
    setup_explore_env(dir.path(), "exp10", &["bash", "read"]);

    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["explore", "--since", "1h"])
        .assert()
        .success()
        .stdout(predicate::str::contains("2 receipts shown"));
}
