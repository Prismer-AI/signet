use assert_cmd::Command;
use base64::Engine;
use predicates::prelude::*;
use serde_json::Value;
use std::fs;
use std::path::Path;
use tempfile::tempdir;

fn signet() -> Command {
    Command::cargo_bin("signet").unwrap()
}

fn read_pubkey_with_prefix(dir: &Path, name: &str) -> String {
    let path = dir.join("keys").join(format!("{name}.pub"));
    let value: Value = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    let pubkey = value["pubkey"].as_str().unwrap();
    if pubkey.starts_with("ed25519:") {
        pubkey.to_string()
    } else {
        format!("ed25519:{pubkey}")
    }
}

fn write_trust_bundle(
    path: &Path,
    env: &str,
    roots: &[(&str, &str)],
    agents: &[(&str, &str)],
    servers: &[(&str, &str)],
) {
    let entries = |items: &[(&str, &str)]| {
        items
            .iter()
            .map(|(id, pubkey)| {
                serde_json::json!({
                    "id": id,
                    "name": id,
                    "owner": "platform",
                    "pubkey": pubkey,
                    "status": "active",
                    "created_at": "2026-04-25T10:00:00Z"
                })
            })
            .collect::<Vec<_>>()
    };

    let bundle = serde_json::json!({
        "version": 1,
        "bundle_id": format!("tb_{env}"),
        "org": "signet",
        "env": env,
        "generated_at": "2026-04-25T10:30:00Z",
        "roots": entries(roots),
        "agents": entries(agents),
        "servers": entries(servers),
    });
    fs::write(path, serde_json::to_string_pretty(&bundle).unwrap()).unwrap();
}

fn write_trust_bundle_yaml(path: &Path, env: &str, agents: &[(&str, &str)]) {
    let agents = agents
        .iter()
        .map(|(id, pubkey)| {
            format!(
                "  - id: {id}\n    name: {id}\n    owner: platform\n    pubkey: \"{pubkey}\"\n    status: active\n    created_at: \"2026-04-25T10:00:00Z\"\n"
            )
        })
        .collect::<String>();

    let yaml = format!(
        "version: 1\nbundle_id: tb_{env}\norg: signet\nenv: {env}\ngenerated_at: \"2026-04-25T10:30:00Z\"\nroots: []\nagents:\n{agents}servers: []\n"
    );
    fs::write(path, yaml).unwrap();
}

fn generate_identity_unencrypted(dir: &Path, name: &str) {
    signet()
        .env("SIGNET_HOME", dir)
        .args(["identity", "generate", "--name", name, "--unencrypted"])
        .assert()
        .success();
}

fn read_json(path: &Path) -> Value {
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

fn read_first_audit_record(dir: &Path) -> Value {
    let audit_dir = dir.join("audit");
    let mut jsonl_files: Vec<_> = fs::read_dir(&audit_dir)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            entry
                .path()
                .extension()
                .map(|ext| ext == "jsonl")
                .unwrap_or(false)
        })
        .collect();
    jsonl_files.sort_by_key(|entry| entry.path());

    let file = jsonl_files.first().unwrap().path();
    let line = fs::read_to_string(file)
        .unwrap()
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap()
        .to_string();
    serde_json::from_str(&line).unwrap()
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
fn test_verify_valid_with_trust_bundle_v1() {
    let dir = tempdir().unwrap();
    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "identity",
            "generate",
            "--name",
            "bundlekey",
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
            "bundlekey",
            "--tool",
            "read_file",
            "--params",
            r#"{"path":"/tmp/foo"}"#,
            "--target",
            "mcp://fs",
            "--output",
            receipt_path.to_str().unwrap(),
            "--no-log",
        ])
        .assert()
        .success();

    let trust_path = dir.path().join("trust.json");
    let agent_pubkey = read_pubkey_with_prefix(dir.path(), "bundlekey");
    write_trust_bundle(
        &trust_path,
        "dev",
        &[],
        &[("bundlekey", agent_pubkey.as_str())],
        &[],
    );

    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "verify",
            receipt_path.to_str().unwrap(),
            "--trust-bundle",
            trust_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Valid"))
        .stderr(predicate::str::contains(
            "Using trust bundle tb_dev (env: dev)",
        ));
}

#[test]
fn test_verify_bilateral_with_trust_bundle_v3() {
    let dir = tempdir().unwrap();
    let (agent_key, agent_vk) = signet_core::generate_keypair();
    let (server_key, server_vk) = signet_core::generate_keypair();
    let action = signet_core::Action {
        tool: "bash".to_string(),
        params: serde_json::json!({"cmd":"echo hi"}),
        params_hash: String::new(),
        target: "mcp://local".to_string(),
        transport: "stdio".to_string(),
        session: None,
        call_id: None,
        response_hash: None,
        trace_id: None,
        parent_receipt_id: None,
    };
    let receipt = signet_core::sign(&agent_key, &action, "agent", "").unwrap();
    let bilateral = signet_core::sign_bilateral(
        &server_key,
        &receipt,
        &serde_json::json!({"ok": true}),
        "server",
        &chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    )
    .unwrap();
    let receipt_path = dir.path().join("bilateral.json");
    fs::write(
        &receipt_path,
        serde_json::to_string_pretty(&bilateral).unwrap(),
    )
    .unwrap();

    let trust_path = dir.path().join("trust.json");
    let agent_pubkey = format!(
        "ed25519:{}",
        base64::engine::general_purpose::STANDARD.encode(agent_vk.as_bytes())
    );
    let server_pubkey = format!(
        "ed25519:{}",
        base64::engine::general_purpose::STANDARD.encode(server_vk.as_bytes())
    );
    write_trust_bundle(
        &trust_path,
        "prod",
        &[],
        &[("agent", agent_pubkey.as_str())],
        &[("server", server_pubkey.as_str())],
    );

    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "verify",
            receipt_path.to_str().unwrap(),
            "--trust-bundle",
            trust_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("bilateral receipt trusted"))
        .stderr(predicate::str::contains(
            "Using trust bundle tb_prod (env: prod)",
        ));
}

#[test]
fn test_verify_v3_nonce_store_persists_across_invocations() {
    // First `signet verify --nonce-store path` verifies a v3 receipt OK.
    // Second invocation on the same receipt must detect replay because
    // the nonce was recorded in the file and survives the process exit.
    let dir = tempdir().unwrap();
    let (agent_key, agent_vk) = signet_core::generate_keypair();
    let (server_key, server_vk) = signet_core::generate_keypair();
    let action = signet_core::Action {
        tool: "bash".to_string(),
        params: serde_json::json!({"cmd": "echo hi"}),
        params_hash: String::new(),
        target: "mcp://local".to_string(),
        transport: "stdio".to_string(),
        session: None,
        call_id: None,
        response_hash: None,
        trace_id: None,
        parent_receipt_id: None,
    };
    let receipt = signet_core::sign(&agent_key, &action, "agent", "").unwrap();
    let bilateral = signet_core::sign_bilateral(
        &server_key,
        &receipt,
        &serde_json::json!({"ok": true}),
        "server",
        &chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    )
    .unwrap();
    let receipt_path = dir.path().join("bilateral.json");
    fs::write(
        &receipt_path,
        serde_json::to_string_pretty(&bilateral).unwrap(),
    )
    .unwrap();

    let trust_path = dir.path().join("trust.json");
    let agent_pk = format!(
        "ed25519:{}",
        base64::engine::general_purpose::STANDARD.encode(agent_vk.as_bytes())
    );
    let server_pk = format!(
        "ed25519:{}",
        base64::engine::general_purpose::STANDARD.encode(server_vk.as_bytes())
    );
    write_trust_bundle(
        &trust_path,
        "prod",
        &[],
        &[("agent", agent_pk.as_str())],
        &[("server", server_pk.as_str())],
    );

    let nonce_store = dir.path().join("nonces.json");

    // First verification — should succeed and record nonce to file.
    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "verify",
            receipt_path.to_str().unwrap(),
            "--trust-bundle",
            trust_path.to_str().unwrap(),
            "--nonce-store",
            nonce_store.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert!(
        nonce_store.exists(),
        "nonce store file should be created on first verify"
    );

    // Second verification (separate process) — replay must be detected
    // because the nonce file persists.
    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "verify",
            receipt_path.to_str().unwrap(),
            "--trust-bundle",
            trust_path.to_str().unwrap(),
            "--nonce-store",
            nonce_store.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("replay").or(predicate::str::contains("nonce")));
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
fn test_delegate_create_with_ttl() {
    let dir = tempdir().unwrap();
    for name in ["owner-ttl", "agent-ttl"] {
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
            "owner-ttl",
            "--to",
            "agent-ttl",
            "--to-name",
            "short-lived-agent",
            "--tools",
            "Bash",
            "--ttl",
            "1h",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let stdout = String::from_utf8(out).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("must be valid JSON");
    // Must have an expires field
    let expires = v["scope"]["expires"].as_str().expect("expires must be set");
    // Should be roughly 1h from now (within a few seconds)
    let exp_dt = chrono::DateTime::parse_from_rfc3339(expires).expect("valid RFC 3339");
    let now = chrono::Utc::now();
    let diff = exp_dt.signed_duration_since(now);
    assert!(
        diff.num_seconds() > 3500 && diff.num_seconds() <= 3600,
        "TTL 1h should produce expires ~3600s from now, got {}s",
        diff.num_seconds()
    );
}

#[test]
fn test_delegate_create_ttl_conflicts_with_expires() {
    let dir = tempdir().unwrap();
    for name in ["own-c", "agt-c"] {
        signet()
            .env("SIGNET_HOME", dir.path())
            .args(["identity", "generate", "--name", name, "--unencrypted"])
            .assert()
            .success();
    }

    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "delegate",
            "create",
            "--from",
            "own-c",
            "--to",
            "agt-c",
            "--to-name",
            "x",
            "--ttl",
            "1h",
            "--expires",
            "2026-12-31T23:59:59Z",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
fn test_delegate_create_ttl_formats() {
    let dir = tempdir().unwrap();
    for name in ["own-f", "agt-f"] {
        signet()
            .env("SIGNET_HOME", dir.path())
            .args(["identity", "generate", "--name", name, "--unencrypted"])
            .assert()
            .success();
    }

    // Test 30m
    let out = signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "delegate",
            "create",
            "--from",
            "own-f",
            "--to",
            "agt-f",
            "--to-name",
            "x",
            "--ttl",
            "30m",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let v: serde_json::Value = serde_json::from_str(&String::from_utf8(out).unwrap()).unwrap();
    let exp_dt =
        chrono::DateTime::parse_from_rfc3339(v["scope"]["expires"].as_str().unwrap()).unwrap();
    let diff = exp_dt.signed_duration_since(chrono::Utc::now());
    assert!(
        diff.num_seconds() > 1700 && diff.num_seconds() <= 1800,
        "30m TTL: got {}s",
        diff.num_seconds()
    );

    // Test 7d
    let out = signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "delegate",
            "create",
            "--from",
            "own-f",
            "--to",
            "agt-f",
            "--to-name",
            "x",
            "--ttl",
            "7d",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let v: serde_json::Value = serde_json::from_str(&String::from_utf8(out).unwrap()).unwrap();
    let exp_dt =
        chrono::DateTime::parse_from_rfc3339(v["scope"]["expires"].as_str().unwrap()).unwrap();
    let diff = exp_dt.signed_duration_since(chrono::Utc::now());
    assert!(
        diff.num_days() >= 6 && diff.num_days() <= 7,
        "7d TTL: got {} days",
        diff.num_days()
    );
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
fn test_delegate_verify_auth_with_trust_bundle() {
    let dir = tempdir().unwrap();
    for name in ["root", "worker"] {
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

    let trust_path = dir.path().join("trust.json");
    let root_pubkey = read_pubkey_with_prefix(dir.path(), "root");
    write_trust_bundle(
        &trust_path,
        "prod",
        &[("root", root_pubkey.as_str())],
        &[],
        &[],
    );

    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "delegate",
            "verify-auth",
            receipt_path.to_str().unwrap(),
            "--trust-bundle",
            trust_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("Authorized receipt verified"))
        .stderr(predicate::str::contains(
            "Using trust bundle tb_prod (env: prod)",
        ));
}

#[test]
fn test_delegate_verify_chain_with_trust_bundle() {
    let dir = tempdir().unwrap();
    for name in ["root", "worker"] {
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

    let trust_path = dir.path().join("trust.json");
    let root_pubkey = read_pubkey_with_prefix(dir.path(), "root");
    write_trust_bundle(
        &trust_path,
        "prod",
        &[("root", root_pubkey.as_str())],
        &[],
        &[],
    );

    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "delegate",
            "verify",
            chain_path.to_str().unwrap(),
            "--trust-bundle",
            trust_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("Chain valid"))
        .stderr(predicate::str::contains(
            "Using trust bundle tb_prod (env: prod)",
        ));
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
            "policy",
            "check",
            policy_path.to_str().unwrap(),
            "--tool",
            "Read",
            "--params",
            r#"{"path":"/tmp"}"#,
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
            "policy",
            "check",
            policy_path.to_str().unwrap(),
            "--tool",
            "Bash",
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
    fs::write(&policy_path, "version: 1\nname: allow-all\nrules: []\n").unwrap();

    let out = signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "sign",
            "--key",
            "polkey",
            "--tool",
            "Read",
            "--params",
            "{}",
            "--target",
            "mcp://local",
            "--policy",
            policy_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("allow-all"))
        .get_output()
        .stdout
        .clone();

    let stdout = String::from_utf8(out).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert!(
        v.get("policy").is_some(),
        "receipt must have policy attestation"
    );
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
            "--key",
            "denkey",
            "--tool",
            "Bash",
            "--params",
            "{}",
            "--target",
            "mcp://local",
            "--policy",
            policy_path.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .code(1) // exit_codes::VERIFICATION_FAILED
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
fn test_sign_encrypt_params_stores_encrypted_audit_record() {
    let dir = tempdir().unwrap();
    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "identity",
            "generate",
            "--name",
            "encauditkey",
            "--unencrypted",
        ])
        .assert()
        .success();

    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "sign",
            "--key",
            "encauditkey",
            "--tool",
            "bash",
            "--params",
            r#"{"cmd":"ls","secret":"top-secret"}"#,
            "--target",
            "mcp://local",
            "--encrypt-params",
        ])
        .assert()
        .success();

    let record = read_first_audit_record(dir.path());
    let action = record["receipt"]["action"].as_object().unwrap();
    assert!(!action.contains_key("params"));
    let envelope = action["params_encrypted"].as_object().unwrap();
    let expected_kid = read_pubkey_with_prefix(dir.path(), "encauditkey");
    assert_eq!(envelope["v"].as_u64(), Some(1));
    assert_eq!(envelope["alg"].as_str(), Some("xchacha20poly1305"));
    assert_eq!(envelope["kid"].as_str(), Some(expected_kid.as_str()));
}

#[test]
fn test_sign_encrypt_params_hash_only_rejected() {
    let dir = tempdir().unwrap();
    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["identity", "generate", "--name", "hashenc", "--unencrypted"])
        .assert()
        .success();

    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "sign",
            "--key",
            "hashenc",
            "--tool",
            "bash",
            "--params",
            r#"{"cmd":"ls"}"#,
            "--target",
            "mcp://local",
            "--hash-only",
            "--encrypt-params",
        ])
        .assert()
        .failure()
        .code(3)
        .stderr(predicate::str::contains(
            "--encrypt-params cannot be used with --hash-only",
        ));
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
fn test_audit_verify_encrypted_params_with_local_key() {
    let dir = tempdir().unwrap();
    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "identity",
            "generate",
            "--name",
            "verifyenc",
            "--unencrypted",
        ])
        .assert()
        .success();

    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "sign",
            "--key",
            "verifyenc",
            "--tool",
            "bash",
            "--params",
            r#"{"cmd":"run"}"#,
            "--target",
            "mcp://local",
            "--encrypt-params",
        ])
        .assert()
        .success();

    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["audit", "--verify"])
        .assert()
        .success()
        .stdout(predicate::str::contains("1/1 signatures valid"))
        .stdout(predicate::str::contains("Warnings:").not());
}

#[test]
fn test_audit_verify_encrypted_params_without_local_key_warns() {
    let dir = tempdir().unwrap();
    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["identity", "generate", "--name", "copyenc", "--unencrypted"])
        .assert()
        .success();

    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "sign",
            "--key",
            "copyenc",
            "--tool",
            "bash",
            "--params",
            r#"{"cmd":"run"}"#,
            "--target",
            "mcp://local",
            "--encrypt-params",
        ])
        .assert()
        .success();

    let other = tempdir().unwrap();
    fs::create_dir_all(other.path().join("audit")).unwrap();
    for entry in fs::read_dir(dir.path().join("audit")).unwrap() {
        let entry = entry.unwrap();
        fs::copy(
            entry.path(),
            other.path().join("audit").join(entry.file_name()),
        )
        .unwrap();
    }

    signet()
        .env("SIGNET_HOME", other.path())
        .args(["audit", "--verify"])
        .assert()
        .success()
        .stdout(predicate::str::contains("0/1 signatures valid"))
        .stdout(predicate::str::contains("Warnings:"))
        .stdout(predicate::str::contains("integrity-only"));
}

#[test]
fn test_audit_export_decrypt_params_includes_materialized_receipt() {
    let dir = tempdir().unwrap();
    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "identity",
            "generate",
            "--name",
            "exportenc",
            "--unencrypted",
        ])
        .assert()
        .success();

    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "sign",
            "--key",
            "exportenc",
            "--tool",
            "bash",
            "--params",
            r#"{"cmd":"run","secret":"top-secret"}"#,
            "--target",
            "mcp://local",
            "--encrypt-params",
        ])
        .assert()
        .success();

    let export_path = dir.path().join("audit-export.json");
    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "audit",
            "--export",
            export_path.to_str().unwrap(),
            "--decrypt-params",
        ])
        .assert()
        .success();

    let exported = read_json(&export_path);
    let records = exported.as_array().unwrap();
    assert_eq!(records.len(), 1);
    assert!(records[0]["receipt"]["action"]["params"].is_null());
    assert!(records[0]["receipt"]["action"]["params_encrypted"].is_object());
    assert_eq!(
        records[0]["materialized_receipt"]["action"]["params"]["secret"].as_str(),
        Some("top-secret")
    );
    assert!(records[0]["materialized_receipt"]["action"]["params_encrypted"].is_null());
}

#[test]
fn test_audit_export_decrypt_params_without_local_key_fails() {
    let dir = tempdir().unwrap();
    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "identity",
            "generate",
            "--name",
            "exportcopy",
            "--unencrypted",
        ])
        .assert()
        .success();

    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "sign",
            "--key",
            "exportcopy",
            "--tool",
            "bash",
            "--params",
            r#"{"cmd":"run"}"#,
            "--target",
            "mcp://local",
            "--encrypt-params",
        ])
        .assert()
        .success();

    let other = tempdir().unwrap();
    fs::create_dir_all(other.path().join("audit")).unwrap();
    for entry in fs::read_dir(dir.path().join("audit")).unwrap() {
        let entry = entry.unwrap();
        fs::copy(
            entry.path(),
            other.path().join("audit").join(entry.file_name()),
        )
        .unwrap();
    }

    let export_path = other.path().join("audit-export.json");
    signet()
        .env("SIGNET_HOME", other.path())
        .args([
            "audit",
            "--export",
            export_path.to_str().unwrap(),
            "--decrypt-params",
        ])
        .assert()
        .failure()
        .code(3)
        .stderr(predicate::str::contains(
            "no matching local identity was found",
        ));
}

#[test]
fn test_audit_decrypt_params_requires_export() {
    let dir = tempdir().unwrap();
    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["audit", "--decrypt-params"])
        .assert()
        .failure()
        .code(3)
        .stderr(predicate::str::contains(
            "--decrypt-params requires --export",
        ));
}

#[test]
fn test_audit_verify_bilateral_warns_without_trusted_keys() {
    let dir = tempdir().unwrap();
    let (agent_key, _) = signet_core::generate_keypair();
    let (server_key, _) = signet_core::generate_keypair();
    let action = signet_core::Action {
        tool: "bash".to_string(),
        params: serde_json::json!({"cmd":"echo hi"}),
        params_hash: String::new(),
        target: "mcp://local".to_string(),
        transport: "stdio".to_string(),
        session: None,
        call_id: None,
        response_hash: None,
        trace_id: None,
        parent_receipt_id: None,
    };
    let receipt = signet_core::sign(&agent_key, &action, "agent", "").unwrap();
    let bilateral = signet_core::sign_bilateral(
        &server_key,
        &receipt,
        &serde_json::json!({"ok": true}),
        "server",
        &chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    )
    .unwrap();
    signet_core::audit::append(dir.path(), &serde_json::to_value(&bilateral).unwrap()).unwrap();

    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["audit", "--verify"])
        .assert()
        .success()
        .stdout(predicate::str::contains("1/1 signatures valid"))
        .stdout(predicate::str::contains("Warnings:"))
        .stdout(predicate::str::contains("integrity only"));
}

#[test]
fn test_audit_verify_bilateral_with_trusted_keys() {
    let dir = tempdir().unwrap();
    let (agent_key, agent_vk) = signet_core::generate_keypair();
    let (server_key, server_vk) = signet_core::generate_keypair();
    let action = signet_core::Action {
        tool: "bash".to_string(),
        params: serde_json::json!({"cmd":"echo hi"}),
        params_hash: String::new(),
        target: "mcp://local".to_string(),
        transport: "stdio".to_string(),
        session: None,
        call_id: None,
        response_hash: None,
        trace_id: None,
        parent_receipt_id: None,
    };
    let receipt = signet_core::sign(&agent_key, &action, "agent", "").unwrap();
    let bilateral = signet_core::sign_bilateral(
        &server_key,
        &receipt,
        &serde_json::json!({"ok": true}),
        "server",
        &chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    )
    .unwrap();
    signet_core::audit::append(dir.path(), &serde_json::to_value(&bilateral).unwrap()).unwrap();

    let agent_pubkey = base64::engine::general_purpose::STANDARD.encode(agent_vk.as_bytes());
    let server_pubkey = base64::engine::general_purpose::STANDARD.encode(server_vk.as_bytes());

    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "audit",
            "--verify",
            "--trusted-agent-key",
            &agent_pubkey,
            "--trusted-server-key",
            &server_pubkey,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("1/1 signatures valid"))
        .stdout(predicate::str::contains("Warnings:").not());
}

#[test]
fn test_audit_verify_bilateral_with_trust_bundle() {
    let dir = tempdir().unwrap();
    let (agent_key, agent_vk) = signet_core::generate_keypair();
    let (server_key, server_vk) = signet_core::generate_keypair();
    let action = signet_core::Action {
        tool: "bash".to_string(),
        params: serde_json::json!({"cmd":"echo hi"}),
        params_hash: String::new(),
        target: "mcp://local".to_string(),
        transport: "stdio".to_string(),
        session: None,
        call_id: None,
        response_hash: None,
        trace_id: None,
        parent_receipt_id: None,
    };
    let receipt = signet_core::sign(&agent_key, &action, "agent", "").unwrap();
    let bilateral = signet_core::sign_bilateral(
        &server_key,
        &receipt,
        &serde_json::json!({"ok": true}),
        "server",
        &chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    )
    .unwrap();
    signet_core::audit::append(dir.path(), &serde_json::to_value(&bilateral).unwrap()).unwrap();

    let trust_path = dir.path().join("trust.json");
    let agent_pubkey = format!(
        "ed25519:{}",
        base64::engine::general_purpose::STANDARD.encode(agent_vk.as_bytes())
    );
    let server_pubkey = format!(
        "ed25519:{}",
        base64::engine::general_purpose::STANDARD.encode(server_vk.as_bytes())
    );
    write_trust_bundle(
        &trust_path,
        "prod",
        &[],
        &[("agent", agent_pubkey.as_str())],
        &[("server", server_pubkey.as_str())],
    );

    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "audit",
            "--verify",
            "--trust-bundle",
            trust_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("1/1 signatures valid"))
        .stdout(predicate::str::contains("Warnings:").not())
        .stderr(predicate::str::contains(
            "Using trust bundle tb_prod (env: prod)",
        ));
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
) -> (std::process::ExitStatus, String, String) {
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

    let output = child.wait_with_output().expect("wait for proxy");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (output.status, stdout, stderr)
}

fn mock_server_cmd() -> String {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    format!("python3 {}/tests/mock_mcp_server.py", manifest_dir)
}

fn parse_mock_tool_payload(stdout: &str) -> Value {
    let line = stdout
        .lines()
        .find(|line| !line.trim().is_empty())
        .expect("mock server should emit a JSON-RPC line");
    let response: Value = serde_json::from_str(line).expect("stdout should be valid JSON-RPC");
    let text = response["result"]["content"][0]["text"]
        .as_str()
        .expect("mock tool response should contain text");
    serde_json::from_str(text).expect("mock tool text should be valid JSON")
}

#[test]
fn test_proxy_signs_tools_call() {
    let dir = tempdir().unwrap();
    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "identity",
            "generate",
            "--name",
            "proxykey",
            "--unencrypted",
        ])
        .assert()
        .success();

    let input = concat!(
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"message":"hello"}}}"#,
        "\n",
    );

    let (status, stdout, stderr) =
        run_proxy(dir.path(), &mock_server_cmd(), "proxykey", input, &[]);
    assert!(status.success(), "proxy should succeed: {stderr}");

    // Proxy should have signed the call
    assert!(
        stderr.contains("[signet proxy] signed: echo"),
        "stderr should log signing: {stderr}",
    );

    // Server should have received the _signet receipt
    // The "signed" field is inside a nested JSON string, so it appears escaped
    let payload = parse_mock_tool_payload(&stdout);
    assert_eq!(
        payload["signed"], "yes",
        "server should see _signet in params: {stdout}"
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

    let (status, stdout, stderr) = run_proxy(dir.path(), &mock_server_cmd(), "passkey", input, &[]);
    assert!(status.success(), "proxy should succeed: {stderr}");

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
        .args([
            "identity",
            "generate",
            "--name",
            "auditkey",
            "--unencrypted",
        ])
        .assert()
        .success();

    let input = concat!(
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"test_tool","arguments":{}}}"#,
        "\n",
    );

    let (status, _stdout, _stderr) =
        run_proxy(dir.path(), &mock_server_cmd(), "auditkey", input, &[]);
    assert!(status.success());

    // Audit log should exist
    let audit_dir = dir.path().join("audit");
    assert!(audit_dir.exists(), "audit/ should exist");
    let files: Vec<_> = fs::read_dir(&audit_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .map(|ext| ext == "jsonl")
                .unwrap_or(false)
        })
        .collect();
    assert!(!files.is_empty(), "should have audit .jsonl file");

    // Read and verify audit content
    let content = fs::read_to_string(files[0].path()).unwrap();
    assert!(
        content.contains("test_tool"),
        "audit should contain tool name"
    );
    assert!(
        content.contains("ed25519:"),
        "audit should contain signature"
    );
}

#[test]
fn test_proxy_no_log_skips_audit() {
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

    let input = concat!(
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{}}}"#,
        "\n",
    );

    let (status, _stdout, stderr) = run_proxy(
        dir.path(),
        &mock_server_cmd(),
        "nologkey",
        input,
        &["--no-log"],
    );
    assert!(status.success(), "proxy should succeed: {stderr}");

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
    fs::write(&policy_path, "version: 1\nname: allow-all\nrules: []\n").unwrap();

    let input = concat!(
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{}}}"#,
        "\n",
    );

    let (status, _stdout, stderr) = run_proxy(
        dir.path(),
        &mock_server_cmd(),
        "polkey",
        input,
        &["--policy", policy_path.to_str().unwrap()],
    );
    assert!(status.success(), "proxy should succeed: {stderr}");

    assert!(
        stderr.contains("[signet proxy] signed:"),
        "should sign with policy: {stderr}"
    );
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

    let (status, stdout, stderr) = run_proxy(
        dir.path(),
        &mock_server_cmd(),
        "denkey",
        input,
        &["--policy", policy_path.to_str().unwrap()],
    );
    assert!(
        status.success(),
        "proxy should return a handled JSON-RPC error: {stderr}"
    );

    assert!(
        stderr.contains("DENIED") || stderr.contains("policy violation"),
        "should deny: {stderr}",
    );
    assert!(
        stderr.contains("1 signed, 1 bilateral"),
        "deny path should still produce a bilateral outcome: {stderr}",
    );

    let forwarded: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(forwarded["error"]["code"].as_i64(), Some(-32600));
    assert!(
        forwarded["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("policy violation"),
        "should forward policy violation as JSON-RPC error: {stdout}",
    );

    let audit_dir = dir.path().join("audit");
    let files: Vec<_> = fs::read_dir(&audit_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .map(|ext| ext == "jsonl")
                .unwrap_or(false)
        })
        .collect();
    assert_eq!(files.len(), 1, "expected exactly one audit jsonl file");
    let content = fs::read_to_string(files[0].path()).unwrap();
    assert!(
        content.contains(r#""type":"policy_violation""#)
            || content.contains(r#""type": "policy_violation""#),
        "should append policy_violation audit record: {content}",
    );
    assert!(
        content.contains(r#""status":"rejected""#)
            && content.contains(r#""reason":"no rules matched, using default action""#),
        "proxy deny path should emit a signed rejected bilateral outcome: {content}",
    );
}

#[test]
fn test_proxy_with_policy_requires_approval() {
    let dir = tempdir().unwrap();
    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["identity", "generate", "--name", "appkey", "--unencrypted"])
        .assert()
        .success();

    let policy_path = dir.path().join("policy.yaml");
    fs::write(
        &policy_path,
        "version: 1\nname: approval-all\ndefault_action: require_approval\nrules: []\n",
    )
    .unwrap();

    let input = concat!(
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"Bash","arguments":{"cmd":"ls"}}}"#,
        "\n",
    );

    let (status, stdout, stderr) = run_proxy(
        dir.path(),
        &mock_server_cmd(),
        "appkey",
        input,
        &["--policy", policy_path.to_str().unwrap()],
    );
    assert!(
        status.success(),
        "proxy should return a handled JSON-RPC error: {stderr}"
    );
    assert!(
        stderr.contains("NEEDS APPROVAL") || stderr.contains("requires approval"),
        "should mark request as needing approval: {stderr}",
    );
    assert!(
        stderr.contains("1 signed, 1 bilateral"),
        "requires-approval path should produce a bilateral outcome: {stderr}",
    );

    let forwarded: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(forwarded["error"]["code"].as_i64(), Some(-32600));
    assert!(
        forwarded["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("requires approval"),
        "should forward approval requirement as JSON-RPC error: {stdout}",
    );

    let audit_dir = dir.path().join("audit");
    let files: Vec<_> = fs::read_dir(&audit_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .map(|ext| ext == "jsonl")
                .unwrap_or(false)
        })
        .collect();
    assert_eq!(files.len(), 1, "expected exactly one audit jsonl file");
    let content = fs::read_to_string(files[0].path()).unwrap();
    assert!(
        content.contains(r#""type":"policy_violation""#)
            || content.contains(r#""type": "policy_violation""#),
        "should append policy_violation audit record: {content}",
    );
    assert!(
        content.contains(r#""status":"requires_approval""#)
            && content.contains(r#""reason":"no rules matched, using default action""#),
        "approval path should emit a signed requires_approval bilateral outcome: {content}",
    );
}

#[test]
fn test_proxy_multiple_messages() {
    let dir = tempdir().unwrap();
    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "identity",
            "generate",
            "--name",
            "multikey",
            "--unencrypted",
        ])
        .assert()
        .success();

    let input = concat!(
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read","arguments":{"path":"/tmp"}}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"write","arguments":{"path":"a.txt"}}}"#,
        "\n",
    );

    let (status, stdout, stderr) =
        run_proxy(dir.path(), &mock_server_cmd(), "multikey", input, &[]);
    assert!(status.success(), "proxy should succeed: {stderr}");

    // Should sign exactly 2 tools/call, not initialize
    let sign_count = stderr.matches("[signet proxy] signed:").count();
    assert_eq!(
        sign_count, 2,
        "should sign 2 tools/call, got {sign_count}: {stderr}"
    );

    // Should get 3 responses
    let response_count = stdout.matches("\"jsonrpc\"").count();
    assert_eq!(
        response_count, 3,
        "should get 3 responses, got {response_count}: {stdout}"
    );
}

#[test]
fn test_proxy_bilateral_cosigning() {
    let dir = tempdir().unwrap();
    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "identity",
            "generate",
            "--name",
            "bilatkey",
            "--unencrypted",
        ])
        .assert()
        .success();

    let input = concat!(
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"msg":"test"}}}"#,
        "\n",
    );

    let (status, stdout, stderr) =
        run_proxy(dir.path(), &mock_server_cmd(), "bilatkey", input, &[]);
    assert!(status.success(), "proxy should succeed: {stderr}");

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
    assert!(
        stderr.contains("bilateral mode: audit-only; responses are forwarded unchanged"),
        "should explain audit-only bilateral mode: {stderr}",
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
        .filter(|e| {
            e.path()
                .extension()
                .map(|ext| ext == "jsonl")
                .unwrap_or(false)
        })
        .collect();
    let content = fs::read_to_string(files[0].path()).unwrap();
    // Bilateral receipt has v:3 and agent_receipt embedded
    assert!(
        content.contains("\"v\":3") || content.contains("\"v\": 3"),
        "should have v3 bilateral receipt: {content}"
    );
    assert!(
        content.contains("agent_receipt"),
        "should embed agent_receipt: {content}"
    );
    assert!(
        content.contains(r#""outcome":{"status":"executed"}"#)
            || content.contains(r#""outcome": {"status": "executed"}"#)
            || content.contains(r#""status":"executed""#),
        "should record executed outcome in bilateral receipt: {content}"
    );

    // The transparent proxy path must not inject bilateral metadata into the
    // JSON-RPC response body; that path is audit-only.
    assert!(
        !stdout.contains("_signet_bilateral"),
        "proxy should forward response unchanged without bilateral metadata: {stdout}",
    );
}

#[test]
fn test_proxy_bilateral_failed_outcome_on_server_error() {
    let dir = tempdir().unwrap();
    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["identity", "generate", "--name", "failkey", "--unencrypted"])
        .assert()
        .success();

    let input = concat!(
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"explode","arguments":{"msg":"test"}}}"#,
        "\n",
    );

    let (status, stdout, stderr) = run_proxy(dir.path(), &mock_server_cmd(), "failkey", input, &[]);
    assert!(status.success(), "proxy should succeed: {stderr}");
    let forwarded: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(forwarded["error"]["code"].as_i64(), Some(-32000));
    assert_eq!(forwarded["error"]["message"].as_str(), Some("boom"));

    let audit_dir = dir.path().join("audit");
    let files: Vec<_> = fs::read_dir(&audit_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .map(|ext| ext == "jsonl")
                .unwrap_or(false)
        })
        .collect();
    let content = fs::read_to_string(files[0].path()).unwrap();
    assert!(
        content.contains(r#""status":"failed""#) && content.contains(r#""error":"boom""#),
        "should record failed outcome with server error in bilateral receipt: {content}"
    );
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
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read","arguments":{}}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"write","arguments":{}}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"bash","arguments":{}}}"#,
        "\n",
    );

    let (status, _stdout, stderr) =
        run_proxy(dir.path(), &mock_server_cmd(), "multibi", input, &[]);
    assert!(status.success(), "proxy should succeed: {stderr}");

    // Should sign 3 and bilateral 3
    assert!(
        stderr.contains("3 signed, 3 bilateral"),
        "should have 3 bilateral: {stderr}",
    );
}

#[test]
fn test_proxy_rejects_shell_syntax_without_shell_flag() {
    let dir = tempdir().unwrap();
    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "identity",
            "generate",
            "--name",
            "shellkey",
            "--unencrypted",
        ])
        .assert()
        .success();

    let input = concat!(
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"message":"hello"}}}"#,
        "\n",
    );

    let target = format!("{} && true", mock_server_cmd());
    let (status, _stdout, stderr) = run_proxy(dir.path(), &target, "shellkey", input, &[]);

    assert!(!status.success(), "proxy should reject shell syntax");
    assert!(
        stderr.contains("pass --shell to opt in to shell execution"),
        "stderr should explain why shell syntax was rejected: {stderr}",
    );
}

#[test]
fn test_proxy_shell_flag_allows_shell_syntax() {
    let dir = tempdir().unwrap();
    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["identity", "generate", "--name", "shellok", "--unencrypted"])
        .assert()
        .success();

    let input = concat!(
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"message":"hello"}}}"#,
        "\n",
    );

    let target = format!("{} && true", mock_server_cmd());
    let (status, stdout, stderr) = run_proxy(dir.path(), &target, "shellok", input, &["--shell"]);

    assert!(status.success(), "proxy should allow shell mode: {stderr}");
    assert!(
        stderr.contains("shell mode: enabled"),
        "shell mode should be logged: {stderr}"
    );
    let payload = parse_mock_tool_payload(&stdout);
    assert_eq!(
        payload["signed"], "yes",
        "server should still receive signed request: {stdout}"
    );
}

#[test]
fn test_proxy_filters_default_sensitive_env() {
    let dir = tempdir().unwrap();
    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["identity", "generate", "--name", "envkey", "--unencrypted"])
        .assert()
        .success();

    let input = concat!(
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"envcheck","arguments":{"names":["OPENAI_API_KEY","PUBLIC_VALUE"]}}}"#,
        "\n",
    );

    let bin = assert_cmd::cargo::cargo_bin("signet");
    let output = std::process::Command::new(bin)
        .env("SIGNET_HOME", dir.path())
        .env("OPENAI_API_KEY", "top-secret")
        .env("PUBLIC_VALUE", "visible")
        .args(["proxy", "--target", &mock_server_cmd(), "--key", "envkey"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(input.as_bytes())?;
            }
            child.wait_with_output()
        })
        .expect("run proxy");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert!(output.status.success(), "proxy should succeed: {stderr}");
    let payload = parse_mock_tool_payload(&stdout);
    assert_eq!(
        payload["env"]["PUBLIC_VALUE"], "visible",
        "public env should pass through: {stdout}"
    );
    assert!(
        payload["env"]["OPENAI_API_KEY"].is_null(),
        "sensitive env should be filtered by default: {stdout}"
    );
}

#[test]
fn test_proxy_allow_env_overrides_default_filter() {
    let dir = tempdir().unwrap();
    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "identity",
            "generate",
            "--name",
            "allowenv",
            "--unencrypted",
        ])
        .assert()
        .success();

    let input = concat!(
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"envcheck","arguments":{"names":["OPENAI_API_KEY"]}}}"#,
        "\n",
    );

    let bin = assert_cmd::cargo::cargo_bin("signet");
    let output = std::process::Command::new(bin)
        .env("SIGNET_HOME", dir.path())
        .env("OPENAI_API_KEY", "top-secret")
        .args([
            "proxy",
            "--target",
            &mock_server_cmd(),
            "--key",
            "allowenv",
            "--allow-env",
            "OPENAI_API_KEY",
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(input.as_bytes())?;
            }
            child.wait_with_output()
        })
        .expect("run proxy");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert!(output.status.success(), "proxy should succeed: {stderr}");
    let payload = parse_mock_tool_payload(&stdout);
    assert_eq!(
        payload["env"]["OPENAI_API_KEY"], "top-secret",
        "allowlist should forward the requested env var: {stdout}"
    );
    assert!(
        stderr.contains("allowlisted OPENAI_API_KEY"),
        "allowlist usage should be logged: {stderr}",
    );
}

#[test]
fn test_proxy_aggressive_env_filter_blocks_generic_secret_names() {
    let dir = tempdir().unwrap();
    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["identity", "generate", "--name", "aggenv", "--unencrypted"])
        .assert()
        .success();

    let input = concat!(
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"envcheck","arguments":{"names":["INTERNAL_SECRET","PUBLIC_VALUE"]}}}"#,
        "\n",
    );

    let bin = assert_cmd::cargo::cargo_bin("signet");
    let output = std::process::Command::new(bin)
        .env("SIGNET_HOME", dir.path())
        .env("INTERNAL_SECRET", "super-secret")
        .env("PUBLIC_VALUE", "visible")
        .args([
            "proxy",
            "--target",
            &mock_server_cmd(),
            "--key",
            "aggenv",
            "--env-filter",
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(input.as_bytes())?;
            }
            child.wait_with_output()
        })
        .expect("run proxy");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert!(output.status.success(), "proxy should succeed: {stderr}");
    let payload = parse_mock_tool_payload(&stdout);
    assert_eq!(
        payload["env"]["PUBLIC_VALUE"], "visible",
        "public env should pass through: {stdout}"
    );
    assert!(
        payload["env"]["INTERNAL_SECRET"].is_null(),
        "aggressive mode should filter generic secret names: {stdout}"
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

fn append_explore_bilateral_outcome_record(
    dir: &std::path::Path,
    status: signet_core::Outcome,
    response: serde_json::Value,
) {
    let (agent_key, _) = signet_core::generate_keypair();
    let (server_key, _) = signet_core::generate_keypair();
    let action = signet_core::Action {
        tool: "payments.refund".to_string(),
        params: serde_json::json!({"order_id":"ord_123","amount":49}),
        params_hash: String::new(),
        target: "mcp://payments".to_string(),
        transport: "stdio".to_string(),
        session: None,
        call_id: None,
        response_hash: None,
        trace_id: Some("tr_explore".to_string()),
        parent_receipt_id: Some("rec_parent".to_string()),
    };
    let receipt = signet_core::sign(&agent_key, &action, "exp-outcome", "").unwrap();
    let bilateral = signet_core::sign_bilateral_with_outcome(
        &server_key,
        &receipt,
        &response,
        "edge-proxy",
        &chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        Some(status),
    )
    .unwrap();
    signet_core::audit::append(dir, &serde_json::to_value(&bilateral).unwrap()).unwrap();
}

fn append_explore_policy_violation(dir: &std::path::Path) {
    let action = signet_core::Action {
        tool: "payments.refund".to_string(),
        params: serde_json::json!({"order_id":"ord_123","amount":99}),
        params_hash: String::new(),
        target: "mcp://payments".to_string(),
        transport: "stdio".to_string(),
        session: None,
        call_id: None,
        response_hash: None,
        trace_id: None,
        parent_receipt_id: None,
    };
    let eval = signet_core::policy::PolicyEvalResult {
        decision: signet_core::policy::RuleAction::Deny,
        matched_rules: vec!["deny-refund".to_string()],
        winning_rule: Some("deny-refund".to_string()),
        reason: "refund exceeds threshold".to_string(),
        evaluated_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        policy_name: "payments-prod".to_string(),
        policy_hash: "sha256:feedface".to_string(),
    };
    signet_core::audit::append_violation(dir, &action, "policy-agent", &eval).unwrap();
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
fn test_explore_show_bilateral_outcome() {
    let dir = tempdir().unwrap();
    append_explore_bilateral_outcome_record(
        dir.path(),
        signet_core::Outcome::requires_approval("manager approval required"),
        serde_json::json!({"blocked": true}),
    );

    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["explore", "--show", "1"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Outcome"))
        .stdout(predicate::str::contains("requires_approval"))
        .stdout(predicate::str::contains("manager approval required"))
        .stdout(predicate::str::contains("Agent sig:"))
        .stdout(predicate::str::contains("Server sig:"))
        .stdout(predicate::str::contains("Server:"));
}

#[test]
fn test_explore_show_policy_violation() {
    let dir = tempdir().unwrap();
    append_explore_policy_violation(dir.path());

    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["explore", "--show", "1"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Policy Violation"))
        .stdout(predicate::str::contains("Status:      rejected"))
        .stdout(predicate::str::contains("Decision:    deny"))
        .stdout(predicate::str::contains("policy-agent"))
        .stdout(predicate::str::contains("refund exceeds threshold"))
        .stdout(predicate::str::contains("deny-refund"));
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
fn test_explore_show_decrypt_params() {
    let dir = tempdir().unwrap();
    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "identity",
            "generate",
            "--name",
            "exploreenc",
            "--unencrypted",
        ])
        .assert()
        .success();

    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "sign",
            "--key",
            "exploreenc",
            "--tool",
            "bash",
            "--params",
            r#"{"cmd":"ls","secret":"shown"}"#,
            "--target",
            "mcp://local",
            "--encrypt-params",
        ])
        .assert()
        .success();

    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["explore", "--show", "1", "--decrypt-params"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Decrypted params"))
        .stdout(predicate::str::contains(r#""secret": "shown""#));
}

#[test]
fn test_explore_show_full_json_decrypt_params() {
    let dir = tempdir().unwrap();
    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "identity",
            "generate",
            "--name",
            "explorefullenc",
            "--unencrypted",
        ])
        .assert()
        .success();

    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "sign",
            "--key",
            "explorefullenc",
            "--tool",
            "read",
            "--params",
            r#"{"path":"/tmp/secret"}"#,
            "--target",
            "mcp://fs",
            "--encrypt-params",
        ])
        .assert()
        .success();

    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["explore", "--show", "1", "--full", "--decrypt-params"])
        .assert()
        .success()
        .stdout(predicate::str::contains(r#""params": {"#))
        .stdout(predicate::str::contains(r#""path": "/tmp/secret""#))
        .stdout(predicate::str::contains("params_encrypted").not());
}

#[test]
fn test_explore_decrypt_params_requires_show() {
    let dir = tempdir().unwrap();
    setup_explore_env(dir.path(), "exp-decrypt", &["bash"]);

    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["explore", "--decrypt-params"])
        .assert()
        .failure()
        .code(3)
        .stderr(predicate::str::contains("--decrypt-params requires --show"));
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
    setup_explore_env(
        dir.path(),
        "exp8",
        &["bash", "bash", "read", "write", "write", "write"],
    );

    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["explore", "--stats"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Total records: 6"))
        .stdout(predicate::str::contains("write"))
        .stdout(predicate::str::contains("v1 (unilateral)"));
}

#[test]
fn test_explore_stats_include_outcomes_and_record_types() {
    let dir = tempdir().unwrap();
    setup_explore_env(dir.path(), "expstats", &["read"]);
    append_explore_bilateral_outcome_record(
        dir.path(),
        signet_core::Outcome::failed("connection refused"),
        serde_json::json!({"error": "connection refused"}),
    );
    append_explore_policy_violation(dir.path());

    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["explore", "--stats"])
        .assert()
        .success()
        .stdout(predicate::str::contains("By outcome:"))
        .stdout(predicate::str::contains("failed"))
        .stdout(predicate::str::contains("By record type:"))
        .stdout(predicate::str::contains("policy_violation"))
        .stdout(predicate::str::contains("Policy gate decisions:"))
        .stdout(predicate::str::contains("deny"));
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

#[test]
fn test_trust_inspect_and_list_active() {
    let dir = tempdir().unwrap();
    generate_identity_unencrypted(dir.path(), "root1");
    generate_identity_unencrypted(dir.path(), "agent1");
    generate_identity_unencrypted(dir.path(), "server1");

    let trust_path = dir.path().join("trust.json");
    let root_pubkey = read_pubkey_with_prefix(dir.path(), "root1");
    let agent_pubkey = read_pubkey_with_prefix(dir.path(), "agent1");
    let server_pubkey = read_pubkey_with_prefix(dir.path(), "server1");
    write_trust_bundle(
        &trust_path,
        "dev",
        &[("root1", root_pubkey.as_str())],
        &[("agent1", agent_pubkey.as_str())],
        &[("server1", server_pubkey.as_str())],
    );

    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["trust", "inspect", trust_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Bundle: tb_dev"))
        .stdout(predicate::str::contains(
            "roots: total=1 active=1 disabled=0 revoked=0 expired=0",
        ))
        .stdout(predicate::str::contains("agent1"))
        .stdout(predicate::str::contains("server1"));

    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "trust",
            "list",
            trust_path.to_str().unwrap(),
            "--section",
            "agents",
            "--active-only",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("agent1"))
        .stdout(predicate::str::contains("root1").not())
        .stdout(predicate::str::contains("server1").not());
}

#[test]
fn test_trust_disable_updates_bundle() {
    let dir = tempdir().unwrap();
    generate_identity_unencrypted(dir.path(), "agent1");

    let trust_path = dir.path().join("trust.json");
    let agent_pubkey = read_pubkey_with_prefix(dir.path(), "agent1");
    write_trust_bundle(
        &trust_path,
        "prod",
        &[],
        &[("agent1", agent_pubkey.as_str())],
        &[],
    );

    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "trust",
            "disable",
            trust_path.to_str().unwrap(),
            "--section",
            "agents",
            "--id",
            "agent1",
            "--at",
            "2026-04-25T12:00:00Z",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "Disabled agents entry 'agent1' in",
        ));

    let bundle = read_json(&trust_path);
    let agent = &bundle["agents"][0];
    assert_eq!(agent["status"].as_str(), Some("disabled"));
    assert_eq!(agent["disabled_at"].as_str(), Some("2026-04-25T12:00:00Z"));
    assert!(agent["revoked_at"].is_null());
    assert_eq!(
        bundle["generated_at"].as_str(),
        Some("2026-04-25T12:00:00Z")
    );
}

#[test]
fn test_trust_revoke_updates_bundle() {
    let dir = tempdir().unwrap();
    generate_identity_unencrypted(dir.path(), "agent1");

    let trust_path = dir.path().join("trust.json");
    let agent_pubkey = read_pubkey_with_prefix(dir.path(), "agent1");
    write_trust_bundle(
        &trust_path,
        "prod",
        &[],
        &[("agent1", agent_pubkey.as_str())],
        &[],
    );

    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "trust",
            "revoke",
            trust_path.to_str().unwrap(),
            "--section",
            "agents",
            "--id",
            "agent1",
            "--at",
            "2026-04-25T12:30:00Z",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("Revoked agents entry 'agent1' in"));

    let bundle = read_json(&trust_path);
    let agent = &bundle["agents"][0];
    assert_eq!(agent["status"].as_str(), Some("revoked"));
    assert_eq!(agent["revoked_at"].as_str(), Some("2026-04-25T12:30:00Z"));
    assert!(agent["disabled_at"].is_null());
    assert_eq!(
        bundle["generated_at"].as_str(),
        Some("2026-04-25T12:30:00Z")
    );
}

#[test]
fn test_trust_rotate_disables_old_entry_by_default() {
    let dir = tempdir().unwrap();
    generate_identity_unencrypted(dir.path(), "agent-old");
    generate_identity_unencrypted(dir.path(), "agent-new");

    let trust_path = dir.path().join("trust.json");
    let old_pubkey = read_pubkey_with_prefix(dir.path(), "agent-old");
    let new_pubkey = read_pubkey_with_prefix(dir.path(), "agent-new");
    write_trust_bundle(
        &trust_path,
        "prod",
        &[],
        &[("agent-old", old_pubkey.as_str())],
        &[],
    );

    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "trust",
            "rotate",
            trust_path.to_str().unwrap(),
            "--section",
            "agents",
            "--id",
            "agent-old",
            "--new-id",
            "agent-new",
            "--new-pubkey",
            new_pubkey.as_str(),
            "--new-owner",
            "ops",
            "--at",
            "2026-04-25T13:00:00Z",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "Rotated agents entry 'agent-old' -> 'agent-new' in",
        ));

    let bundle = read_json(&trust_path);
    let agents = bundle["agents"].as_array().unwrap();
    assert_eq!(agents.len(), 2);
    assert_eq!(
        bundle["generated_at"].as_str(),
        Some("2026-04-25T13:00:00Z")
    );

    let old_entry = agents
        .iter()
        .find(|entry| entry["id"].as_str() == Some("agent-old"))
        .unwrap();
    assert_eq!(old_entry["status"].as_str(), Some("disabled"));
    assert_eq!(
        old_entry["disabled_at"].as_str(),
        Some("2026-04-25T13:00:00Z")
    );
    assert!(old_entry["expires_at"].is_null());

    let new_entry = agents
        .iter()
        .find(|entry| entry["id"].as_str() == Some("agent-new"))
        .unwrap();
    assert_eq!(new_entry["status"].as_str(), Some("active"));
    assert_eq!(
        new_entry["created_at"].as_str(),
        Some("2026-04-25T13:00:00Z")
    );
    assert_eq!(new_entry["owner"].as_str(), Some("ops"));
    assert_eq!(
        new_entry["comment"].as_str(),
        Some("rotated from agent-old")
    );
}

#[test]
fn test_trust_rotate_with_overlap_sets_expiration() {
    let dir = tempdir().unwrap();
    generate_identity_unencrypted(dir.path(), "agent-old");
    generate_identity_unencrypted(dir.path(), "agent-new");

    let trust_path = dir.path().join("trust.json");
    let old_pubkey = read_pubkey_with_prefix(dir.path(), "agent-old");
    let new_pubkey = read_pubkey_with_prefix(dir.path(), "agent-new");
    write_trust_bundle(
        &trust_path,
        "prod",
        &[],
        &[("agent-old", old_pubkey.as_str())],
        &[],
    );

    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "trust",
            "rotate",
            trust_path.to_str().unwrap(),
            "--section",
            "agents",
            "--id",
            "agent-old",
            "--new-id",
            "agent-new",
            "--new-pubkey",
            new_pubkey.as_str(),
            "--overlap-until",
            "2026-05-01T00:00:00Z",
            "--at",
            "2026-04-25T13:30:00Z",
        ])
        .assert()
        .success();

    let bundle = read_json(&trust_path);
    let agents = bundle["agents"].as_array().unwrap();
    assert_eq!(
        bundle["generated_at"].as_str(),
        Some("2026-04-25T13:30:00Z")
    );

    let old_entry = agents
        .iter()
        .find(|entry| entry["id"].as_str() == Some("agent-old"))
        .unwrap();
    assert_eq!(old_entry["status"].as_str(), Some("active"));
    assert_eq!(
        old_entry["expires_at"].as_str(),
        Some("2026-05-01T00:00:00Z")
    );
    assert!(old_entry["disabled_at"].is_null());

    let new_entry = agents
        .iter()
        .find(|entry| entry["id"].as_str() == Some("agent-new"))
        .unwrap();
    assert_eq!(new_entry["status"].as_str(), Some("active"));
    assert_eq!(
        new_entry["created_at"].as_str(),
        Some("2026-04-25T13:30:00Z")
    );
}

#[test]
fn test_trust_rotate_rejects_non_overlapping_window() {
    let dir = tempdir().unwrap();
    generate_identity_unencrypted(dir.path(), "agent-old");
    generate_identity_unencrypted(dir.path(), "agent-new");

    let trust_path = dir.path().join("trust.json");
    let old_pubkey = read_pubkey_with_prefix(dir.path(), "agent-old");
    let new_pubkey = read_pubkey_with_prefix(dir.path(), "agent-new");
    write_trust_bundle(
        &trust_path,
        "prod",
        &[],
        &[("agent-old", old_pubkey.as_str())],
        &[],
    );

    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "trust",
            "rotate",
            trust_path.to_str().unwrap(),
            "--section",
            "agents",
            "--id",
            "agent-old",
            "--new-id",
            "agent-new",
            "--new-pubkey",
            new_pubkey.as_str(),
            "--overlap-until",
            "2026-04-25T12:00:00Z",
            "--at",
            "2026-04-25T13:00:00Z",
        ])
        .assert()
        .failure()
        .code(3)
        .stderr(predicate::str::contains(
            "overlap_until must be later than the rotation timestamp",
        ));

    let bundle = read_json(&trust_path);
    let agents = bundle["agents"].as_array().unwrap();
    assert_eq!(agents.len(), 1);
    assert_eq!(
        bundle["generated_at"].as_str(),
        Some("2026-04-25T10:30:00Z")
    );
}

#[test]
fn test_trust_inspect_rejects_non_utc_bundle() {
    let dir = tempdir().unwrap();
    let trust_path = dir.path().join("trust.json");
    fs::write(
        &trust_path,
        r#"{
  "version": 1,
  "bundle_id": "tb_prod",
  "org": "signet",
  "env": "prod",
  "generated_at": "2026-04-25T10:30:00+08:00",
  "roots": [],
  "agents": [{
    "id": "agent1",
    "name": "agent1",
    "owner": "platform",
    "pubkey": "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    "status": "active",
    "created_at": "2026-04-25T10:00:00Z"
  }],
  "servers": []
}"#,
    )
    .unwrap();

    signet()
        .args(["trust", "inspect", trust_path.to_str().unwrap()])
        .assert()
        .failure()
        .code(3)
        .stderr(predicate::str::contains(
            "generated_at must be RFC 3339 UTC",
        ));
}

#[test]
fn test_trust_disable_yaml_updates_bundle() {
    let dir = tempdir().unwrap();
    generate_identity_unencrypted(dir.path(), "agent1");

    let trust_path = dir.path().join("trust.yaml");
    let agent_pubkey = read_pubkey_with_prefix(dir.path(), "agent1");
    write_trust_bundle_yaml(&trust_path, "prod", &[("agent1", agent_pubkey.as_str())]);

    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "trust",
            "disable",
            trust_path.to_str().unwrap(),
            "--section",
            "agents",
            "--id",
            "agent1",
            "--at",
            "2026-04-25T14:00:00Z",
        ])
        .assert()
        .success();

    let bundle = signet_core::load_trust_bundle(&trust_path).unwrap();
    assert_eq!(bundle.generated_at, "2026-04-25T14:00:00Z");
    assert_eq!(bundle.agents.len(), 1);
    assert_eq!(
        bundle.agents[0].status,
        signet_core::TrustKeyStatus::Disabled
    );
    assert_eq!(
        bundle.agents[0].disabled_at.as_deref(),
        Some("2026-04-25T14:00:00Z")
    );
}

// ─── proxy --server-key (persistent server identity) ─────────────────────────

// ─── audit --bundle / --restore ───────────────────────────────────────────────

#[test]
fn test_audit_bundle_roundtrip() {
    // Create identity, sign 3 actions, build bundle, restore bundle on the
    // same dir. Restoration must succeed and report the correct chain tip.
    let dir = tempdir().unwrap();
    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "identity",
            "generate",
            "--name",
            "bundle-key",
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
                "bundle-key",
                "--tool",
                "bash",
                "--params",
                &format!(r#"{{"i":{i}}}"#),
                "--target",
                "mcp://local",
            ])
            .assert()
            .success();
    }

    let bundle_dir = dir.path().join("bundle1");
    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["audit", "--bundle", bundle_dir.to_str().unwrap()])
        .assert()
        .success()
        .stderr(predicate::str::contains("Bundle written"));

    assert!(bundle_dir.join("records.jsonl").exists());
    assert!(bundle_dir.join("manifest.json").exists());
    assert!(bundle_dir.join("hash-summary.txt").exists());

    // Parse manifest and check shape.
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(bundle_dir.join("manifest.json")).unwrap())
            .unwrap();
    assert_eq!(manifest["format_version"], 1);
    assert_eq!(manifest["record_count"], 3);
    assert!(manifest["records_sha256"].as_str().unwrap().len() == 64);
    assert!(manifest["chain_tip_record_hash"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));

    // Restore the bundle — must succeed.
    signet()
        .args(["audit", "--restore", bundle_dir.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Bundle valid"))
        .stdout(predicate::str::contains("records:           3"));
}

#[test]
fn test_audit_bundle_restore_detects_jsonl_tamper() {
    // Build a bundle, tamper records.jsonl content (single byte flip),
    // restore must fail with sha mismatch.
    let dir = tempdir().unwrap();
    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "identity",
            "generate",
            "--name",
            "tamper-key",
            "--unencrypted",
        ])
        .assert()
        .success();
    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "sign",
            "--key",
            "tamper-key",
            "--tool",
            "bash",
            "--params",
            r#"{"x":1}"#,
            "--target",
            "mcp://local",
        ])
        .assert()
        .success();

    let bundle_dir = dir.path().join("b2");
    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["audit", "--bundle", bundle_dir.to_str().unwrap()])
        .assert()
        .success();

    // Tamper records.jsonl (replace the first character).
    let path = bundle_dir.join("records.jsonl");
    let mut content = std::fs::read_to_string(&path).unwrap();
    content.insert(0, ' '); // prepend a space
    std::fs::write(&path, content).unwrap();

    signet()
        .args(["audit", "--restore", bundle_dir.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("sha256 mismatch"));
}

#[test]
fn test_audit_bundle_with_trust_bundle_snapshot() {
    let dir = tempdir().unwrap();
    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["identity", "generate", "--name", "tb-key", "--unencrypted"])
        .assert()
        .success();
    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "sign",
            "--key",
            "tb-key",
            "--tool",
            "bash",
            "--params",
            r#"{"x":1}"#,
            "--target",
            "mcp://local",
        ])
        .assert()
        .success();

    // Create a minimal trust bundle file.
    let trust_path = dir.path().join("trust.json");
    write_trust_bundle(&trust_path, "dev", &[], &[], &[]);

    let bundle_dir = dir.path().join("b3");
    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "audit",
            "--bundle",
            bundle_dir.to_str().unwrap(),
            "--include-trust-bundle",
            trust_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert!(bundle_dir.join("trust-bundle.json").exists());
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(bundle_dir.join("manifest.json")).unwrap())
            .unwrap();
    assert_eq!(manifest["has_trust_bundle"], true);
}

#[test]
fn test_audit_bundle_restore_recomputes_record_hash() {
    // Detect tampering of receipt content even when chain hashes are consistent.
    let dir = tempdir().unwrap();
    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["identity", "generate", "--name", "rh-key", "--unencrypted"])
        .assert()
        .success();
    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "sign",
            "--key",
            "rh-key",
            "--tool",
            "bash",
            "--params",
            r#"{"x":1}"#,
            "--target",
            "mcp://local",
        ])
        .assert()
        .success();

    let bundle_dir = dir.path().join("bn-rh");
    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["audit", "--bundle", bundle_dir.to_str().unwrap()])
        .assert()
        .success();

    // Tamper a receipt field WITHOUT updating record_hash. SHA-256 of
    // records.jsonl will differ; if we keep the manifest's hash too,
    // the file-level check fails. We need to also update the manifest's
    // SHA so only the record_hash check catches it.
    let records_path = bundle_dir.join("records.jsonl");
    let records = std::fs::read_to_string(&records_path).unwrap();
    let tampered = records.replace(r#""tool":"bash""#, r#""tool":"evil""#);
    std::fs::write(&records_path, &tampered).unwrap();

    // Recompute and update the manifest's records_sha256 to bypass the
    // file-level check, isolating the record_hash mismatch path.
    use sha2::{Digest, Sha256};
    let new_sha = format!("{:x}", Sha256::digest(tampered.as_bytes()));
    let manifest_path = bundle_dir.join("manifest.json");
    let mut m: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
    m["records_sha256"] = serde_json::Value::String(new_sha);
    std::fs::write(&manifest_path, serde_json::to_string(&m).unwrap()).unwrap();

    signet()
        .args(["audit", "--restore", bundle_dir.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("record_hash mismatch"));
}

#[test]
fn test_audit_bundle_restore_with_trust_bundle_verifies_signatures() {
    let dir = tempdir().unwrap();
    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["identity", "generate", "--name", "tbv-key", "--unencrypted"])
        .assert()
        .success();
    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "sign",
            "--key",
            "tbv-key",
            "--tool",
            "bash",
            "--params",
            r#"{"x":1}"#,
            "--target",
            "mcp://local",
        ])
        .assert()
        .success();

    // Read the identity's pubkey from the keystore .pub JSON.
    let pub_json = std::fs::read_to_string(dir.path().join("keys/tbv-key.pub")).unwrap();
    let pub_obj: serde_json::Value = serde_json::from_str(&pub_json).unwrap();
    let pubkey = format!("ed25519:{}", pub_obj["pubkey"].as_str().unwrap());
    let trust_path = dir.path().join("trust.json");
    write_trust_bundle(
        &trust_path,
        "pilot",
        &[],
        &[("tbv-key", pubkey.as_str())],
        &[],
    );

    let bundle_dir = dir.path().join("bn-tbv");
    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "audit",
            "--bundle",
            bundle_dir.to_str().unwrap(),
            "--include-trust-bundle",
            trust_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Restore must verify signatures (trust-bundle.json is included).
    signet()
        .args(["audit", "--restore", bundle_dir.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("verified against trust bundle"));
}

#[test]
fn test_audit_bundle_refuses_clobber_foreign_dir() {
    // --bundle should refuse to write into a directory that contains
    // unrelated files (e.g. an attacker-controlled drop point).
    let dir = tempdir().unwrap();
    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["identity", "generate", "--name", "rk", "--unencrypted"])
        .assert()
        .success();
    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "sign",
            "--key",
            "rk",
            "--tool",
            "bash",
            "--params",
            r#"{"x":1}"#,
            "--target",
            "mcp://local",
        ])
        .assert()
        .success();

    let bundle_dir = dir.path().join("dirty");
    std::fs::create_dir_all(&bundle_dir).unwrap();
    std::fs::write(bundle_dir.join("foreign.txt"), b"do not touch").unwrap();

    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["audit", "--bundle", bundle_dir.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("foreign file"));

    // The foreign file is preserved.
    assert_eq!(
        std::fs::read(bundle_dir.join("foreign.txt")).unwrap(),
        b"do not touch"
    );
}

#[test]
fn test_audit_bundle_empty_filter_errors() {
    // No records → bundle should refuse rather than produce empty evidence.
    let dir = tempdir().unwrap();
    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["identity", "generate", "--name", "k", "--unencrypted"])
        .assert()
        .success();

    let bundle_dir = dir.path().join("b4");
    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["audit", "--bundle", bundle_dir.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("nothing to bundle"));
}

#[test]
fn test_proxy_server_key_persistent_pubkey_stable() {
    // With --server-key, the bilateral server pubkey must be the same across
    // restarts (it's the named keystore identity). This is the core property
    // pilot trust bundles depend on.
    let dir = tempdir().unwrap();
    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "identity",
            "generate",
            "--name",
            "agent-pk",
            "--unencrypted",
        ])
        .assert()
        .success();
    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "identity",
            "generate",
            "--name",
            "server-pk",
            "--unencrypted",
        ])
        .assert()
        .success();

    let input = concat!(
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"msg":"x"}}}"#,
        "\n",
    );

    // Run twice; the persistent server key should produce the same pubkey both runs.
    let extract_server_pubkey = |stderr: &str| -> String {
        // Line format: "[signet proxy] server key: <base64> (persistent: <name>)"
        for line in stderr.lines() {
            if let Some(rest) = line.strip_prefix("[signet proxy] server key: ") {
                if let Some((pubkey, _)) = rest.split_once(' ') {
                    return pubkey.to_string();
                }
            }
        }
        panic!("could not parse server pubkey from stderr:\n{stderr}");
    };

    let (status1, _, stderr1) = run_proxy(
        dir.path(),
        &mock_server_cmd(),
        "agent-pk",
        input,
        &["--server-key", "server-pk"],
    );
    assert!(status1.success(), "first run should succeed: {stderr1}");
    let pubkey1 = extract_server_pubkey(&stderr1);
    assert!(
        stderr1.contains("server key:") && stderr1.contains("(persistent: server-pk)"),
        "should report persistent origin: {stderr1}",
    );

    let (status2, _, stderr2) = run_proxy(
        dir.path(),
        &mock_server_cmd(),
        "agent-pk",
        input,
        &["--server-key", "server-pk"],
    );
    assert!(status2.success(), "second run should succeed: {stderr2}");
    let pubkey2 = extract_server_pubkey(&stderr2);

    assert_eq!(
        pubkey1, pubkey2,
        "persistent --server-key must produce a stable pubkey across runs"
    );
}

#[test]
fn test_proxy_ephemeral_pubkey_changes_each_run() {
    // Without --server-key, the proxy generates a fresh ephemeral key each
    // run. This is the documented "demo mode" — fine for trying things out,
    // but trust bundles can't anchor to it.
    let dir = tempdir().unwrap();
    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "identity",
            "generate",
            "--name",
            "agent-eph",
            "--unencrypted",
        ])
        .assert()
        .success();

    let input = concat!(
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"msg":"x"}}}"#,
        "\n",
    );

    let extract_server_pubkey = |stderr: &str| -> String {
        for line in stderr.lines() {
            if let Some(rest) = line.strip_prefix("[signet proxy] server key: ") {
                if let Some((pubkey, _)) = rest.split_once(' ') {
                    return pubkey.to_string();
                }
            }
        }
        panic!("could not parse server pubkey from stderr:\n{stderr}");
    };

    let (s1, _, e1) = run_proxy(dir.path(), &mock_server_cmd(), "agent-eph", input, &[]);
    let (s2, _, e2) = run_proxy(dir.path(), &mock_server_cmd(), "agent-eph", input, &[]);
    assert!(s1.success() && s2.success(), "both runs should succeed");
    assert!(
        e1.contains("(ephemeral)"),
        "first run should report ephemeral: {e1}"
    );
    assert!(
        e2.contains("(ephemeral)"),
        "second run should report ephemeral: {e2}"
    );
    assert_ne!(
        extract_server_pubkey(&e1),
        extract_server_pubkey(&e2),
        "ephemeral keys must differ across runs",
    );
}

#[test]
fn test_proxy_server_key_rejects_same_as_agent_key() {
    // Bilateral is meaningless if --key and --server-key are the same identity.
    let dir = tempdir().unwrap();
    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "identity",
            "generate",
            "--name",
            "shared-id",
            "--unencrypted",
        ])
        .assert()
        .success();

    let input = concat!(
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"msg":"x"}}}"#,
        "\n",
    );
    let (status, _, stderr) = run_proxy(
        dir.path(),
        &mock_server_cmd(),
        "shared-id",
        input,
        &["--server-key", "shared-id"],
    );
    assert!(
        !status.success(),
        "proxy should reject identical key/server-key"
    );
    assert!(
        stderr.contains("must differ from --key") || stderr.contains("same pubkey"),
        "stderr should explain rejection: {stderr}",
    );
}
