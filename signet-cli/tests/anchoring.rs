//! CLI tests for off-host anchoring. The sink and the Bitcoin node are local
//! mock servers; nothing here touches the network.

use assert_cmd::Command;
use predicates::prelude::*;
use std::path::Path;
use tempfile::tempdir;

fn signet() -> Command {
    Command::cargo_bin("signet").unwrap()
}

fn log_with_records(dir: &Path, n: usize) {
    signet()
        .env("SIGNET_HOME", dir)
        .args([
            "identity",
            "generate",
            "--name",
            "anchorkey",
            "--unencrypted",
        ])
        .assert()
        .success();
    for i in 0..n {
        signet()
            .env("SIGNET_HOME", dir)
            .args([
                "sign",
                "--key",
                "anchorkey",
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
}

#[test]
fn verify_anchors_without_anchors_is_missing_not_success() {
    let dir = tempdir().unwrap();
    log_with_records(dir.path(), 2);
    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["audit", "--verify-anchors"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("Result: MISSING"))
        .stdout(predicate::str::contains("no auditor checkpoint given"));
}

#[test]
fn export_checkpoint_needs_an_anchor() {
    let dir = tempdir().unwrap();
    log_with_records(dir.path(), 1);
    let out = dir.path().join("cp.json");
    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["audit", "--export-checkpoint", out.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("no anchors to export"));
}

#[test]
fn existing_audit_flags_are_unchanged() {
    let dir = tempdir().unwrap();
    log_with_records(dir.path(), 2);
    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["audit"])
        .assert()
        .success()
        .stdout(predicate::str::contains("2 records"));
    signet()
        .env("SIGNET_HOME", dir.path())
        .args(["audit", "--verify"])
        .assert()
        .success();
}

#[test]
fn export_checkpoint_cannot_be_silently_skipped_by_another_operation() {
    let dir = tempdir().unwrap();
    log_with_records(dir.path(), 1);
    let out = dir.path().join("cp.json");
    signet()
        .env("SIGNET_HOME", dir.path())
        .args([
            "audit",
            "--verify-anchors",
            "--export-checkpoint",
            out.to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("cannot be used with"));
    assert!(!out.exists());
}

#[cfg(feature = "anchoring")]
mod with_network_feature {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    type Handler = dyn Fn(&str, &str, &[u8]) -> (u16, Vec<u8>) + Send + Sync;

    /// Minimal HTTP/1.1 server: one request per connection.
    fn serve(handler: Arc<Handler>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut request_line = String::new();
                if reader.read_line(&mut request_line).is_err() {
                    continue;
                }
                let mut parts = request_line.split_whitespace();
                let method = parts.next().unwrap_or("").to_string();
                let path = parts.next().unwrap_or("").to_string();
                let mut len = 0usize;
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" || line.is_empty() {
                        break;
                    }
                    if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        len = v.trim().parse().unwrap_or(0);
                    }
                }
                let mut body = vec![0u8; len];
                reader.read_exact(&mut body).unwrap();
                let (status, payload) = handler(&method, &path, &body);
                let head = format!(
                    "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n",
                    payload.len()
                );
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(&payload);
            }
        });
        format!("http://{addr}")
    }

    /// Detached OTS proof: sha256(digest) is the "merkle root" of `height`,
    /// or a pending attestation when `height` is None.
    fn ots_proof(digest: &[u8; 32], height: Option<u64>) -> Vec<u8> {
        let mut v = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94".to_vec();
        v.extend_from_slice(&[0x01, 0x08]);
        v.extend_from_slice(digest);
        v.extend_from_slice(&[0x08, 0x00]);
        match height {
            Some(mut h) => {
                v.extend_from_slice(&[0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01]);
                let mut payload = Vec::new();
                loop {
                    let b = (h & 0x7f) as u8;
                    h >>= 7;
                    if h == 0 {
                        payload.push(b);
                        break;
                    }
                    payload.push(b | 0x80);
                }
                v.push(payload.len() as u8);
                v.extend_from_slice(&payload);
            }
            None => {
                let uri = b"https://calendar.example";
                v.extend_from_slice(&[0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e]);
                v.push((uri.len() + 1) as u8);
                v.push(uri.len() as u8);
                v.extend_from_slice(uri);
            }
        }
        v
    }

    const ID: &str = "00000000-0000-4000-8000-000000000001";
    const HEIGHT: u64 = 900_001;

    /// Mock DEUSPROOF register. `confirmed` decides whether the proof it
    /// serves already carries a Bitcoin attestation.
    fn mock_deusproof(confirmed: bool) -> (String, Arc<Mutex<Option<String>>>) {
        let submitted: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let seen = submitted.clone();
        let url = serve(Arc::new(move |method: &str, path: &str, body: &[u8]| {
            if method == "POST" && path == "/api/certifications/hash" {
                let v: serde_json::Value = serde_json::from_slice(body).unwrap();
                assert!(v.get("agent_handle").is_none(), "no name unless opted in");
                *seen.lock().unwrap() = v["output_hash"].as_str().map(str::to_string);
                return (
                    201,
                    format!(r#"{{"id":"{ID}","status":"pending"}}"#).into_bytes(),
                );
            }
            let hash = seen.lock().unwrap().clone().unwrap_or_default();
            let seed = format!(":{hash}:{ID}").into_bytes();
            let digest: [u8; 32] = Sha256::digest(&seed).into();
            match path {
                p if p == format!("/api/anchors/seed/{ID}") => (200, seed),
                p if p == format!("/api/anchors/ots/{ID}") => {
                    (200, ots_proof(&digest, confirmed.then_some(HEIGHT)))
                }
                _ => (404, b"not found".to_vec()),
            }
        }));
        (url, submitted)
    }

    /// Mock Bitcoin Core node that knows one block.
    fn mock_node(merkle_root_display: String) -> String {
        serve(Arc::new(move |_m: &str, _p: &str, body: &[u8]| {
            let v: serde_json::Value = serde_json::from_slice(body).unwrap();
            let result = match v["method"].as_str().unwrap() {
                "getblockhash" => serde_json::json!("00".repeat(32)),
                "getblockheader" => serde_json::json!({
                    "height": HEIGHT,
                    "confirmations": 12,
                    "merkleroot": merkle_root_display,
                    "time": 1_793_000_000u64,
                }),
                _ => serde_json::Value::Null,
            };
            (
                200,
                serde_json::json!({"result": result, "error": null, "id": "signet"})
                    .to_string()
                    .into_bytes(),
            )
        }))
    }

    #[test]
    fn anchor_then_pending_then_verified_against_own_node() {
        let dir = tempdir().unwrap();
        log_with_records(dir.path(), 2);
        let (sink_url, submitted) = mock_deusproof(true);

        signet()
            .env("SIGNET_HOME", dir.path())
            .args(["audit", "--anchor", "deusproof", "--anchor-url", &sink_url])
            .assert()
            .success()
            .stdout(predicate::str::contains("Anchored 2 records"));
        let hash = submitted.lock().unwrap().clone().unwrap();

        // Without a node, the Bitcoin attestation is reported, not trusted.
        signet()
            .env("SIGNET_HOME", dir.path())
            .args(["audit", "--verify-anchors"])
            .assert()
            .code(1)
            .stdout(predicate::str::contains("Result: UNAVAILABLE"));

        // With the auditor's own node it verifies.
        let seed = format!(":{hash}:{ID}");
        let digest = Sha256::digest(seed.as_bytes());
        let mut root: [u8; 32] = Sha256::digest(digest).into();
        root.reverse();
        let node = mock_node(hex::encode(root));
        let cookie = dir.path().join(".cookie");
        fs::write(&cookie, "__cookie__:secret").unwrap();
        let cp = dir.path().join("checkpoint.json");
        signet()
            .env("SIGNET_HOME", dir.path())
            .args(["audit", "--export-checkpoint", cp.to_str().unwrap()])
            .assert()
            .success();
        signet()
            .env("SIGNET_HOME", dir.path())
            .args([
                "audit",
                "--verify-anchors",
                "--bitcoin-rpc",
                &node,
                "--bitcoin-rpc-cookie",
                cookie.to_str().unwrap(),
                "--checkpoint",
                cp.to_str().unwrap(),
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("Result: VERIFIED"))
            .stdout(predicate::str::contains("Bitcoin block 900001"))
            .stdout(predicate::str::contains("consistent"));
    }

    #[test]
    fn pending_proof_exits_non_zero() {
        let dir = tempdir().unwrap();
        log_with_records(dir.path(), 1);
        let (sink_url, _) = mock_deusproof(false);
        signet()
            .env("SIGNET_HOME", dir.path())
            .args(["audit", "--anchor", "deusproof", "--anchor-url", &sink_url])
            .assert()
            .success();
        signet()
            .env("SIGNET_HOME", dir.path())
            .args(["audit", "--verify-anchors"])
            .assert()
            .code(1)
            .stdout(predicate::str::contains("Result: PENDING"));
    }

    #[test]
    fn sink_failure_changes_nothing() {
        let dir = tempdir().unwrap();
        log_with_records(dir.path(), 1);
        let audit_dir = dir.path().join("audit");
        let snapshot = |d: &Path| -> Vec<(String, Vec<u8>)> {
            let mut v: Vec<_> = fs::read_dir(d)
                .unwrap()
                .map(|e| e.unwrap().path())
                .filter(|p| p.extension().is_some_and(|e| e == "jsonl"))
                .map(|p| (p.display().to_string(), fs::read(&p).unwrap()))
                .collect();
            v.sort();
            v
        };
        let before = snapshot(&audit_dir);
        let url = serve(Arc::new(|_m: &str, _p: &str, _b: &[u8]| {
            (500, b"internal error".to_vec())
        }));
        signet()
            .env("SIGNET_HOME", dir.path())
            .args(["audit", "--anchor", "deusproof", "--anchor-url", &url])
            .assert()
            .failure()
            .stderr(predicate::str::contains("HTTP 500"));
        assert_eq!(snapshot(&audit_dir), before);
        assert!(!dir.path().join("anchors").join("anchors.jsonl").exists());
    }

    /// Mock register that hands out a new record id per submission and can
    /// fail the proof download for chosen record numbers (1-based).
    fn mock_deusproof_sequential(fail_ots_for: Vec<usize>) -> String {
        let estado: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        serve(Arc::new(move |method: &str, path: &str, body: &[u8]| {
            let mut hashes = estado.lock().unwrap();
            if method == "POST" && path == "/api/certifications/hash" {
                let v: serde_json::Value = serde_json::from_slice(body).unwrap();
                hashes.push(v["output_hash"].as_str().unwrap().to_string());
                let id = format!("00000000-0000-4000-8000-{:012x}", hashes.len());
                return (201, format!(r#"{{"id":"{id}"}}"#).into_bytes());
            }
            for (i, hash) in hashes.iter().enumerate() {
                let id = format!("00000000-0000-4000-8000-{:012x}", i + 1);
                if path == format!("/api/anchors/ots/{id}") {
                    if fail_ots_for.contains(&(i + 1)) {
                        return (500, b"internal error".to_vec());
                    }
                    let seed = format!(":{hash}:{id}");
                    let digest: [u8; 32] = Sha256::digest(seed.as_bytes()).into();
                    return (200, ots_proof(&digest, None));
                }
            }
            (404, b"not found".to_vec())
        }))
    }

    #[test]
    fn anchor_and_export_checkpoint_in_one_call_writes_the_checkpoint() {
        let dir = tempdir().unwrap();
        log_with_records(dir.path(), 1);
        let url = mock_deusproof_sequential(vec![]);
        let cp = dir.path().join("checkpoint.json");
        signet()
            .env("SIGNET_HOME", dir.path())
            .args([
                "audit",
                "--anchor",
                "deusproof",
                "--anchor-url",
                &url,
                "--export-checkpoint",
                cp.to_str().unwrap(),
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("Anchored 1 records"))
            .stdout(predicate::str::contains("Wrote anchor #1"));
        let v: serde_json::Value = serde_json::from_str(&fs::read_to_string(&cp).unwrap()).unwrap();
        assert_eq!(v["count"], 1);
    }

    #[test]
    fn refresh_with_an_http_failure_exits_non_zero() {
        let dir = tempdir().unwrap();
        log_with_records(dir.path(), 1);
        let url = mock_deusproof_sequential(vec![1]);
        signet()
            .env("SIGNET_HOME", dir.path())
            .args(["audit", "--anchor", "deusproof", "--anchor-url", &url])
            .assert()
            .success();
        signet()
            .env("SIGNET_HOME", dir.path())
            .args([
                "audit",
                "--refresh-anchors",
                "deusproof",
                "--anchor-url",
                &url,
            ])
            .assert()
            .failure()
            .stdout(predicate::str::contains(
                "0 of 1 anchor(s) updated, 1 failed",
            ))
            .stderr(predicate::str::contains("HTTP 500"));
    }

    #[test]
    fn refresh_partial_success_keeps_the_update_and_exits_non_zero() {
        let dir = tempdir().unwrap();
        log_with_records(dir.path(), 1);
        // Record 1 cannot serve its proof at anchor time or refresh time;
        // record 2 serves it at refresh time only.
        let url = mock_deusproof_sequential(vec![1]);
        signet()
            .env("SIGNET_HOME", dir.path())
            .args(["audit", "--anchor", "deusproof", "--anchor-url", &url])
            .assert()
            .success();
        signet()
            .env("SIGNET_HOME", dir.path())
            .args([
                "sign",
                "--key",
                "anchorkey",
                "--tool",
                "bash",
                "--params",
                r#"{"cmd":"more"}"#,
                "--target",
                "mcp://local",
            ])
            .assert()
            .success();
        signet()
            .env("SIGNET_HOME", dir.path())
            .args(["audit", "--anchor", "deusproof", "--anchor-url", &url])
            .assert()
            .success();
        // Drop the proof the second anchor got at submission time, so the
        // refresh has something to add.
        let path = dir.path().join("anchors").join("anchors.jsonl");
        let lines: Vec<serde_json::Value> = fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        let mut rewritten = String::new();
        for (i, mut v) in lines.into_iter().enumerate() {
            if i == 1 {
                v["proofs"] = serde_json::json!([]);
            }
            rewritten.push_str(&v.to_string());
            rewritten.push('\n');
        }
        fs::write(&path, rewritten).unwrap();

        signet()
            .env("SIGNET_HOME", dir.path())
            .args([
                "audit",
                "--refresh-anchors",
                "deusproof",
                "--anchor-url",
                &url,
            ])
            .assert()
            .failure()
            .stdout(predicate::str::contains(
                "1 of 2 anchor(s) updated, 1 failed",
            ));
        let second: serde_json::Value =
            serde_json::from_str(fs::read_to_string(&path).unwrap().lines().nth(1).unwrap())
                .unwrap();
        assert_eq!(
            second["proofs"].as_array().unwrap().len(),
            1,
            "the partial update is kept"
        );
    }
}
