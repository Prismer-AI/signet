#![cfg(not(target_arch = "wasm32"))]

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use fs2::FileExt;

use chrono::{DateTime, NaiveDate, Utc};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::canonical;
use crate::error::SignetError;

const GENESIS_HASH: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub receipt: serde_json::Value,
    pub prev_hash: String,
    pub record_hash: String,
}

#[derive(Debug, Default)]
pub struct AuditFilter {
    pub since: Option<DateTime<Utc>>,
    pub tool: Option<String>,
    pub signer: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct ChainStatus {
    pub total_records: usize,
    pub valid: bool,
    pub break_point: Option<ChainBreak>,
}

#[derive(Debug, Serialize)]
pub struct ChainBreak {
    pub file: String,
    pub line: usize,
    pub expected_hash: String,
    pub actual_hash: String,
}

#[derive(Debug, Serialize)]
pub struct VerifyResult {
    pub total: usize,
    pub valid: usize,
    pub warnings: Vec<VerifyWarning>,
    pub failures: Vec<VerifyFailure>,
}

#[derive(Debug, Serialize)]
pub struct VerifyFailure {
    pub file: String,
    pub line: usize,
    pub receipt_id: String,
    pub reason: String,
}

#[derive(Debug, Serialize)]
pub struct VerifyWarning {
    pub file: String,
    pub line: usize,
    pub receipt_id: String,
    pub reason: String,
}

#[derive(Debug, Default)]
pub struct AuditVerifyOptions {
    /// Optional trusted server public keys for v3 bilateral receipts.
    /// When empty, v3 server verification falls back to the self-reported
    /// `receipt.server.pubkey` and produces a warning instead of a trust anchor.
    pub trusted_server_pubkeys: Vec<VerifyingKey>,
    /// Optional trusted agent public keys. For v1/v2 this constrains the signer.
    /// For v3 this constrains the embedded agent receipt signer.
    pub trusted_agent_pubkeys: Vec<VerifyingKey>,
}

#[derive(Debug)]
struct LocatedAuditRecord {
    record: AuditRecord,
    file: String,
    line: usize,
}

fn audit_dir(base: &Path) -> PathBuf {
    base.join("audit")
}

pub fn extract_tool(receipt: &serde_json::Value) -> Option<&str> {
    // v1/v2: receipt.action.tool
    receipt
        .get("action")
        .and_then(|a| a.get("tool"))
        .and_then(|t| t.as_str())
        // v3: receipt.agent_receipt.action.tool
        .or_else(|| {
            receipt
                .get("agent_receipt")
                .and_then(|ar| ar.get("action"))
                .and_then(|a| a.get("tool"))
                .and_then(|t| t.as_str())
        })
}

pub fn extract_timestamp(receipt: &serde_json::Value) -> Option<&str> {
    let version = receipt.get("v").and_then(|v| v.as_u64()).unwrap_or(1);
    match version {
        1 | 4 => receipt.get("ts").and_then(|t| t.as_str()),
        2 => receipt.get("ts_request").and_then(|t| t.as_str()),
        3 => receipt.get("ts_response").and_then(|t| t.as_str()),
        _ => None,
    }
}

pub fn extract_signer_name(receipt: &serde_json::Value) -> Option<&str> {
    // v1/v2: receipt.signer.name
    receipt
        .get("signer")
        .and_then(|s| s.get("name"))
        .and_then(|n| n.as_str())
        // v3: receipt.agent_receipt.signer.name
        .or_else(|| {
            receipt
                .get("agent_receipt")
                .and_then(|ar| ar.get("signer"))
                .and_then(|s| s.get("name"))
                .and_then(|n| n.as_str())
        })
}

fn compute_record_hash(
    receipt: &serde_json::Value,
    prev_hash: &str,
) -> Result<String, SignetError> {
    let hashable = serde_json::json!({
        "prev_hash": prev_hash,
        "receipt": receipt,
    });
    let canonical = canonical::canonicalize(&hashable)?;
    let hash = Sha256::digest(canonical.as_bytes());
    Ok(format!("sha256:{}", hex::encode(hash)))
}

fn date_from_receipt(receipt: &serde_json::Value) -> Result<NaiveDate, SignetError> {
    let ts = extract_timestamp(receipt)
        .ok_or_else(|| SignetError::CorruptedRecord("missing timestamp field".to_string()))?;
    let dt = DateTime::parse_from_rfc3339(ts)
        .map_err(|e| SignetError::CorruptedRecord(format!("invalid timestamp: {e}")))?;
    Ok(dt.date_naive())
}

fn sorted_audit_files(dir: &Path, ascending: bool) -> Result<Vec<PathBuf>, SignetError> {
    let adir = audit_dir(dir);
    if !adir.exists() {
        return Ok(vec![]);
    }
    let mut files: Vec<PathBuf> = fs::read_dir(&adir)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().map(|e| e == "jsonl").unwrap_or(false))
        .collect();
    files.sort();
    if !ascending {
        files.reverse();
    }
    Ok(files)
}

fn last_record_hash(dir: &Path) -> Result<String, SignetError> {
    let files = sorted_audit_files(dir, false)?; // newest first
    for file in files {
        let content = fs::read_to_string(&file)?;
        if let Some(last_line) = content.lines().rev().find(|l| !l.trim().is_empty()) {
            let record: AuditRecord = serde_json::from_str(last_line).map_err(|e| {
                SignetError::CorruptedRecord(format!(
                    "{}: {e}",
                    file.file_name().unwrap_or_default().to_string_lossy()
                ))
            })?;
            return Ok(record.record_hash);
        }
    }
    Ok(GENESIS_HASH.to_string())
}

pub fn append(dir: &Path, receipt: &serde_json::Value) -> Result<AuditRecord, SignetError> {
    let adir = audit_dir(dir);
    fs::create_dir_all(&adir)?;

    let date = date_from_receipt(receipt)?;
    let filename = format!("{}.jsonl", date);
    let filepath = adir.join(&filename);

    // Acquire an exclusive lock on a .lock file to prevent concurrent writers
    // from corrupting the hash chain.
    let lock_path = adir.join(format!("{filename}.lock"));
    let lock_file = File::create(&lock_path)?;
    lock_file.lock_exclusive()?;

    let result = (|| -> Result<AuditRecord, SignetError> {
        let prev_hash = if filepath.exists() {
            let content = fs::read_to_string(&filepath)?;
            if let Some(last_line) = content.lines().rev().find(|l| !l.trim().is_empty()) {
                let record: AuditRecord = serde_json::from_str(last_line)
                    .map_err(|e| SignetError::CorruptedRecord(format!("{filename}: {e}")))?;
                record.record_hash
            } else {
                last_record_hash(dir)?
            }
        } else {
            last_record_hash(dir)?
        };

        let record_hash = compute_record_hash(receipt, &prev_hash)?;

        let record = AuditRecord {
            receipt: receipt.clone(),
            prev_hash,
            record_hash,
        };

        let json = serde_json::to_string(&record)?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&filepath)?;
        writeln!(file, "{json}")?;

        Ok(record)
    })();

    // Always release the lock
    let _ = lock_file.unlock();

    result
}

/// Append a policy violation record to the audit log. Violations are logged
/// even though no receipt is produced (the action was denied).
pub fn append_violation(
    dir: &Path,
    action: &crate::receipt::Action,
    agent_name: &str,
    eval: &crate::policy::PolicyEvalResult,
) -> Result<AuditRecord, SignetError> {
    let violation = serde_json::json!({
        "type": "policy_violation",
        "action": {
            "tool": action.tool,
            "params_hash": if action.params_hash.is_empty() {
                crate::sign::compute_params_hash(action)?
            } else {
                action.params_hash.clone()
            },
            "target": action.target,
        },
        "agent": agent_name,
        "policy": eval.policy_name,
        "policy_hash": eval.policy_hash,
        "matched_rules": eval.matched_rules,
        "decision": eval.decision.to_string(),
        "reason": eval.reason,
        "ts": crate::delegation::current_timestamp(),
    });
    append(dir, &violation)
}

pub fn query(dir: &Path, filter: &AuditFilter) -> Result<Vec<AuditRecord>, SignetError> {
    Ok(query_with_locations(dir, filter)?
        .into_iter()
        .map(|record| record.record)
        .collect())
}

fn query_with_locations(
    dir: &Path,
    filter: &AuditFilter,
) -> Result<Vec<LocatedAuditRecord>, SignetError> {
    let files = sorted_audit_files(dir, false)?; // newest first
    let mut results = Vec::new();

    for file in files {
        let content = fs::read_to_string(&file)?;
        let fname = file
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let lines: Vec<&str> = content.lines().collect();

        for (idx, line) in lines.iter().enumerate().rev() {
            if line.trim().is_empty() {
                continue;
            }
            let record: AuditRecord = serde_json::from_str(line).map_err(|e| {
                SignetError::CorruptedRecord(format!(
                    "{}: {e}",
                    file.file_name().unwrap_or_default().to_string_lossy()
                ))
            })?;

            // Check since filter — stop scanning if record is too old
            if let Some(since) = filter.since {
                match extract_timestamp(&record.receipt)
                    .and_then(|ts| DateTime::parse_from_rfc3339(ts).ok())
                {
                    Some(parsed) if parsed >= since => {} // passes filter, continue
                    Some(_) => {
                        // Record is older than since — stop scanning (records are chronological)
                        return Ok(results.into_iter().rev().collect());
                    }
                    None => continue, // missing or unparseable timestamp — skip
                }
            }

            // Check tool filter (substring)
            if let Some(ref tool) = filter.tool {
                match extract_tool(&record.receipt) {
                    Some(t) if t.contains(tool.as_str()) => {}
                    _ => continue,
                }
            }

            // Check signer filter (exact)
            if let Some(ref signer) = filter.signer {
                match extract_signer_name(&record.receipt) {
                    Some(n) if n == signer.as_str() => {}
                    _ => continue,
                }
            }

            results.push(LocatedAuditRecord {
                record,
                file: fname.clone(),
                line: idx + 1,
            });

            if let Some(limit) = filter.limit {
                if results.len() >= limit {
                    return Ok(results.into_iter().rev().collect());
                }
            }
        }
    }

    results.reverse();
    Ok(results)
}

pub fn verify_chain(dir: &Path) -> Result<ChainStatus, SignetError> {
    let files = sorted_audit_files(dir, true)?; // oldest first
    let mut expected_prev = GENESIS_HASH.to_string();
    let mut total = 0usize;

    for file in &files {
        let content = fs::read_to_string(file)?;
        let fname = file
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        for (i, line) in content.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            total += 1;
            let record: AuditRecord = serde_json::from_str(line)
                .map_err(|e| SignetError::CorruptedRecord(format!("{fname}:{}: {e}", i + 1)))?;

            // Check prev_hash links
            if record.prev_hash != expected_prev {
                return Ok(ChainStatus {
                    total_records: total,
                    valid: false,
                    break_point: Some(ChainBreak {
                        file: fname,
                        line: i + 1,
                        expected_hash: expected_prev,
                        actual_hash: record.prev_hash,
                    }),
                });
            }

            // Recompute and check record_hash
            let recomputed = compute_record_hash(&record.receipt, &record.prev_hash)?;
            if recomputed != record.record_hash {
                return Ok(ChainStatus {
                    total_records: total,
                    valid: false,
                    break_point: Some(ChainBreak {
                        file: fname,
                        line: i + 1,
                        expected_hash: recomputed,
                        actual_hash: record.record_hash,
                    }),
                });
            }

            expected_prev = record.record_hash;
        }
    }

    Ok(ChainStatus {
        total_records: total,
        valid: true,
        break_point: None,
    })
}

pub fn verify_signatures(dir: &Path, filter: &AuditFilter) -> Result<VerifyResult, SignetError> {
    verify_signatures_with_options(dir, filter, &AuditVerifyOptions::default())
}

fn parse_prefixed_verifying_key(label: &str, pubkey: &str) -> Result<VerifyingKey, String> {
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;

    let b64 = pubkey
        .strip_prefix("ed25519:")
        .ok_or_else(|| format!("{label} missing prefix"))?;
    let bytes = BASE64
        .decode(b64)
        .map_err(|e| format!("{label} base64: {e}"))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| format!("{label} not 32 bytes"))?;
    VerifyingKey::from_bytes(&arr).map_err(|e| format!("{label} invalid: {e}"))
}

fn matching_trusted_key<'a>(
    actual: &VerifyingKey,
    trusted_keys: &'a [VerifyingKey],
) -> Option<&'a VerifyingKey> {
    trusted_keys
        .iter()
        .find(|trusted| trusted.as_bytes() == actual.as_bytes())
}

pub fn verify_signatures_with_options(
    dir: &Path,
    filter: &AuditFilter,
    options: &AuditVerifyOptions,
) -> Result<VerifyResult, SignetError> {
    let records = query_with_locations(dir, filter)?;
    let mut valid = 0usize;
    let mut warnings = Vec::new();
    let mut failures = Vec::new();

    for located in &records {
        let receipt = &located.record.receipt;

        // Extract receipt id for error reporting
        let receipt_id = receipt
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let push_failure = |reason: String, failures: &mut Vec<VerifyFailure>| {
            failures.push(VerifyFailure {
                file: located.file.clone(),
                line: located.line,
                receipt_id: receipt_id.clone(),
                reason,
            });
        };

        let version = receipt.get("v").and_then(|v| v.as_u64()).unwrap_or(1);

        if version == 3 {
            // v3: verify bilateral receipts, optionally anchoring the server and
            // agent keys to trusted inputs supplied by the caller.
            let bilateral: crate::BilateralReceipt = match serde_json::from_value(receipt.clone()) {
                Ok(b) => b,
                Err(e) => {
                    push_failure(format!("v3 parse: {e}"), &mut failures);
                    continue;
                }
            };
            let server_vk = match parse_prefixed_verifying_key("server pubkey", &bilateral.server.pubkey)
            {
                Ok(vk) => vk,
                Err(reason) => {
                    push_failure(reason, &mut failures);
                    continue;
                }
            };
            let agent_vk = match parse_prefixed_verifying_key(
                "agent pubkey",
                &bilateral.agent_receipt.signer.pubkey,
            ) {
                Ok(vk) => vk,
                Err(reason) => {
                    push_failure(reason, &mut failures);
                    continue;
                }
            };

            let trusted_server = matching_trusted_key(&server_vk, &options.trusted_server_pubkeys);
            if !options.trusted_server_pubkeys.is_empty() && trusted_server.is_none() {
                push_failure("untrusted server pubkey".to_string(), &mut failures);
                continue;
            }

            let trusted_agent = matching_trusted_key(&agent_vk, &options.trusted_agent_pubkeys);
            if !options.trusted_agent_pubkeys.is_empty() && trusted_agent.is_none() {
                push_failure("untrusted agent pubkey".to_string(), &mut failures);
                continue;
            }

            let verify_options = crate::BilateralVerifyOptions {
                trusted_agent_pubkey: trusted_agent.cloned(),
                ..Default::default()
            };

            match crate::verify_bilateral_with_options_detailed(
                &bilateral,
                trusted_server.unwrap_or(&server_vk),
                &verify_options,
            ) {
                Ok(crate::BilateralVerifyOutcome::AgentTrusted) if trusted_server.is_some() => {
                    valid += 1
                }
                Ok(crate::BilateralVerifyOutcome::AgentTrusted) => {
                    valid += 1;
                    warnings.push(VerifyWarning {
                        file: located.file.clone(),
                        line: located.line,
                        receipt_id: receipt_id.clone(),
                        reason: "bilateral receipt verified with a trusted agent key, but server identity was checked only against self-reported receipt.server.pubkey".to_string(),
                    });
                }
                Ok(crate::BilateralVerifyOutcome::AgentSelfConsistent) => {
                    valid += 1;
                    warnings.push(VerifyWarning {
                        file: located.file.clone(),
                        line: located.line,
                        receipt_id: receipt_id.clone(),
                        reason: if trusted_server.is_some() {
                            "bilateral receipt verified with a trusted server key, but embedded agent identity was not anchored to trusted_agent_pubkeys".to_string()
                        } else {
                            "bilateral receipt verified for integrity only; audit used receipt.server.pubkey from the record and did not supply trusted_server_pubkeys or trusted_agent_pubkeys".to_string()
                        },
                    });
                }
                Err(e) => push_failure(
                    format!("bilateral verification failed: {e}"),
                    &mut failures,
                ),
            }
            continue; // skip the v1/v2 path below
        }

        // Existing v1/v2: decode pubkey from receipt["signer"]["pubkey"]
        let pubkey_result = (|| -> Result<ed25519_dalek::VerifyingKey, String> {
            let pubkey = receipt
                .get("signer")
                .and_then(|s| s.get("pubkey"))
                .and_then(|p| p.as_str())
                .ok_or("missing signer.pubkey")?;
            parse_prefixed_verifying_key("signer pubkey", pubkey)
        })();

        match pubkey_result {
            Ok(vk) => {
                if !options.trusted_agent_pubkeys.is_empty()
                    && matching_trusted_key(&vk, &options.trusted_agent_pubkeys).is_none()
                {
                    push_failure("untrusted signer pubkey".to_string(), &mut failures);
                    continue;
                }
                let receipt_str = serde_json::to_string(receipt)
                    .map_err(|e| SignetError::CorruptedRecord(format!("serialize: {e}")))?;
                match crate::verify_any(&receipt_str, &vk) {
                    Ok(()) => valid += 1,
                    Err(_) => push_failure("signature mismatch".to_string(), &mut failures),
                }
            }
            Err(reason) => push_failure(format!("invalid pubkey: {reason}"), &mut failures),
        }
    }

    Ok(VerifyResult {
        total: records.len(),
        valid,
        warnings,
        failures,
    })
}

/// Parse a duration string like "24h" or "7d" into a DateTime.
pub fn parse_since(s: &str) -> Result<DateTime<Utc>, SignetError> {
    let s = s.trim();
    if s.len() < 2 {
        return Err(SignetError::CorruptedRecord(format!(
            "invalid duration: '{s}' (use e.g. 24h, 7d)"
        )));
    }
    let (num_str, unit) = s.split_at(s.len() - 1);
    let num: i64 = num_str
        .parse()
        .map_err(|_| SignetError::CorruptedRecord(format!("invalid duration: '{s}'")))?;
    let duration = match unit {
        "h" => chrono::Duration::hours(num),
        "d" => chrono::Duration::days(num),
        _ => {
            return Err(SignetError::CorruptedRecord(format!(
                "invalid duration unit: '{unit}' (use h or d)"
            )))
        }
    };
    Ok(Utc::now() - duration)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::generate_keypair;
    use crate::sign;
    use crate::test_helpers::test_action;
    use serde_json::json;

    fn sign_receipt_simple() -> serde_json::Value {
        let (sk, _) = generate_keypair();
        let action = test_action();
        let receipt = sign::sign(&sk, &action, "test-agent", "").unwrap();
        serde_json::to_value(&receipt).unwrap()
    }

    #[test]
    fn test_append_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let receipt = sign_receipt_simple();
        let record = append(dir.path(), &receipt).unwrap();
        assert!(record.record_hash.starts_with("sha256:"));
        // Verify file exists
        let files = sorted_audit_files(dir.path(), true).unwrap();
        assert_eq!(files.len(), 1);
    }

    #[test]
    fn test_append_genesis_hash() {
        let dir = tempfile::tempdir().unwrap();
        let receipt = sign_receipt_simple();
        let record = append(dir.path(), &receipt).unwrap();
        assert_eq!(record.prev_hash, GENESIS_HASH);
    }

    #[test]
    fn test_append_chain_continuity() {
        let dir = tempfile::tempdir().unwrap();
        let r1 = sign_receipt_simple();
        let rec1 = append(dir.path(), &r1).unwrap();

        let r2 = sign_receipt_simple();
        let rec2 = append(dir.path(), &r2).unwrap();

        assert_eq!(rec2.prev_hash, rec1.record_hash);
    }

    #[test]
    fn test_append_cross_day() {
        let dir = tempfile::tempdir().unwrap();
        let adir = dir.path().join("audit");
        fs::create_dir_all(&adir).unwrap();

        // Write a fake "yesterday" record
        let yesterday_hash =
            "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let yesterday_record = serde_json::json!({
            "receipt": {
                "v": 1, "id": "rec_old", "action": {"tool":"test","params":null,"params_hash":"","target":"","transport":"stdio"},
                "signer": {"pubkey":"ed25519:AAAA","name":"old","owner":""},
                "ts": "2026-03-28T23:59:00.000Z", "nonce": "rnd_0000", "sig": "ed25519:AAAA"
            },
            "prev_hash": GENESIS_HASH,
            "record_hash": yesterday_hash
        });
        fs::write(
            adir.join("2026-03-28.jsonl"),
            format!("{}\n", yesterday_record),
        )
        .unwrap();

        // Append a new receipt (today)
        let receipt = sign_receipt_simple();
        let record = append(dir.path(), &receipt).unwrap();
        assert_eq!(record.prev_hash, yesterday_hash);
    }

    #[test]
    fn test_query_no_filter() {
        let dir = tempfile::tempdir().unwrap();
        for _ in 0..3 {
            let r = sign_receipt_simple();
            append(dir.path(), &r).unwrap();
        }
        let results = query(dir.path(), &AuditFilter::default()).unwrap();
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn test_query_since() {
        let dir = tempfile::tempdir().unwrap();
        for _ in 0..3 {
            let r = sign_receipt_simple();
            append(dir.path(), &r).unwrap();
        }
        // Since 1 hour ago should include all recent records
        let filter = AuditFilter {
            since: Some(Utc::now() - chrono::Duration::hours(1)),
            ..Default::default()
        };
        let results = query(dir.path(), &filter).unwrap();
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn test_query_tool_substring() {
        let dir = tempfile::tempdir().unwrap();
        let r = sign_receipt_simple(); // tool = "github_create_issue"
        append(dir.path(), &r).unwrap();

        let filter = AuditFilter {
            tool: Some("github".to_string()),
            ..Default::default()
        };
        let results = query(dir.path(), &filter).unwrap();
        assert_eq!(results.len(), 1);

        let filter_miss = AuditFilter {
            tool: Some("slack".to_string()),
            ..Default::default()
        };
        let results_miss = query(dir.path(), &filter_miss).unwrap();
        assert_eq!(results_miss.len(), 0);
    }

    #[test]
    fn test_verify_chain_intact() {
        let dir = tempfile::tempdir().unwrap();
        for _ in 0..5 {
            let r = sign_receipt_simple();
            append(dir.path(), &r).unwrap();
        }
        let status = verify_chain(dir.path()).unwrap();
        assert!(status.valid);
        assert_eq!(status.total_records, 5);
        assert!(status.break_point.is_none());
    }

    #[test]
    fn test_verify_chain_broken() {
        let dir = tempfile::tempdir().unwrap();
        for _ in 0..3 {
            let r = sign_receipt_simple();
            append(dir.path(), &r).unwrap();
        }
        // Tamper with the second record
        let files = sorted_audit_files(dir.path(), true).unwrap();
        let content = fs::read_to_string(&files[0]).unwrap();
        let mut lines: Vec<String> = content.lines().map(String::from).collect();
        if lines.len() >= 2 {
            let mut record: serde_json::Value = serde_json::from_str(&lines[1]).unwrap();
            record["record_hash"] = serde_json::json!(
                "sha256:tampered0000000000000000000000000000000000000000000000000000"
            );
            lines[1] = serde_json::to_string(&record).unwrap();
        }
        fs::write(&files[0], lines.join("\n") + "\n").unwrap();

        let status = verify_chain(dir.path()).unwrap();
        assert!(!status.valid);
        assert!(status.break_point.is_some());
    }

    #[test]
    fn test_verify_signatures() {
        let dir = tempfile::tempdir().unwrap();
        // Sign with a real key so signatures are valid
        let (sk, _) = generate_keypair();
        let action = test_action();
        for _ in 0..3 {
            let receipt = sign::sign(&sk, &action, "agent", "").unwrap();
            append(dir.path(), &serde_json::to_value(&receipt).unwrap()).unwrap();
        }
        let result = verify_signatures(dir.path(), &AuditFilter::default()).unwrap();
        assert_eq!(result.total, 3);
        assert_eq!(result.valid, 3);
        assert!(result.warnings.is_empty());
        assert!(result.failures.is_empty());
    }

    // --- v2 (CompoundReceipt) tests ---

    #[test]
    fn test_audit_append_v2() {
        let dir = tempfile::tempdir().unwrap();
        let (sk, _) = generate_keypair();
        let action = test_action();
        let ts_req = chrono::Utc::now();
        let ts_res = ts_req + chrono::Duration::milliseconds(150);
        let ts_request = ts_req.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let ts_response = ts_res.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let v2 = sign::sign_compound(
            &sk,
            &action,
            &json!({"text": "ok"}),
            "agent",
            "",
            &ts_request,
            &ts_response,
        )
        .unwrap();
        let record = append(dir.path(), &serde_json::to_value(&v2).unwrap()).unwrap();
        assert!(record.record_hash.starts_with("sha256:"));
        let files = sorted_audit_files(dir.path(), true).unwrap();
        assert_eq!(files.len(), 1);
    }

    #[test]
    fn test_audit_query_mixed_v1_v2() {
        let dir = tempfile::tempdir().unwrap();
        let (sk, _) = generate_keypair();
        let action = test_action();

        // Append v1
        let v1 = sign::sign(&sk, &action, "agent", "").unwrap();
        append(dir.path(), &serde_json::to_value(&v1).unwrap()).unwrap();

        // Append v2
        let ts_req = chrono::Utc::now();
        let ts_res = ts_req + chrono::Duration::milliseconds(150);
        let ts_request = ts_req.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let ts_response = ts_res.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let v2 = sign::sign_compound(
            &sk,
            &action,
            &json!({"text": "ok"}),
            "agent",
            "",
            &ts_request,
            &ts_response,
        )
        .unwrap();
        append(dir.path(), &serde_json::to_value(&v2).unwrap()).unwrap();

        let results = query(dir.path(), &AuditFilter::default()).unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_audit_verify_chain_mixed() {
        let dir = tempfile::tempdir().unwrap();
        let (sk, _) = generate_keypair();
        let action = test_action();

        // v1 record
        let v1 = sign::sign(&sk, &action, "agent", "").unwrap();
        append(dir.path(), &serde_json::to_value(&v1).unwrap()).unwrap();

        // v2 record
        let ts_req = chrono::Utc::now();
        let ts_res = ts_req + chrono::Duration::milliseconds(150);
        let ts_request = ts_req.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let ts_response = ts_res.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let v2 = sign::sign_compound(
            &sk,
            &action,
            &json!({"text": "ok"}),
            "agent",
            "",
            &ts_request,
            &ts_response,
        )
        .unwrap();
        append(dir.path(), &serde_json::to_value(&v2).unwrap()).unwrap();

        // Another v1
        let v1b = sign::sign(&sk, &action, "agent", "").unwrap();
        append(dir.path(), &serde_json::to_value(&v1b).unwrap()).unwrap();

        let status = verify_chain(dir.path()).unwrap();
        assert!(status.valid);
        assert_eq!(status.total_records, 3);
        assert!(status.break_point.is_none());
    }

    #[test]
    fn test_audit_append_v3_bilateral() {
        let dir = tempfile::tempdir().unwrap();
        let (agent_key, _) = generate_keypair();
        let (server_key, _) = generate_keypair();
        let action = test_action();
        let agent_receipt = sign::sign(&agent_key, &action, "test-agent", "owner").unwrap();
        let response = json!({"content": [{"type": "text", "text": "ok"}]});
        let ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let bilateral =
            sign::sign_bilateral(&server_key, &agent_receipt, &response, "test-server", &ts)
                .unwrap();
        let receipt_json = serde_json::to_value(&bilateral).unwrap();

        append(dir.path(), &receipt_json).unwrap();
        let records = query(dir.path(), &AuditFilter::default()).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(extract_signer_name(&records[0].receipt), Some("test-agent"));
        assert_eq!(
            extract_tool(&records[0].receipt),
            Some("github_create_issue")
        );
    }

    #[test]
    fn test_audit_verify_signatures_v3() {
        let dir = tempfile::tempdir().unwrap();
        let (agent_key, _) = generate_keypair();
        let (server_key, _) = generate_keypair();
        let action = test_action();
        let agent_receipt = sign::sign(&agent_key, &action, "test-agent", "owner").unwrap();
        let response = json!({"content": [{"type": "text", "text": "ok"}]});
        let ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let bilateral =
            sign::sign_bilateral(&server_key, &agent_receipt, &response, "test-server", &ts)
                .unwrap();

        append(dir.path(), &serde_json::to_value(&bilateral).unwrap()).unwrap();
        let result = verify_signatures(dir.path(), &AuditFilter::default()).unwrap();
        assert_eq!(result.valid, 1);
        assert_eq!(result.warnings.len(), 1);
        assert!(result.warnings[0]
            .reason
            .contains("verified for integrity only"));
        assert!(result.failures.is_empty());
    }

    #[test]
    fn test_audit_verify_signatures_v3_with_trusted_keys() {
        let dir = tempfile::tempdir().unwrap();
        let (agent_key, agent_vk) = generate_keypair();
        let (server_key, server_vk) = generate_keypair();
        let action = test_action();
        let agent_receipt = sign::sign(&agent_key, &action, "test-agent", "owner").unwrap();
        let response = json!({"content": [{"type": "text", "text": "ok"}]});
        let ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let bilateral =
            sign::sign_bilateral(&server_key, &agent_receipt, &response, "test-server", &ts)
                .unwrap();

        append(dir.path(), &serde_json::to_value(&bilateral).unwrap()).unwrap();
        let result = verify_signatures_with_options(
            dir.path(),
            &AuditFilter::default(),
            &AuditVerifyOptions {
                trusted_server_pubkeys: vec![server_vk],
                trusted_agent_pubkeys: vec![agent_vk],
            },
        )
        .unwrap();
        assert_eq!(result.valid, 1);
        assert!(result.warnings.is_empty());
        assert!(result.failures.is_empty());
    }

    #[test]
    fn test_audit_verify_signatures_v3_untrusted_server_fails() {
        let dir = tempfile::tempdir().unwrap();
        let (agent_key, agent_vk) = generate_keypair();
        let (server_key, _) = generate_keypair();
        let (_, wrong_server_vk) = generate_keypair();
        let action = test_action();
        let agent_receipt = sign::sign(&agent_key, &action, "test-agent", "owner").unwrap();
        let response = json!({"content": [{"type": "text", "text": "ok"}]});
        let ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let bilateral =
            sign::sign_bilateral(&server_key, &agent_receipt, &response, "test-server", &ts)
                .unwrap();

        append(dir.path(), &serde_json::to_value(&bilateral).unwrap()).unwrap();
        let result = verify_signatures_with_options(
            dir.path(),
            &AuditFilter::default(),
            &AuditVerifyOptions {
                trusted_server_pubkeys: vec![wrong_server_vk],
                trusted_agent_pubkeys: vec![agent_vk],
            },
        )
        .unwrap();
        assert_eq!(result.valid, 0);
        assert!(result.warnings.is_empty());
        assert_eq!(result.failures.len(), 1);
        assert_eq!(result.failures[0].reason, "untrusted server pubkey");
    }

    #[test]
    fn test_audit_mixed_v1_v2_v3() {
        let dir = tempfile::tempdir().unwrap();
        let (agent_key, _) = generate_keypair();
        let (server_key, _) = generate_keypair();
        let action = test_action();

        // v1
        let receipt_v1 = sign::sign(&agent_key, &action, "test-agent", "owner").unwrap();
        append(dir.path(), &serde_json::to_value(&receipt_v1).unwrap()).unwrap();

        // v3
        let bilateral = sign::sign_bilateral(
            &server_key,
            &receipt_v1,
            &json!({"ok": true}),
            "server",
            &chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        )
        .unwrap();
        append(dir.path(), &serde_json::to_value(&bilateral).unwrap()).unwrap();

        let result = verify_signatures(dir.path(), &AuditFilter::default()).unwrap();
        assert_eq!(result.valid, 2);
        assert_eq!(result.warnings.len(), 1);
        assert!(result.failures.is_empty());
    }

    #[test]
    fn test_audit_verify_sigs_v2() {
        let dir = tempfile::tempdir().unwrap();
        let (sk, _) = generate_keypair();
        let action = test_action();

        let ts_req = chrono::Utc::now();
        let ts_res = ts_req + chrono::Duration::milliseconds(150);
        let ts_request = ts_req.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let ts_response = ts_res.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let v2 = sign::sign_compound(
            &sk,
            &action,
            &json!({"text": "ok"}),
            "agent",
            "",
            &ts_request,
            &ts_response,
        )
        .unwrap();
        append(dir.path(), &serde_json::to_value(&v2).unwrap()).unwrap();

        let result = verify_signatures(dir.path(), &AuditFilter::default()).unwrap();
        assert_eq!(result.total, 1);
        assert_eq!(result.valid, 1);
        assert!(result.warnings.is_empty());
        assert!(result.failures.is_empty());
    }

    // ─── trace correlation in audit ─────────────────────────────────────

    #[test]
    fn test_audit_preserves_trace_fields() {
        let dir = tempfile::tempdir().unwrap();
        let (sk, _) = generate_keypair();
        let mut action = test_action();
        action.trace_id = Some("tr_audit_test".to_string());
        action.parent_receipt_id = Some("rec_parent".to_string());
        let receipt = sign::sign(&sk, &action, "agent", "").unwrap();
        append(dir.path(), &serde_json::to_value(&receipt).unwrap()).unwrap();

        let records = query(dir.path(), &AuditFilter::default()).unwrap();
        assert_eq!(records.len(), 1);
        let stored = &records[0].receipt;
        assert_eq!(
            stored["action"]["trace_id"].as_str(),
            Some("tr_audit_test"),
        );
        assert_eq!(
            stored["action"]["parent_receipt_id"].as_str(),
            Some("rec_parent"),
        );
    }

    #[test]
    fn test_audit_trace_fields_absent_when_none() {
        let dir = tempfile::tempdir().unwrap();
        let receipt = sign_receipt_simple(); // no trace fields
        append(dir.path(), &receipt).unwrap();

        let records = query(dir.path(), &AuditFilter::default()).unwrap();
        let stored = &records[0].receipt;
        assert!(stored["action"].get("trace_id").is_none());
        assert!(stored["action"].get("parent_receipt_id").is_none());
    }

    #[test]
    fn test_audit_chain_intact_with_trace_fields() {
        let dir = tempfile::tempdir().unwrap();
        let (sk, _) = generate_keypair();

        for i in 0..3 {
            let mut action = test_action();
            action.trace_id = Some("tr_chain".to_string());
            action.parent_receipt_id = Some(format!("rec_{}", i));
            let receipt = sign::sign(&sk, &action, "agent", "").unwrap();
            append(dir.path(), &serde_json::to_value(&receipt).unwrap()).unwrap();
        }

        let status = verify_chain(dir.path()).unwrap();
        assert!(status.valid);
        assert_eq!(status.total_records, 3);
    }

    #[test]
    fn test_audit_verify_signatures_with_trace() {
        let dir = tempfile::tempdir().unwrap();
        let (sk, _) = generate_keypair();

        let mut action = test_action();
        action.trace_id = Some("tr_sig".to_string());
        let receipt = sign::sign(&sk, &action, "agent", "").unwrap();
        append(dir.path(), &serde_json::to_value(&receipt).unwrap()).unwrap();

        let result = verify_signatures(dir.path(), &AuditFilter::default()).unwrap();
        assert_eq!(result.valid, 1);
        assert!(result.warnings.is_empty());
        assert!(result.failures.is_empty());
    }
}
