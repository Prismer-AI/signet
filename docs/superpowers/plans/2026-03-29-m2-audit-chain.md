# M2: Audit Log + Hash Chain Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add append-only JSONL audit log with SHA-256 hash chain to signet-core, and extend CLI with audit/chain commands.

**Architecture:** New `audit.rs` module in signet-core (cfg-gated for wasm). CLI gets new `audit` subcommand and modified `verify --chain`. `signet sign` auto-appends to audit log.

**Tech Stack:** Rust, sha2 (existing), chrono (existing), serde/serde_json (existing). No new crates needed.

**Spec:** `docs/superpowers/specs/2026-03-29-m2-audit-chain-design.md`

**Toolchain:** Rust 1.95.0-nightly, cargo at `~/.cargo/bin/`.

**Existing code:** 34 core tests + 14 CLI tests = 48 total. signet-core has sign/verify/identity/keystore. signet-cli has identity/sign/verify commands.

---

## File Map

| File | Action | Responsibility |
|------|--------|----------------|
| `crates/signet-core/src/error.rs` | Modify | Add CorruptedRecord variant |
| `crates/signet-core/src/audit.rs` | Create | Audit log append/query/verify_chain/verify_signatures |
| `crates/signet-core/src/lib.rs` | Modify | Add audit module + re-exports |
| `signet-cli/src/main.rs` | Modify | Add Audit subcommand, modify Verify |
| `signet-cli/src/cmd_sign.rs` | Modify | Add --no-log flag, call audit::append |
| `signet-cli/src/cmd_verify.rs` | Modify | Refactor VerifyArgs for --chain |
| `signet-cli/src/cmd_audit.rs` | Create | audit list/verify/export subcommand |

---

### Task 1: Add CorruptedRecord error variant

**Files:**
- Modify: `crates/signet-core/src/error.rs`

- [ ] **Step 1: Add the new variant**

Add after the `CorruptedFile` variant in `error.rs`:

```rust
    #[cfg(not(target_arch = "wasm32"))]
    #[error("corrupted audit record: {0}")]
    CorruptedRecord(String),
```

- [ ] **Step 2: Verify tests pass**

Run: `~/.cargo/bin/cargo test -p signet-core`
Expected: 34 tests PASS

- [ ] **Step 3: Commit**

```bash
git add crates/signet-core/src/error.rs
git commit -m "feat(core): add CorruptedRecord error variant for audit module"
```

---

### Task 2: Audit module — append + chain

**Files:**
- Create: `crates/signet-core/src/audit.rs`
- Modify: `crates/signet-core/src/lib.rs`

- [ ] **Step 1: Create audit.rs**

Create `crates/signet-core/src/audit.rs`:

```rust
#![cfg(not(target_arch = "wasm32"))]

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::canonical;
use crate::error::SignetError;
use crate::receipt::Receipt;

const GENESIS_HASH: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub receipt: Receipt,
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

#[derive(Debug)]
pub struct ChainStatus {
    pub total_records: usize,
    pub valid: bool,
    pub break_point: Option<ChainBreak>,
}

#[derive(Debug)]
pub struct ChainBreak {
    pub file: String,
    pub line: usize,
    pub expected_hash: String,
    pub actual_hash: String,
}

#[derive(Debug)]
pub struct VerifyResult {
    pub total: usize,
    pub valid: usize,
    pub failures: Vec<VerifyFailure>,
}

#[derive(Debug)]
pub struct VerifyFailure {
    pub file: String,
    pub line: usize,
    pub receipt_id: String,
    pub reason: String,
}

fn audit_dir(base: &Path) -> PathBuf {
    base.join("audit")
}

fn compute_record_hash(receipt: &Receipt, prev_hash: &str) -> Result<String, SignetError> {
    let hashable = serde_json::json!({
        "prev_hash": prev_hash,
        "receipt": receipt,
    });
    let canonical = canonical::canonicalize(&hashable)?;
    let hash = Sha256::digest(canonical.as_bytes());
    Ok(format!("sha256:{}", hex::encode(hash)))
}

fn date_from_receipt(receipt: &Receipt) -> Result<NaiveDate, SignetError> {
    let dt = DateTime::parse_from_rfc3339(&receipt.ts)
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
            let record: AuditRecord = serde_json::from_str(last_line)
                .map_err(|e| SignetError::CorruptedRecord(format!(
                    "{}: {e}", file.file_name().unwrap_or_default().to_string_lossy()
                )))?;
            return Ok(record.record_hash);
        }
    }
    Ok(GENESIS_HASH.to_string())
}

pub fn append(dir: &Path, receipt: &Receipt) -> Result<AuditRecord, SignetError> {
    let adir = audit_dir(dir);
    fs::create_dir_all(&adir)?;

    let date = date_from_receipt(receipt)?;
    let filename = format!("{}.jsonl", date);
    let filepath = adir.join(&filename);

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
}

pub fn query(dir: &Path, filter: &AuditFilter) -> Result<Vec<AuditRecord>, SignetError> {
    let files = sorted_audit_files(dir, false)?; // newest first
    let mut results = Vec::new();

    for file in files {
        let content = fs::read_to_string(&file)?;
        let lines: Vec<&str> = content.lines().collect();

        for line in lines.iter().rev() {
            if line.trim().is_empty() {
                continue;
            }
            let record: AuditRecord = serde_json::from_str(line)
                .map_err(|e| SignetError::CorruptedRecord(format!(
                    "{}: {e}", file.file_name().unwrap_or_default().to_string_lossy()
                )))?;

            // Check since filter — stop scanning if record is too old
            if let Some(since) = filter.since {
                if let Ok(ts) = DateTime::parse_from_rfc3339(&record.receipt.ts) {
                    if ts < since {
                        return Ok(results.into_iter().rev().collect());
                    }
                }
            }

            // Check tool filter (substring)
            if let Some(ref tool) = filter.tool {
                if !record.receipt.action.tool.contains(tool.as_str()) {
                    continue;
                }
            }

            // Check signer filter (exact)
            if let Some(ref signer) = filter.signer {
                if record.receipt.signer.name != *signer {
                    continue;
                }
            }

            results.push(record);

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
        let fname = file.file_name().unwrap_or_default().to_string_lossy().to_string();

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
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64;

    let records = query(dir, filter)?;
    let mut valid = 0usize;
    let mut failures = Vec::new();

    for record in &records {
        let receipt = &record.receipt;

        // Decode pubkey from receipt
        let pubkey_result = (|| -> Result<ed25519_dalek::VerifyingKey, String> {
            let b64 = receipt.signer.pubkey
                .strip_prefix("ed25519:")
                .ok_or("missing ed25519: prefix")?;
            let bytes = BASE64.decode(b64).map_err(|e| format!("base64: {e}"))?;
            let arr: [u8; 32] = bytes.try_into().map_err(|_| "not 32 bytes")?;
            ed25519_dalek::VerifyingKey::from_bytes(&arr).map_err(|e| format!("{e}"))
        })();

        match pubkey_result {
            Ok(vk) => match crate::verify(receipt, &vk) {
                Ok(()) => valid += 1,
                Err(_) => failures.push(VerifyFailure {
                    file: String::new(),
                    line: 0,
                    receipt_id: receipt.id.clone(),
                    reason: "signature mismatch".to_string(),
                }),
            },
            Err(reason) => failures.push(VerifyFailure {
                file: String::new(),
                line: 0,
                receipt_id: receipt.id.clone(),
                reason: format!("invalid pubkey: {reason}"),
            }),
        }
    }

    Ok(VerifyResult {
        total: records.len(),
        valid,
        failures,
    })
}

/// Parse a duration string like "24h" or "7d" into a DateTime.
pub fn parse_since(s: &str) -> Result<DateTime<Utc>, SignetError> {
    let s = s.trim();
    if s.len() < 2 {
        return Err(SignetError::CorruptedRecord(format!("invalid duration: '{s}' (use e.g. 24h, 7d)")));
    }
    let (num_str, unit) = s.split_at(s.len() - 1);
    let num: i64 = num_str.parse()
        .map_err(|_| SignetError::CorruptedRecord(format!("invalid duration: '{s}'")))?;
    let duration = match unit {
        "h" => chrono::Duration::hours(num),
        "d" => chrono::Duration::days(num),
        _ => return Err(SignetError::CorruptedRecord(format!("invalid duration unit: '{unit}' (use h or d)"))),
    };
    Ok(Utc::now() - duration)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::generate_keypair;
    use crate::sign;
    use crate::test_helpers::test_action;

    fn sign_receipt(dir: &std::path::Path) -> Receipt {
        let (sk, _) = generate_keypair();
        // Save key so we have metadata
        crate::generate_and_save(dir, "test-agent", "", None, None).unwrap();
        let action = test_action();
        sign::sign(&sk, &action, "test-agent", "").unwrap()
    }

    fn sign_receipt_simple() -> Receipt {
        let (sk, _) = generate_keypair();
        let action = test_action();
        sign::sign(&sk, &action, "test-agent", "").unwrap()
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
        let yesterday_hash = "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let yesterday_record = serde_json::json!({
            "receipt": {
                "v": 1, "id": "rec_old", "action": {"tool":"test","params":null,"params_hash":"","target":"","transport":"stdio"},
                "signer": {"pubkey":"ed25519:AAAA","name":"old","owner":""},
                "ts": "2026-03-28T23:59:00.000Z", "nonce": "rnd_0000", "sig": "ed25519:AAAA"
            },
            "prev_hash": GENESIS_HASH,
            "record_hash": yesterday_hash
        });
        fs::write(adir.join("2026-03-28.jsonl"), format!("{}\n", yesterday_record)).unwrap();

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
        let adir = dir.path().join("audit");
        let files = sorted_audit_files(dir.path(), true).unwrap();
        let content = fs::read_to_string(&files[0]).unwrap();
        let mut lines: Vec<String> = content.lines().map(String::from).collect();
        if lines.len() >= 2 {
            let mut record: serde_json::Value = serde_json::from_str(&lines[1]).unwrap();
            record["record_hash"] = serde_json::json!("sha256:tampered0000000000000000000000000000000000000000000000000000");
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
            append(dir.path(), &receipt).unwrap();
        }
        let result = verify_signatures(dir.path(), &AuditFilter::default()).unwrap();
        assert_eq!(result.total, 3);
        assert_eq!(result.valid, 3);
        assert!(result.failures.is_empty());
    }
}
```

- [ ] **Step 2: Add audit module to lib.rs**

Add after keystore module in `crates/signet-core/src/lib.rs`:

```rust
#[cfg(not(target_arch = "wasm32"))]
pub mod audit;
```

- [ ] **Step 3: Run tests**

Run: `~/.cargo/bin/cargo test -p signet-core`
Expected: 34 old + 10 new audit = 44 tests PASS

- [ ] **Step 4: Commit**

```bash
git add crates/signet-core/
git commit -m "feat(core): add audit module with JSONL append, query, chain verification"
```

---

### Task 3: Modify signet sign to auto-log

**Files:**
- Modify: `signet-cli/src/cmd_sign.rs`

- [ ] **Step 1: Add --no-log flag and audit::append call**

Add to `SignArgs` struct:

```rust
    /// Skip writing to audit log
    #[arg(long)]
    pub no_log: bool,
```

Add after the receipt is created (after `let json = serde_json::to_string(&receipt)?;`), before the output match:

```rust
    // Append to audit log unless --no-log
    if !args.no_log {
        signet_core::audit::append(&dir, &receipt)?;
    }
```

- [ ] **Step 2: Verify it compiles**

Run: `~/.cargo/bin/cargo check -p signet-cli`

- [ ] **Step 3: Commit**

```bash
git add signet-cli/src/cmd_sign.rs
git commit -m "feat(cli): auto-append to audit log on sign (--no-log to skip)"
```

---

### Task 4: Refactor verify command for --chain

**Files:**
- Modify: `signet-cli/src/cmd_verify.rs`

- [ ] **Step 1: Replace cmd_verify.rs**

```rust
use std::fs;

use anyhow::{bail, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use clap::Args;

#[derive(Args)]
pub struct VerifyArgs {
    /// Path to receipt JSON file
    pub receipt: Option<String>,

    /// Public key name or file path
    #[arg(long)]
    pub pubkey: Option<String>,

    /// Verify audit log hash chain integrity
    #[arg(long)]
    pub chain: bool,
}

pub fn verify(args: VerifyArgs) -> Result<()> {
    if args.chain {
        if args.receipt.is_some() || args.pubkey.is_some() {
            bail!("--chain cannot be used with receipt or --pubkey");
        }
        return verify_chain();
    }

    // Receipt verification mode
    let receipt_path = args.receipt
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("receipt file path required (or use --chain)"))?;
    let pubkey = args.pubkey
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("--pubkey required for receipt verification"))?;

    let receipt_str = fs::read_to_string(receipt_path)
        .map_err(|e| anyhow::anyhow!("failed to read receipt '{receipt_path}': {e}"))?;
    let receipt: signet_core::Receipt = serde_json::from_str(&receipt_str)?;

    let vk = if pubkey.contains('/') || pubkey.ends_with(".pub") {
        let content = fs::read_to_string(pubkey)
            .map_err(|e| anyhow::anyhow!("failed to read pubkey file '{pubkey}': {e}"))?;
        let pub_file: signet_core::keystore::PubKeyFile = serde_json::from_str(&content)?;
        let b64 = pub_file
            .pubkey
            .strip_prefix("ed25519:")
            .unwrap_or(&pub_file.pubkey);
        let bytes = BASE64.decode(b64)?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("pubkey is not 32 bytes"))?;
        ed25519_dalek::VerifyingKey::from_bytes(&arr)?
    } else {
        let dir = signet_core::default_signet_dir();
        signet_core::load_verifying_key(&dir, pubkey)?
    };

    match signet_core::verify(&receipt, &vk) {
        Ok(()) => {
            println!(
                "Valid: \"{}\" signed \"{}\" at {}",
                receipt.signer.name, receipt.action.tool, receipt.ts
            );
        }
        Err(signet_core::SignetError::SignatureMismatch) => {
            bail!("signature verification failed");
        }
        Err(e) => {
            bail!("verification error: {e}");
        }
    }
    Ok(())
}

fn verify_chain() -> Result<()> {
    let dir = signet_core::default_signet_dir();
    eprintln!("Verifying chain integrity...");

    let status = signet_core::audit::verify_chain(&dir)?;

    if status.valid {
        println!("Chain intact: {} records verified", status.total_records);
    } else if let Some(bp) = status.break_point {
        eprintln!("Chain broken at {}:{}", bp.file, bp.line);
        eprintln!("  expected prev_hash: {}", bp.expected_hash);
        eprintln!("  actual prev_hash:   {}", bp.actual_hash);
        bail!("signature verification failed");
    }
    Ok(())
}
```

- [ ] **Step 2: Verify it compiles**

Run: `~/.cargo/bin/cargo check -p signet-cli`

- [ ] **Step 3: Commit**

```bash
git add signet-cli/src/cmd_verify.rs
git commit -m "feat(cli): add --chain flag to verify command for hash chain integrity"
```

---

### Task 5: Audit CLI subcommand

**Files:**
- Create: `signet-cli/src/cmd_audit.rs`
- Modify: `signet-cli/src/main.rs`

- [ ] **Step 1: Create cmd_audit.rs**

```rust
use std::fs;

use anyhow::{bail, Result};
use clap::Args;
use signet_core::audit::{self, AuditFilter};

#[derive(Args)]
pub struct AuditArgs {
    /// Filter by time (e.g. 24h, 7d)
    #[arg(long)]
    pub since: Option<String>,

    /// Filter by tool name (substring match)
    #[arg(long)]
    pub tool: Option<String>,

    /// Filter by signer name (exact match)
    #[arg(long)]
    pub signer: Option<String>,

    /// Maximum number of records
    #[arg(long)]
    pub limit: Option<usize>,

    /// Verify all receipt signatures
    #[arg(long)]
    pub verify: bool,

    /// Export records to JSON file
    #[arg(long)]
    pub export: Option<String>,
}

pub fn audit(args: AuditArgs) -> Result<()> {
    if args.verify && args.export.is_some() {
        bail!("--verify and --export are mutually exclusive");
    }

    let dir = signet_core::default_signet_dir();

    let filter = AuditFilter {
        since: match &args.since {
            Some(s) => Some(audit::parse_since(s)?),
            None => None,
        },
        tool: args.tool.clone(),
        signer: args.signer.clone(),
        limit: args.limit,
    };

    if args.verify {
        return verify_signatures(&dir, &filter);
    }

    if let Some(ref path) = args.export {
        return export_records(&dir, &filter, path);
    }

    // Default: list records as table
    list_records(&dir, &filter)
}

fn list_records(dir: &std::path::Path, filter: &AuditFilter) -> Result<()> {
    let records = audit::query(dir, filter)?;

    if records.is_empty() {
        println!("No audit records found.");
        return Ok(());
    }

    println!(
        "{:<30} {:<15} {:<30} {}",
        "TIME", "SIGNER", "TOOL", "TARGET"
    );
    println!("{}", "-".repeat(90));
    for record in &records {
        let r = &record.receipt;
        println!(
            "{:<30} {:<15} {:<30} {}",
            r.ts, r.signer.name, r.action.tool, r.action.target
        );
    }
    println!("\n{} records", records.len());
    Ok(())
}

fn verify_signatures(dir: &std::path::Path, filter: &AuditFilter) -> Result<()> {
    let result = audit::verify_signatures(dir, filter)?;

    if result.failures.is_empty() {
        println!("{}/{} signatures valid", result.valid, result.total);
    } else {
        for f in &result.failures {
            eprintln!("Record {}: {}", f.receipt_id, f.reason);
        }
        println!(
            "{}/{} signatures valid, {} FAILED",
            result.valid,
            result.total,
            result.failures.len()
        );
        bail!("signature verification failed");
    }
    Ok(())
}

fn export_records(dir: &std::path::Path, filter: &AuditFilter, path: &str) -> Result<()> {
    let records = audit::query(dir, filter)?;
    let json = serde_json::to_string_pretty(&records)?;
    fs::write(path, json)?;
    eprintln!("Exported {} records to {path}", records.len());
    Ok(())
}
```

- [ ] **Step 2: Update main.rs to add Audit command**

Add to the `Commands` enum:

```rust
    /// Query and verify the audit log
    Audit(cmd_audit::AuditArgs),
```

Add the module declaration at the top:

```rust
mod cmd_audit;
```

Add to the match in `run()`:

```rust
        Commands::Audit(args) => cmd_audit::audit(args)?,
```

- [ ] **Step 3: Verify it compiles**

Run: `~/.cargo/bin/cargo check -p signet-cli`

- [ ] **Step 4: Commit**

```bash
git add signet-cli/
git commit -m "feat(cli): add audit subcommand with query, verify, and export"
```

---

### Task 6: CLI integration tests for audit

**Files:**
- Modify: `signet-cli/tests/cli.rs`

- [ ] **Step 1: Add 6 audit integration tests**

Append to the existing `signet-cli/tests/cli.rs`:

```rust
#[test]
fn test_sign_creates_audit_log() {
    let dir = tempfile::tempdir().unwrap();
    signet()
        .args(["identity", "generate", "--name", "audit-bot", "--unencrypted"])
        .env("SIGNET_HOME", dir.path())
        .assert()
        .success();
    signet()
        .args(["sign", "--key", "audit-bot", "--tool", "test",
               "--params", r#"{}"#, "--target", "mcp://test"])
        .env("SIGNET_HOME", dir.path())
        .assert()
        .success();
    // Verify audit file exists
    let audit_dir = dir.path().join("audit");
    assert!(audit_dir.exists());
    let files: Vec<_> = std::fs::read_dir(&audit_dir).unwrap().collect();
    assert_eq!(files.len(), 1);
}

#[test]
fn test_sign_no_log() {
    let dir = tempfile::tempdir().unwrap();
    signet()
        .args(["identity", "generate", "--name", "nolog-bot", "--unencrypted"])
        .env("SIGNET_HOME", dir.path())
        .assert()
        .success();
    signet()
        .args(["sign", "--key", "nolog-bot", "--tool", "test",
               "--params", r#"{}"#, "--target", "mcp://test", "--no-log"])
        .env("SIGNET_HOME", dir.path())
        .assert()
        .success();
    // Audit dir should not exist
    assert!(!dir.path().join("audit").exists());
}

#[test]
fn test_audit_list() {
    let dir = tempfile::tempdir().unwrap();
    signet()
        .args(["identity", "generate", "--name", "list-bot", "--unencrypted"])
        .env("SIGNET_HOME", dir.path())
        .assert()
        .success();
    for _ in 0..3 {
        signet()
            .args(["sign", "--key", "list-bot", "--tool", "github_create_issue",
                   "--params", r#"{"n":1}"#, "--target", "mcp://gh"])
            .env("SIGNET_HOME", dir.path())
            .assert()
            .success();
    }
    signet()
        .args(["audit"])
        .env("SIGNET_HOME", dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("github_create_issue"))
        .stdout(predicate::str::contains("3 records"));
}

#[test]
fn test_audit_since() {
    let dir = tempfile::tempdir().unwrap();
    signet()
        .args(["identity", "generate", "--name", "since-bot", "--unencrypted"])
        .env("SIGNET_HOME", dir.path())
        .assert()
        .success();
    signet()
        .args(["sign", "--key", "since-bot", "--tool", "test",
               "--params", r#"{}"#, "--target", "mcp://test"])
        .env("SIGNET_HOME", dir.path())
        .assert()
        .success();
    signet()
        .args(["audit", "--since", "1h"])
        .env("SIGNET_HOME", dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("1 records"));
}

#[test]
fn test_audit_verify() {
    let dir = tempfile::tempdir().unwrap();
    signet()
        .args(["identity", "generate", "--name", "sigver-bot", "--unencrypted"])
        .env("SIGNET_HOME", dir.path())
        .assert()
        .success();
    for _ in 0..3 {
        signet()
            .args(["sign", "--key", "sigver-bot", "--tool", "test",
                   "--params", r#"{}"#, "--target", "mcp://test"])
            .env("SIGNET_HOME", dir.path())
            .assert()
            .success();
    }
    signet()
        .args(["audit", "--verify"])
        .env("SIGNET_HOME", dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("3/3 signatures valid"));
}

#[test]
fn test_verify_chain() {
    let dir = tempfile::tempdir().unwrap();
    signet()
        .args(["identity", "generate", "--name", "chain-bot", "--unencrypted"])
        .env("SIGNET_HOME", dir.path())
        .assert()
        .success();
    for _ in 0..3 {
        signet()
            .args(["sign", "--key", "chain-bot", "--tool", "test",
                   "--params", r#"{}"#, "--target", "mcp://test"])
            .env("SIGNET_HOME", dir.path())
            .assert()
            .success();
    }
    signet()
        .args(["verify", "--chain"])
        .env("SIGNET_HOME", dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("Chain intact"))
        .stdout(predicate::str::contains("3 records"));
}
```

- [ ] **Step 2: Run all tests**

Run: `~/.cargo/bin/cargo test --workspace`
Expected: 44 core + 20 CLI = 64 tests PASS

- [ ] **Step 3: Commit**

```bash
git add signet-cli/tests/cli.rs
git commit -m "test(cli): add 6 audit integration tests for log, chain, and verify"
```

---

### Task 7: Final verification

- [ ] **Step 1: Full test suite**

Run: `~/.cargo/bin/cargo test --workspace`
Expected: all tests PASS

- [ ] **Step 2: WASM regression**

Run: `~/.cargo/bin/wasm-pack build bindings/signet-ts --target nodejs --out-dir pkg && node examples/wasm-roundtrip/test.mjs`
Expected: WASM builds + 8 Node.js tests pass

- [ ] **Step 3: Clippy**

Run: `~/.cargo/bin/cargo clippy --workspace -- -D warnings`
Expected: no warnings

- [ ] **Step 4: End-to-end smoke test**

```bash
export SIGNET_HOME=$(mktemp -d)
export PATH="$HOME/.cargo/bin:$PATH"
cargo run -p signet-cli -- identity generate --name smoke --unencrypted
for i in 1 2 3 4 5; do
  cargo run -p signet-cli -- sign --key smoke --tool "action_$i" --params "{\"n\":$i}" --target mcp://test
done
cargo run -p signet-cli -- audit
cargo run -p signet-cli -- audit --verify
cargo run -p signet-cli -- audit --tool action_3
cargo run -p signet-cli -- audit --export /tmp/audit-export.json
cargo run -p signet-cli -- verify --chain
rm -rf "$SIGNET_HOME" /tmp/audit-export.json
```
Expected: all commands succeed, audit shows 5 records, verify shows 5/5 valid, chain intact

- [ ] **Step 5: Check for unsafe**

Run: `grep -r "unsafe" crates/signet-core/src/ signet-cli/src/`
Expected: no matches

- [ ] **Step 6: Commit if needed**

```bash
git status
# If changes exist:
git add -A && git commit -m "feat: complete M2 — audit log with hash chain"
```

---

## Exit Criteria Checklist

| # | Criterion | Verified by |
|---|-----------|-------------|
| 1 | sign auto-appends to audit | Task 6: test_sign_creates_audit_log |
| 2 | sign --no-log skips | Task 6: test_sign_no_log |
| 3 | audit lists records | Task 6: test_audit_list |
| 4 | audit --since filters | Task 6: test_audit_since |
| 5 | audit --tool filters | Task 6: test_audit_list (contains github) |
| 6 | audit --verify checks sigs | Task 6: test_audit_verify |
| 7 | audit --export writes JSON | Task 7 Step 4 (smoke test) |
| 8 | verify --chain validates chain | Task 6: test_verify_chain |
| 9 | Chain continuous across days | Task 2: test_append_cross_day |
| 10 | All tests pass | Task 7 Step 1 |
| 11 | WASM still works | Task 7 Step 2 |
