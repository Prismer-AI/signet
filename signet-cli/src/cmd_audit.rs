use std::fs;

use anyhow::{bail, Result};
use clap::Args;
use serde::Serialize;
use signet_core::audit::{self, AuditFilter};

use crate::audit_helpers::materialize_receipt_for_output;
use crate::trust_helpers::{load_cli_trust_bundle, resolve_pubkeys};

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

    /// Trusted agent public key(s) for anchored verification.
    /// Accepts key names, raw base64, ed25519-prefixed keys, or .pub files.
    #[arg(long = "trusted-agent-key", value_delimiter = ',', value_name = "KEY")]
    pub trusted_agent_keys: Vec<String>,

    /// Trusted server public key(s) for v3 bilateral anchored verification.
    /// Accepts key names, raw base64, ed25519-prefixed keys, or .pub files.
    #[arg(long = "trusted-server-key", value_delimiter = ',', value_name = "KEY")]
    pub trusted_server_keys: Vec<String>,

    /// Trust bundle file (YAML or JSON) containing active trusted roots/agents/servers.
    #[arg(long)]
    pub trust_bundle: Option<String>,

    /// Export records to JSON file
    #[arg(long)]
    pub export: Option<String>,

    /// Materialize encrypted action.params during export using local identities.
    #[arg(long)]
    pub decrypt_params: bool,

    /// Build a portable signed evidence bundle directory.
    ///
    /// Produces:
    /// - `<dir>/records.jsonl` (one audit record per line)
    /// - `<dir>/manifest.json` (record count, hash range, time window, host info)
    /// - `<dir>/hash-summary.txt` (genesis + tip hash, line count, SHA-256 of records.jsonl)
    /// - `<dir>/trust-bundle.json` (optional, copied if --include-trust-bundle is set)
    ///
    /// Suitable for off-host audit handoff. Can be re-verified on another
    /// machine with `signet audit --restore <dir>`.
    #[arg(long, value_name = "DIR")]
    pub bundle: Option<String>,

    /// Include a copy of a trust bundle in the evidence bundle.
    /// Path to a trust bundle JSON/YAML.
    #[arg(long, value_name = "PATH")]
    pub include_trust_bundle: Option<String>,

    /// Re-verify a previously produced evidence bundle.
    ///
    /// Reads `<dir>/records.jsonl`, recomputes the canonical hash chain
    /// (each record's `record_hash` re-derived from its receipt + prev_hash),
    /// recomputes the SHA-256 of records.jsonl and matches manifest, and
    /// — when a `trust-bundle.json` snapshot is present, or one is supplied
    /// via `--trust-bundle` — verifies every receipt's Ed25519 signature
    /// against the trust bundle's active agent / server / root keys.
    #[arg(long, value_name = "DIR", conflicts_with_all = &["export", "bundle", "verify"])]
    pub restore: Option<String>,
}

pub fn audit(args: AuditArgs) -> Result<()> {
    if args.verify && args.export.is_some() {
        bail!("--verify and --export are mutually exclusive");
    }
    if args.decrypt_params && args.verify {
        bail!("--decrypt-params cannot be used with --verify");
    }
    if args.decrypt_params && args.export.is_none() {
        bail!("--decrypt-params requires --export");
    }
    if args.include_trust_bundle.is_some() && args.bundle.is_none() {
        bail!("--include-trust-bundle requires --bundle");
    }

    let dir = signet_core::default_signet_dir();

    if let Some(restore_path) = args.restore.as_deref() {
        return restore_bundle(restore_path, args.trust_bundle.as_deref());
    }

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
        return verify_signatures(
            &dir,
            &filter,
            &args.trusted_agent_keys,
            &args.trusted_server_keys,
            args.trust_bundle.as_deref(),
        );
    }

    if let Some(ref bundle_path) = args.bundle {
        return build_bundle(
            &dir,
            &filter,
            bundle_path,
            args.include_trust_bundle.as_deref(),
        );
    }

    if let Some(ref path) = args.export {
        return export_records(&dir, &filter, path, args.decrypt_params);
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

    println!("{:<30} {:<15} {:<30} TARGET", "TIME", "SIGNER", "TOOL");
    println!("{}", "-".repeat(90));
    for record in &records {
        let r = &record.receipt;
        let ts = r
            .get("ts")
            .or_else(|| r.get("ts_request"))
            .and_then(|v| v.as_str())
            .unwrap_or("-");
        let signer = r
            .get("signer")
            .and_then(|s| s.get("name"))
            .and_then(|n| n.as_str())
            .unwrap_or("-");
        let tool = r
            .get("action")
            .and_then(|a| a.get("tool"))
            .and_then(|t| t.as_str())
            .unwrap_or("-");
        let target = r
            .get("action")
            .and_then(|a| a.get("target"))
            .and_then(|t| t.as_str())
            .unwrap_or("-");
        println!("{:<30} {:<15} {:<30} {}", ts, signer, tool, target);
    }
    println!("\n{} records", records.len());
    Ok(())
}

fn verify_signatures(
    dir: &std::path::Path,
    filter: &AuditFilter,
    trusted_agent_keys: &[String],
    trusted_server_keys: &[String],
    trust_bundle_path: Option<&str>,
) -> Result<()> {
    let trust_bundle = match trust_bundle_path {
        Some(path) => {
            let bundle = load_cli_trust_bundle(path)?;
            eprintln!("Using trust bundle {}", bundle.describe());
            Some(bundle)
        }
        None => None,
    };

    let mut trusted_agent_pubkeys = match &trust_bundle {
        Some(bundle) => bundle.active_agent_pubkeys.clone(),
        None => Vec::new(),
    };
    trusted_agent_pubkeys.extend(resolve_pubkeys(dir, trusted_agent_keys)?);

    let mut trusted_server_pubkeys = match &trust_bundle {
        Some(bundle) => bundle.active_server_pubkeys.clone(),
        None => Vec::new(),
    };
    trusted_server_pubkeys.extend(resolve_pubkeys(dir, trusted_server_keys)?);

    let options = audit::AuditVerifyOptions {
        trusted_agent_pubkeys,
        trusted_server_pubkeys,
    };
    let result = audit::verify_signatures_with_options(dir, filter, &options)?;

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
    }

    if !result.warnings.is_empty() {
        println!("\nWarnings:");
        for w in &result.warnings {
            println!(
                "Record {} ({}:{}): {}",
                w.receipt_id, w.file, w.line, w.reason
            );
        }
    }

    if !result.failures.is_empty() {
        bail!("signature verification failed");
    }
    Ok(())
}

#[derive(Serialize)]
struct MaterializedAuditExportRecord {
    receipt: serde_json::Value,
    materialized_receipt: serde_json::Value,
    prev_hash: String,
    record_hash: String,
}

fn export_records(
    dir: &std::path::Path,
    filter: &AuditFilter,
    path: &str,
    decrypt_params: bool,
) -> Result<()> {
    let records = audit::query(dir, filter)?;
    let json = if decrypt_params {
        let exported: Vec<MaterializedAuditExportRecord> = records
            .iter()
            .map(|record| {
                Ok(MaterializedAuditExportRecord {
                    receipt: record.receipt.clone(),
                    materialized_receipt: materialize_receipt_for_output(dir, &record.receipt)?,
                    prev_hash: record.prev_hash.clone(),
                    record_hash: record.record_hash.clone(),
                })
            })
            .collect::<Result<_>>()?;
        serde_json::to_string_pretty(&exported)?
    } else {
        serde_json::to_string_pretty(&records)?
    };
    fs::write(path, json)?;
    eprintln!("Exported {} records to {path}", records.len());
    Ok(())
}

// ─── Signed evidence bundle ───────────────────────────────────────────────

#[derive(Serialize, serde::Deserialize)]
struct BundleManifest {
    /// Format version of this manifest.
    format_version: u8,
    /// Tool that produced the bundle.
    producer: String,
    /// RFC 3339 timestamp of bundle generation.
    generated_at: String,
    /// Hostname or operator-supplied identifier (best-effort).
    host: String,
    /// Number of records in records.jsonl.
    record_count: usize,
    /// First record's prev_hash. For a complete chain export this is
    /// the genesis hash; for a partial slice it's the prev_hash of the
    /// earliest record in the slice.
    chain_start_prev_hash: String,
    /// The record_hash of the last record (chain tip in this slice).
    chain_tip_record_hash: String,
    /// Earliest receipt timestamp seen, if any.
    earliest_ts: Option<String>,
    /// Latest receipt timestamp seen, if any.
    latest_ts: Option<String>,
    /// SHA-256 of the verbatim records.jsonl bytes.
    records_sha256: String,
    /// True if a trust-bundle.json snapshot was included.
    has_trust_bundle: bool,
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let h = Sha256::digest(bytes);
    hex::encode(h)
}

fn build_bundle(
    audit_dir: &std::path::Path,
    filter: &AuditFilter,
    out_dir: &str,
    include_trust_bundle: Option<&str>,
) -> Result<()> {
    let records = audit::query(audit_dir, filter)?;
    if records.is_empty() {
        bail!("no records match the filter — nothing to bundle");
    }

    // Refuse to clobber a directory that already exists with foreign content.
    // We only accept either a fresh empty directory or one that already
    // looks like a Signet bundle (i.e. the operator is rebuilding in place).
    let out = std::path::Path::new(out_dir);
    if out.exists() {
        if !out.is_dir() {
            bail!("--bundle target is not a directory: {out_dir}");
        }
        let allowed: std::collections::HashSet<&'static str> = [
            "records.jsonl",
            "manifest.json",
            "hash-summary.txt",
            "trust-bundle.json",
        ]
        .into_iter()
        .collect();
        for entry in fs::read_dir(out)? {
            let entry = entry?;
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.starts_with('.') {
                continue;
            }
            if !allowed.contains(name_str.as_ref()) {
                bail!(
                    "--bundle target {out_dir} contains foreign file '{}' — refusing to overwrite. \
                     Use a fresh directory or remove unrelated files first.",
                    name_str
                );
            }
        }
    }
    fs::create_dir_all(out)?;

    // 1) records.jsonl — one record per line, deterministic JSON encoding.
    let mut records_buf = String::new();
    for record in &records {
        records_buf.push_str(&serde_json::to_string(record)?);
        records_buf.push('\n');
    }
    let records_path = out.join("records.jsonl");
    fs::write(&records_path, &records_buf)?;

    // 2) hash-summary.txt — human-readable + machine-checkable.
    let records_sha = sha256_hex(records_buf.as_bytes());
    let earliest_ts = records
        .iter()
        .filter_map(|r| {
            audit::extract_timestamp(&r.receipt).map(|s| s.to_string())
        })
        .min();
    let latest_ts = records
        .iter()
        .filter_map(|r| {
            audit::extract_timestamp(&r.receipt).map(|s| s.to_string())
        })
        .max();
    let summary = format!(
        "signet-evidence-bundle-summary\n\
         records: {}\n\
         records.jsonl sha256: {}\n\
         chain start prev_hash: {}\n\
         chain tip record_hash: {}\n\
         earliest timestamp: {}\n\
         latest timestamp: {}\n",
        records.len(),
        records_sha,
        records[0].prev_hash,
        records.last().unwrap().record_hash,
        earliest_ts.as_deref().unwrap_or("-"),
        latest_ts.as_deref().unwrap_or("-"),
    );
    fs::write(out.join("hash-summary.txt"), &summary)?;

    // 3) Optional trust bundle copy.
    let mut has_trust_bundle = false;
    if let Some(src) = include_trust_bundle {
        let src_path = std::path::Path::new(src);
        if !src_path.exists() {
            bail!("--include-trust-bundle path does not exist: {src}");
        }
        fs::copy(src_path, out.join("trust-bundle.json"))?;
        has_trust_bundle = true;
    }

    // 4) manifest.json
    let host = hostname_best_effort();
    let manifest = BundleManifest {
        format_version: 1,
        producer: format!("signet-cli {}", env!("CARGO_PKG_VERSION")),
        generated_at: chrono::Utc::now()
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        host,
        record_count: records.len(),
        chain_start_prev_hash: records[0].prev_hash.clone(),
        chain_tip_record_hash: records.last().unwrap().record_hash.clone(),
        earliest_ts,
        latest_ts,
        records_sha256: records_sha,
        has_trust_bundle,
    };
    fs::write(
        out.join("manifest.json"),
        serde_json::to_string_pretty(&manifest)?,
    )?;

    eprintln!(
        "Bundle written to {out_dir} ({} records, sha256={})",
        records.len(),
        manifest.records_sha256
    );
    if has_trust_bundle {
        eprintln!("Trust bundle snapshot included.");
    }
    Ok(())
}

fn hostname_best_effort() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}

fn restore_bundle(in_dir: &str, override_trust_bundle: Option<&str>) -> Result<()> {
    let dir = std::path::Path::new(in_dir);
    if !dir.is_dir() {
        bail!("--restore path is not a directory: {in_dir}");
    }
    let manifest_path = dir.join("manifest.json");
    let records_path = dir.join("records.jsonl");
    if !manifest_path.exists() {
        bail!("missing manifest.json in {in_dir}");
    }
    if !records_path.exists() {
        bail!("missing records.jsonl in {in_dir}");
    }

    let manifest: BundleManifest = serde_json::from_str(&fs::read_to_string(&manifest_path)?)
        .map_err(|e| anyhow::anyhow!("failed to parse manifest.json: {e}"))?;
    if manifest.format_version != 1 {
        bail!(
            "unsupported bundle format_version: {} (this CLI understands version 1)",
            manifest.format_version
        );
    }

    let records_bytes = fs::read(&records_path)?;
    let records_sha = sha256_hex(&records_bytes);
    if records_sha != manifest.records_sha256 {
        bail!(
            "records.jsonl sha256 mismatch: manifest={}, actual={}",
            manifest.records_sha256,
            records_sha
        );
    }

    // Resolve trust bundle to use for signature verification, in priority:
    //   1. Explicit --trust-bundle override
    //   2. <dir>/trust-bundle.json snapshot (if manifest claims has_trust_bundle)
    //   3. None — chain integrity verified, signatures NOT verified
    let trust_bundle_path: Option<std::path::PathBuf> = if let Some(p) = override_trust_bundle {
        Some(std::path::PathBuf::from(p))
    } else if manifest.has_trust_bundle {
        let p = dir.join("trust-bundle.json");
        if !p.exists() {
            bail!(
                "manifest claims has_trust_bundle but {} is missing",
                p.display()
            );
        }
        Some(p)
    } else {
        None
    };
    let trust_bundle = match trust_bundle_path.as_ref() {
        Some(p) => Some(crate::trust_helpers::load_cli_trust_bundle(
            p.to_str().unwrap_or_default(),
        )?),
        None => None,
    };

    // Parse records and replay the hash chain. Recompute record_hash from
    // (prev_hash, receipt) so a forged record_hash field is detected.
    let records_str = std::str::from_utf8(&records_bytes)
        .map_err(|e| anyhow::anyhow!("records.jsonl is not UTF-8: {e}"))?;
    let mut count = 0usize;
    let mut prev_hash: Option<String> = None;
    let mut last_record_hash: Option<String> = None;
    let mut sig_verified = 0usize;
    let mut sig_skipped = 0usize;
    for (lineno, line) in records_str.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let record: signet_core::audit::AuditRecord =
            serde_json::from_str(line).map_err(|e| {
                anyhow::anyhow!("records.jsonl line {} invalid JSON: {e}", lineno + 1)
            })?;

        // 1. Chain shape: prev_hash matches previous record_hash.
        if let Some(ref expected) = prev_hash {
            if &record.prev_hash != expected {
                bail!(
                    "chain break at line {}: expected prev_hash {}, got {}",
                    lineno + 1,
                    expected,
                    record.prev_hash
                );
            }
        }

        // 2. Re-derive record_hash from (prev_hash, receipt). Detects
        //    tampering with the receipt that didn't update record_hash.
        let recomputed = signet_core::audit::compute_record_hash(
            &record.receipt,
            &record.prev_hash,
        )
        .map_err(|e| anyhow::anyhow!("line {}: hash compute failed: {e}", lineno + 1))?;
        if recomputed != record.record_hash {
            bail!(
                "record_hash mismatch at line {}: stored={}, recomputed={} (receipt was tampered)",
                lineno + 1,
                record.record_hash,
                recomputed
            );
        }

        // 3. If a trust bundle is available, re-verify the receipt's
        //    Ed25519 signature against the trust bundle.
        if let Some(ref tb) = trust_bundle {
            verify_audit_receipt_against_bundle(&record.receipt, tb, lineno + 1)?;
            sig_verified += 1;
        } else {
            sig_skipped += 1;
        }

        prev_hash = Some(record.record_hash.clone());
        last_record_hash = Some(record.record_hash.clone());
        count += 1;
    }
    if count != manifest.record_count {
        bail!(
            "record_count mismatch: manifest={}, jsonl={}",
            manifest.record_count,
            count
        );
    }
    if last_record_hash.as_deref() != Some(manifest.chain_tip_record_hash.as_str()) {
        bail!(
            "chain tip mismatch: manifest={}, jsonl={}",
            manifest.chain_tip_record_hash,
            last_record_hash.unwrap_or_default()
        );
    }

    println!("Bundle valid:");
    println!("  records:           {}", count);
    println!("  records.jsonl sha: {}", records_sha);
    println!("  chain tip:         {}", manifest.chain_tip_record_hash);
    println!("  generated at:      {}", manifest.generated_at);
    println!("  producer:          {}", manifest.producer);
    println!("  host:              {}", manifest.host);
    if trust_bundle.is_some() {
        println!(
            "  signatures:        {}/{} verified against trust bundle",
            sig_verified,
            sig_verified + sig_skipped
        );
    } else {
        println!(
            "  signatures:        SKIPPED ({} records). Re-run with --trust-bundle <path> \
             or include a trust-bundle.json snapshot in the bundle to verify Ed25519 \
             signatures.",
            sig_skipped
        );
    }
    if manifest.has_trust_bundle {
        println!(
            "  trust-bundle.json: {}",
            if dir.join("trust-bundle.json").exists() {
                "present"
            } else {
                "MISSING (manifest claims included)"
            }
        );
    }
    Ok(())
}

fn verify_audit_receipt_against_bundle(
    raw: &serde_json::Value,
    bundle: &crate::trust_helpers::LoadedTrustBundle,
    lineno: usize,
) -> Result<()> {
    let version = raw.get("v").and_then(|v| v.as_u64()).unwrap_or(1);
    let receipt_str = serde_json::to_string(raw)
        .map_err(|e| anyhow::anyhow!("line {lineno}: re-serialize failed: {e}"))?;
    match version {
        1 | 2 | 4 => {
            let signer_pubkey = raw
                .get("signer")
                .and_then(|s| s.get("pubkey"))
                .and_then(|p| p.as_str())
                .ok_or_else(|| anyhow::anyhow!("line {lineno}: missing signer.pubkey"))?;
            let vk = bundle
                .find_active_agent_key(signer_pubkey)?
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "line {lineno}: untrusted signer pubkey: {signer_pubkey}"
                    )
                })?;
            signet_core::verify_any(&receipt_str, &vk).map_err(|e| {
                anyhow::anyhow!("line {lineno}: signature verification failed: {e}")
            })
        }
        3 => {
            // Bilateral: verify against the trust-bundle server pubkey.
            let server_pubkey = raw
                .get("server")
                .and_then(|s| s.get("pubkey"))
                .and_then(|p| p.as_str())
                .ok_or_else(|| anyhow::anyhow!("line {lineno}: missing server.pubkey"))?;
            let vk = bundle
                .find_active_server_key(server_pubkey)?
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "line {lineno}: untrusted server pubkey: {server_pubkey}"
                    )
                })?;
            // Forensic re-verification: signature still required, but
            // disable time window, nonce replay, AND embedded-agent `exp`
            // checks (historical receipts may have expired).
            let opts = signet_core::BilateralVerifyOptions::forensic();
            let bilateral: signet_core::BilateralReceipt =
                serde_json::from_str(&receipt_str).map_err(|e| {
                    anyhow::anyhow!("line {lineno}: parse v3: {e}")
                })?;
            signet_core::verify_bilateral_with_options(&bilateral, &vk, &opts).map_err(
                |e| anyhow::anyhow!("line {lineno}: bilateral verify failed: {e}"),
            )
        }
        v => bail!("line {lineno}: unsupported receipt version: {v}"),
    }
}
