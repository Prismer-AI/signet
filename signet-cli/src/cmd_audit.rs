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
        return verify_signatures(
            &dir,
            &filter,
            &args.trusted_agent_keys,
            &args.trusted_server_keys,
            args.trust_bundle.as_deref(),
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
