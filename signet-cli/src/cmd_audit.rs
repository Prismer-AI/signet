use std::fs;

use anyhow::{bail, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use clap::Args;
use ed25519_dalek::VerifyingKey;
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

    /// Trusted agent public key(s) for anchored verification.
    /// Accepts key names, raw base64, ed25519-prefixed keys, or .pub files.
    #[arg(long = "trusted-agent-key", value_delimiter = ',', value_name = "KEY")]
    pub trusted_agent_keys: Vec<String>,

    /// Trusted server public key(s) for v3 bilateral anchored verification.
    /// Accepts key names, raw base64, ed25519-prefixed keys, or .pub files.
    #[arg(long = "trusted-server-key", value_delimiter = ',', value_name = "KEY")]
    pub trusted_server_keys: Vec<String>,

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
        return verify_signatures(
            &dir,
            &filter,
            &args.trusted_agent_keys,
            &args.trusted_server_keys,
        );
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

fn resolve_pubkey(dir: &std::path::Path, key_ref: &str) -> Result<VerifyingKey> {
    let key_path = std::path::Path::new(key_ref);
    if key_ref.ends_with(".pub") || key_path.exists() {
        let content = fs::read_to_string(key_ref)?;
        let pub_file: signet_core::keystore::PubKeyFile = serde_json::from_str(&content)?;
        let b64 = pub_file
            .pubkey
            .strip_prefix("ed25519:")
            .unwrap_or(&pub_file.pubkey);
        let bytes = BASE64.decode(b64)?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("pubkey is not 32 bytes"))?;
        return Ok(VerifyingKey::from_bytes(&arr)?);
    }

    if let Ok(vk) = signet_core::load_verifying_key(dir, key_ref) {
        return Ok(vk);
    }

    let b64 = key_ref.strip_prefix("ed25519:").unwrap_or(key_ref);
    let bytes = BASE64
        .decode(b64)
        .map_err(|e| anyhow::anyhow!("'{}' is not a key name or valid base64: {}", key_ref, e))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("pubkey is not 32 bytes"))?;
    Ok(VerifyingKey::from_bytes(&arr)?)
}

fn resolve_pubkeys(dir: &std::path::Path, key_refs: &[String]) -> Result<Vec<VerifyingKey>> {
    key_refs.iter().map(|key| resolve_pubkey(dir, key)).collect()
}

fn verify_signatures(
    dir: &std::path::Path,
    filter: &AuditFilter,
    trusted_agent_keys: &[String],
    trusted_server_keys: &[String],
) -> Result<()> {
    let options = audit::AuditVerifyOptions {
        trusted_agent_pubkeys: resolve_pubkeys(dir, trusted_agent_keys)?,
        trusted_server_pubkeys: resolve_pubkeys(dir, trusted_server_keys)?,
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

fn export_records(dir: &std::path::Path, filter: &AuditFilter, path: &str) -> Result<()> {
    let records = audit::query(dir, filter)?;
    let json = serde_json::to_string_pretty(&records)?;
    fs::write(path, json)?;
    eprintln!("Exported {} records to {path}", records.len());
    Ok(())
}
