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
