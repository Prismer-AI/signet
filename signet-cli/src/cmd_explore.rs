use std::path::Path;

use anyhow::{bail, Result};
use clap::Args;
use signet_core::audit::{self, AuditFilter, AuditRecord};

#[derive(Args)]
pub struct ExploreArgs {
    /// Filter by time (e.g. 1h, 24h, 7d)
    #[arg(long)]
    pub since: Option<String>,

    /// Filter by tool name (substring match)
    #[arg(long)]
    pub tool: Option<String>,

    /// Filter by signer name
    #[arg(long)]
    pub signer: Option<String>,

    /// Show receipt at index (1-based) from the results
    #[arg(long)]
    pub show: Option<usize>,

    /// Show last N receipts (default: 20)
    #[arg(long, default_value = "20")]
    pub tail: usize,

    /// Show full receipt JSON (with --show)
    #[arg(long)]
    pub full: bool,

    /// Show chain status summary
    #[arg(long)]
    pub chain: bool,

    /// Show statistics summary
    #[arg(long)]
    pub stats: bool,

    /// Show receipts for a specific trace_id
    #[arg(long)]
    pub trace: Option<String>,
}

pub fn explore(args: ExploreArgs) -> Result<()> {
    let dir = signet_core::default_signet_dir();

    if args.chain {
        return show_chain_status(&dir);
    }

    let filter = AuditFilter {
        since: match &args.since {
            Some(s) => Some(audit::parse_since(s)?),
            None => None,
        },
        tool: args.tool.clone(),
        signer: args.signer.clone(),
        limit: None,
    };

    let records = audit::query(&dir, &filter)?;

    if records.is_empty() {
        println!("No receipts found.");
        return Ok(());
    }

    // Filter by trace_id if specified
    let records: Vec<&AuditRecord> = if let Some(ref trace_id) = args.trace {
        records
            .iter()
            .filter(|r| {
                extract_trace_id(&r.receipt)
                    .map(|t| t == trace_id)
                    .unwrap_or(false)
            })
            .collect()
    } else {
        records.iter().collect()
    };

    if records.is_empty() {
        println!("No receipts found matching filters.");
        return Ok(());
    }

    if args.stats {
        return show_stats(&records);
    }

    if let Some(idx) = args.show {
        if idx == 0 || idx > records.len() {
            bail!("--show index out of range (1-{})", records.len());
        }
        return show_receipt(records[idx - 1], args.full);
    }

    // Default: show last N as table
    let start = if records.len() > args.tail {
        records.len() - args.tail
    } else {
        0
    };
    let slice = &records[start..];

    print_table(slice, start + 1);

    println!(
        "\n{} receipts shown (of {} total). Use --show N for details.",
        slice.len(),
        records.len()
    );

    Ok(())
}

fn print_table(records: &[&AuditRecord], start_idx: usize) {
    println!(
        " {:<4} {:<22} {:<15} {:<25} {:<10} {:<12}",
        "#", "TIME", "SIGNER", "TOOL", "VERSION", "CHAIN"
    );
    println!(" {}", "─".repeat(92));

    for (i, record) in records.iter().enumerate() {
        let r = &record.receipt;
        let idx = start_idx + i;

        let ts = audit::extract_timestamp(r)
            .map(|t| {
                // Shorten: "2026-04-19T10:30:00Z" → "04-19 10:30:00"
                if t.len() >= 19 {
                    format!("{} {}", &t[5..10], &t[11..19])
                } else {
                    t.to_string()
                }
            })
            .unwrap_or_else(|| "-".to_string());

        let signer = audit::extract_signer_name(r).unwrap_or("-");
        let tool = audit::extract_tool(r).unwrap_or("-");
        let version = r.get("v").and_then(|v| v.as_u64()).unwrap_or(0);
        let version_label = match version {
            1 => "v1",
            2 => "v2 compound",
            3 => "v3 bilateral",
            4 => "v4 delegated",
            _ => "?",
        };

        let chain_ok = if record.prev_hash == "genesis" {
            "genesis"
        } else {
            "linked"
        };

        println!(
            " {:<4} {:<22} {:<15} {:<25} {:<10} {:<12}",
            idx,
            ts,
            truncate(signer, 14),
            truncate(tool, 24),
            version_label,
            chain_ok,
        );
    }
}

fn show_receipt(record: &AuditRecord, full: bool) -> Result<()> {
    let r = &record.receipt;

    if full {
        println!("{}", serde_json::to_string_pretty(r)?);
        return Ok(());
    }

    // Compact view
    let version = r.get("v").and_then(|v| v.as_u64()).unwrap_or(0);
    let id = r.get("id").and_then(|v| v.as_str()).unwrap_or("-");
    let ts = audit::extract_timestamp(r).unwrap_or("-");
    let signer_name = audit::extract_signer_name(r).unwrap_or("-");
    let tool = audit::extract_tool(r).unwrap_or("-");

    let sig = r.get("sig").and_then(|v| v.as_str()).unwrap_or("-");
    let pubkey = r
        .get("signer")
        .and_then(|s| s.get("pubkey"))
        .and_then(|p| p.as_str())
        .unwrap_or("-");
    let params_hash = r
        .get("action")
        .and_then(|a| a.get("params_hash"))
        .and_then(|h| h.as_str())
        .unwrap_or("-");
    let nonce = r.get("nonce").and_then(|v| v.as_str()).unwrap_or("-");

    println!("┌─────────────────────────────────────────────────────┐");
    println!("│ Receipt Details                                     │");
    println!("├─────────────────────────────────────────────────────┤");
    println!("│ ID:          {}", truncate(id, 40));
    println!("│ Version:     v{}", version);
    println!("│ Timestamp:   {}", ts);
    println!("│ Signer:      {}", signer_name);
    println!("│ Tool:        {}", tool);
    println!("│ Params hash: {}", truncate(params_hash, 40));
    println!("│ Nonce:       {}", truncate(nonce, 40));
    println!("│ Signature:   {}...", truncate(sig, 36));
    println!("│ Public key:  {}...", truncate(pubkey, 36));

    // Policy attestation
    if let Some(policy) = r.get("policy") {
        println!("├─────────────────────────────────────────────────────┤");
        println!("│ Policy Attestation                                  │");
        let decision = policy
            .get("decision")
            .and_then(|d| d.as_str())
            .unwrap_or("-");
        let policy_hash = policy
            .get("policy_hash")
            .and_then(|h| h.as_str())
            .unwrap_or("-");
        println!("│ Decision:    {}", decision);
        println!("│ Policy hash: {}", truncate(policy_hash, 40));
        if let Some(rules) = policy.get("matched_rules").and_then(|r| r.as_array()) {
            let rule_names: Vec<&str> = rules.iter().filter_map(|r| r.as_str()).collect();
            println!("│ Rules:       {}", rule_names.join(", "));
        }
    }

    // Expiration
    if let Some(exp) = r.get("exp").and_then(|e| e.as_str()) {
        println!("│ Expires:     {}", exp);
    }

    // Trace correlation
    if let Some(trace_id) = extract_trace_id(r) {
        println!("├─────────────────────────────────────────────────────┤");
        println!("│ Trace Correlation                                   │");
        println!("│ Trace ID:    {}", truncate(trace_id, 40));
        if let Some(parent) = r
            .get("action")
            .and_then(|a| a.get("parent_receipt_id"))
            .and_then(|p| p.as_str())
        {
            println!("│ Parent:      {}", truncate(parent, 40));
        }
    }

    // Chain info
    println!("├─────────────────────────────────────────────────────┤");
    println!("│ Chain                                               │");
    println!("│ Prev hash:   {}", truncate(&record.prev_hash, 40));
    println!("│ Record hash: {}", truncate(&record.record_hash, 40));
    println!("└─────────────────────────────────────────────────────┘");

    println!("\nUse --full for raw JSON.");
    Ok(())
}

fn show_chain_status(dir: &Path) -> Result<()> {
    let status = audit::verify_chain(dir)?;

    println!("Chain Status");
    println!("────────────");
    println!("Total records: {}", status.total_records);
    println!(
        "Integrity:     {}",
        if status.valid { "INTACT" } else { "BROKEN" }
    );

    if let Some(bp) = &status.break_point {
        println!("\nChain break detected:");
        println!("  File:     {}", bp.file);
        println!("  Line:     {}", bp.line);
        println!("  Expected: {}", truncate(&bp.expected_hash, 40));
        println!("  Actual:   {}", truncate(&bp.actual_hash, 40));
    }

    // Also show signature verification
    let filter = AuditFilter::default();
    let verify_result = audit::verify_signatures(dir, &filter)?;
    println!(
        "Signatures:    {}/{} valid",
        verify_result.valid, verify_result.total
    );
    if !verify_result.failures.is_empty() {
        println!("\nSignature failures:");
        for f in &verify_result.failures {
            println!("  {} ({}): {}", f.receipt_id, f.file, f.reason);
        }
    }

    Ok(())
}

fn show_stats(records: &[&AuditRecord]) -> Result<()> {
    use std::collections::HashMap;

    let mut tool_counts: HashMap<String, usize> = HashMap::new();
    let mut signer_counts: HashMap<String, usize> = HashMap::new();
    let mut version_counts: HashMap<u64, usize> = HashMap::new();
    let mut policy_decisions: HashMap<String, usize> = HashMap::new();
    let mut trace_ids: std::collections::HashSet<String> = std::collections::HashSet::new();

    for record in records {
        let r = &record.receipt;

        let tool = audit::extract_tool(r).unwrap_or("unknown").to_string();
        *tool_counts.entry(tool).or_insert(0) += 1;

        let signer = audit::extract_signer_name(r)
            .unwrap_or("unknown")
            .to_string();
        *signer_counts.entry(signer).or_insert(0) += 1;

        let version = r.get("v").and_then(|v| v.as_u64()).unwrap_or(0);
        *version_counts.entry(version).or_insert(0) += 1;

        if let Some(policy) = r.get("policy") {
            let decision = policy
                .get("decision")
                .and_then(|d| d.as_str())
                .unwrap_or("unknown")
                .to_string();
            *policy_decisions.entry(decision).or_insert(0) += 1;
        }

        if let Some(tid) = extract_trace_id(r) {
            trace_ids.insert(tid.to_string());
        }
    }

    println!("Receipt Statistics");
    println!("──────────────────");
    println!("Total receipts: {}", records.len());
    println!("Unique traces:  {}", trace_ids.len());
    println!();

    println!("By tool:");
    let mut tools: Vec<_> = tool_counts.into_iter().collect();
    tools.sort_by_key(|b| std::cmp::Reverse(b.1));
    for (tool, count) in &tools {
        println!("  {:<30} {}", tool, count);
    }

    println!("\nBy signer:");
    let mut signers: Vec<_> = signer_counts.into_iter().collect();
    signers.sort_by_key(|b| std::cmp::Reverse(b.1));
    for (signer, count) in &signers {
        println!("  {:<30} {}", signer, count);
    }

    println!("\nBy version:");
    let mut versions: Vec<_> = version_counts.into_iter().collect();
    versions.sort_by_key(|v| v.0);
    for (v, count) in &versions {
        let label = match v {
            1 => "v1 (unilateral)",
            2 => "v2 (compound)",
            3 => "v3 (bilateral)",
            4 => "v4 (delegated)",
            _ => "unknown",
        };
        println!("  {:<30} {}", label, count);
    }

    if !policy_decisions.is_empty() {
        println!("\nPolicy decisions:");
        for (decision, count) in &policy_decisions {
            println!("  {:<30} {}", decision, count);
        }
    }

    Ok(())
}

fn extract_trace_id(receipt: &serde_json::Value) -> Option<&str> {
    receipt
        .get("action")
        .and_then(|a| a.get("trace_id"))
        .and_then(|t| t.as_str())
}

fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        s
    } else {
        &s[..max]
    }
}
