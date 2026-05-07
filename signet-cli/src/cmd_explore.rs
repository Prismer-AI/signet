use std::path::Path;

use anyhow::{bail, Result};
use clap::Args;
use signet_core::audit::{self, AuditFilter, AuditRecord};

use crate::audit_helpers::{has_encrypted_params, materialize_receipt_for_output};

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

    /// Materialize encrypted action.params using local identities (with --show).
    #[arg(long)]
    pub decrypt_params: bool,

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
    if args.decrypt_params && args.show.is_none() {
        bail!("--decrypt-params requires --show");
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
        return show_receipt(&dir, records[idx - 1], args.full, args.decrypt_params);
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
        " {:<4} {:<19} {:<12} {:<19} {:<15} {:<20} {:<10}",
        "#", "TIME", "TYPE", "STATUS", "SIGNER", "TOOL", "CHAIN"
    );
    println!(" {}", "─".repeat(111));

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
        let record_type = display_record_type(r);
        let status = display_record_status(r);

        let chain_ok = if record.prev_hash == "genesis" {
            "genesis"
        } else {
            "linked"
        };

        println!(
            " {:<4} {:<19} {:<12} {:<19} {:<15} {:<20} {:<10}",
            idx,
            ts,
            record_type,
            truncate(status, 18),
            truncate(signer, 14),
            truncate(tool, 19),
            chain_ok,
        );
    }
}

fn show_receipt(dir: &Path, record: &AuditRecord, full: bool, decrypt_params: bool) -> Result<()> {
    let materialized = if decrypt_params {
        Some(materialize_receipt_for_output(dir, &record.receipt)?)
    } else {
        None
    };
    let r = materialized.as_ref().unwrap_or(&record.receipt);

    if full {
        println!("{}", serde_json::to_string_pretty(r)?);
        return Ok(());
    }

    if audit::extract_record_type(r) == "policy_violation" {
        return show_policy_violation(record);
    }

    // Compact view
    let version = r.get("v").and_then(|v| v.as_u64()).unwrap_or(0);
    let id = r.get("id").and_then(|v| v.as_str()).unwrap_or("-");
    let ts = audit::extract_timestamp(r).unwrap_or("-");
    let signer_name = audit::extract_signer_name(r).unwrap_or("-");
    let tool = audit::extract_tool(r).unwrap_or("-");

    let sig = r.get("sig").and_then(|v| v.as_str()).unwrap_or("-");
    let agent_sig = r
        .get("agent_receipt")
        .and_then(|agent| agent.get("sig"))
        .and_then(|sig| sig.as_str());
    let pubkey = r
        .get("signer")
        .and_then(|s| s.get("pubkey"))
        .and_then(|p| p.as_str())
        .or_else(|| {
            r.get("agent_receipt")
                .and_then(|agent| agent.get("signer"))
                .and_then(|signer| signer.get("pubkey"))
                .and_then(|pubkey| pubkey.as_str())
        })
        .unwrap_or("-");
    let params_hash = r
        .get("action")
        .and_then(|a| a.get("params_hash"))
        .and_then(|h| h.as_str())
        .or_else(|| {
            r.get("agent_receipt")
                .and_then(|agent| agent.get("action"))
                .and_then(|action| action.get("params_hash"))
                .and_then(|hash| hash.as_str())
        })
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
    if let Some(server_name) = r
        .get("server")
        .and_then(|server| server.get("name"))
        .and_then(|name| name.as_str())
    {
        if let Some(agent_sig) = agent_sig {
            println!("│ Agent sig:   {}...", truncate(agent_sig, 36));
        }
        println!("│ Agent key:   {}...", truncate(pubkey, 36));
        let server_pubkey = r
            .get("server")
            .and_then(|server| server.get("pubkey"))
            .and_then(|pubkey| pubkey.as_str())
            .unwrap_or("-");
        println!("│ Server:      {}", server_name);
        println!("│ Server sig:  {}...", truncate(sig, 36));
        println!("│ Server key:  {}...", truncate(server_pubkey, 36));
    } else {
        println!("│ Signature:   {}...", truncate(sig, 36));
        println!("│ Public key:  {}...", truncate(pubkey, 36));
    }

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

    if let Some(outcome) = r
        .get("response")
        .and_then(|response| response.get("outcome"))
    {
        println!("├─────────────────────────────────────────────────────┤");
        println!("│ Outcome                                             │");
        let status = outcome
            .get("status")
            .and_then(|status| status.as_str())
            .unwrap_or("-");
        println!("│ Status:      {}", status);
        if let Some(reason) = outcome.get("reason").and_then(|reason| reason.as_str()) {
            println!("│ Reason:      {}", reason);
        }
        if let Some(error) = outcome.get("error").and_then(|error| error.as_str()) {
            println!("│ Error:       {}", error);
        }
        if let Some(content_hash) = r
            .get("response")
            .and_then(|response| response.get("content_hash"))
            .and_then(|hash| hash.as_str())
        {
            println!("│ Content hash: {}", truncate(content_hash, 39));
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
        if let Some(parent) = extract_parent_receipt_id(r) {
            println!("│ Parent:      {}", truncate(parent, 40));
        }
    }

    // Chain info
    println!("├─────────────────────────────────────────────────────┤");
    println!("│ Chain                                               │");
    println!("│ Prev hash:   {}", truncate(&record.prev_hash, 40));
    println!("│ Record hash: {}", truncate(&record.record_hash, 40));
    println!("└─────────────────────────────────────────────────────┘");

    if has_encrypted_params(&record.receipt) && !decrypt_params {
        println!("\nEncrypted params present. Re-run with --decrypt-params to materialize action.params.");
    }

    if decrypt_params {
        if let Some(params) = r.get("action").and_then(|action| action.get("params")) {
            println!("\nDecrypted params");
            println!("────────────────");
            println!("{}", serde_json::to_string_pretty(params)?);
        }
    }

    println!("\nUse --full for raw JSON.");
    Ok(())
}

fn show_policy_violation(record: &AuditRecord) -> Result<()> {
    let r = &record.receipt;
    let ts = audit::extract_timestamp(r).unwrap_or("-");
    let agent = audit::extract_signer_name(r).unwrap_or("-");
    let tool = audit::extract_tool(r).unwrap_or("-");
    let target = r
        .get("action")
        .and_then(|action| action.get("target"))
        .and_then(|target| target.as_str())
        .unwrap_or("-");
    let params_hash = r
        .get("action")
        .and_then(|action| action.get("params_hash"))
        .and_then(|hash| hash.as_str())
        .unwrap_or("-");
    let decision = r
        .get("decision")
        .and_then(|value| value.as_str())
        .unwrap_or("-");
    let status = normalize_policy_status(decision);
    let reason = r
        .get("reason")
        .and_then(|value| value.as_str())
        .unwrap_or("-");
    let policy = r
        .get("policy")
        .and_then(|value| value.as_str())
        .unwrap_or("-");
    let policy_hash = r
        .get("policy_hash")
        .and_then(|value| value.as_str())
        .unwrap_or("-");

    println!("┌─────────────────────────────────────────────────────┐");
    println!("│ Policy Violation                                    │");
    println!("├─────────────────────────────────────────────────────┤");
    println!("│ Timestamp:   {}", ts);
    println!("│ Agent:       {}", agent);
    println!("│ Tool:        {}", tool);
    println!("│ Target:      {}", target);
    println!("│ Status:      {}", status);
    println!("│ Decision:    {}", decision);
    println!("│ Reason:      {}", reason);
    println!("│ Policy:      {}", policy);
    println!("│ Policy hash: {}", truncate(policy_hash, 40));
    println!("│ Params hash: {}", truncate(params_hash, 40));
    if let Some(rules) = r.get("matched_rules").and_then(|value| value.as_array()) {
        let rule_names: Vec<&str> = rules.iter().filter_map(|rule| rule.as_str()).collect();
        if !rule_names.is_empty() {
            println!("│ Rules:       {}", rule_names.join(", "));
        }
    }
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
    if !verify_result.warnings.is_empty() {
        println!("\nSignature warnings:");
        for w in &verify_result.warnings {
            println!("  {} ({}:{}): {}", w.receipt_id, w.file, w.line, w.reason);
        }
    }
    if !verify_result.failures.is_empty() {
        println!("\nSignature failures:");
        for f in &verify_result.failures {
            println!("  {} ({}:{}): {}", f.receipt_id, f.file, f.line, f.reason);
        }
    }

    Ok(())
}

fn show_stats(records: &[&AuditRecord]) -> Result<()> {
    use std::collections::HashMap;

    let mut tool_counts: HashMap<String, usize> = HashMap::new();
    let mut signer_counts: HashMap<String, usize> = HashMap::new();
    let mut record_type_counts: HashMap<String, usize> = HashMap::new();
    let mut outcome_counts: HashMap<String, usize> = HashMap::new();
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

        let record_type = audit::extract_record_type(r).to_string();
        *record_type_counts.entry(record_type).or_insert(0) += 1;

        if let Some(version) = r.get("v").and_then(|v| v.as_u64()) {
            *version_counts.entry(version).or_insert(0) += 1;
        }

        if let Some(status) = audit::extract_outcome_status(r) {
            *outcome_counts.entry(status.to_string()).or_insert(0) += 1;
        }

        if let Some(decision) = audit::extract_policy_decision(r) {
            *policy_decisions.entry(decision.to_string()).or_insert(0) += 1;
        }

        if let Some(tid) = extract_trace_id(r) {
            trace_ids.insert(tid.to_string());
        }
    }

    println!("Audit Record Statistics");
    println!("───────────────────────");
    println!("Total records: {}", records.len());
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

    println!("\nBy record type:");
    let mut record_types: Vec<_> = record_type_counts.into_iter().collect();
    record_types.sort_by_key(|item| std::cmp::Reverse(item.1));
    for (record_type, count) in &record_types {
        println!("  {:<30} {}", record_type, count);
    }

    if !outcome_counts.is_empty() {
        println!("\nBy outcome:");
        let mut outcomes: Vec<_> = outcome_counts.into_iter().collect();
        outcomes.sort_by_key(|item| std::cmp::Reverse(item.1));
        for (status, count) in &outcomes {
            println!("  {:<30} {}", status, count);
        }
    }

    if !policy_decisions.is_empty() {
        println!("\nPolicy gate decisions:");
        let mut decisions: Vec<_> = policy_decisions.into_iter().collect();
        decisions.sort_by_key(|item| std::cmp::Reverse(item.1));
        for (decision, count) in &decisions {
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
        .or_else(|| {
            receipt
                .get("agent_receipt")
                .and_then(|agent| agent.get("action"))
                .and_then(|action| action.get("trace_id"))
                .and_then(|trace| trace.as_str())
        })
}

fn extract_parent_receipt_id(receipt: &serde_json::Value) -> Option<&str> {
    receipt
        .get("action")
        .and_then(|a| a.get("parent_receipt_id"))
        .and_then(|p| p.as_str())
        .or_else(|| {
            receipt
                .get("agent_receipt")
                .and_then(|agent| agent.get("action"))
                .and_then(|action| action.get("parent_receipt_id"))
                .and_then(|parent| parent.as_str())
        })
}

fn display_record_type(receipt: &serde_json::Value) -> &'static str {
    match audit::extract_record_type(receipt) {
        "policy_violation" => "policy",
        _ => match receipt
            .get("v")
            .and_then(|value| value.as_u64())
            .unwrap_or(0)
        {
            1 => "v1",
            2 => "v2",
            3 => "v3",
            4 => "v4",
            _ => "?",
        },
    }
}

fn display_record_status(receipt: &serde_json::Value) -> &str {
    audit::extract_outcome_status(receipt)
        .or_else(|| {
            if audit::extract_record_type(receipt) == "policy_violation" {
                receipt
                    .get("decision")
                    .and_then(|decision| decision.as_str())
                    .map(normalize_policy_status)
            } else {
                None
            }
        })
        .unwrap_or("intent")
}

fn normalize_policy_status(decision: &str) -> &str {
    match decision {
        "deny" => "rejected",
        "require_approval" => "requires_approval",
        other => other,
    }
}

fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        s
    } else {
        &s[..max]
    }
}
