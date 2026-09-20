use std::fs;
use std::path::Path;

use anyhow::{bail, Result};
use clap::Args;
use signet_core::receipt::Action;
use signet_core::{CanonicalIntent, DecisionBasis, DecisionType};

/// `signet authorize` — authority-side pre-authorization of one intent
/// (spec §3.5, two-step flow). Produces a signed AuthorizationDecision the
/// agent consumes later with `signet sign --decision <file>`.
#[derive(Args)]
pub struct AuthorizeArgs {
    /// Authority key name (from keystore)
    #[arg(long)]
    pub key: String,
    /// Authority principal URI (e.g. agent://prismer/security)
    #[arg(long)]
    pub authority: String,
    /// Subject principal URI — the agent being authorized (e.g. agent://prismer/deploy-bot)
    #[arg(long)]
    pub subject: String,
    /// Tool name
    #[arg(long)]
    pub tool: String,
    /// Params JSON (inline or @file)
    #[arg(long, default_value = "{}")]
    pub params: String,
    /// Target URI
    #[arg(long)]
    pub target: String,
    /// Transport (normalized to lowercase in the intent hash)
    #[arg(long, default_value = "stdio")]
    pub transport: String,
    /// Policy file (YAML/JSON) — the decision's basis; must evaluate to allow
    #[arg(long)]
    pub policy: String,
    /// Time-to-live for the decision (e.g. 30m, 1h, 24h)
    #[arg(long)]
    pub ttl: Option<String>,
    /// Max uses for the decision (becomes a call_count constraint)
    #[arg(long)]
    pub max_calls: Option<u64>,
    /// Credential reference claim (grant://… — stored verbatim, never resolved)
    #[arg(long)]
    pub credential_ref: Option<String>,
    /// Output file (default: stdout)
    #[arg(long)]
    pub output: Option<String>,
}

pub fn authorize(args: AuthorizeArgs) -> Result<()> {
    let dir = signet_core::default_signet_dir();
    let info = signet_core::load_key_info(&dir, &args.key)?;

    let sk = crate::load_signing_key_with_prompt(&dir, &args.key, "Enter passphrase: ")?;

    let params_str = if let Some(path) = args.params.strip_prefix('@') {
        fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("failed to read params file '{path}': {e}"))?
    } else {
        args.params
    };
    let params: serde_json::Value = serde_json::from_str(&params_str)?;

    let action = Action {
        tool: args.tool.clone(),
        params,
        params_hash: String::new(),
        target: args.target.clone(),
        transport: args.transport.clone(),
        session: None,
        call_id: None,
        response_hash: None,
        trace_id: None,
        parent_receipt_id: None,
    };

    // The policy is the basis — it must allow, and its obligations bind.
    let policy = signet_core::load_policy(Path::new(&args.policy))?;
    let eval = signet_core::evaluate_policy(&action, &info.name, &policy, None)?;
    match eval.decision {
        signet_core::RuleAction::Allow => {}
        signet_core::RuleAction::Deny => {
            bail!("policy violation: {}", eval.reason);
        }
        signet_core::RuleAction::RequireApproval => {
            bail!("requires approval: {}", eval.reason);
        }
    }

    let expires_at = args.ttl.as_deref().map(crate::parse_ttl).transpose()?;

    let mut constraints = Vec::new();
    if let Some(max_calls) = args.max_calls {
        constraints.push(signet_core::Constraint::CallCount { max_calls });
    }

    let intent = CanonicalIntent::from_action(&action)?;
    let decision = signet_core::authorize(
        &sk,
        &args.authority,
        &args.subject,
        &intent,
        DecisionType::Allow,
        DecisionBasis::Policy {
            policy_hash: eval.policy_hash.clone(),
            policy_name: eval.policy_name.clone(),
            matched_rules: eval.matched_rules.clone(),
            reason: eval.reason.clone(),
        },
        constraints,
        eval.obligations.clone(),
        expires_at.as_deref(),
        args.credential_ref.as_deref(),
    )?;

    eprintln!(
        "Decision {} authorized: {} → {} for tool '{}' (policy \"{}\")",
        decision.decision_id, decision.authority, decision.subject, args.tool, eval.policy_name
    );
    if !eval.obligations.is_empty() {
        eprintln!("Obligations (all must hold):");
        for ob in &eval.obligations {
            eprintln!("  - {}", serde_json::to_string(ob)?);
        }
    }
    if let Some(ref exp) = expires_at {
        eprintln!("Expires at: {exp}");
    }

    let json = serde_json::to_string_pretty(&decision)?;
    match args.output {
        Some(ref path) => {
            fs::write(path, &json)?;
            eprintln!("Decision written to {path}");
        }
        None => println!("{json}"),
    }
    Ok(())
}
