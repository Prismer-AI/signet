use std::path::Path;

use anyhow::Result;
use clap::{Args, Subcommand};
use signet_core::receipt::Action;

#[derive(Subcommand)]
pub enum PolicyAction {
    /// Validate a policy file (check syntax and rules)
    Validate(ValidateArgs),
    /// Dry-run: check if an action would be allowed by a policy
    Check(CheckArgs),
}

#[derive(Args)]
pub struct ValidateArgs {
    /// Policy file path (YAML or JSON)
    pub path: String,
}

#[derive(Args)]
pub struct CheckArgs {
    /// Policy file path (YAML or JSON)
    pub path: String,
    /// Tool name
    #[arg(long)]
    pub tool: String,
    /// Params JSON
    #[arg(long, default_value = "{}")]
    pub params: String,
    /// Agent name
    #[arg(long, default_value = "anonymous")]
    pub agent: String,
    /// Target URI
    #[arg(long, default_value = "")]
    pub target: String,
}

pub fn run(action: PolicyAction) -> Result<()> {
    match action {
        PolicyAction::Validate(args) => validate(args),
        PolicyAction::Check(args) => check(args),
    }
}

fn validate(args: ValidateArgs) -> Result<()> {
    let policy = signet_core::load_policy(Path::new(&args.path))?;
    signet_core::validate_policy(&policy)?;
    let hash = signet_core::compute_policy_hash(&policy)?;
    eprintln!(
        "Policy \"{}\" is valid ({} rules, {})",
        policy.name,
        policy.rules.len(),
        hash,
    );
    Ok(())
}

fn check(args: CheckArgs) -> Result<()> {
    let policy = signet_core::load_policy(Path::new(&args.path))?;

    let params: serde_json::Value = serde_json::from_str(&args.params)?;
    let action = Action {
        tool: args.tool,
        params,
        params_hash: String::new(),
        target: args.target,
        transport: "stdio".to_string(),
        session: None,
        call_id: None,
        response_hash: None,
    };

    let eval = signet_core::evaluate_policy(&action, &args.agent, &policy, None);

    let decision_str = eval.decision.to_string().to_uppercase();
    let rules_str = if eval.matched_rules.is_empty() {
        "default action".to_string()
    } else {
        format!("rule \"{}\"", eval.matched_rules.join(", "))
    };

    match eval.decision {
        signet_core::RuleAction::Allow => {
            eprintln!("{decision_str} ({rules_str})");
        }
        signet_core::RuleAction::Deny => {
            eprintln!("{decision_str} by {rules_str}: {}", eval.reason);
            std::process::exit(1);
        }
        signet_core::RuleAction::RequireApproval => {
            eprintln!("{decision_str} by {rules_str}: {}", eval.reason);
            std::process::exit(2);
        }
    }
    Ok(())
}
