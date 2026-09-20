use std::fs;

use anyhow::Result;
use clap::Args;
use sha2::{Digest, Sha256};
use signet_core::receipt::Action;

#[derive(Args)]
pub struct SignArgs {
    #[arg(long)]
    pub key: String,
    #[arg(long, required_unless_present = "tool_from_env")]
    pub tool: Option<String>,
    #[arg(long, required_unless_present = "tool")]
    /// Read tool name from this environment variable (avoids shell injection)
    pub tool_from_env: Option<String>,
    #[arg(long, required_unless_present = "params_from_env")]
    pub params: Option<String>,
    #[arg(long, required_unless_present = "params")]
    /// Read params JSON from this environment variable (avoids shell injection)
    pub params_from_env: Option<String>,
    #[arg(long)]
    pub target: String,
    #[arg(long)]
    pub hash_only: bool,
    /// Encrypt action.params in the audit log while keeping the signed receipt output unchanged.
    #[arg(long)]
    pub encrypt_params: bool,
    #[arg(long)]
    pub output: Option<String>,
    /// Skip writing to audit log
    #[arg(long)]
    pub no_log: bool,
    /// Policy file (YAML/JSON) — evaluate before signing
    #[arg(long)]
    pub policy: Option<String>,
    /// Logical session identifier for the originating agent conversation.
    #[arg(long)]
    pub session: Option<String>,
    /// Tool-call identifier from the host runtime (e.g. MCP id, OpenClaw toolCallId).
    #[arg(long)]
    pub call_id: Option<String>,
    /// Trace identifier for cross-receipt correlation.
    #[arg(long)]
    pub trace_id: Option<String>,
    /// Parent receipt id for chained execution proofs.
    #[arg(long)]
    pub parent_receipt_id: Option<String>,
    /// Signer principal URI (e.g. agent://prismer/deploy-bot); defaults to the key's stored principal
    #[arg(long)]
    pub principal: Option<String>,
    /// Principal the signer acts for (e.g. user://prismer/alice) — a signed claim
    #[arg(long)]
    pub acting_for: Option<String>,
    /// Authority decision file (two-step flow from `signet authorize`)
    #[arg(long)]
    pub decision: Option<String>,
    /// Delegation chain JSON file — produces a v4 receipt
    #[arg(long)]
    pub chain: Option<String>,
    /// Authority key name (one-step flow): evaluate --policy, authority-sign the decision, sign
    #[arg(long)]
    pub authority_key: Option<String>,
    /// Authority principal URI; defaults to the authority key's stored principal
    #[arg(long)]
    pub authority_principal: Option<String>,
}

fn load_chain_json(path: &str) -> Result<String> {
    fs::read_to_string(path).map_err(|e| anyhow::anyhow!("failed to read chain file '{path}': {e}"))
}

pub fn sign(args: SignArgs) -> Result<()> {
    if args.hash_only && args.encrypt_params {
        anyhow::bail!("--encrypt-params cannot be used with --hash-only");
    }

    let dir = signet_core::default_signet_dir();
    let info = signet_core::load_key_info(&dir, &args.key)?;

    // Load signing key: try unencrypted first, then prompt
    let sk = match signet_core::load_signing_key(&dir, &args.key, None) {
        Ok(sk) => sk,
        Err(_) => {
            let pass = super::get_passphrase("Enter passphrase: ")?;
            signet_core::load_signing_key(&dir, &args.key, Some(&pass))?
        }
    };

    // Resolve tool name: --tool or --tool-from-env
    let tool = match (&args.tool, &args.tool_from_env) {
        (Some(t), _) => t.clone(),
        (None, Some(env_name)) => std::env::var(env_name)
            .map_err(|_| anyhow::anyhow!("env var '{}' not set", env_name))?,
        (None, None) => anyhow::bail!("either --tool or --tool-from-env is required"),
    };

    // Resolve params: --params or --params-from-env
    let params_raw = match (&args.params, &args.params_from_env) {
        (Some(p), _) => p.clone(),
        (None, Some(env_name)) => std::env::var(env_name)
            .map_err(|_| anyhow::anyhow!("env var '{}' not set", env_name))?,
        (None, None) => "{}".to_string(),
    };

    // Parse params (inline JSON or @file)
    let params_str = if let Some(path) = params_raw.strip_prefix('@') {
        fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("failed to read params file '{path}': {e}"))?
    } else {
        params_raw
    };
    let params: serde_json::Value = serde_json::from_str(&params_str)?;

    let action = if args.hash_only {
        let canonical = signet_core::canonical::canonicalize(&params)?;
        let hash = Sha256::digest(canonical.as_bytes());
        Action {
            tool,
            params: serde_json::Value::Null,
            params_hash: format!("sha256:{}", hex::encode(hash)),
            target: args.target,
            transport: "stdio".to_string(),
            session: args.session.clone(),
            call_id: args.call_id.clone(),
            response_hash: None,
            trace_id: args.trace_id.clone(),
            parent_receipt_id: args.parent_receipt_id.clone(),
        }
    } else {
        Action {
            tool,
            params,
            params_hash: String::new(),
            target: args.target,
            transport: "stdio".to_string(),
            session: args.session.clone(),
            call_id: args.call_id.clone(),
            response_hash: None,
            trace_id: args.trace_id.clone(),
            parent_receipt_id: args.parent_receipt_id.clone(),
        }
    };

    let owner = info.owner.as_deref().unwrap_or("");
    let principal = args.principal.as_deref().or(info.principal.as_deref());

    let chain_json = match args.chain {
        Some(ref path) => Some(load_chain_json(path)?),
        None => None,
    };

    let receipt = if let Some(ref decision_path) = args.decision {
        // Two-step flow: consume a pre-made authority decision.
        if args.policy.is_some() {
            anyhow::bail!("--decision cannot be combined with --policy");
        }
        if args.authority_key.is_some() {
            anyhow::bail!("--decision cannot be combined with --authority-key (the decision is already signed)");
        }
        let decision_str = fs::read_to_string(decision_path)
            .map_err(|e| anyhow::anyhow!("failed to read decision file '{decision_path}': {e}"))?;
        let decision: signet_core::AuthorizationDecision = serde_json::from_str(&decision_str)?;
        let principal = principal.ok_or_else(|| {
            anyhow::anyhow!(
                "--principal (or key metadata principal) is required with --decision: the decision subject must be corroborated"
            )
        })?;
        signet_core::sign_with_decision(
            &sk,
            &action,
            &info.name,
            owner,
            Some(principal),
            &decision,
            chain_json.as_deref(),
        )?
    } else if let Some(ref policy_path) = args.policy {
        let policy = signet_core::load_policy(std::path::Path::new(policy_path))?;
        // Evaluate once, then branch — avoids double load and TOCTOU issues
        let eval = signet_core::evaluate_policy(&action, &info.name, &policy, None)?;
        let rules_str = if eval.matched_rules.is_empty() {
            "default action".to_string()
        } else {
            eval.matched_rules.join(", ")
        };
        eprintln!(
            "Policy \"{}\": {} ({})",
            eval.policy_name, eval.decision, rules_str
        );

        match eval.decision {
            signet_core::RuleAction::Allow => {
                if let Some(ref authority_key_name) = args.authority_key {
                    // One-step flow: the decision is authority-signed here.
                    let authority_info = signet_core::load_key_info(&dir, authority_key_name)?;
                    let authority_principal = args
                        .authority_principal
                        .as_deref()
                        .or(authority_info.principal.as_deref())
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "--authority-principal (or authority key metadata principal) is required with --authority-key"
                            )
                        })?;
                    let authority_sk =
                        match signet_core::load_signing_key(&dir, authority_key_name, None) {
                            Ok(k) => k,
                            Err(_) => {
                                let pass = super::get_passphrase("Authority key passphrase: ")?;
                                signet_core::load_signing_key(
                                    &dir,
                                    authority_key_name,
                                    Some(&pass),
                                )?
                            }
                        };
                    let agent_principal = principal.ok_or_else(|| {
                        anyhow::anyhow!(
                            "--principal (or key metadata principal) is required with --authority-key: the decision subject must be corroborated"
                        )
                    })?;
                    eprintln!(
                        "Authority-signed decision by {authority_principal} for {agent_principal}"
                    );
                    signet_core::sign_with_policy_authority(
                        &sk,
                        &authority_sk,
                        authority_principal,
                        agent_principal,
                        &action,
                        &info.name,
                        owner,
                        &policy,
                        None,
                        chain_json.as_deref(),
                    )?
                    .0
                } else {
                    signet_core::sign_with_policy_with_principal(
                        &sk,
                        &action,
                        &info.name,
                        owner,
                        principal,
                        args.acting_for.as_deref(),
                        &policy,
                        None,
                    )?
                    .0
                }
            }
            signet_core::RuleAction::Deny | signet_core::RuleAction::RequireApproval => {
                if !args.no_log {
                    if let Err(e) =
                        signet_core::audit::append_violation(&dir, &action, &info.name, &eval)
                    {
                        eprintln!("Warning: failed to log violation: {e}");
                    }
                }
                if eval.decision == signet_core::RuleAction::Deny {
                    anyhow::bail!("policy violation: {}", eval.reason);
                } else {
                    anyhow::bail!("requires approval: {}", eval.reason);
                }
            }
        }
    } else if chain_json.is_some() {
        // v4 receipt without a decision: delegation proof only.
        let chain: Vec<signet_core::DelegationToken> =
            serde_json::from_str(chain_json.as_deref().unwrap())?;
        signet_core::sign_authorized_with_principal(
            &sk,
            &action,
            &info.name,
            principal,
            args.acting_for.as_deref(),
            chain,
        )?
    } else {
        signet_core::sign_with_principal(
            &sk,
            &action,
            &info.name,
            owner,
            principal,
            args.acting_for.as_deref(),
        )?
    };

    let json = serde_json::to_string(&receipt)?;

    if !args.no_log {
        let receipt_json = serde_json::to_value(&receipt)?;
        if args.encrypt_params {
            signet_core::audit::append_encrypted(&dir, &receipt_json, &sk)?;
        } else {
            signet_core::audit::append(&dir, &receipt_json)?;
        }
    }

    match args.output {
        Some(ref path) => {
            fs::write(path, &json)?;
            eprintln!("Receipt written to {path}");
        }
        None => println!("{json}"),
    }
    Ok(())
}
