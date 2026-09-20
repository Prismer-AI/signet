use std::fs;

use anyhow::{bail, Result};
use clap::{Args, Subcommand};
use signet_core::receipt::Action;

use crate::trust_helpers::{load_cli_trust_bundle, resolve_pubkey};

#[derive(Subcommand)]
pub enum DelegateAction {
    /// Create a delegation token granting scoped authority to a delegate
    Create(CreateArgs),
    /// Verify a delegation token or chain
    Verify(DelegateVerifyArgs),
    /// Sign an action with a delegation chain (produces v4 receipt)
    Sign(DelegateSignArgs),
    /// Verify an authorized (v4) receipt against trusted roots
    VerifyAuth(VerifyAuthArgs),
}

#[derive(Args)]
pub struct CreateArgs {
    /// Delegator key name (from keystore)
    #[arg(long)]
    pub from: String,
    /// Delegate public key (base64 or key name)
    #[arg(long)]
    pub to: String,
    /// Delegate display name
    #[arg(long)]
    pub to_name: String,
    /// Allowed tools (comma-separated, or * for all)
    #[arg(long, default_value = "*")]
    pub tools: String,
    /// Allowed targets (comma-separated, or * for all)
    #[arg(long, default_value = "*")]
    pub targets: String,
    /// Max re-delegation depth (0 = cannot re-delegate)
    #[arg(long, default_value_t = 0)]
    pub max_depth: u32,
    /// Expiry (RFC 3339 UTC, e.g. 2026-12-31T23:59:59Z)
    #[arg(long, conflicts_with = "ttl")]
    pub expires: Option<String>,
    /// Time-to-live from now (e.g. 1h, 24h, 7d, 30m)
    #[arg(long, conflicts_with = "expires")]
    pub ttl: Option<String>,
    /// Parent scope JSON file (for scope narrowing validation)
    #[arg(long)]
    pub parent_scope: Option<String>,
    /// Delegator principal URI (e.g. user://prismer/alice); defaults to the key's stored principal
    #[arg(long)]
    pub from_principal: Option<String>,
    /// Delegate principal URI (e.g. agent://prismer/deploy-bot)
    #[arg(long)]
    pub to_principal: Option<String>,
    /// Output file (default: stdout)
    #[arg(long)]
    pub output: Option<String>,
}

#[derive(Args)]
pub struct DelegateVerifyArgs {
    /// Token JSON file or chain JSON file
    pub input: String,
    /// Trusted root public keys (comma-separated base64 or key names)
    #[arg(long)]
    pub trusted_roots: Option<String>,
    /// Trust bundle file (YAML or JSON) containing active trusted roots.
    #[arg(long)]
    pub trust_bundle: Option<String>,
}

#[derive(Args)]
pub struct DelegateSignArgs {
    /// Signing key name (from keystore)
    #[arg(long)]
    pub key: String,
    /// Tool name
    #[arg(long)]
    pub tool: String,
    /// Params JSON (inline or @file)
    #[arg(long, default_value = "{}")]
    pub params: String,
    /// Target
    #[arg(long)]
    pub target: String,
    /// Delegation chain JSON file
    #[arg(long)]
    pub chain: String,
    /// Signer principal URI; defaults to the key's stored principal
    #[arg(long)]
    pub principal: Option<String>,
    /// Principal the signer acts for; defaults to the chain root's principal when set
    #[arg(long)]
    pub acting_for: Option<String>,
    /// Output file (default: stdout)
    #[arg(long)]
    pub output: Option<String>,
    /// Skip writing to audit log
    #[arg(long)]
    pub no_log: bool,
}

#[derive(Args)]
pub struct VerifyAuthArgs {
    /// Receipt JSON file
    pub input: String,
    /// Trusted root public keys (comma-separated base64 or key names)
    #[arg(long)]
    pub trusted_roots: Option<String>,
    /// Trust bundle file (YAML or JSON) containing active trusted roots.
    #[arg(long)]
    pub trust_bundle: Option<String>,
    /// Clock skew tolerance in seconds
    #[arg(long, default_value_t = 60)]
    pub clock_skew: u64,
}

fn parse_tools_targets(s: &str) -> Result<Vec<String>> {
    if s == "*" {
        return Ok(vec!["*".to_string()]);
    }
    let items: Vec<String> = s
        .split(',')
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .collect();
    if items.is_empty() {
        bail!("tools/targets cannot be empty");
    }
    Ok(items)
}

pub fn run(action: DelegateAction) -> Result<()> {
    match action {
        DelegateAction::Create(args) => create(args),
        DelegateAction::Verify(args) => verify(args),
        DelegateAction::Sign(args) => sign(args),
        DelegateAction::VerifyAuth(args) => verify_auth(args),
    }
}

fn create(args: CreateArgs) -> Result<()> {
    let dir = signet_core::default_signet_dir();
    let info = signet_core::load_key_info(&dir, &args.from)?;

    let sk = crate::load_signing_key_with_prompt(&dir, &args.from, "Enter passphrase: ")?;

    let delegate_vk = resolve_pubkey(&dir, &args.to)?;

    let expires = match (&args.expires, &args.ttl) {
        (Some(exp), _) => Some(exp.clone()),
        (_, Some(ttl)) => Some(crate::parse_ttl(ttl)?),
        _ => None,
    };

    let scope = signet_core::Scope {
        tools: parse_tools_targets(&args.tools)?,
        targets: parse_tools_targets(&args.targets)?,
        max_depth: args.max_depth,
        expires,
        budget: None,
    };

    let parent_scope = if let Some(ref path) = args.parent_scope {
        let json = fs::read_to_string(path)?;
        Some(serde_json::from_str::<signet_core::Scope>(&json)?)
    } else {
        None
    };

    let from_principal = args.from_principal.as_deref().or(info.principal.as_deref());

    let token = signet_core::sign_delegation_with_principals(
        &sk,
        &info.name,
        from_principal,
        &delegate_vk,
        &args.to_name,
        args.to_principal.as_deref(),
        &scope,
        parent_scope.as_ref(),
    )?;

    let json = serde_json::to_string_pretty(&token)?;
    match args.output {
        Some(ref path) => {
            fs::write(path, &json)?;
            eprintln!("Delegation token written to {path}");
        }
        None => println!("{json}"),
    }
    Ok(())
}

fn verify(args: DelegateVerifyArgs) -> Result<()> {
    let json = fs::read_to_string(&args.input)?;
    let trust_bundle = match args.trust_bundle.as_deref() {
        Some(path) => {
            let bundle = load_cli_trust_bundle(path)?;
            eprintln!("Using trust bundle {}", bundle.describe());
            Some(bundle)
        }
        None => None,
    };

    // Try parsing as array (chain) first, then single token
    if let Ok(chain) = serde_json::from_str::<Vec<signet_core::DelegationToken>>(&json) {
        // Verify chain
        let dir = signet_core::default_signet_dir();
        let mut trusted_roots = match &trust_bundle {
            Some(bundle) => bundle.active_root_pubkeys.clone(),
            None => Vec::new(),
        };
        if let Some(keys) = &args.trusted_roots {
            trusted_roots.extend(
                keys.split(',')
                    .map(|k| resolve_pubkey(&dir, k.trim()))
                    .collect::<Result<Vec<_>>>()?,
            );
        }
        if trusted_roots.is_empty() {
            bail!("--trusted-roots or --trust-bundle required for chain verification");
        }

        let scope = signet_core::verify_delegation_chain(&chain, &trusted_roots, None, None)?;
        eprintln!("Chain valid. {} tokens verified.", chain.len());
        eprintln!("Effective scope:");
        println!("{}", serde_json::to_string_pretty(&scope)?);
    } else {
        // Single token
        let token: signet_core::DelegationToken = serde_json::from_str(&json)?;
        signet_core::verify_delegation(&token, None)?;
        eprintln!(
            "Token valid. Delegator: {}, Delegate: {}",
            token.delegator.name, token.delegate.name
        );
    }
    Ok(())
}

fn sign(args: DelegateSignArgs) -> Result<()> {
    let dir = signet_core::default_signet_dir();
    let info = signet_core::load_key_info(&dir, &args.key)?;

    let sk = crate::load_signing_key_with_prompt(&dir, &args.key, "Enter passphrase: ")?;

    let chain_json = fs::read_to_string(&args.chain)?;
    let chain: Vec<signet_core::DelegationToken> = serde_json::from_str(&chain_json)?;

    let params_str = if let Some(path) = args.params.strip_prefix('@') {
        fs::read_to_string(path)?
    } else {
        args.params
    };
    let params: serde_json::Value = serde_json::from_str(&params_str)?;

    let action = Action {
        tool: args.tool,
        params,
        params_hash: String::new(),
        target: args.target,
        transport: "stdio".to_string(),
        session: None,
        call_id: None,
        response_hash: None,
        trace_id: None,
        parent_receipt_id: None,
    };

    let principal = args.principal.as_deref().or(info.principal.as_deref());

    let receipt = signet_core::sign_authorized_with_principal(
        &sk,
        &action,
        &info.name,
        principal,
        args.acting_for.as_deref(),
        chain,
    )?;
    let json = serde_json::to_string(&receipt)?;

    if !args.no_log {
        let receipt_json = serde_json::to_value(&receipt)?;
        signet_core::audit::append(&dir, &receipt_json)?;
    }

    match args.output {
        Some(ref path) => {
            fs::write(path, &json)?;
            eprintln!("Authorized receipt (v4) written to {path}");
        }
        None => println!("{json}"),
    }
    Ok(())
}

fn verify_auth(args: VerifyAuthArgs) -> Result<()> {
    let dir = signet_core::default_signet_dir();
    let json = fs::read_to_string(&args.input)?;
    let receipt: signet_core::Receipt = serde_json::from_str(&json)?;
    let trust_bundle = match args.trust_bundle.as_deref() {
        Some(path) => {
            let bundle = load_cli_trust_bundle(path)?;
            eprintln!("Using trust bundle {}", bundle.describe());
            Some(bundle)
        }
        None => None,
    };

    let mut trusted_roots = match &trust_bundle {
        Some(bundle) => bundle.active_root_pubkeys.clone(),
        None => Vec::new(),
    };
    if let Some(keys) = &args.trusted_roots {
        trusted_roots.extend(
            keys.split(',')
                .map(|k| resolve_pubkey(&dir, k.trim()))
                .collect::<Result<Vec<_>>>()?,
        );
    }
    if trusted_roots.is_empty() {
        bail!("--trusted-roots or --trust-bundle required for authorization verification");
    }

    let opts = signet_core::AuthorizedVerifyOptions {
        trusted_roots,
        clock_skew_secs: args.clock_skew,
        max_chain_depth: 16,
    };

    let scope = signet_core::verify_authorized(&receipt, &opts)?;
    eprintln!("Authorized receipt verified.");
    eprintln!(
        "Signer: {} (owner: {})",
        receipt.signer.name, receipt.signer.owner
    );
    let auth = receipt
        .authorization
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("receipt has no authorization field (not a v4 receipt)"))?;
    eprintln!("Root: {}", auth.root_pubkey);
    if let Some(ref signer_principal) = receipt.signer.principal {
        eprintln!("Signer principal: {signer_principal}");
    }
    // acting_for corroboration: the one machine-checkable claim match.
    if let Some(ref acting_for) = receipt.signer.acting_for {
        let root_principal = auth
            .chain
            .first()
            .and_then(|t| t.delegator.principal.as_deref());
        match root_principal {
            Some(root) if root == acting_for => {
                eprintln!("Acting for: {acting_for} (corroborated by chain root)");
            }
            Some(root) => {
                eprintln!(
                    "Warning: acting_for '{acting_for}' does not match chain root principal '{root}' — claim NOT corroborated"
                );
            }
            None => {
                eprintln!(
                    "Acting for: {acting_for} (chain root has no principal — uncorroborated claim)"
                );
            }
        }
    }
    eprintln!("Effective scope:");
    println!("{}", serde_json::to_string_pretty(&scope)?);
    Ok(())
}
