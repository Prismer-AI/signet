use std::fs;

use anyhow::{bail, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use clap::{Args, Subcommand};
use signet_core::receipt::Action;

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
    pub trusted_roots: String,
    /// Clock skew tolerance in seconds
    #[arg(long, default_value_t = 60)]
    pub clock_skew: u64,
}

fn resolve_pubkey(dir: &std::path::Path, key_ref: &str) -> Result<ed25519_dalek::VerifyingKey> {
    // Try as key name first
    if let Ok(vk) = signet_core::load_verifying_key(dir, key_ref) {
        return Ok(vk);
    }
    // Try as raw base64
    let bytes = BASE64
        .decode(key_ref)
        .map_err(|e| anyhow::anyhow!("'{}' is not a key name or valid base64: {}", key_ref, e))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("key must be 32 bytes"))?;
    Ok(ed25519_dalek::VerifyingKey::from_bytes(&arr)?)
}

fn parse_ttl(s: &str) -> Result<String> {
    let s = s.trim();
    let (num_str, unit) = if let Some(n) = s.strip_suffix('d') {
        (n, "d")
    } else if let Some(n) = s.strip_suffix('h') {
        (n, "h")
    } else if let Some(n) = s.strip_suffix('m') {
        (n, "m")
    } else {
        bail!("invalid TTL format '{}': expected e.g. 30m, 1h, 24h, 7d", s);
    };

    let num: u64 = num_str
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid TTL number: '{}'", num_str))?;
    if num == 0 {
        bail!("TTL must be > 0");
    }

    let secs = match unit {
        "m" => num * 60,
        "h" => num * 3600,
        "d" => num * 86400,
        _ => unreachable!(),
    };

    let expires = chrono::Utc::now() + chrono::Duration::seconds(secs as i64);
    Ok(expires.format("%Y-%m-%dT%H:%M:%SZ").to_string())
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

    let sk = match signet_core::load_signing_key(&dir, &args.from, None) {
        Ok(sk) => sk,
        Err(_) => {
            let pass = super::get_passphrase("Enter passphrase: ")?;
            signet_core::load_signing_key(&dir, &args.from, Some(&pass))?
        }
    };

    let delegate_vk = resolve_pubkey(&dir, &args.to)?;

    let expires = match (&args.expires, &args.ttl) {
        (Some(exp), _) => Some(exp.clone()),
        (_, Some(ttl)) => Some(parse_ttl(ttl)?),
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

    let token = signet_core::sign_delegation(
        &sk,
        &info.name,
        &delegate_vk,
        &args.to_name,
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

    // Try parsing as array (chain) first, then single token
    if let Ok(chain) = serde_json::from_str::<Vec<signet_core::DelegationToken>>(&json) {
        // Verify chain
        let dir = signet_core::default_signet_dir();
        let trusted_roots = match &args.trusted_roots {
            Some(keys) => keys
                .split(',')
                .map(|k| resolve_pubkey(&dir, k.trim()))
                .collect::<Result<Vec<_>>>()?,
            None => bail!("--trusted-roots required for chain verification"),
        };

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

    let sk = match signet_core::load_signing_key(&dir, &args.key, None) {
        Ok(sk) => sk,
        Err(_) => {
            let pass = super::get_passphrase("Enter passphrase: ")?;
            signet_core::load_signing_key(&dir, &args.key, Some(&pass))?
        }
    };

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

    let receipt = signet_core::sign_authorized(&sk, &action, &info.name, chain)?;
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

    let trusted_roots = args
        .trusted_roots
        .split(',')
        .map(|k| resolve_pubkey(&dir, k.trim()))
        .collect::<Result<Vec<_>>>()?;

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
    eprintln!("Effective scope:");
    println!("{}", serde_json::to_string_pretty(&scope)?);
    Ok(())
}
