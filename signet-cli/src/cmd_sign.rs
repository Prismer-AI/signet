use std::fs;

use anyhow::Result;
use clap::Args;
use sha2::{Digest, Sha256};
use signet_core::receipt::Action;

#[derive(Args)]
pub struct SignArgs {
    #[arg(long)]
    pub key: String,
    #[arg(long)]
    pub tool: String,
    #[arg(long)]
    pub params: String,
    #[arg(long)]
    pub target: String,
    #[arg(long)]
    pub hash_only: bool,
    #[arg(long)]
    pub output: Option<String>,
    /// Skip writing to audit log
    #[arg(long)]
    pub no_log: bool,
}

pub fn sign(args: SignArgs) -> Result<()> {
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

    // Parse params (inline JSON or @file)
    let params_str = if let Some(path) = args.params.strip_prefix('@') {
        fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("failed to read params file '{path}': {e}"))?
    } else {
        args.params.clone()
    };
    let params: serde_json::Value = serde_json::from_str(&params_str)?;

    let action = if args.hash_only {
        let canonical = signet_core::canonical::canonicalize(&params)?;
        let hash = Sha256::digest(canonical.as_bytes());
        Action {
            tool: args.tool,
            params: serde_json::Value::Null,
            params_hash: format!("sha256:{}", hex::encode(hash)),
            target: args.target,
            transport: "stdio".to_string(),
        }
    } else {
        Action {
            tool: args.tool,
            params,
            params_hash: String::new(),
            target: args.target,
            transport: "stdio".to_string(),
        }
    };

    let owner = info.owner.as_deref().unwrap_or("");
    let receipt = signet_core::sign(&sk, &action, &info.name, owner)?;
    let json = serde_json::to_string(&receipt)?;

    if !args.no_log {
        signet_core::audit::append(&dir, &receipt)?;
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
