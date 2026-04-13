use std::process::Stdio;

use anyhow::{bail, Result};
use clap::Args;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

/// Env vars that are never passed to the child MCP server process.
const ENV_DENYLIST: &[&str] = &[
    "SIGNET_PASSPHRASE",
    "AWS_SECRET_ACCESS_KEY",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GITHUB_TOKEN",
    "NPM_TOKEN",
    "PYPI_TOKEN",
    "CARGO_REGISTRY_TOKEN",
];

#[derive(Args)]
pub struct ProxyArgs {
    /// Target MCP server command (e.g. "npx @modelcontextprotocol/server-github")
    #[arg(long)]
    pub target: String,

    /// Signing key name (from keystore)
    #[arg(long)]
    pub key: String,

    /// Target URI for audit trail (e.g. "mcp://github.local")
    #[arg(long, default_value = "")]
    pub target_uri: String,

    /// Skip writing to audit log
    #[arg(long)]
    pub no_log: bool,

    /// Policy file (YAML/JSON) — evaluate before signing
    #[arg(long)]
    pub policy: Option<String>,

    /// Allow all env vars to pass to child process (disables env filtering)
    #[arg(long)]
    pub no_env_filter: bool,
}

pub fn run(args: ProxyArgs) -> Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run_proxy(args))
}

async fn run_proxy(args: ProxyArgs) -> Result<()> {
    let dir = signet_core::default_signet_dir();
    let info = signet_core::load_key_info(&dir, &args.key)?;
    let sk = match signet_core::load_signing_key(&dir, &args.key, None) {
        Ok(sk) => sk,
        Err(_) => {
            let pass = super::get_passphrase("Enter passphrase: ")?;
            signet_core::load_signing_key(&dir, &args.key, Some(&pass))?
        }
    };
    let owner = info.owner.as_deref().unwrap_or("").to_string();
    let signer_name = info.name.clone();

    let policy = if let Some(ref path) = args.policy {
        Some(signet_core::load_policy(std::path::Path::new(path))?)
    } else {
        None
    };

    // Derive target_uri from --target-uri or --target command
    let target_uri = if args.target_uri.is_empty() {
        format!("mcp://{}", args.target.split_whitespace().last().unwrap_or("local"))
    } else {
        args.target_uri.clone()
    };

    // Parse target command
    let parts: Vec<&str> = args.target.split_whitespace().collect();
    if parts.is_empty() {
        bail!("--target cannot be empty");
    }
    let (cmd, cmd_args) = (parts[0], &parts[1..]);

    eprintln!("[signet proxy] target: {}", args.target);
    eprintln!("[signet proxy] target_uri: {}", target_uri);
    eprintln!("[signet proxy] signer: {} ({})", signer_name, info.pubkey);

    // Spawn target MCP server with filtered env
    let mut command = Command::new(cmd);
    command
        .args(cmd_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());

    if !args.no_env_filter {
        // Clear env and re-add non-sensitive vars
        command.env_clear();
        for (k, v) in std::env::vars() {
            if !ENV_DENYLIST.iter().any(|&denied| k == denied) {
                command.env(&k, &v);
            }
        }
    }

    let mut child = command
        .spawn()
        .map_err(|e| anyhow::anyhow!("failed to spawn '{}': {e}", args.target))?;

    let child_stdin = child.stdin.take().expect("child stdin");
    let child_stdout = child.stdout.take().expect("child stdout");

    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();

    let no_log = args.no_log;
    let dir_clone = dir.clone();

    let call_counter = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));

    // Agent → Server (intercept tools/call, sign, forward)
    let agent_to_server = {
        let sk = sk.clone();
        let signer_name = signer_name.clone();
        let owner = owner.clone();
        let policy = policy.clone();
        let dir = dir_clone.clone();
        let target_uri = target_uri.clone();
        let call_counter = call_counter.clone();
        async move {
            let mut reader = BufReader::new(stdin);
            let mut writer = child_stdin;
            let mut out_writer = tokio::io::stdout();
            let mut line = String::new();

            loop {
                line.clear();
                let n = reader.read_line(&mut line).await?;
                if n == 0 {
                    break;
                }

                let trimmed = line.trim();
                if trimmed.is_empty() {
                    writer.write_all(line.as_bytes()).await?;
                    writer.flush().await?;
                    continue;
                }

                let output = match serde_json::from_str::<serde_json::Value>(trimmed) {
                    Ok(mut msg) => {
                        if is_tools_call(&msg) {
                            match sign_tools_call(
                                &mut msg, &sk, &signer_name, &owner,
                                policy.as_ref(), &dir, no_log, &target_uri,
                            ) {
                                Ok(_receipt_id) => {
                                    call_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                }
                                Err(e) => {
                                    // Policy denial: return JSON-RPC error to agent, don't forward
                                    let rpc_id = msg.get("id").cloned().unwrap_or(serde_json::json!(null));
                                    let error_response = serde_json::json!({
                                        "jsonrpc": "2.0",
                                        "id": rpc_id,
                                        "error": {
                                            "code": -32600,
                                            "message": e.to_string(),
                                        }
                                    });
                                    let mut json = serde_json::to_string(&error_response)?;
                                    json.push('\n');
                                    out_writer.write_all(json.as_bytes()).await?;
                                    out_writer.flush().await?;
                                    continue; // don't forward to server
                                }
                            }
                        }
                        let mut json = serde_json::to_string(&msg)?;
                        json.push('\n');
                        json
                    }
                    Err(_) => line.clone(),
                };

                writer.write_all(output.as_bytes()).await?;
                writer.flush().await?;
            }
            anyhow::Ok(())
        }
    };

    // Server → Agent (pass through)
    let server_to_agent = async move {
        let mut reader = BufReader::new(child_stdout);
        let mut writer = stdout;
        let mut line = String::new();

        loop {
            line.clear();
            let n = reader.read_line(&mut line).await?;
            if n == 0 {
                break;
            }
            writer.write_all(line.as_bytes()).await?;
            writer.flush().await?;
        }
        anyhow::Ok(())
    };

    let server_handle = tokio::spawn(server_to_agent);

    tokio::select! {
        r = agent_to_server => {
            if let Err(e) = r {
                eprintln!("[signet proxy] agent→server error: {e}");
            }
            let _ = server_handle.await;
        }
        _ = tokio::signal::ctrl_c() => {
            eprintln!("[signet proxy] shutting down");
        }
    }

    let count = call_counter.load(std::sync::atomic::Ordering::Relaxed);
    eprintln!("[signet proxy] done: {count} tool calls signed");

    let _ = child.kill().await;
    Ok(())
}

fn is_tools_call(msg: &serde_json::Value) -> bool {
    msg.get("method")
        .and_then(|m| m.as_str())
        .map(|m| m == "tools/call")
        .unwrap_or(false)
}

/// Sign a tools/call request, inject receipt, return receipt ID on success.
fn sign_tools_call(
    msg: &mut serde_json::Value,
    sk: &ed25519_dalek::SigningKey,
    signer_name: &str,
    signer_owner: &str,
    policy: Option<&signet_core::Policy>,
    dir: &std::path::Path,
    no_log: bool,
    target_uri: &str,
) -> Result<String> {
    let params = msg
        .get("params")
        .ok_or_else(|| anyhow::anyhow!("tools/call missing params"))?;

    let tool_name = params
        .get("name")
        .and_then(|n| n.as_str())
        .unwrap_or("unknown")
        .to_string();
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or(serde_json::json!({}));

    // Extract JSON-RPC id as call_id
    let call_id = msg.get("id").and_then(|id| match id {
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::String(s) => Some(s.clone()),
        _ => None,
    });

    let action = signet_core::Action {
        tool: tool_name.clone(),
        params: arguments,
        params_hash: String::new(),
        target: target_uri.to_string(),
        transport: "stdio".to_string(),
        session: None,
        call_id,
        response_hash: None,
    };

    let receipt = if let Some(pol) = policy {
        let eval = signet_core::evaluate_policy(&action, signer_name, pol, None);
        match eval.decision {
            signet_core::RuleAction::Deny => {
                eprintln!("[signet proxy] DENIED: {} ({})", tool_name, eval.reason);
                if !no_log {
                    if let Err(e) = signet_core::audit::append_violation(dir, &action, signer_name, &eval) {
                        eprintln!("[signet proxy] warning: audit log failed: {e}");
                    }
                }
                bail!("policy violation: {}", eval.reason);
            }
            signet_core::RuleAction::RequireApproval => {
                eprintln!("[signet proxy] NEEDS APPROVAL: {} ({})", tool_name, eval.reason);
                if !no_log {
                    if let Err(e) = signet_core::audit::append_violation(dir, &action, signer_name, &eval) {
                        eprintln!("[signet proxy] warning: audit log failed: {e}");
                    }
                }
                bail!("requires approval: {}", eval.reason);
            }
            signet_core::RuleAction::Allow => {
                let (receipt, _) = signet_core::sign_with_policy(
                    sk, &action, signer_name, signer_owner, pol, None,
                )?;
                receipt
            }
        }
    } else {
        signet_core::sign(sk, &action, signer_name, signer_owner)?
    };

    let receipt_id = receipt.id.clone();

    // Log to audit
    if !no_log {
        let receipt_val = serde_json::to_value(&receipt)?;
        if let Err(e) = signet_core::audit::append(dir, &receipt_val) {
            eprintln!("[signet proxy] warning: audit log failed: {e}");
        }
    }

    // Inject receipt into params._meta._signet (no unwrap)
    let receipt_val = serde_json::to_value(&receipt)?;
    if let Some(params_mut) = msg.get_mut("params") {
        let obj = params_mut
            .as_object_mut()
            .ok_or_else(|| anyhow::anyhow!("params is not an object"))?;
        if !obj.contains_key("_meta") {
            obj.insert("_meta".to_string(), serde_json::json!({}));
        }
        if let Some(meta) = obj.get_mut("_meta") {
            if let Some(meta_obj) = meta.as_object_mut() {
                meta_obj.insert("_signet".to_string(), receipt_val);
            }
        }
    }

    eprintln!("[signet proxy] signed: {} ({})", tool_name, receipt_id);

    Ok(receipt_id)
}
