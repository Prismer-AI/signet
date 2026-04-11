use std::collections::HashMap;
use std::process::Stdio;
use std::sync::{Arc, Mutex};

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

/// Pending request: receipt waiting for server response to co-sign.
struct PendingRequest {
    receipt: signet_core::Receipt,
    tool_name: String,
}

/// Shared state between agent→server and server→agent tasks.
type PendingMap = Arc<Mutex<HashMap<String, PendingRequest>>>;

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

    let target_uri = if args.target_uri.is_empty() {
        format!("mcp://{}", args.target.split_whitespace().last().unwrap_or("local"))
    } else {
        args.target_uri.clone()
    };

    let parts: Vec<&str> = args.target.split_whitespace().collect();
    if parts.is_empty() {
        bail!("--target cannot be empty");
    }
    let (cmd, cmd_args) = (parts[0], &parts[1..]);

    eprintln!("[signet proxy] target: {}", args.target);
    eprintln!("[signet proxy] target_uri: {}", target_uri);
    eprintln!("[signet proxy] signer: {} ({})", signer_name, info.pubkey);
    eprintln!("[signet proxy] bilateral co-signing: enabled");

    let mut command = Command::new(cmd);
    command
        .args(cmd_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());

    if !args.no_env_filter {
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
    let pending: PendingMap = Arc::new(Mutex::new(HashMap::new()));
    let call_counter = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let bilateral_counter = Arc::new(std::sync::atomic::AtomicU64::new(0));

    // Agent → Server
    let agent_to_server = {
        let sk = sk.clone();
        let signer_name = signer_name.clone();
        let owner = owner.clone();
        let policy = policy.clone();
        let dir = dir.clone();
        let target_uri = target_uri.clone();
        let call_counter = call_counter.clone();
        let pending = pending.clone();
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
                                &pending,
                            ) {
                                Ok(_) => {
                                    call_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                }
                                Err(e) => {
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
                                    continue;
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

    // Server → Agent (intercept responses, bilateral co-sign)
    let server_to_agent = {
        let sk = sk.clone();
        let dir = dir.clone();
        let pending = pending.clone();
        let bilateral_counter = bilateral_counter.clone();
        async move {
            let mut reader = BufReader::new(child_stdout);
            let mut writer = stdout;
            let mut line = String::new();

            loop {
                line.clear();
                let n = reader.read_line(&mut line).await?;
                if n == 0 {
                    break;
                }

                let trimmed = line.trim();
                if !trimmed.is_empty() {
                    if let Ok(msg) = serde_json::from_str::<serde_json::Value>(trimmed) {
                        // Check if this is a response (has "id" + "result", no "method")
                        if is_rpc_response(&msg) {
                            if let Some(rpc_id) = extract_rpc_id(&msg) {
                                // Look up pending request
                                let pending_req = pending.lock().unwrap().remove(&rpc_id);
                                if let Some(req) = pending_req {
                                    // Bilateral co-sign: proxy signs the response
                                    let response_content = msg.get("result")
                                        .cloned()
                                        .unwrap_or(serde_json::json!({}));
                                    let ts = chrono::Utc::now()
                                        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
                                    match signet_core::sign_bilateral(
                                        &sk, &req.receipt, &response_content,
                                        "signet-proxy", &ts,
                                    ) {
                                        Ok(bilateral) => {
                                            if !no_log {
                                                let val = serde_json::to_value(&bilateral).unwrap_or_default();
                                                if let Err(e) = signet_core::audit::append(&dir, &val) {
                                                    eprintln!("[signet proxy] warning: bilateral audit failed: {e}");
                                                }
                                            }
                                            bilateral_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                            eprintln!(
                                                "[signet proxy] bilateral: {} ({}) ← response co-signed",
                                                req.tool_name, bilateral.id,
                                            );
                                        }
                                        Err(e) => {
                                            eprintln!("[signet proxy] bilateral sign error: {e}");
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Always forward the response to agent
                writer.write_all(line.as_bytes()).await?;
                writer.flush().await?;
            }
            anyhow::Ok(())
        }
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

    let calls = call_counter.load(std::sync::atomic::Ordering::Relaxed);
    let bilaterals = bilateral_counter.load(std::sync::atomic::Ordering::Relaxed);
    eprintln!("[signet proxy] done: {calls} signed, {bilaterals} bilateral");

    let _ = child.kill().await;
    Ok(())
}

fn is_tools_call(msg: &serde_json::Value) -> bool {
    msg.get("method")
        .and_then(|m| m.as_str())
        .map(|m| m == "tools/call")
        .unwrap_or(false)
}

fn is_rpc_response(msg: &serde_json::Value) -> bool {
    msg.get("id").is_some()
        && (msg.get("result").is_some() || msg.get("error").is_some())
        && msg.get("method").is_none()
}

fn extract_rpc_id(msg: &serde_json::Value) -> Option<String> {
    msg.get("id").and_then(|id| match id {
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::String(s) => Some(s.clone()),
        _ => None,
    })
}

/// Sign a tools/call request, store pending receipt for bilateral, inject into params.
fn sign_tools_call(
    msg: &mut serde_json::Value,
    sk: &ed25519_dalek::SigningKey,
    signer_name: &str,
    signer_owner: &str,
    policy: Option<&signet_core::Policy>,
    dir: &std::path::Path,
    no_log: bool,
    target_uri: &str,
    pending: &PendingMap,
) -> Result<()> {
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

    let call_id = msg.get("id").and_then(|id| match id {
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::String(s) => Some(s.clone()),
        _ => None,
    });
    let rpc_id = call_id.clone().unwrap_or_default();

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

    // Don't log v1 receipt to audit — the bilateral receipt (v3) will be logged
    // when the response arrives. If the server never responds, we lose the record,
    // but that's better than logging both v1 and v3 for the same action.

    // Store pending request for bilateral co-signing
    pending.lock().unwrap().insert(
        rpc_id,
        PendingRequest {
            receipt: receipt.clone(),
            tool_name: tool_name.clone(),
        },
    );

    // Inject receipt into params._meta._signet
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

    eprintln!("[signet proxy] signed: {} ({})", tool_name, receipt.id);

    Ok(())
}
