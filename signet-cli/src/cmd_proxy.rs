use std::process::Stdio;

use anyhow::{bail, Result};
use clap::Args;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

#[derive(Args)]
pub struct ProxyArgs {
    /// Target MCP server command (e.g. "npx @modelcontextprotocol/server-github")
    #[arg(long)]
    pub target: String,

    /// Signing key name (from keystore)
    #[arg(long)]
    pub key: String,

    /// Skip writing to audit log
    #[arg(long)]
    pub no_log: bool,

    /// Policy file (YAML/JSON) — evaluate before signing
    #[arg(long)]
    pub policy: Option<String>,
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

    // Parse target command
    let parts: Vec<&str> = args.target.split_whitespace().collect();
    if parts.is_empty() {
        bail!("--target cannot be empty");
    }
    let (cmd, cmd_args) = (parts[0], &parts[1..]);

    eprintln!("[signet proxy] target: {}", args.target);
    eprintln!("[signet proxy] signer: {} ({})", signer_name, info.pubkey);

    // Spawn target MCP server
    let mut child = Command::new(cmd)
        .args(cmd_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit()) // pass server stderr through
        .spawn()
        .map_err(|e| anyhow::anyhow!("failed to spawn '{}': {e}", args.target))?;

    let child_stdin = child.stdin.take().expect("child stdin");
    let child_stdout = child.stdout.take().expect("child stdout");

    // Bidirectional pipe: our stdin → child stdin, child stdout → our stdout
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();

    let no_log = args.no_log;
    let dir_clone = dir.clone();

    // Agent → Server (intercept tools/call, sign, forward)
    let agent_to_server = {
        let sk = sk.clone();
        let signer_name = signer_name.clone();
        let owner = owner.clone();
        let policy = policy.clone();
        let dir = dir_clone.clone();
        async move {
            let mut reader = BufReader::new(stdin);
            let mut writer = child_stdin;
            let mut line = String::new();

            loop {
                line.clear();
                let n = reader.read_line(&mut line).await?;
                if n == 0 {
                    break; // EOF
                }

                let trimmed = line.trim();
                if trimmed.is_empty() {
                    writer.write_all(line.as_bytes()).await?;
                    writer.flush().await?;
                    continue;
                }

                // Try to parse as JSON-RPC and intercept tools/call
                let output = match serde_json::from_str::<serde_json::Value>(trimmed) {
                    Ok(mut msg) => {
                        if is_tools_call(&msg) {
                            if let Err(e) = sign_tools_call(
                                &mut msg, &sk, &signer_name, &owner,
                                policy.as_ref(), &dir, no_log,
                            ) {
                                eprintln!("[signet proxy] sign error: {e}");
                            }
                        }
                        let mut json = serde_json::to_string(&msg)?;
                        json.push('\n');
                        json
                    }
                    Err(_) => line.clone(), // not JSON, pass through
                };

                writer.write_all(output.as_bytes()).await?;
                writer.flush().await?;
            }
            anyhow::Ok(())
        }
    };

    // Server → Agent (pass through, no modification)
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

    // Run both directions concurrently.
    // When agent stdin closes (EOF), we drop child_stdin so the server sees EOF too.
    // Then wait for server stdout to drain before exiting.
    let server_handle = tokio::spawn(server_to_agent);

    tokio::select! {
        r = agent_to_server => {
            if let Err(e) = r {
                eprintln!("[signet proxy] agent→server error: {e}");
            }
            // agent_to_server finished (stdin EOF) — child_stdin is dropped,
            // so the server will see EOF and eventually close stdout.
            // Wait for server responses to drain.
            let _ = server_handle.await;
        }
        _ = tokio::signal::ctrl_c() => {
            eprintln!("[signet proxy] shutting down");
        }
    }

    // Clean up child process
    let _ = child.kill().await;
    Ok(())
}

/// Check if a JSON-RPC message is a tools/call request
fn is_tools_call(msg: &serde_json::Value) -> bool {
    msg.get("method")
        .and_then(|m| m.as_str())
        .map(|m| m == "tools/call")
        .unwrap_or(false)
}

/// Sign a tools/call request and inject the receipt into params._meta._signet
fn sign_tools_call(
    msg: &mut serde_json::Value,
    sk: &ed25519_dalek::SigningKey,
    signer_name: &str,
    signer_owner: &str,
    policy: Option<&signet_core::Policy>,
    dir: &std::path::Path,
    no_log: bool,
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

    let action = signet_core::Action {
        tool: tool_name.clone(),
        params: arguments,
        params_hash: String::new(),
        target: String::new(),
        transport: "stdio".to_string(),
        session: None,
        call_id: None,
        response_hash: None,
    };

    let receipt = if let Some(pol) = policy {
        let eval = signet_core::evaluate_policy(&action, signer_name, pol, None);
        match eval.decision {
            signet_core::RuleAction::Deny => {
                eprintln!("[signet proxy] DENIED: {} ({})", tool_name, eval.reason);
                if !no_log {
                    let _ = signet_core::audit::append_violation(dir, &action, signer_name, &eval);
                }
                bail!("policy violation: {}", eval.reason);
            }
            signet_core::RuleAction::RequireApproval => {
                eprintln!("[signet proxy] NEEDS APPROVAL: {} ({})", tool_name, eval.reason);
                if !no_log {
                    let _ = signet_core::audit::append_violation(dir, &action, signer_name, &eval);
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

    // Log to audit
    if !no_log {
        let receipt_json = serde_json::to_value(&receipt)?;
        signet_core::audit::append(dir, &receipt_json)?;
    }

    // Inject receipt into params._meta._signet
    let receipt_json = serde_json::to_value(&receipt)?;
    let params_mut = msg.get_mut("params").unwrap();
    if params_mut.get("_meta").is_none() {
        params_mut
            .as_object_mut()
            .unwrap()
            .insert("_meta".to_string(), serde_json::json!({}));
    }
    params_mut
        .get_mut("_meta")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert("_signet".to_string(), receipt_json);

    eprintln!(
        "[signet proxy] signed: {} ({})",
        tool_name, receipt.id
    );

    Ok(())
}
