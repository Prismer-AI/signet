use std::collections::HashMap;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::{bail, Result};
use clap::Args;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

/// Env vars always filtered from child process (Signet's own secrets).
const ALWAYS_FILTER: &[&str] = &["SIGNET_PASSPHRASE", "SIGNET_SECRET_KEY"];

/// Common credentials filtered by default. Use `--allow-env NAME` to forward
/// a specific variable to the child process when it is actually required.
const DEFAULT_FILTER_EXACT: &[&str] = &[
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GITHUB_TOKEN",
    "GITLAB_TOKEN",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AZURE_OPENAI_API_KEY",
    "GOOGLE_API_KEY",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "SLACK_BOT_TOKEN",
];

const DEFAULT_FILTER_SUFFIXES: &[&str] = &["_API_KEY", "_TOKEN", "_ACCESS_TOKEN"];

/// Aggressive env filter: strips vars whose name contains these patterns.
/// Only applied when --env-filter is explicitly enabled.
fn is_sensitive_env(name: &str) -> bool {
    let upper = name.to_uppercase();
    upper.contains("SECRET")
        || upper.contains("PASSWORD")
        || upper.contains("PASSPHRASE")
        || upper.contains("PRIVATE_KEY")
        || upper.contains("CREDENTIAL")
}

fn is_default_filtered_env(name: &str) -> bool {
    let upper = name.to_uppercase();
    DEFAULT_FILTER_EXACT
        .iter()
        .any(|candidate| upper == *candidate)
        || DEFAULT_FILTER_SUFFIXES
            .iter()
            .any(|suffix| upper.ends_with(suffix))
}

fn is_env_allowed(name: &str, allow_env: &[String]) -> bool {
    allow_env
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(name))
}

fn should_forward_env(name: &str, allow_env: &[String], aggressive_filter: bool) -> bool {
    if ALWAYS_FILTER
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(name))
    {
        return false;
    }
    if is_env_allowed(name, allow_env) {
        return true;
    }
    if is_default_filtered_env(name) {
        return false;
    }
    if aggressive_filter && is_sensitive_env(name) {
        return false;
    }
    true
}

#[derive(Debug, Clone)]
struct ParsedTarget {
    program: String,
    args: Vec<String>,
}

fn split_command_line(input: &str) -> Result<Vec<String>> {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum QuoteMode {
        None,
        Single,
        Double,
    }

    let mut parts = Vec::new();
    let mut current = String::new();
    let mut quote_mode = QuoteMode::None;
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        match quote_mode {
            QuoteMode::None => match ch {
                '\'' => quote_mode = QuoteMode::Single,
                '"' => quote_mode = QuoteMode::Double,
                '\\' => {
                    let escaped = chars
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("--target ends with an escape"))?;
                    current.push(escaped);
                }
                c if c.is_whitespace() => {
                    if !current.is_empty() {
                        parts.push(std::mem::take(&mut current));
                    }
                }
                _ => current.push(ch),
            },
            QuoteMode::Single => match ch {
                '\'' => quote_mode = QuoteMode::None,
                _ => current.push(ch),
            },
            QuoteMode::Double => match ch {
                '"' => quote_mode = QuoteMode::None,
                '\\' => {
                    let escaped = chars
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("--target ends with an escape"))?;
                    match escaped {
                        '"' | '\\' | '$' | '`' => current.push(escaped),
                        other => {
                            current.push('\\');
                            current.push(other);
                        }
                    }
                }
                _ => current.push(ch),
            },
        }
    }

    if quote_mode != QuoteMode::None {
        bail!("--target has an unterminated quote");
    }
    if !current.is_empty() {
        parts.push(current);
    }
    Ok(parts)
}

fn token_requires_shell(token: &str) -> bool {
    matches!(
        token,
        "|" | "||" | "&&" | ";" | "&" | ">" | ">>" | "<" | "<<" | "2>" | "2>>"
    ) || token.contains("$(")
        || token.contains('`')
}

fn parse_target(target: &str, allow_shell_syntax: bool) -> Result<ParsedTarget> {
    let parts = split_command_line(target)?;
    let Some(program) = parts.first() else {
        bail!("--target cannot be empty");
    };
    if !allow_shell_syntax {
        if let Some(token) = parts.iter().find(|token| token_requires_shell(token)) {
            bail!(
                "--target uses shell syntax ({token}); pass --shell to opt in to shell execution"
            );
        }
    }
    Ok(ParsedTarget {
        program: program.clone(),
        args: parts[1..].to_vec(),
    })
}

fn derive_target_uri(parts: &[String]) -> String {
    let first = parts.first().map(|s| s.as_str()).unwrap_or("local");
    let meaningful = match first {
        "npx" | "node" | "python" | "python3" | "bun" | "deno" | "cargo" | "go" => {
            parts.get(1).map(|s| s.as_str()).unwrap_or(first)
        }
        _ => first,
    };
    let name = std::path::Path::new(meaningful)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(meaningful);
    format!("mcp://{name}")
}

/// Stale pending request timeout (seconds). Entries older than this are
/// evicted. v1 receipt is already logged upfront, so eviction just cleans
/// memory — no audit data is lost.
const PENDING_TTL_SECS: u64 = 1800; // 30 minutes

/// Pending request: receipt waiting for server response to co-sign.
///
/// ## Trust boundary (RPC ID spoofing)
///
/// The bilateral receipt proves "the proxy observed this response for this
/// JSON-RPC request id." It does NOT prove the server acted honestly — a
/// malicious server can return fabricated content for any id. The
/// `response.content_hash` in the bilateral receipt binds the response
/// content cryptographically, so a verifier can later compare the actual
/// response against the hash. But the proxy cannot detect if the server
/// returned a correct response for the wrong id.
struct PendingRequest {
    receipt: signet_core::Receipt,
    tool_name: String,
    created_at: Instant,
}

type PendingMap = Arc<Mutex<HashMap<String, PendingRequest>>>;

enum SignToolsCallDisposition {
    Forwarded,
    LocalResponse {
        response_json: String,
        bilateral_recorded: bool,
    },
}

/// Evict stale entries from the pending map. Returns evicted entries
/// so the caller can log their v1 receipts.
fn evict_stale(pending: &PendingMap, ttl_secs: u64) -> Vec<PendingRequest> {
    let mut map = pending.lock().unwrap_or_else(|p| p.into_inner());
    let cutoff = Instant::now() - std::time::Duration::from_secs(ttl_secs);
    let stale_keys: Vec<String> = map
        .iter()
        .filter(|(_, v)| v.created_at < cutoff)
        .map(|(k, _)| k.clone())
        .collect();
    stale_keys.iter().filter_map(|k| map.remove(k)).collect()
}

#[derive(Args)]
pub struct ProxyArgs {
    /// Target MCP server command (e.g. "npx @modelcontextprotocol/server-github")
    #[arg(long)]
    pub target: String,

    /// Execute --target through a shell (`sh -c` / `cmd /C`).
    /// Disabled by default to avoid shell injection.
    #[arg(long)]
    pub shell: bool,

    /// Signing key name (from keystore)
    #[arg(long)]
    pub key: String,

    /// Persistent server signing key name (from keystore) for bilateral
    /// co-signing. When set, the proxy uses this key for the server-side
    /// signature so trust bundles can pin a stable server identity across
    /// restarts. When omitted, an ephemeral key is generated each run
    /// (suitable for demos but not for enterprise pilots).
    ///
    /// MUST differ from --key (the agent key); the proxy refuses to start
    /// if both resolve to the same identity.
    #[arg(long)]
    pub server_key: Option<String>,

    /// Target URI for audit trail (e.g. "mcp://github.local")
    #[arg(long, default_value = "")]
    pub target_uri: String,

    /// Skip writing to audit log
    #[arg(long)]
    pub no_log: bool,

    /// Policy file (YAML/JSON) — evaluate before signing
    #[arg(long)]
    pub policy: Option<String>,

    /// Enable aggressive env filtering (strips vars with SECRET, PASSWORD, etc.)
    /// By default, common tokens/API keys are already filtered.
    #[arg(long)]
    pub env_filter: bool,

    /// Explicitly allow a filtered env var through to the child process.
    #[arg(long, action = clap::ArgAction::Append, value_name = "NAME")]
    pub allow_env: Vec<String>,
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

    // Server key for bilateral co-signing.
    // MUST be different from the agent signing key — if they're the same,
    // bilateral receipts are meaningless (one key compromise forges both sides).
    //
    // --server-key (persistent, named keystore identity): required for
    // enterprise pilots where trust bundles pin a stable server pubkey.
    // No --server-key (ephemeral): convenient for demos; the server pubkey
    // changes on every restart, so trust bundles cannot anchor it.
    let (server_sk, server_vk, server_key_origin) = match &args.server_key {
        Some(name) => {
            if name == &args.key {
                bail!(
                    "--server-key must differ from --key (got both = '{}'). \
                     Bilateral co-signing requires independent identities.",
                    name
                );
            }
            let server_info = signet_core::load_key_info(&dir, name)?;
            if server_info.pubkey == info.pubkey {
                bail!(
                    "--server-key '{}' resolves to the same pubkey as --key '{}'. \
                     Bilateral co-signing requires independent identities.",
                    name,
                    args.key
                );
            }
            let sk = match signet_core::load_signing_key(&dir, name, None) {
                Ok(sk) => sk,
                Err(_) => {
                    let pass = super::get_passphrase(&format!(
                        "Enter passphrase for server key '{}': ",
                        name
                    ))?;
                    signet_core::load_signing_key(&dir, name, Some(&pass))?
                }
            };
            let vk = sk.verifying_key();
            (sk, vk, format!("persistent: {}", name))
        }
        None => {
            let (sk, vk) = signet_core::generate_keypair();
            (sk, vk, "ephemeral".to_string())
        }
    };
    let server_pubkey_b64 = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(server_vk.to_bytes())
    };

    let policy = if let Some(ref path) = args.policy {
        Some(signet_core::load_policy(std::path::Path::new(path))?)
    } else {
        None
    };

    if args.target.trim().is_empty() {
        bail!("--target cannot be empty");
    }

    let parsed_target = parse_target(&args.target, args.shell)?;
    let display_target = if args.shell {
        args.target.clone()
    } else if parsed_target.args.is_empty() {
        parsed_target.program.clone()
    } else {
        format!("{} {}", parsed_target.program, parsed_target.args.join(" "))
    };

    let target_uri = if args.target_uri.is_empty() {
        let mut parts = Vec::with_capacity(parsed_target.args.len() + 1);
        parts.push(parsed_target.program.clone());
        parts.extend(parsed_target.args.iter().cloned());
        derive_target_uri(&parts)
    } else {
        args.target_uri.clone()
    };

    eprintln!("[signet proxy] target: {}", display_target);
    eprintln!("[signet proxy] target_uri: {}", target_uri);
    eprintln!(
        "[signet proxy] agent key: {} ({})",
        signer_name, info.pubkey
    );
    eprintln!(
        "[signet proxy] server key: {} ({})",
        server_pubkey_b64, server_key_origin
    );
    eprintln!("[signet proxy] bilateral co-signing: enabled (independent keys)");
    eprintln!(
        "[signet proxy] bilateral mode: audit-only; responses are forwarded unchanged. \
         Use client/server helpers for client-visible bilateral artifacts."
    );

    let mut command = if args.shell {
        if cfg!(windows) {
            let mut c = Command::new("cmd");
            c.args(["/C", &args.target]);
            c
        } else {
            let mut c = Command::new("sh");
            c.args(["-c", &args.target]);
            c
        }
    } else {
        let mut c = Command::new(&parsed_target.program);
        c.args(&parsed_target.args);
        c
    };
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());

    // Forward a filtered environment instead of ambient inheritance.
    command.env_clear();
    for (k, v) in std::env::vars() {
        if should_forward_env(&k, &args.allow_env, args.env_filter) {
            command.env(&k, &v);
        }
    }
    if args.shell {
        eprintln!("[signet proxy] shell mode: enabled");
    }
    if args.env_filter {
        eprintln!("[signet proxy] env: aggressive filtering enabled");
    }
    if !args.allow_env.is_empty() {
        eprintln!(
            "[signet proxy] env: allowlisted {}",
            args.allow_env.join(", ")
        );
    }

    let mut child = command
        .spawn()
        .map_err(|e| anyhow::anyhow!("failed to spawn '{}': {e}", display_target))?;

    let child_stdin = child
        .stdin
        .take()
        .ok_or_else(|| anyhow::anyhow!("failed to capture child stdin"))?;
    let child_stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("failed to capture child stdout"))?;

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
        let server_sk = server_sk.clone();
        let call_counter = call_counter.clone();
        let bilateral_counter = bilateral_counter.clone();
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

                // Periodically evict stale pending entries (v1 already logged upfront)
                let stale = evict_stale(&pending, PENDING_TTL_SECS);
                for req in &stale {
                    eprintln!(
                        "[signet proxy] evicted: {} ({}) — no bilateral after {}s",
                        req.tool_name, req.receipt.id, PENDING_TTL_SECS,
                    );
                }

                let output = match serde_json::from_str::<serde_json::Value>(trimmed) {
                    Ok(mut msg) => {
                        if is_tools_call(&msg) {
                            match sign_tools_call(
                                &mut msg,
                                &sk,
                                &server_sk,
                                &signer_name,
                                &owner,
                                policy.as_ref(),
                                &dir,
                                no_log,
                                &target_uri,
                                &pending,
                            ) {
                                Ok(SignToolsCallDisposition::Forwarded) => {
                                    call_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                }
                                Ok(SignToolsCallDisposition::LocalResponse {
                                    response_json,
                                    bilateral_recorded,
                                }) => {
                                    call_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    if bilateral_recorded {
                                        bilateral_counter
                                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    }
                                    out_writer.write_all(response_json.as_bytes()).await?;
                                    out_writer.flush().await?;
                                    continue;
                                }
                                Err(e) => {
                                    let rpc_id =
                                        msg.get("id").cloned().unwrap_or(serde_json::json!(null));
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

    // Server → Agent (intercept responses, bilateral co-sign with server key)
    let server_to_agent = {
        let server_sk = server_sk.clone();
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
                        if is_rpc_response(&msg) {
                            if let Some(rpc_id) = extract_rpc_id(&msg) {
                                let pending_req = pending
                                    .lock()
                                    .unwrap_or_else(|p| p.into_inner())
                                    .remove(&rpc_id);
                                if let Some(req) = pending_req {
                                    // Use result content, or error content for error responses
                                    let response_content = msg
                                        .get("result")
                                        .or_else(|| msg.get("error"))
                                        .cloned()
                                        .unwrap_or(serde_json::json!({}));
                                    let outcome = infer_response_outcome(&msg);
                                    let ts = chrono::Utc::now()
                                        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
                                    match signet_core::sign_bilateral_with_outcome(
                                        &server_sk,
                                        &req.receipt,
                                        &response_content,
                                        "signet-proxy",
                                        &ts,
                                        Some(outcome),
                                    ) {
                                        Ok(bilateral) => {
                                            if !no_log {
                                                match serde_json::to_value(&bilateral) {
                                                    Ok(val) => {
                                                        if let Err(e) =
                                                            signet_core::audit::append(&dir, &val)
                                                        {
                                                            eprintln!("[signet proxy] warning: bilateral audit failed: {e}");
                                                        }
                                                    }
                                                    Err(e) => {
                                                        eprintln!("[signet proxy] warning: bilateral serialize failed: {e}");
                                                    }
                                                }
                                            }
                                            bilateral_counter
                                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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

                // Forward response unmodified. The v3 bilateral receipt goes to the
                // audit log only, NOT injected into the response — modifying the
                // JSON-RPC body would break MCP clients. For client-side bilateral
                // verification, use SigningTransport + onBilateral callback instead.
                writer.write_all(line.as_bytes()).await?;
                writer.flush().await?;
            }
            anyhow::Ok(())
        }
    };

    let mut server_handle = tokio::spawn(server_to_agent);

    tokio::select! {
        r = agent_to_server => {
            if let Err(e) = r {
                eprintln!("[signet proxy] agent→server error: {e}");
            }
            // stdin EOF — wait for server responses to drain
            let _ = server_handle.await;
        }
        r = &mut server_handle => {
            // Server exited (crashed or finished) — stop reading stdin
            match r {
                Ok(Err(e)) => eprintln!("[signet proxy] server exited with error: {e}"),
                Err(e) => eprintln!("[signet proxy] server task failed: {e}"),
                _ => eprintln!("[signet proxy] server exited"),
            }
        }
        _ = tokio::signal::ctrl_c() => {
            eprintln!("[signet proxy] shutting down");
        }
    }

    // Clean up remaining pending entries (v1 already logged upfront).
    {
        let mut map = pending.lock().unwrap_or_else(|p| p.into_inner());
        let remaining = map.len();
        map.clear();
        if remaining > 0 {
            eprintln!("[signet proxy] {remaining} pending call(s) without bilateral response");
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

/// Extract RPC id as a type-prefixed string to distinguish numeric 1 from string "1".
/// JSON-RPC treats them as different ids, so we key the pending map with "n:1" vs "s:1".
fn extract_rpc_id(msg: &serde_json::Value) -> Option<String> {
    msg.get("id").and_then(|id| match id {
        serde_json::Value::Number(n) => Some(format!("n:{n}")),
        serde_json::Value::String(s) => Some(format!("s:{s}")),
        _ => None,
    })
}

fn extract_error_message(value: &serde_json::Value) -> String {
    value
        .get("message")
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned)
        .or_else(|| {
            value
                .get("content")
                .and_then(|c| c.as_array())
                .and_then(|items| items.first())
                .and_then(|item| item.get("text"))
                .and_then(|v| v.as_str())
                .map(ToOwned::to_owned)
        })
        .unwrap_or_else(|| value.to_string())
}

fn infer_response_outcome(msg: &serde_json::Value) -> signet_core::Outcome {
    if let Some(error) = msg.get("error") {
        return signet_core::Outcome::failed(extract_error_message(error));
    }

    if let Some(result) = msg.get("result") {
        if result
            .get("isError")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            return signet_core::Outcome::failed(extract_error_message(result));
        }
    }

    signet_core::Outcome::executed()
}

fn append_audit_value(dir: &std::path::Path, value: &serde_json::Value, warning_label: &str) {
    if let Err(e) = signet_core::audit::append(dir, value) {
        eprintln!("[signet proxy] warning: {warning_label}: {e}");
    }
}

/// Sign a tools/call request, store pending receipt for bilateral, inject into params.
#[allow(clippy::too_many_arguments)]
fn sign_tools_call(
    msg: &mut serde_json::Value,
    sk: &ed25519_dalek::SigningKey,
    server_sk: &ed25519_dalek::SigningKey,
    signer_name: &str,
    signer_owner: &str,
    policy: Option<&signet_core::Policy>,
    dir: &std::path::Path,
    no_log: bool,
    target_uri: &str,
    pending: &PendingMap,
) -> Result<SignToolsCallDisposition> {
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

    let call_id = extract_rpc_id(msg);
    let rpc_id_json = msg.get("id").cloned().unwrap_or(serde_json::json!(null));

    let action = signet_core::Action {
        tool: tool_name.clone(),
        params: arguments,
        params_hash: String::new(),
        target: target_uri.to_string(),
        transport: "stdio".to_string(),
        session: None,
        call_id: call_id.clone(),
        response_hash: None,
        trace_id: None,
        parent_receipt_id: None,
    };

    let receipt = if let Some(pol) = policy {
        let eval = signet_core::evaluate_policy(&action, signer_name, pol, None);
        match eval.decision {
            signet_core::RuleAction::Deny => {
                eprintln!("[signet proxy] DENIED: {} ({})", tool_name, eval.reason);
                let receipt = signet_core::sign(sk, &action, signer_name, signer_owner)?;
                if !no_log {
                    if let Ok(val) = serde_json::to_value(&receipt) {
                        append_audit_value(dir, &val, "audit log failed");
                    }
                }
                eprintln!("[signet proxy] signed: {} ({})", tool_name, receipt.id);

                let error_message = format!("policy violation: {}", eval.reason);
                let error_body = serde_json::json!({
                    "code": -32600,
                    "message": error_message,
                });
                let ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
                let bilateral = signet_core::sign_bilateral_with_outcome(
                    server_sk,
                    &receipt,
                    &error_body,
                    "signet-proxy",
                    &ts,
                    Some(signet_core::Outcome::rejected(eval.reason.clone())),
                )?;
                if !no_log {
                    if let Ok(val) = serde_json::to_value(&bilateral) {
                        append_audit_value(dir, &val, "bilateral audit failed");
                    }
                }
                if !no_log {
                    if let Err(e) =
                        signet_core::audit::append_violation(dir, &action, signer_name, &eval)
                    {
                        eprintln!("[signet proxy] warning: audit log failed: {e}");
                    }
                }
                eprintln!(
                    "[signet proxy] bilateral: {} ({}) ← locally rejected",
                    tool_name, bilateral.id,
                );
                let mut response_json = serde_json::to_string(&serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": rpc_id_json,
                    "error": error_body,
                }))?;
                response_json.push('\n');
                return Ok(SignToolsCallDisposition::LocalResponse {
                    response_json,
                    bilateral_recorded: true,
                });
            }
            signet_core::RuleAction::RequireApproval => {
                eprintln!(
                    "[signet proxy] NEEDS APPROVAL: {} ({})",
                    tool_name, eval.reason
                );
                let receipt = signet_core::sign(sk, &action, signer_name, signer_owner)?;
                if !no_log {
                    if let Ok(val) = serde_json::to_value(&receipt) {
                        append_audit_value(dir, &val, "audit log failed");
                    }
                }
                eprintln!("[signet proxy] signed: {} ({})", tool_name, receipt.id);

                let error_message = format!("requires approval: {}", eval.reason);
                let error_body = serde_json::json!({
                    "code": -32600,
                    "message": error_message,
                });
                let ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
                let bilateral = signet_core::sign_bilateral_with_outcome(
                    server_sk,
                    &receipt,
                    &error_body,
                    "signet-proxy",
                    &ts,
                    Some(signet_core::Outcome::requires_approval(eval.reason.clone())),
                )?;
                if !no_log {
                    if let Ok(val) = serde_json::to_value(&bilateral) {
                        append_audit_value(dir, &val, "bilateral audit failed");
                    }
                }
                if !no_log {
                    if let Err(e) =
                        signet_core::audit::append_violation(dir, &action, signer_name, &eval)
                    {
                        eprintln!("[signet proxy] warning: audit log failed: {e}");
                    }
                }
                eprintln!(
                    "[signet proxy] bilateral: {} ({}) ← waiting for approval",
                    tool_name, bilateral.id,
                );
                let mut response_json = serde_json::to_string(&serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": rpc_id_json,
                    "error": error_body,
                }))?;
                response_json.push('\n');
                return Ok(SignToolsCallDisposition::LocalResponse {
                    response_json,
                    bilateral_recorded: true,
                });
            }
            signet_core::RuleAction::Allow => {
                let (receipt, _) = signet_core::sign_with_policy(
                    sk,
                    &action,
                    signer_name,
                    signer_owner,
                    pol,
                    None,
                )?;
                receipt
            }
        }
    } else {
        signet_core::sign(sk, &action, signer_name, signer_owner)?
    };

    // Always log v1 receipt immediately — ensures audit trail even if proxy
    // crashes before the server responds. The bilateral (v3) receipt is logged
    // separately when the response arrives.
    if !no_log {
        if let Ok(val) = serde_json::to_value(&receipt) {
            if let Err(e) = signet_core::audit::append(dir, &val) {
                eprintln!("[signet proxy] warning: audit log failed: {e}");
            }
        }
    }

    // Store pending for bilateral co-signing (only if we have a valid RPC id)
    if let Some(ref id) = call_id {
        if !id.is_empty() {
            pending.lock().unwrap_or_else(|p| p.into_inner()).insert(
                id.clone(),
                PendingRequest {
                    receipt: receipt.clone(),
                    tool_name: tool_name.clone(),
                    created_at: Instant::now(),
                },
            );
        }
    }

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

    Ok(SignToolsCallDisposition::Forwarded)
}
