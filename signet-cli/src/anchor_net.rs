//! Network side of off-host anchoring. Only built with `--features anchoring`.
//!
//! * [`DeusproofSink`] submits commitments to a DEUSPROOF register and fetches
//!   the RFC 3161 and OpenTimestamps proofs it issues.
//! * [`BitcoinRpc`] reads block headers from the auditor's own Bitcoin Core
//!   node, which is the only Bitcoin trust mode this draft supports.

use std::io::Read;
use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use signet_core::anchor::{
    self, AnchorProof, AnchorRecord, AnchorSink, BitcoinHeaderSource, BlockHeader, SinkSubmission,
};

const USER_AGENT: &str = concat!(
    "signet-cli/",
    env!("CARGO_PKG_VERSION"),
    " (off-host anchoring)"
);
const MAX_PROOF_BYTES: u64 = 1 << 20;

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(30))
        .user_agent(USER_AGENT)
        .build()
}

fn excerpt(s: &str) -> String {
    s.chars().take(300).collect()
}

pub struct DeusproofSink {
    base: String,
    handle: Option<String>,
    agent: ureq::Agent,
}

impl DeusproofSink {
    pub fn new(base: &str, handle: Option<&str>) -> Self {
        DeusproofSink {
            base: base.trim_end_matches('/').to_string(),
            handle: handle.map(str::to_string),
            agent: agent(),
        }
    }

    fn get_bytes(&self, path: &str) -> Result<Option<Vec<u8>>, String> {
        match self.agent.get(&format!("{}{path}", self.base)).call() {
            Ok(resp) => {
                let mut buf = Vec::new();
                resp.into_reader()
                    .take(MAX_PROOF_BYTES)
                    .read_to_end(&mut buf)
                    .map_err(|e| format!("{path}: {e}"))?;
                Ok(Some(buf))
            }
            Err(ureq::Error::Status(404, _)) => Ok(None),
            Err(ureq::Error::Status(code, _)) => Err(format!("{path}: HTTP {code}")),
            Err(e) => Err(format!("{path}: {e}")),
        }
    }

    fn proofs(&self, id: &str) -> Result<Vec<AnchorProof>, String> {
        let mut out = Vec::new();
        if let Some(b) = self.get_bytes(&format!("/api/anchors/ots/{id}"))? {
            out.push(AnchorProof {
                kind: anchor::PROOF_OPENTIMESTAMPS.into(),
                data_b64: B64.encode(b),
            });
        }
        if let Some(b) = self.get_bytes(&format!("/api/anchors/tsr/{id}"))? {
            out.push(AnchorProof {
                kind: anchor::PROOF_RFC3161.into(),
                data_b64: B64.encode(b),
            });
        }
        Ok(out)
    }
}

impl AnchorSink for DeusproofSink {
    fn id(&self) -> &str {
        "deusproof"
    }

    fn submit(&self, commitment: &[u8; 32]) -> Result<SinkSubmission, String> {
        // Only the 32-byte commitment leaves the machine. No name is sent
        // unless the user opted in with --anchor-handle.
        let mut body = serde_json::json!({
            "output_hash": hex::encode(commitment),
            "platform": "signet",
        });
        if let Some(h) = &self.handle {
            body["agent_handle"] = h.clone().into();
        }
        let resp = self
            .agent
            .post(&format!("{}/api/certifications/hash", self.base))
            .set("Content-Type", "application/json")
            .send_string(&body.to_string());
        let text = match resp {
            Ok(r) => r.into_string().map_err(|e| e.to_string())?,
            Err(ureq::Error::Status(code, r)) => {
                return Err(format!(
                    "HTTP {code}: {}",
                    excerpt(&r.into_string().unwrap_or_default())
                ))
            }
            Err(e) => return Err(e.to_string()),
        };
        let v: serde_json::Value =
            serde_json::from_str(&text).map_err(|e| format!("unexpected response: {e}"))?;
        let id = v
            .get("id")
            .and_then(|x| x.as_str())
            .ok_or("response has no record id")?
            .to_string();
        let sealed = anchor::deusproof_sealed_bytes(commitment, &id);
        // Validate the id (and so the whole layout) before using it in any URL.
        anchor::sealed_commitment(anchor::SEALED_DEUSPROOF_SEED_V1, &sealed, &id)?;
        // If the sink already serves the sealed bytes, they must be exactly
        // the documented layout. (It serves them once a proof exists.)
        if let Some(served) = self.get_bytes(&format!("/api/anchors/seed/{id}"))? {
            if served != sealed {
                return Err(
                    "the sealed bytes served by the sink differ from the documented layout".into(),
                );
            }
        }
        let proofs = self.proofs(&id).unwrap_or_default();
        Ok(SinkSubmission {
            sink_ref: id,
            sealed_format: anchor::SEALED_DEUSPROOF_SEED_V1.into(),
            sealed_bytes: sealed,
            proofs,
        })
    }

    fn refresh(&self, record: &AnchorRecord) -> Result<Vec<AnchorProof>, String> {
        self.proofs(&record.sink_ref)
    }
}

/// Block headers from the auditor's own Bitcoin Core node (JSON-RPC).
pub struct BitcoinRpc {
    url: String,
    auth: Option<String>,
    agent: ureq::Agent,
}

impl BitcoinRpc {
    /// `cookie` is Bitcoin Core's `.cookie` file. Without it,
    /// `SIGNET_BITCOIN_RPC_AUTH=user:password` is used if set.
    pub fn new(url: &str, cookie: Option<&str>) -> Result<Self> {
        let userpass = match cookie {
            Some(path) => Some(
                std::fs::read_to_string(path)
                    .with_context(|| format!("reading Bitcoin RPC cookie {path}"))?
                    .trim()
                    .to_string(),
            ),
            None => std::env::var("SIGNET_BITCOIN_RPC_AUTH").ok(),
        };
        Ok(BitcoinRpc {
            url: url.to_string(),
            auth: userpass.map(|up| format!("Basic {}", B64.encode(up))),
            agent: agent(),
        })
    }

    fn call(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value, String> {
        let body = serde_json::json!({
            "jsonrpc": "1.0",
            "id": "signet",
            "method": method,
            "params": params,
        });
        let mut req = self
            .agent
            .post(&self.url)
            .set("Content-Type", "application/json");
        if let Some(a) = &self.auth {
            req = req.set("Authorization", a);
        }
        let text = match req.send_string(&body.to_string()) {
            Ok(r) => r.into_string().map_err(|e| e.to_string())?,
            Err(ureq::Error::Status(401, _)) => {
                return Err("the node rejected the credentials (HTTP 401)".into())
            }
            // Bitcoin Core answers RPC errors with a non-200 status and a JSON body.
            Err(ureq::Error::Status(code, r)) => {
                r.into_string().map_err(|_| format!("HTTP {code}"))?
            }
            Err(e) => return Err(e.to_string()),
        };
        let v: serde_json::Value =
            serde_json::from_str(&text).map_err(|e| format!("{method}: bad response: {e}"))?;
        if let Some(err) = v.get("error").filter(|e| !e.is_null()) {
            return Err(format!("{method}: {err}"));
        }
        v.get("result")
            .cloned()
            .ok_or_else(|| format!("{method}: no result"))
    }
}

impl BitcoinHeaderSource for BitcoinRpc {
    fn header_at(&self, height: u64) -> Result<BlockHeader, String> {
        let hash = self.call("getblockhash", serde_json::json!([height]))?;
        let hash = hash
            .as_str()
            .ok_or("getblockhash: not a string")?
            .to_string();
        let h = self.call("getblockheader", serde_json::json!([hash, true]))?;
        if h.get("height").and_then(|x| x.as_u64()) != Some(height) {
            return Err("the node returned a header for another height".into());
        }
        if h.get("confirmations")
            .and_then(|x| x.as_i64())
            .unwrap_or(-1)
            < 1
        {
            return Err("the block is not on the node's best chain".into());
        }
        let root_hex = h
            .get("merkleroot")
            .and_then(|x| x.as_str())
            .ok_or("getblockheader: no merkleroot")?;
        let mut root = [0u8; 32];
        hex::decode_to_slice(root_hex, &mut root).map_err(|e| format!("merkleroot: {e}"))?;
        root.reverse(); // RPC shows it byte-reversed
        let time = h
            .get("time")
            .and_then(|x| x.as_u64())
            .ok_or("getblockheader: no time")?;
        Ok(BlockHeader {
            merkle_root: root,
            time,
        })
    }
}

fn make_sink(name: &str, url: &str, handle: Option<&str>) -> Result<DeusproofSink> {
    match name {
        "deusproof" => Ok(DeusproofSink::new(url, handle)),
        other => bail!("unknown anchoring sink `{other}` (available: deusproof)"),
    }
}

pub fn anchor_cmd(dir: &Path, sink: &str, url: &str, handle: Option<&str>) -> Result<()> {
    let sink = make_sink(sink, url, handle)?;
    let r = anchor::anchor_now(dir, &sink)?;
    println!("Anchored {} records as {}", r.count, r.commitment);
    println!("Sink record: {} ({})", r.sink_ref, r.sink);
    if r.proofs.is_empty() {
        println!(
            "Proofs: none yet. Run `signet audit --refresh-anchors {}` later.",
            r.sink
        );
    } else {
        let kinds: Vec<&str> = r.proofs.iter().map(|p| p.kind.as_str()).collect();
        println!("Proofs: {}", kinds.join(", "));
    }
    if let Some(h) = handle {
        println!("Filed under the public name `{h}`: anyone can list these anchors by that name.");
    }
    Ok(())
}

pub fn refresh_cmd(
    dir: &Path,
    sink: &str,
    url: &str,
    bitcoin: Option<&dyn BitcoinHeaderSource>,
) -> Result<()> {
    let sink = make_sink(sink, url, None)?;
    let report = anchor::refresh_anchors(dir, &sink, bitcoin)?;
    println!(
        "{} of {} anchor(s) updated, {} failed",
        report.updated,
        report.considered,
        report.errors.len()
    );
    for e in &report.errors {
        eprintln!("  {e}");
    }
    // Partial updates are kept on disk; the exit status still says the
    // refresh did not fully succeed, so a script can tell.
    if !report.errors.is_empty() {
        bail!(
            "anchor refresh failed for {} of {} anchor(s)",
            report.errors.len(),
            report.considered
        );
    }
    Ok(())
}
