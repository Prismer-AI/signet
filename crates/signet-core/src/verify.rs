use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use std::sync::OnceLock;

use crate::canonical;
use crate::error::SignetError;
use crate::receipt::{BilateralReceipt, CompoundReceipt, Receipt};

/// Verify the Ed25519 signature on a v1/v4 receipt. Does NOT check expiration.
fn verify_receipt_signature(receipt: &Receipt, pubkey: &VerifyingKey) -> Result<(), SignetError> {
    let sig_b64 = receipt
        .sig
        .strip_prefix("ed25519:")
        .ok_or_else(|| SignetError::InvalidReceipt("sig missing ed25519: prefix".to_string()))?;
    let sig_bytes = BASE64
        .decode(sig_b64)
        .map_err(|e| SignetError::InvalidReceipt(format!("invalid sig base64: {e}")))?;
    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|e| SignetError::InvalidReceipt(format!("invalid sig bytes: {e}")))?;

    let mut signable = serde_json::json!({
        "v": receipt.v,
        "action": receipt.action,
        "signer": receipt.signer,
        "ts": receipt.ts,
        "nonce": receipt.nonce,
    });
    // Include optional fields in signable when present.
    // JCS canonicalization guarantees key-order independence, so insertion order is irrelevant.
    let obj = signable
        .as_object_mut()
        .ok_or_else(|| SignetError::InvalidReceipt("signable is not a JSON object".into()))?;
    if let Some(ref policy) = receipt.policy {
        obj.insert(
            "policy".to_string(),
            serde_json::to_value(policy).map_err(|e| {
                SignetError::InvalidReceipt(format!("failed to serialize policy: {e}"))
            })?,
        );
    }
    if let Some(ref exp) = receipt.exp {
        obj.insert("exp".to_string(), serde_json::Value::String(exp.clone()));
    }
    let canonical_bytes = canonical::canonicalize(&signable)?;

    pubkey
        .verify(canonical_bytes.as_bytes(), &signature)
        .map_err(|_| SignetError::SignatureMismatch)
}

pub fn verify(receipt: &Receipt, pubkey: &VerifyingKey) -> Result<(), SignetError> {
    verify_receipt_signature(receipt, pubkey)?;

    // Check expiration if present — default verify() is strict.
    if let Some(ref exp) = receipt.exp {
        let exp_dt = chrono::DateTime::parse_from_rfc3339(exp)
            .map_err(|e| SignetError::InvalidReceipt(format!("invalid exp timestamp: {e}")))?;
        if chrono::Utc::now() > exp_dt {
            return Err(SignetError::InvalidReceipt(format!(
                "receipt expired at {exp}"
            )));
        }
    }

    Ok(())
}

/// Verify a receipt allowing expired receipts (for audit/forensic contexts).
pub fn verify_allow_expired(receipt: &Receipt, pubkey: &VerifyingKey) -> Result<(), SignetError> {
    verify_receipt_signature(receipt, pubkey)
}

pub fn verify_compound(
    receipt: &CompoundReceipt,
    pubkey: &VerifyingKey,
) -> Result<(), SignetError> {
    let sig_b64 = receipt
        .sig
        .strip_prefix("ed25519:")
        .ok_or_else(|| SignetError::InvalidReceipt("sig missing ed25519: prefix".to_string()))?;
    let sig_bytes = BASE64
        .decode(sig_b64)
        .map_err(|e| SignetError::InvalidReceipt(format!("invalid sig base64: {e}")))?;
    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|e| SignetError::InvalidReceipt(format!("invalid sig bytes: {e}")))?;

    let signable = serde_json::json!({
        "v": receipt.v,
        "action": receipt.action,
        "response": receipt.response,
        "signer": receipt.signer,
        "ts_request": receipt.ts_request,
        "ts_response": receipt.ts_response,
        "nonce": receipt.nonce,
    });
    let canonical_bytes = canonical::canonicalize(&signable)?;

    pubkey
        .verify(canonical_bytes.as_bytes(), &signature)
        .map_err(|_| SignetError::SignatureMismatch)
}

fn is_server_key_mismatch(error: &SignetError) -> bool {
    matches!(
        error,
        SignetError::InvalidReceipt(message)
            if message == "caller-supplied server key does not match receipt.server.pubkey"
    )
}

/// Version-detecting verify: parses JSON, checks "v", dispatches.
///
/// For v3 bilateral receipts, this uses `BilateralVerifyOptions::default()`
/// (secure-by-default: in-memory nonce replay protection enabled). To
/// customize bilateral verification (audit replay, persistent nonce store,
/// session/call_id binding), call `verify_bilateral_with_options()` directly.
pub fn verify_any(receipt_json: &str, pubkey: &VerifyingKey) -> Result<(), SignetError> {
    let raw: serde_json::Value = serde_json::from_str(receipt_json)
        .map_err(|e| SignetError::InvalidReceipt(format!("invalid JSON: {e}")))?;
    let version = raw.get("v").and_then(|v| v.as_u64()).ok_or_else(|| {
        SignetError::InvalidReceipt("missing or non-integer 'v' field".to_string())
    })?;
    match version {
        1 => {
            let receipt: Receipt = serde_json::from_value(raw)
                .map_err(|e| SignetError::InvalidReceipt(format!("v1 parse: {e}")))?;
            verify(&receipt, pubkey)
        }
        2 => {
            let receipt: CompoundReceipt = serde_json::from_value(raw)
                .map_err(|e| SignetError::InvalidReceipt(format!("v2 parse: {e}")))?;
            verify_compound(&receipt, pubkey)
        }
        3 => {
            // v3 bilateral: dispatches to verify_bilateral() with default
            // options. This applies the standard secure-by-default checks:
            // signatures, 5-minute timestamp window, and in-memory nonce
            // replay protection (10k entries, 1 hour TTL).
            //
            // For audit / forensic replay (where you intentionally want to
            // re-verify previously-seen receipts), call
            // verify_bilateral_with_options() with
            // BilateralVerifyOptions::insecure_no_replay_check().
            let receipt: BilateralReceipt = serde_json::from_value(raw)
                .map_err(|e| SignetError::InvalidReceipt(format!("v3 parse: {e}")))?;
            match verify_bilateral(&receipt, pubkey) {
                Err(error) if is_server_key_mismatch(&error) => Err(SignetError::SignatureMismatch),
                other => other,
            }
        }
        4 => {
            let receipt: Receipt = serde_json::from_value(raw)
                .map_err(|e| SignetError::InvalidReceipt(format!("v4 parse: {e}")))?;
            // Check provided pubkey matches receipt's signer
            let expected_pubkey = format!(
                "ed25519:{}",
                base64::engine::general_purpose::STANDARD.encode(pubkey.to_bytes())
            );
            if receipt.signer.pubkey != expected_pubkey {
                return Err(SignetError::SignatureMismatch);
            }
            crate::verify_delegation::verify_v4_signature_only(&receipt)
        }
        _ => Err(SignetError::InvalidReceipt(format!(
            "unsupported version: {version}"
        ))),
    }
}

/// Trait for checking nonce replay. Implement with any backend (in-memory, Redis, DB).
pub trait NonceChecker: Send + Sync {
    /// Returns true if this nonce has been seen before (should be rejected).
    fn is_replay(&self, nonce: &str) -> bool;
    /// Record that this nonce has been seen.
    fn record(&self, nonce: &str);
}

static DEFAULT_BILATERAL_NONCE_CHECKER: OnceLock<InMemoryNonceChecker> = OnceLock::new();

struct ProcessGlobalNonceChecker;

impl ProcessGlobalNonceChecker {
    fn shared() -> &'static InMemoryNonceChecker {
        DEFAULT_BILATERAL_NONCE_CHECKER.get_or_init(|| InMemoryNonceChecker::new(10_000, 3600))
    }
}

impl NonceChecker for ProcessGlobalNonceChecker {
    fn is_replay(&self, nonce: &str) -> bool {
        Self::shared().is_replay(nonce)
    }

    fn record(&self, nonce: &str) {
        Self::shared().record(nonce);
    }
}

/// In-memory nonce checker with capacity limit and TTL.
///
/// Uses `chrono::Utc::now()` for timestamps so the same implementation
/// works on both native and WASM targets (`std::time::Instant` panics
/// under wasm32-unknown-unknown).
pub struct InMemoryNonceChecker {
    seen: std::sync::Mutex<std::collections::HashMap<String, chrono::DateTime<chrono::Utc>>>,
    max_entries: usize,
    ttl: chrono::Duration,
}

impl InMemoryNonceChecker {
    pub fn new(max_entries: usize, ttl_secs: u64) -> Self {
        Self {
            seen: std::sync::Mutex::new(std::collections::HashMap::new()),
            max_entries,
            ttl: chrono::Duration::seconds(ttl_secs as i64),
        }
    }
}

impl NonceChecker for InMemoryNonceChecker {
    fn is_replay(&self, nonce: &str) -> bool {
        let mut map = self.seen.lock().unwrap_or_else(|p| p.into_inner());
        // Evict expired entries
        let cutoff = chrono::Utc::now() - self.ttl;
        map.retain(|_, ts| *ts > cutoff);
        map.contains_key(nonce)
    }

    fn record(&self, nonce: &str) {
        let mut map = self.seen.lock().unwrap_or_else(|p| p.into_inner());
        // Sweep expired entries first (matches is_replay() behavior).
        let cutoff = chrono::Utc::now() - self.ttl;
        map.retain(|_, ts| *ts > cutoff);
        if map.len() >= self.max_entries {
            // Evict oldest if still over capacity after TTL sweep.
            if let Some(oldest_key) = map.iter().min_by_key(|(_, ts)| *ts).map(|(k, _)| k.clone()) {
                map.remove(&oldest_key);
            }
        }
        map.insert(nonce.to_string(), chrono::Utc::now());
    }
}

/// Nonce checker that persists state to a JSON file, surviving process restarts.
///
/// Format: `{ "<nonce>": "<RFC3339 timestamp>" }`.
///
/// Concurrency model:
/// - An adjacent lock file (`<path>.lock`) is opened with an exclusive
///   advisory file lock (`fs2::FileExt::lock_exclusive`) for the duration
///   of every read+write, so multiple processes pointing at the same
///   path serialize cleanly.
/// - Writes are atomic: the new state is written to `<path>.tmp` then
///   renamed over the live file. A crash mid-write leaves either the
///   pre-write state or the post-write state, never a truncated file.
///
/// TTL eviction is performed on every read and write.
///
/// Suitable for single-host pilot deployments. For multi-host or HA,
/// use a Redis or DB implementation of `NonceChecker` instead.
///
/// Native-only (uses `std::fs` + `fs2`); not available on `wasm32-*` targets.
#[cfg(not(target_arch = "wasm32"))]
pub struct FileNonceChecker {
    path: std::path::PathBuf,
    max_entries: usize,
    ttl: chrono::Duration,
}

#[cfg(not(target_arch = "wasm32"))]
impl FileNonceChecker {
    /// Create a file-backed nonce checker. The path is created on first
    /// `record()` if it doesn't exist.
    pub fn new(
        path: impl Into<std::path::PathBuf>,
        max_entries: usize,
        ttl_secs: u64,
    ) -> Self {
        Self {
            path: path.into(),
            max_entries,
            ttl: chrono::Duration::seconds(ttl_secs as i64),
        }
    }

    fn read_state(&self) -> std::collections::HashMap<String, chrono::DateTime<chrono::Utc>> {
        if !self.path.exists() {
            return std::collections::HashMap::new();
        }
        let contents = match std::fs::read_to_string(&self.path) {
            Ok(s) => s,
            Err(_) => return std::collections::HashMap::new(),
        };
        if contents.trim().is_empty() {
            return std::collections::HashMap::new();
        }
        let raw: std::collections::HashMap<String, String> =
            serde_json::from_str(&contents).unwrap_or_default();
        raw.into_iter()
            .filter_map(|(k, v)| {
                chrono::DateTime::parse_from_rfc3339(&v)
                    .ok()
                    .map(|dt| (k, dt.with_timezone(&chrono::Utc)))
            })
            .collect()
    }

    fn write_state(
        &self,
        map: &std::collections::HashMap<String, chrono::DateTime<chrono::Utc>>,
    ) -> Result<(), SignetError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                SignetError::CorruptedRecord(format!(
                    "failed to create nonce dir {}: {e}",
                    parent.display()
                ))
            })?;
        }
        let raw: std::collections::HashMap<String, String> = map
            .iter()
            .map(|(k, v)| (k.clone(), v.to_rfc3339()))
            .collect();
        let json = serde_json::to_string(&raw).map_err(|e| {
            SignetError::CorruptedRecord(format!("failed to serialize nonce state: {e}"))
        })?;
        // Atomic write: write to <path>.tmp then rename. A crash mid-write
        // leaves either the pre-write state or the new state, never a
        // truncated/corrupt file.
        let tmp_path = {
            let mut p = self.path.clone();
            let mut name = p
                .file_name()
                .map(|n| n.to_os_string())
                .unwrap_or_default();
            name.push(".tmp");
            p.set_file_name(name);
            p
        };
        std::fs::write(&tmp_path, json).map_err(|e| {
            SignetError::CorruptedRecord(format!(
                "failed to write tmp nonce file {}: {e}",
                tmp_path.display()
            ))
        })?;
        std::fs::rename(&tmp_path, &self.path).map_err(|e| {
            SignetError::CorruptedRecord(format!(
                "failed to atomically rename {} -> {}: {e}",
                tmp_path.display(),
                self.path.display()
            ))
        })?;
        Ok(())
    }

    /// Acquire an exclusive advisory file lock on `<path>.lock` for the
    /// scope of one read+write. Multiple processes pointing at the same
    /// nonce file serialize through this lock.
    fn with_lock<F, R>(&self, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        use fs2::FileExt;
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let lock_path = {
            let mut p = self.path.clone();
            let mut name = p
                .file_name()
                .map(|n| n.to_os_string())
                .unwrap_or_default();
            name.push(".lock");
            p.set_file_name(name);
            p
        };
        match std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&lock_path)
        {
            Ok(lock_file) => {
                let _ = lock_file.lock_exclusive();
                let result = f();
                let _ = fs2::FileExt::unlock(&lock_file);
                result
            }
            Err(_) => {
                // If we can't acquire the lock file (e.g. read-only fs), fall
                // back to lockless operation. Single-writer assumption holds.
                f()
            }
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl NonceChecker for FileNonceChecker {
    fn is_replay(&self, nonce: &str) -> bool {
        self.with_lock(|| {
            let mut map = self.read_state();
            let cutoff = chrono::Utc::now() - self.ttl;
            map.retain(|_, ts| *ts > cutoff);
            map.contains_key(nonce)
        })
    }

    fn record(&self, nonce: &str) {
        self.with_lock(|| {
            let mut map = self.read_state();
            let cutoff = chrono::Utc::now() - self.ttl;
            map.retain(|_, ts| *ts > cutoff);
            if map.len() >= self.max_entries {
                if let Some(oldest_key) =
                    map.iter().min_by_key(|(_, ts)| *ts).map(|(k, _)| k.clone())
                {
                    map.remove(&oldest_key);
                }
            }
            map.insert(nonce.to_string(), chrono::Utc::now());
            // Best-effort write; silent failure preserves the no-recovery
            // semantics of the in-memory checker.
            let _ = self.write_state(&map);
        })
    }
}

/// Options for bilateral receipt verification.
pub struct BilateralVerifyOptions {
    /// Maximum allowed seconds between agent signing and server response.
    /// Default: 300 (5 minutes). Set to 0 to disable time window check.
    pub max_time_window_secs: u64,

    /// Optional trusted agent public key. When set, the embedded agent pubkey
    /// in the receipt is checked against this key. Without this, the function
    /// only verifies self-consistency (the agent receipt is valid under *its own*
    /// embedded key) but cannot confirm the agent's identity is authorized.
    pub trusted_agent_pubkey: Option<VerifyingKey>,

    /// Optional expected session ID. When set, the agent receipt's
    /// action.session must match this value.
    pub expected_session: Option<String>,

    /// Optional expected call ID. When set, the agent receipt's
    /// action.call_id must match this value.
    pub expected_call_id: Option<String>,

    /// Optional nonce checker for replay protection. Only the server nonce
    /// is checked — not the agent nonce (which is already verified by the
    /// unilateral path).
    pub nonce_checker: Option<Box<dyn NonceChecker>>,
}

impl Default for BilateralVerifyOptions {
    /// Default options for bilateral verification.
    ///
    /// **Secure-by-default:** an in-memory `NonceChecker` (10k entries,
    /// 1 hour TTL) is enabled to detect server-nonce replay within a single
    /// process, including repeated calls to `verify_bilateral()` and
    /// `verify_any()`. For production, replace with a persistent backend
    /// (Redis, DB) via `BilateralVerifyOptions::with_nonce_checker()`.
    ///
    /// To explicitly disable replay protection (e.g. read-only audit replay
    /// where nonces are expected to repeat), use `BilateralVerifyOptions::insecure_no_replay_check()`.
    fn default() -> Self {
        Self {
            max_time_window_secs: 300,
            trusted_agent_pubkey: None,
            expected_session: None,
            expected_call_id: None,
            nonce_checker: Some(Box::new(ProcessGlobalNonceChecker)),
        }
    }
}

impl BilateralVerifyOptions {
    /// Disable nonce replay checking. **Use only for forensic / audit replay
    /// where you intentionally want to verify previously-seen receipts.**
    pub fn insecure_no_replay_check() -> Self {
        Self {
            max_time_window_secs: 300,
            trusted_agent_pubkey: None,
            expected_session: None,
            expected_call_id: None,
            nonce_checker: None,
        }
    }

    /// Replace the default in-memory nonce checker with a persistent one.
    pub fn with_nonce_checker(mut self, checker: Box<dyn NonceChecker>) -> Self {
        self.nonce_checker = Some(checker);
        self
    }
}

/// Outcome for bilateral verification after signature and timestamp checks pass.
///
/// This only describes whether the embedded agent identity was anchored to an
/// expected public key. Server trust still depends on the caller providing a
/// trusted `server_pubkey` argument rather than a self-reported key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BilateralVerifyOutcome {
    /// The bilateral receipt is internally consistent, but the embedded agent
    /// identity was not checked against a trusted public key.
    AgentSelfConsistent,
    /// The bilateral receipt is internally consistent and the embedded agent
    /// identity matched `trusted_agent_pubkey`.
    AgentTrusted,
}

impl BilateralVerifyOutcome {
    pub fn is_agent_trusted(self) -> bool {
        matches!(self, Self::AgentTrusted)
    }
}

/// Verify a bilateral receipt with default options (5-minute window).
pub fn verify_bilateral(
    receipt: &BilateralReceipt,
    server_pubkey: &VerifyingKey,
) -> Result<(), SignetError> {
    verify_bilateral_detailed(receipt, server_pubkey).map(|_| ())
}

/// Verify a bilateral receipt with default options and return trust detail.
pub fn verify_bilateral_detailed(
    receipt: &BilateralReceipt,
    server_pubkey: &VerifyingKey,
) -> Result<BilateralVerifyOutcome, SignetError> {
    verify_bilateral_with_options_detailed(
        receipt,
        server_pubkey,
        &BilateralVerifyOptions::default(),
    )
}

/// Verify a bilateral receipt with custom options.
pub fn verify_bilateral_with_options(
    receipt: &BilateralReceipt,
    server_pubkey: &VerifyingKey,
    options: &BilateralVerifyOptions,
) -> Result<(), SignetError> {
    verify_bilateral_with_options_detailed(receipt, server_pubkey, options).map(|_| ())
}

/// Verify a bilateral receipt with custom options and return trust detail.
pub fn verify_bilateral_with_options_detailed(
    receipt: &BilateralReceipt,
    server_pubkey: &VerifyingKey,
    options: &BilateralVerifyOptions,
) -> Result<BilateralVerifyOutcome, SignetError> {
    // 0. Cross-check: caller's key must match receipt.server.pubkey
    let receipt_server_b64 = receipt
        .server
        .pubkey
        .strip_prefix("ed25519:")
        .ok_or_else(|| SignetError::InvalidReceipt("server.pubkey missing prefix".to_string()))?;
    let receipt_server_bytes = BASE64
        .decode(receipt_server_b64)
        .map_err(|e| SignetError::InvalidReceipt(format!("server.pubkey base64: {e}")))?;
    if receipt_server_bytes.as_slice() != server_pubkey.as_bytes() {
        return Err(SignetError::InvalidReceipt(
            "caller-supplied server key does not match receipt.server.pubkey".to_string(),
        ));
    }

    // 1. Verify server signature over v3 body
    let sig_b64 = receipt
        .sig
        .strip_prefix("ed25519:")
        .ok_or_else(|| SignetError::InvalidReceipt("sig missing ed25519: prefix".to_string()))?;
    let sig_bytes = BASE64
        .decode(sig_b64)
        .map_err(|e| SignetError::InvalidReceipt(format!("invalid sig base64: {e}")))?;
    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|e| SignetError::InvalidReceipt(format!("invalid sig bytes: {e}")))?;

    let signable = serde_json::json!({
        "v": receipt.v,
        "agent_receipt": receipt.agent_receipt,
        "response": receipt.response,
        "server": receipt.server,
        "ts_response": receipt.ts_response,
        "nonce": receipt.nonce,
    });
    let canonical_bytes = canonical::canonicalize(&signable)?;

    server_pubkey
        .verify(canonical_bytes.as_bytes(), &signature)
        .map_err(|_| SignetError::SignatureMismatch)?;

    // 2. Verify embedded agent receipt using its own pubkey
    let agent_pubkey_b64 = receipt
        .agent_receipt
        .signer
        .pubkey
        .strip_prefix("ed25519:")
        .ok_or_else(|| SignetError::InvalidReceipt("agent pubkey missing prefix".to_string()))?;
    let agent_pubkey_bytes = BASE64
        .decode(agent_pubkey_b64)
        .map_err(|e| SignetError::InvalidReceipt(format!("invalid agent pubkey: {e}")))?;
    let agent_pubkey_arr: [u8; 32] = agent_pubkey_bytes
        .try_into()
        .map_err(|_| SignetError::InvalidReceipt("agent pubkey not 32 bytes".to_string()))?;
    let agent_vk = VerifyingKey::from_bytes(&agent_pubkey_arr)
        .map_err(|e| SignetError::InvalidReceipt(format!("invalid agent pubkey: {e}")))?;

    // 2a. If a trusted agent key was supplied, ensure the receipt's agent key matches
    if let Some(ref trusted) = options.trusted_agent_pubkey {
        if agent_vk.as_bytes() != trusted.as_bytes() {
            return Err(SignetError::InvalidReceipt(
                "agent pubkey in receipt does not match trusted_agent_pubkey".to_string(),
            ));
        }
    }

    verify(&receipt.agent_receipt, &agent_vk)?;

    // 3. Verify timestamp ordering: agent signed before server responded
    let agent_ts = chrono::DateTime::parse_from_rfc3339(&receipt.agent_receipt.ts)
        .map_err(|e| SignetError::InvalidReceipt(format!("invalid agent timestamp: {e}")))?;
    let server_ts = chrono::DateTime::parse_from_rfc3339(&receipt.ts_response)
        .map_err(|e| SignetError::InvalidReceipt(format!("invalid server timestamp: {e}")))?;

    if agent_ts > server_ts {
        return Err(SignetError::InvalidReceipt(
            "agent receipt timestamp is after server response timestamp".to_string(),
        ));
    }

    // 4. Check time window between agent signing and server response
    if options.max_time_window_secs > 0 {
        let gap = server_ts
            .signed_duration_since(agent_ts)
            .num_seconds()
            .unsigned_abs();
        if gap > options.max_time_window_secs {
            return Err(SignetError::InvalidReceipt(format!(
                "time gap between agent and server ({gap}s) exceeds max window ({}s)",
                options.max_time_window_secs
            )));
        }
    }

    // 5. Check session binding (Issue #4)
    if let Some(ref expected) = options.expected_session {
        let actual = receipt
            .agent_receipt
            .action
            .session
            .as_deref()
            .unwrap_or("");
        if actual != expected.as_str() {
            return Err(SignetError::InvalidReceipt(format!(
                "session mismatch: expected '{}', got '{}'",
                expected, actual
            )));
        }
    }

    // 6. Check call_id binding (Issue #4)
    if let Some(ref expected) = options.expected_call_id {
        let actual = receipt
            .agent_receipt
            .action
            .call_id
            .as_deref()
            .unwrap_or("");
        if actual != expected.as_str() {
            return Err(SignetError::InvalidReceipt(format!(
                "call_id mismatch: expected '{}', got '{}'",
                expected, actual
            )));
        }
    }

    // 7. Check server nonce replay (Issue #1)
    // Only check the server nonce — agent nonce is already verified by verify().
    if let Some(ref checker) = options.nonce_checker {
        if checker.is_replay(&receipt.nonce) {
            return Err(SignetError::InvalidReceipt(format!(
                "bilateral nonce replay detected: {}",
                receipt.nonce
            )));
        }
        checker.record(&receipt.nonce);
    }

    Ok(if options.trusted_agent_pubkey.is_some() {
        BilateralVerifyOutcome::AgentTrusted
    } else {
        BilateralVerifyOutcome::AgentSelfConsistent
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::generate_keypair;
    use crate::sign;
    use crate::sign::sign_compound;
    use crate::test_helpers::test_action;
    use serde_json::json;

    #[test]
    fn test_sign_verify_roundtrip() {
        let (signing_key, verifying_key) = generate_keypair();
        let action = test_action();
        let receipt = sign::sign(&signing_key, &action, "agent", "owner").unwrap();
        assert!(verify(&receipt, &verifying_key).is_ok());
    }

    #[test]
    fn test_verify_wrong_key() {
        let (signing_key, _) = generate_keypair();
        let (_, wrong_key) = generate_keypair();
        let action = test_action();
        let receipt = sign::sign(&signing_key, &action, "agent", "owner").unwrap();

        let result = verify(&receipt, &wrong_key);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SignetError::SignatureMismatch
        ));
    }

    #[test]
    fn test_verify_tampered_action() {
        let (signing_key, verifying_key) = generate_keypair();
        let action = test_action();
        let mut receipt = sign::sign(&signing_key, &action, "agent", "owner").unwrap();
        receipt.action.tool = "evil_tool".to_string();

        assert!(matches!(
            verify(&receipt, &verifying_key),
            Err(SignetError::SignatureMismatch)
        ));
    }

    #[test]
    fn test_verify_tampered_signer() {
        let (signing_key, verifying_key) = generate_keypair();
        let action = test_action();
        let mut receipt = sign::sign(&signing_key, &action, "agent", "owner").unwrap();
        receipt.signer.name = "impostor".to_string();

        assert!(matches!(
            verify(&receipt, &verifying_key),
            Err(SignetError::SignatureMismatch)
        ));
    }

    #[test]
    fn test_verify_tampered_timestamp() {
        let (signing_key, verifying_key) = generate_keypair();
        let action = test_action();
        let mut receipt = sign::sign(&signing_key, &action, "agent", "owner").unwrap();
        receipt.ts = "2099-01-01T00:00:00.000Z".to_string();

        assert!(matches!(
            verify(&receipt, &verifying_key),
            Err(SignetError::SignatureMismatch)
        ));
    }

    #[test]
    fn test_verify_tampered_nonce() {
        let (signing_key, verifying_key) = generate_keypair();
        let action = test_action();
        let mut receipt = sign::sign(&signing_key, &action, "agent", "owner").unwrap();
        receipt.nonce = "rnd_0000000000000000".to_string();

        assert!(matches!(
            verify(&receipt, &verifying_key),
            Err(SignetError::SignatureMismatch)
        ));
    }

    fn test_response() -> serde_json::Value {
        json!({"content": [{"type": "text", "text": "issue #42 created"}]})
    }

    #[test]
    fn test_compound_verify_roundtrip() {
        let (sk, vk) = generate_keypair();
        let action = test_action();
        let receipt = sign_compound(
            &sk,
            &action,
            &test_response(),
            "agent",
            "owner",
            "2026-04-02T10:00:00.000Z",
            "2026-04-02T10:00:00.150Z",
        )
        .unwrap();
        assert!(verify_compound(&receipt, &vk).is_ok());
    }

    #[test]
    fn test_compound_verify_wrong_key() {
        let (sk, _) = generate_keypair();
        let (_, wrong_vk) = generate_keypair();
        let action = test_action();
        let receipt = sign_compound(
            &sk,
            &action,
            &test_response(),
            "agent",
            "owner",
            "2026-04-02T10:00:00.000Z",
            "2026-04-02T10:00:00.150Z",
        )
        .unwrap();
        assert!(matches!(
            verify_compound(&receipt, &wrong_vk),
            Err(SignetError::SignatureMismatch)
        ));
    }

    #[test]
    fn test_compound_tampered_action() {
        let (sk, vk) = generate_keypair();
        let action = test_action();
        let mut receipt = sign_compound(
            &sk,
            &action,
            &test_response(),
            "agent",
            "owner",
            "2026-04-02T10:00:00.000Z",
            "2026-04-02T10:00:00.150Z",
        )
        .unwrap();
        receipt.action.tool = "evil_tool".to_string();
        assert!(matches!(
            verify_compound(&receipt, &vk),
            Err(SignetError::SignatureMismatch)
        ));
    }

    #[test]
    fn test_compound_tampered_response() {
        let (sk, vk) = generate_keypair();
        let action = test_action();
        let mut receipt = sign_compound(
            &sk,
            &action,
            &test_response(),
            "agent",
            "owner",
            "2026-04-02T10:00:00.000Z",
            "2026-04-02T10:00:00.150Z",
        )
        .unwrap();
        receipt.response.content_hash = "sha256:tampered".to_string();
        assert!(matches!(
            verify_compound(&receipt, &vk),
            Err(SignetError::SignatureMismatch)
        ));
    }

    #[test]
    fn test_compound_tampered_ts_response() {
        let (sk, vk) = generate_keypair();
        let action = test_action();
        let mut receipt = sign_compound(
            &sk,
            &action,
            &test_response(),
            "agent",
            "owner",
            "2026-04-02T10:00:00.000Z",
            "2026-04-02T10:00:00.150Z",
        )
        .unwrap();
        receipt.ts_response = "2099-01-01T00:00:00.000Z".to_string();
        assert!(matches!(
            verify_compound(&receipt, &vk),
            Err(SignetError::SignatureMismatch)
        ));
    }

    #[test]
    fn test_bilateral_verify_roundtrip() {
        let (agent_key, _) = generate_keypair();
        let (server_key, server_vk) = generate_keypair();
        let action = test_action();
        let agent_receipt = sign::sign(&agent_key, &action, "agent", "owner").unwrap();
        let response = json!({"content": [{"type": "text", "text": "issue #42"}]});
        let ts_response = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let bilateral = sign::sign_bilateral(
            &server_key,
            &agent_receipt,
            &response,
            "github-mcp",
            &ts_response,
        )
        .unwrap();
        assert!(verify_bilateral(&bilateral, &server_vk).is_ok());
    }

    #[test]
    fn test_bilateral_default_rejects_replay_across_convenience_api() {
        let (agent_key, _) = generate_keypair();
        let (server_key, server_vk) = generate_keypair();
        let action = test_action();
        let agent_receipt = sign::sign(&agent_key, &action, "agent", "owner").unwrap();
        let bilateral = sign::sign_bilateral(
            &server_key,
            &agent_receipt,
            &json!({"content": [{"type": "text", "text": "ok"}]}),
            "github-mcp",
            &chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        )
        .unwrap();

        assert!(verify_bilateral(&bilateral, &server_vk).is_ok());
        assert!(matches!(
            verify_bilateral(&bilateral, &server_vk),
            Err(SignetError::InvalidReceipt(ref msg)) if msg.contains("replay")
        ));
    }

    #[test]
    fn test_bilateral_detailed_defaults_to_self_consistent() {
        let (agent_key, agent_vk) = generate_keypair();
        let (server_key, server_vk) = generate_keypair();
        let action = test_action();
        let agent_receipt = sign::sign(&agent_key, &action, "agent", "owner").unwrap();
        let bilateral = sign::sign_bilateral(
            &server_key,
            &agent_receipt,
            &json!({"content": [{"type": "text", "text": "ok"}]}),
            "github-mcp",
            &chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        )
        .unwrap();

        assert_eq!(
            verify_bilateral_detailed(&bilateral, &server_vk).unwrap(),
            BilateralVerifyOutcome::AgentSelfConsistent
        );
        let opts = BilateralVerifyOptions {
            trusted_agent_pubkey: Some(agent_vk),
            ..BilateralVerifyOptions::insecure_no_replay_check()
        };
        assert_eq!(
            verify_bilateral_with_options_detailed(&bilateral, &server_vk, &opts).unwrap(),
            BilateralVerifyOutcome::AgentTrusted
        );
    }

    #[test]
    fn test_bilateral_verify_wrong_server_key() {
        let (agent_key, _) = generate_keypair();
        let (server_key, _) = generate_keypair();
        let (_, wrong_vk) = generate_keypair();
        let action = test_action();
        let agent_receipt = sign::sign(&agent_key, &action, "agent", "owner").unwrap();
        let response = json!({"content": [{"type": "text", "text": "ok"}]});
        let bilateral = sign::sign_bilateral(
            &server_key,
            &agent_receipt,
            &response,
            "github-mcp",
            &chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        )
        .unwrap();
        // With the cross-check, passing a wrong key now returns InvalidReceipt
        // (key mismatch detected before signature verification)
        let result = verify_bilateral(&bilateral, &wrong_vk);
        assert!(result.is_err());
    }

    #[test]
    fn test_bilateral_tampered_response() {
        let (agent_key, _) = generate_keypair();
        let (server_key, server_vk) = generate_keypair();
        let action = test_action();
        let agent_receipt = sign::sign(&agent_key, &action, "agent", "owner").unwrap();
        let response = json!({"content": [{"type": "text", "text": "ok"}]});
        let mut bilateral = sign::sign_bilateral(
            &server_key,
            &agent_receipt,
            &response,
            "github-mcp",
            &chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        )
        .unwrap();
        bilateral.response.content_hash = "sha256:tampered".to_string();
        assert!(matches!(
            verify_bilateral(&bilateral, &server_vk),
            Err(SignetError::SignatureMismatch)
        ));
    }

    #[test]
    fn test_bilateral_tampered_agent_receipt() {
        let (agent_key, _) = generate_keypair();
        let (server_key, server_vk) = generate_keypair();
        let action = test_action();
        let agent_receipt = sign::sign(&agent_key, &action, "agent", "owner").unwrap();
        let response = json!({"content": [{"type": "text", "text": "ok"}]});
        let mut bilateral = sign::sign_bilateral(
            &server_key,
            &agent_receipt,
            &response,
            "github-mcp",
            &chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        )
        .unwrap();
        bilateral.agent_receipt.signer.name = "impostor".to_string();
        assert!(matches!(
            verify_bilateral(&bilateral, &server_vk),
            Err(SignetError::SignatureMismatch)
        ));
    }

    #[test]
    fn test_verify_any_v3_dispatches() {
        let (agent_key, _) = generate_keypair();
        let (server_key, server_vk) = generate_keypair();
        let action = test_action();
        let agent_receipt = sign::sign(&agent_key, &action, "agent", "owner").unwrap();
        let response = json!({"content": [{"type": "text", "text": "ok"}]});
        let bilateral = sign::sign_bilateral(
            &server_key,
            &agent_receipt,
            &response,
            "github-mcp",
            &chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        )
        .unwrap();
        let json = serde_json::to_string(&bilateral).unwrap();
        // verify_any now auto-dispatches v3 to verify_bilateral with the
        // provided pubkey treated as the server pubkey.
        assert!(verify_any(&json, &server_vk).is_ok());

        // Wrong pubkey should still fail. Use a fresh receipt so the
        // in-memory nonce checker (default) doesn't short-circuit on replay.
        let (agent_key2, _) = generate_keypair();
        let agent_receipt2 = sign::sign(&agent_key2, &action, "agent2", "owner").unwrap();
        let bilateral2 = sign::sign_bilateral(
            &server_key,
            &agent_receipt2,
            &response,
            "github-mcp",
            &chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        )
        .unwrap();
        let json2 = serde_json::to_string(&bilateral2).unwrap();
        let (_, wrong_vk) = generate_keypair();
        assert!(matches!(
            verify_any(&json2, &wrong_vk),
            Err(SignetError::SignatureMismatch)
        ));
    }

    #[test]
    fn test_verify_any_v3_rejects_replay_by_default() {
        let (agent_key, _) = generate_keypair();
        let (server_key, server_vk) = generate_keypair();
        let action = test_action();
        let agent_receipt = sign::sign(&agent_key, &action, "agent", "owner").unwrap();
        let bilateral = sign::sign_bilateral(
            &server_key,
            &agent_receipt,
            &json!({"content": [{"type": "text", "text": "ok"}]}),
            "github-mcp",
            &chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        )
        .unwrap();
        let json = serde_json::to_string(&bilateral).unwrap();

        assert!(verify_any(&json, &server_vk).is_ok());
        assert!(matches!(
            verify_any(&json, &server_vk),
            Err(SignetError::InvalidReceipt(ref msg)) if msg.contains("replay")
        ));
    }

    #[test]
    fn test_verify_any_v1() {
        let (sk, vk) = generate_keypair();
        let action = test_action();
        let receipt = sign::sign(&sk, &action, "agent", "owner").unwrap();
        let json = serde_json::to_string(&receipt).unwrap();
        assert!(verify_any(&json, &vk).is_ok());
    }

    #[test]
    fn test_verify_any_v2() {
        let (sk, vk) = generate_keypair();
        let action = test_action();
        let receipt = sign_compound(
            &sk,
            &action,
            &test_response(),
            "agent",
            "owner",
            "2026-04-02T10:00:00.000Z",
            "2026-04-02T10:00:00.150Z",
        )
        .unwrap();
        let json = serde_json::to_string(&receipt).unwrap();
        assert!(verify_any(&json, &vk).is_ok());
    }

    // --- Bilateral timestamp ordering tests ---

    fn make_bilateral_with_ts(ts_response: &str) -> (BilateralReceipt, VerifyingKey) {
        let (agent_key, _) = generate_keypair();
        let (server_key, server_vk) = generate_keypair();
        let action = test_action();
        let agent_receipt = sign::sign(&agent_key, &action, "agent", "owner").unwrap();
        let response = json!({"content": [{"type": "text", "text": "ok"}]});
        let bilateral = sign::sign_bilateral(
            &server_key,
            &agent_receipt,
            &response,
            "test-server",
            ts_response,
        )
        .unwrap();
        (bilateral, server_vk)
    }

    #[test]
    fn test_bilateral_timestamp_ordering_valid() {
        // ts_response must be after agent signs (Utc::now()), so add 1 second
        let ts = (chrono::Utc::now() + chrono::Duration::seconds(1))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let (bilateral, server_vk) = make_bilateral_with_ts(&ts);
        assert!(verify_bilateral(&bilateral, &server_vk).is_ok());
    }

    #[test]
    fn test_bilateral_timestamp_ordering_reversed() {
        // Agent signs now, but server ts_response is 1 hour in the past
        let past = (chrono::Utc::now() - chrono::Duration::hours(1))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let (bilateral, server_vk) = make_bilateral_with_ts(&past);
        let result = verify_bilateral(&bilateral, &server_vk);
        assert!(matches!(
            result,
            Err(SignetError::InvalidReceipt(ref msg)) if msg.contains("after server response")
        ));
    }

    #[test]
    fn test_bilateral_timestamp_gap_exceeded() {
        // Server responds 10 minutes later, but max window is 5 minutes
        let future = (chrono::Utc::now() + chrono::Duration::minutes(10))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let (bilateral, server_vk) = make_bilateral_with_ts(&future);
        let result = verify_bilateral(&bilateral, &server_vk);
        assert!(matches!(
            result,
            Err(SignetError::InvalidReceipt(ref msg)) if msg.contains("exceeds max window")
        ));
    }

    #[test]
    fn test_bilateral_timestamp_gap_within_window() {
        // Server responds 2 minutes later — within default 5 min window
        let future = (chrono::Utc::now() + chrono::Duration::minutes(2))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let (bilateral, server_vk) = make_bilateral_with_ts(&future);
        assert!(verify_bilateral(&bilateral, &server_vk).is_ok());
    }

    #[test]
    fn test_bilateral_timestamp_custom_window() {
        // Server responds 10 minutes later, window set to 20 minutes — ok
        let future = (chrono::Utc::now() + chrono::Duration::minutes(10))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let (bilateral, server_vk) = make_bilateral_with_ts(&future);
        let opts = BilateralVerifyOptions {
            max_time_window_secs: 1200,
            ..Default::default()
        };
        assert!(verify_bilateral_with_options(&bilateral, &server_vk, &opts).is_ok());
    }

    #[test]
    fn test_bilateral_timestamp_window_disabled() {
        // Server responds 1 hour later, but window is disabled (0)
        let future = (chrono::Utc::now() + chrono::Duration::hours(1))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let (bilateral, server_vk) = make_bilateral_with_ts(&future);
        let opts = BilateralVerifyOptions {
            max_time_window_secs: 0,
            ..Default::default()
        };
        assert!(verify_bilateral_with_options(&bilateral, &server_vk, &opts).is_ok());
    }

    // ─── session/call_id cross-check (Issue #4) ──────────────────────

    fn make_bilateral_with_ids(
        session: Option<&str>,
        call_id: Option<&str>,
    ) -> (BilateralReceipt, VerifyingKey) {
        let (agent_key, _) = generate_keypair();
        let (server_key, server_vk) = generate_keypair();
        let mut action = crate::test_helpers::test_action();
        action.session = session.map(|s| s.to_string());
        action.call_id = call_id.map(|s| s.to_string());
        let agent_receipt = crate::sign::sign(&agent_key, &action, "agent", "owner").unwrap();
        let response = serde_json::json!({"text": "ok"});
        let ts = (chrono::Utc::now() + chrono::Duration::seconds(1))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let bilateral =
            crate::sign::sign_bilateral(&server_key, &agent_receipt, &response, "server", &ts)
                .unwrap();
        (bilateral, server_vk)
    }

    #[test]
    fn test_bilateral_session_match() {
        let (bilateral, server_vk) = make_bilateral_with_ids(Some("sess_123"), None);
        let opts = BilateralVerifyOptions {
            expected_session: Some("sess_123".to_string()),
            ..Default::default()
        };
        assert!(verify_bilateral_with_options(&bilateral, &server_vk, &opts).is_ok());
    }

    #[test]
    fn test_bilateral_session_mismatch() {
        let (bilateral, server_vk) = make_bilateral_with_ids(Some("sess_123"), None);
        let opts = BilateralVerifyOptions {
            expected_session: Some("sess_wrong".to_string()),
            ..Default::default()
        };
        let err = verify_bilateral_with_options(&bilateral, &server_vk, &opts).unwrap_err();
        assert!(err.to_string().contains("session mismatch"));
        assert!(err.to_string().contains("sess_wrong"));
        assert!(err.to_string().contains("sess_123"));
    }

    #[test]
    fn test_bilateral_call_id_match() {
        let (bilateral, server_vk) = make_bilateral_with_ids(None, Some("call_abc"));
        let opts = BilateralVerifyOptions {
            expected_call_id: Some("call_abc".to_string()),
            ..Default::default()
        };
        assert!(verify_bilateral_with_options(&bilateral, &server_vk, &opts).is_ok());
    }

    #[test]
    fn test_bilateral_call_id_mismatch() {
        let (bilateral, server_vk) = make_bilateral_with_ids(None, Some("call_abc"));
        let opts = BilateralVerifyOptions {
            expected_call_id: Some("call_xyz".to_string()),
            ..Default::default()
        };
        let err = verify_bilateral_with_options(&bilateral, &server_vk, &opts).unwrap_err();
        assert!(err.to_string().contains("call_id mismatch"));
        assert!(err.to_string().contains("call_xyz"));
        assert!(err.to_string().contains("call_abc"));
    }

    #[test]
    fn test_bilateral_session_unset_skips_check() {
        let (bilateral, server_vk) = make_bilateral_with_ids(Some("sess_123"), None);
        // No expected_session = skip check
        let opts = BilateralVerifyOptions::default();
        assert!(verify_bilateral_with_options(&bilateral, &server_vk, &opts).is_ok());
    }

    // ─── bilateral nonce replay (Issue #1) ───────────────────────────

    #[test]
    fn test_bilateral_nonce_first_time_passes() {
        let (bilateral, server_vk) = make_bilateral_with_ids(None, None);
        let checker = InMemoryNonceChecker::new(100, 300);
        let opts = BilateralVerifyOptions {
            nonce_checker: Some(Box::new(checker)),
            ..Default::default()
        };
        assert!(verify_bilateral_with_options(&bilateral, &server_vk, &opts).is_ok());
    }

    #[test]
    fn test_bilateral_nonce_replay_rejected() {
        let (bilateral, server_vk) = make_bilateral_with_ids(None, None);
        let checker = InMemoryNonceChecker::new(100, 300);
        // First verification: passes and records nonce
        let opts = BilateralVerifyOptions {
            nonce_checker: Some(Box::new(checker)),
            ..Default::default()
        };
        assert!(verify_bilateral_with_options(&bilateral, &server_vk, &opts).is_ok());
        // Second verification with same receipt: replay detected
        let err = verify_bilateral_with_options(&bilateral, &server_vk, &opts).unwrap_err();
        assert!(err.to_string().contains("nonce replay"));
    }

    #[test]
    fn test_bilateral_nonce_different_receipts_pass() {
        let (bilateral1, server_vk1) = make_bilateral_with_ids(None, None);
        let (bilateral2, server_vk2) = make_bilateral_with_ids(None, None);
        let checker = InMemoryNonceChecker::new(100, 300);
        let opts1 = BilateralVerifyOptions {
            nonce_checker: Some(Box::new(checker)),
            ..Default::default()
        };
        assert!(verify_bilateral_with_options(&bilateral1, &server_vk1, &opts1).is_ok());
        assert!(verify_bilateral_with_options(&bilateral2, &server_vk2, &opts1).is_ok());
    }

    #[test]
    fn test_bilateral_nonce_no_checker_skips() {
        let (bilateral, server_vk) = make_bilateral_with_ids(None, None);
        // insecure_no_replay_check() explicitly opts out of nonce checking.
        let opts = BilateralVerifyOptions::insecure_no_replay_check();
        // Can verify same receipt twice with no checker
        assert!(verify_bilateral_with_options(&bilateral, &server_vk, &opts).is_ok());
        assert!(verify_bilateral_with_options(&bilateral, &server_vk, &opts).is_ok());
    }

    #[test]
    fn test_bilateral_default_rejects_replay() {
        let (bilateral, server_vk) = make_bilateral_with_ids(None, None);
        // Default options now have an in-memory nonce checker.
        let opts = BilateralVerifyOptions::default();
        // First verification: ok.
        assert!(verify_bilateral_with_options(&bilateral, &server_vk, &opts).is_ok());
        // Second verification of same nonce: replay detected.
        assert!(matches!(
            verify_bilateral_with_options(&bilateral, &server_vk, &opts),
            Err(SignetError::InvalidReceipt(ref msg)) if msg.contains("replay")
        ));
    }

    // ─── FileNonceChecker (durable across process restarts) ──────────────
    // Native-only — tests reference `FileNonceChecker` which is gated to
    // `not(target_arch = "wasm32")`.

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn test_file_nonce_checker_records_and_detects() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("nonces.json");
        let checker = FileNonceChecker::new(&path, 100, 3600);

        assert!(!checker.is_replay("nonce-A"));
        checker.record("nonce-A");
        assert!(checker.is_replay("nonce-A"));
        assert!(!checker.is_replay("nonce-B"));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn test_file_nonce_checker_survives_restart() {
        // Two FileNonceChecker instances on the same path simulate a
        // process restart. The recorded nonce must still be detected
        // by the second instance.
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("nonces.json");

        // First "process".
        {
            let checker = FileNonceChecker::new(&path, 100, 3600);
            checker.record("durable-nonce");
            assert!(checker.is_replay("durable-nonce"));
        }
        // Second "process" — fresh checker on the same path.
        {
            let checker = FileNonceChecker::new(&path, 100, 3600);
            assert!(
                checker.is_replay("durable-nonce"),
                "nonce recorded by previous process must be detected after restart"
            );
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn test_file_nonce_checker_evicts_expired() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("nonces.json");
        // 0-second TTL means anything is immediately expired.
        let checker = FileNonceChecker::new(&path, 100, 0);
        checker.record("ephemeral-nonce");
        // Sleep slightly to ensure cutoff math (Utc::now() - 0s) excludes
        // the recorded timestamp.
        std::thread::sleep(std::time::Duration::from_millis(10));
        assert!(
            !checker.is_replay("ephemeral-nonce"),
            "expired nonce should be evicted on read"
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn test_file_nonce_checker_caps_at_max_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("nonces.json");
        let checker = FileNonceChecker::new(&path, 3, 3600);
        for i in 0..5 {
            checker.record(&format!("nonce-{i}"));
        }
        // Read state directly. Exactly 3 entries should remain
        // (the most recent 3, oldest evicted).
        let state = checker.read_state();
        assert_eq!(state.len(), 3, "must cap at max_entries");
        assert!(state.contains_key("nonce-4"));
    }
}
