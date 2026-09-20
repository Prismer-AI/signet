//! Typed constraints — countable or declarative limits attached to grants.
//!
//! Two kinds exist today (spec: docs/specs/principal-authorization-spec.md §6):
//!
//! - `CallCount { max_calls }` — locally enforceable: usage is counted from
//!   receipts (single-host honesty, the `FileNonceChecker` grade).
//! - `Monetary { amount, currency }` — declarative-only: proven in the signed
//!   artifact, enforced by nobody in 0.11. Amounts are decimal *strings*
//!   (never floats — JCS determinism and exact comparison).
//!
//! Constraints are narrowing-only: a decision's constraints may shrink a
//! token's, never widen (enforced from Phase 5 when Scope wiring lands).

use std::cmp::Ordering;

use serde::{Deserialize, Serialize};

use crate::error::SignetError;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Constraint {
    CallCount { max_calls: u64 },
    Monetary { amount: String, currency: String },
}

impl Constraint {
    pub fn validate(&self) -> Result<(), SignetError> {
        match self {
            Constraint::CallCount { max_calls } => {
                if *max_calls == 0 {
                    return Err(SignetError::InvalidConstraint(
                        "call_count max_calls must be >= 1".into(),
                    ));
                }
            }
            Constraint::Monetary { amount, currency } => {
                validate_currency(currency).map_err(|e| {
                    SignetError::InvalidConstraint(format!("monetary currency: {e}"))
                })?;
                parse_decimal(amount)
                    .map_err(|e| SignetError::InvalidConstraint(format!("monetary amount: {e}")))?;
            }
        }
        Ok(())
    }
}

/// ISO 4217 alpha-3: three uppercase ASCII letters.
fn validate_currency(currency: &str) -> Result<(), SignetError> {
    if currency.len() == 3
        && currency
            .chars()
            .all(|c| c.is_ascii_uppercase() && c.is_ascii_alphabetic())
    {
        Ok(())
    } else {
        Err(SignetError::InvalidConstraint(format!(
            "must be ISO 4217 alpha-3 uppercase (e.g. \"USD\"), got \"{currency}\""
        )))
    }
}

/// A non-negative arbitrary-precision decimal: `[0-9]+(\.[0-9]+)?`.
/// Stored verbatim; compared after scale normalization (trailing zeros
/// irrelevant: "5.00" == "5"). Equality is semantic, not structural.
#[derive(Debug, Clone, Eq)]
pub struct Decimal {
    /// Digits with the decimal point removed.
    digits: Vec<u8>,
    /// Number of digits after the decimal point.
    scale: usize,
}

impl PartialEq for Decimal {
    fn eq(&self, other: &Self) -> bool {
        self.cmp_decimal(other) == Ordering::Equal
    }
}

pub fn parse_decimal(s: &str) -> Result<Decimal, SignetError> {
    let err = |msg: &str| {
        SignetError::InvalidConstraint(format!(
            "must be a decimal string like \"500\" or \"500.00\", {msg}, got \"{s}\""
        ))
    };
    let (int_part, frac_part) = match s.split_once('.') {
        Some((i, f)) => (i, Some(f)),
        None => (s, None),
    };

    if int_part.is_empty() || !int_part.chars().all(|c| c.is_ascii_digit()) {
        return Err(err("integer part must be digits"));
    }
    if let Some(f) = frac_part {
        if f.is_empty() || !f.chars().all(|c| c.is_ascii_digit()) {
            return Err(err("fractional part must be digits"));
        }
    }
    // Reject a second dot ("1.2.3" splits into int="1", frac="2.3" which fails
    // the digits check above) and any sign/whitespace.

    let mut digits: Vec<u8> = Vec::with_capacity(s.len());
    digits.extend(int_part.bytes().map(|b| b - b'0'));
    let scale = frac_part.map(|f| f.len()).unwrap_or(0);
    if let Some(f) = frac_part {
        digits.extend(f.bytes().map(|b| b - b'0'));
    }
    let d = Decimal { digits, scale };
    if d.is_zero() {
        return Err(err("must be > 0"));
    }
    Ok(d)
}

impl Decimal {
    fn is_zero(&self) -> bool {
        self.digits.iter().all(|&d| d == 0)
    }

    /// Normalize to a common scale, returning comparable digit vectors.
    /// Both get padded with trailing zeros so scales match and lengths equal.
    fn aligned(a: &Decimal, b: &Decimal) -> (Vec<u8>, Vec<u8>, usize) {
        let scale = a.scale.max(b.scale);
        let mut da = a.digits.clone();
        let mut db = b.digits.clone();
        da.resize(a.digits.len() + (scale - a.scale), 0);
        db.resize(b.digits.len() + (scale - b.scale), 0);
        // Left-pad the shorter integer part so lengths match.
        let len = da.len().max(db.len());
        let ia = len - da.len();
        let ib = len - db.len();
        let mut pa = vec![0u8; ia];
        pa.extend_from_slice(&da);
        let mut pb = vec![0u8; ib];
        pb.extend_from_slice(&db);
        (pa, pb, scale)
    }

    pub fn cmp_decimal(&self, other: &Decimal) -> Ordering {
        let (da, db, _) = Decimal::aligned(self, other);
        da.cmp(&db)
    }
}

/// Convenience: `a <= b` with trailing-zero irrelevance.
pub fn decimal_lte(a: &str, b: &str) -> Result<bool, SignetError> {
    Ok(parse_decimal(a)?.cmp_decimal(&parse_decimal(b)?) != Ordering::Greater)
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_call_count_valid_and_zero_rejected() {
        assert!(Constraint::CallCount { max_calls: 1 }.validate().is_ok());
        assert!(Constraint::CallCount {
            max_calls: 1_000_000
        }
        .validate()
        .is_ok());
        let err = Constraint::CallCount { max_calls: 0 }
            .validate()
            .unwrap_err();
        assert!(matches!(err, SignetError::InvalidConstraint(_)));
    }

    #[test]
    fn test_monetary_valid() {
        assert!(Constraint::Monetary {
            amount: "500".into(),
            currency: "USD".into(),
        }
        .validate()
        .is_ok());
        assert!(Constraint::Monetary {
            amount: "500.00".into(),
            currency: "JPY".into(),
        }
        .validate()
        .is_ok());
    }

    #[test]
    fn test_monetary_bad_currency_rejected() {
        for bad in ["usd", "US", "USDD", "US1", "US$", ""] {
            assert!(
                Constraint::Monetary {
                    amount: "1".into(),
                    currency: bad.into(),
                }
                .validate()
                .is_err(),
                "currency \"{bad}\" should be rejected"
            );
        }
    }

    #[test]
    fn test_monetary_bad_amount_rejected() {
        for bad in [
            "-5", "1.2.3", ".5", "5.", "", " 5", "5 ", "+5", "1e3", "abc", "0", "0.00",
        ] {
            assert!(
                Constraint::Monetary {
                    amount: bad.into(),
                    currency: "USD".into(),
                }
                .validate()
                .is_err(),
                "amount \"{bad}\" should be rejected"
            );
        }
    }

    #[test]
    fn test_decimal_compare_trailing_zeros_irrelevant() {
        assert_eq!(parse_decimal("5").unwrap(), parse_decimal("5.00").unwrap());
        assert_eq!(
            parse_decimal("5")
                .unwrap()
                .cmp_decimal(&parse_decimal("5.00").unwrap()),
            Ordering::Equal
        );
    }

    #[test]
    fn test_decimal_compare_ordering() {
        assert_eq!(
            parse_decimal("4.99")
                .unwrap()
                .cmp_decimal(&parse_decimal("5").unwrap()),
            Ordering::Less
        );
        assert_eq!(
            parse_decimal("5.01")
                .unwrap()
                .cmp_decimal(&parse_decimal("5").unwrap()),
            Ordering::Greater
        );
        assert_eq!(
            parse_decimal("10")
                .unwrap()
                .cmp_decimal(&parse_decimal("9.99").unwrap()),
            Ordering::Greater
        );
        assert_eq!(
            parse_decimal("0.1")
                .unwrap()
                .cmp_decimal(&parse_decimal("0.09").unwrap()),
            Ordering::Greater
        );
    }

    #[test]
    fn test_decimal_compare_big_numbers_exact() {
        // Floats would lose precision here — the reason amounts are strings.
        let a = "9007199254740993.01"; // 2^53 + 1
        let b = "9007199254740993.02";
        assert_eq!(
            parse_decimal(a)
                .unwrap()
                .cmp_decimal(&parse_decimal(b).unwrap()),
            Ordering::Less
        );
        assert!(decimal_lte(a, b).unwrap());
        assert!(!decimal_lte(b, a).unwrap());
    }

    #[test]
    fn test_decimal_lte_helper() {
        assert!(decimal_lte("5", "5").unwrap());
        assert!(decimal_lte("5.00", "5").unwrap());
        assert!(decimal_lte("4.99", "5").unwrap());
        assert!(!decimal_lte("5.001", "5").unwrap());
    }

    // ─── usage / narrowing ───

    #[test]
    fn test_budget_usage_counts_tokens_and_decisions() {
        use crate::delegation::Authorization;
        let mut receipt = crate::receipt::Receipt {
            v: 4,
            id: "rec_x".into(),
            action: crate::receipt::Action {
                tool: "T".into(),
                params: serde_json::json!({}),
                params_hash: "sha256:x".into(),
                target: "mcp://x".into(),
                transport: "stdio".into(),
                session: None,
                call_id: None,
                response_hash: None,
                trace_id: None,
                parent_receipt_id: None,
            },
            signer: crate::receipt::Signer {
                pubkey: "ed25519:AA==".into(),
                name: "bot".into(),
                owner: "alice".into(),
                principal: None,
                acting_for: None,
            },
            authorization: None,
            policy: None,
            authz_decision: None,
            ts: "2026-09-20T00:00:00.000Z".into(),
            exp: None,
            nonce: "rnd_x".into(),
            sig: "ed25519:AA==".into(),
        };
        let _ = Authorization {
            chain: vec![],
            chain_hash: String::new(),
            root_pubkey: String::new(),
        };
        // Two receipts under the same token, one carrying a decision.
        let token = crate::delegation::DelegationToken {
            v: 1,
            id: "del_abc".into(),
            delegator: crate::delegation::DelegationIdentity {
                pubkey: "ed25519:AA==".into(),
                name: "alice".into(),
                principal: None,
            },
            delegate: crate::delegation::DelegationIdentity {
                pubkey: "ed25519:BB==".into(),
                name: "bot".into(),
                principal: None,
            },
            scope: crate::delegation::Scope {
                tools: vec!["*".into()],
                targets: vec!["*".into()],
                max_depth: 0,
                expires: None,
                constraints: None,
            },
            issued_at: "2026-09-20T00:00:00.000Z".into(),
            nonce: "rnd_1".into(),
            sig: "ed25519:AA==".into(),
            correlation_id: None,
        };
        let auth = Authorization {
            chain: vec![token.clone()],
            chain_hash: "sha256:x".into(),
            root_pubkey: "ed25519:AA==".into(),
        };
        receipt.authorization = Some(auth);
        // Give the second copy a decision.
        let mut receipt2 = receipt.clone();
        let (authority_key, _) = crate::identity::generate_keypair();
        let action = receipt.action.clone();
        let intent = crate::authorization::CanonicalIntent::from_action(&action).unwrap();
        let dec = crate::authorization::authorize(
            &authority_key,
            "agent://prismer/security",
            "agent://prismer/bot",
            &intent,
            crate::authorization::DecisionType::Allow,
            crate::authorization::DecisionBasis::Policy {
                policy_hash: "sha256:a".into(),
                policy_name: "p".into(),
                matched_rules: vec![],
                reason: String::new(),
            },
            vec![],
            vec![],
            None,
            None,
        )
        .unwrap();
        receipt2.authz_decision = Some(dec);

        let dec_id = receipt2
            .authz_decision
            .as_ref()
            .unwrap()
            .decision_id
            .clone();
        let usage = BudgetUsage::from_receipts(&[receipt, receipt2]);
        assert_eq!(usage.get("del:del_abc"), 2);
        assert_eq!(usage.get(&format!("dec:{dec_id}")), 1);
        assert_eq!(usage.get("del:nonexistent"), 0);
    }

    #[test]
    fn test_check_call_count_exhausts_at_exactly_max() {
        let mut usage = BudgetUsage::default();
        assert!(check_call_count("k", 2, &usage).is_ok());
        usage = BudgetUsage::from_pairs(vec![("k".to_string(), 1)]);
        assert!(check_call_count("k", 2, &usage).is_ok());
        usage = BudgetUsage::from_pairs(vec![("k".to_string(), 2)]);
        let err = check_call_count("k", 2, &usage).unwrap_err();
        assert!(matches!(err, SignetError::BudgetExhausted { .. }));
    }

    #[test]
    fn test_narrowing_rules() {
        use crate::constraint::constraint_narrows;
        // call_count: equal and smaller narrow; larger widens.
        assert!(constraint_narrows(
            &Constraint::CallCount { max_calls: 5 },
            &Constraint::CallCount { max_calls: 5 },
        )
        .unwrap());
        assert!(constraint_narrows(
            &Constraint::CallCount { max_calls: 3 },
            &Constraint::CallCount { max_calls: 5 },
        )
        .unwrap());
        assert!(!constraint_narrows(
            &Constraint::CallCount { max_calls: 6 },
            &Constraint::CallCount { max_calls: 5 },
        )
        .unwrap());
        // monetary: same currency compares by decimal; cross-currency refuses.
        assert!(constraint_narrows(
            &Constraint::Monetary {
                amount: "4.99".into(),
                currency: "USD".into()
            },
            &Constraint::Monetary {
                amount: "5".into(),
                currency: "USD".into()
            },
        )
        .unwrap());
        assert!(!constraint_narrows(
            &Constraint::Monetary {
                amount: "5.01".into(),
                currency: "USD".into()
            },
            &Constraint::Monetary {
                amount: "5".into(),
                currency: "USD".into()
            },
        )
        .unwrap());
        let err = constraint_narrows(
            &Constraint::Monetary {
                amount: "1".into(),
                currency: "USD".into(),
            },
            &Constraint::Monetary {
                amount: "1".into(),
                currency: "EUR".into(),
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("cross-currency"));
        // different kinds do not interact.
        assert!(constraint_narrows(
            &Constraint::CallCount { max_calls: 100 },
            &Constraint::Monetary {
                amount: "1".into(),
                currency: "USD".into()
            },
        )
        .unwrap());
    }

    #[test]
    fn test_scope_json_with_legacy_budget_still_parses() {
        // v0.10-era token JSON carrying the dead "budget" field must still
        // load — serde drops unknown fields.
        let json = r#"{
            "tools": ["*"], "targets": ["*"], "max_depth": 0,
            "budget": {"amount": 999}
        }"#;
        let scope: crate::delegation::Scope = serde_json::from_str(json).unwrap();
        assert!(scope.constraints.is_none());
        let json = r#"{
            "tools": ["*"], "targets": ["*"], "max_depth": 0,
            "constraints": [{"type": "call_count", "max_calls": 3}]
        }"#;
        let scope: crate::delegation::Scope = serde_json::from_str(json).unwrap();
        assert_eq!(
            scope.constraints.as_deref(),
            Some(&[Constraint::CallCount { max_calls: 3 }][..])
        );
    }

    #[test]
    fn test_constraint_serde_field_names() {
        let c = Constraint::CallCount { max_calls: 10 };
        let json = serde_json::to_string(&c).unwrap();
        assert_eq!(json, r#"{"type":"call_count","max_calls":10}"#);

        let m = Constraint::Monetary {
            amount: "500.00".into(),
            currency: "USD".into(),
        };
        let json = serde_json::to_string(&m).unwrap();
        assert_eq!(
            json,
            r#"{"type":"monetary","amount":"500.00","currency":"USD"}"#
        );

        let back: Constraint = serde_json::from_str(&json).unwrap();
        assert_eq!(back, m);
    }
}

// ─── Usage counting and enforcement (spec §6.2) ─────────────────────────────

use std::collections::HashMap;

/// Per-key usage counts derived from prior receipts. Keys are namespaced:
/// `del:<token_id>` for every token in each receipt's chain (counting
/// against ALL budgeted ancestors — minting child tokens cannot expand a
/// parent's budget), `dec:<decision_id>` for each embedded decision
/// (decision replay visibility, spec §3.6).
#[derive(Debug, Clone, Default)]
pub struct BudgetUsage(HashMap<String, u64>);

impl BudgetUsage {
    /// Test/CLI convenience: build from explicit (key, count) pairs.
    pub fn from_pairs(pairs: Vec<(String, u64)>) -> BudgetUsage {
        BudgetUsage(pairs.into_iter().collect())
    }

    /// Count usage from prior receipts (typically the local audit log —
    /// single-host honesty, the `FileNonceChecker` grade).
    pub fn from_receipts(receipts: &[crate::receipt::Receipt]) -> BudgetUsage {
        let mut map: HashMap<String, u64> = HashMap::new();
        for receipt in receipts {
            if let Some(auth) = receipt.authorization.as_ref() {
                for token in &auth.chain {
                    *map.entry(format!("del:{}", token.id)).or_insert(0) += 1;
                }
            }
            if let Some(dec) = receipt.authz_decision.as_ref() {
                *map.entry(format!("dec:{}", dec.decision_id)).or_insert(0) += 1;
            }
        }
        BudgetUsage(map)
    }

    /// Same counting from raw audit-record receipt values; a receipt that
    /// fails to parse is an error (fail closed — skipping would undercount).
    pub fn from_receipt_values(values: &[serde_json::Value]) -> Result<BudgetUsage, SignetError> {
        let mut receipts = Vec::with_capacity(values.len());
        for v in values {
            receipts.push(serde_json::from_value(v.clone()).map_err(|e| {
                SignetError::InvalidReceipt(format!(
                    "audit receipt does not parse as a Receipt: {e}"
                ))
            })?);
        }
        Ok(BudgetUsage::from_receipts(&receipts))
    }

    pub fn get(&self, key: &str) -> u64 {
        self.0.get(key).copied().unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Audit-time / sign-time call_count check against counted usage.
/// Fails at exactly `max_calls` prior uses (the N+1th call exhausts N).
pub fn check_call_count(key: &str, max_calls: u64, usage: &BudgetUsage) -> Result<(), SignetError> {
    let used = usage.get(key);
    if used >= max_calls {
        return Err(SignetError::BudgetExhausted {
            key: key.to_string(),
            limit: max_calls,
            usage: used,
        });
    }
    Ok(())
}

/// Narrowing-only comparison (spec §6.3): `child` must constrain at most as
/// much as `parent` (≤), never more. Cross-currency monetary pairs are not
/// comparable and refuse outright.
pub fn constraint_narrows(child: &Constraint, parent: &Constraint) -> Result<bool, SignetError> {
    match (child, parent) {
        (Constraint::CallCount { max_calls: c }, Constraint::CallCount { max_calls: p }) => {
            Ok(c <= p)
        }
        (
            Constraint::Monetary {
                amount: ca,
                currency: cc,
            },
            Constraint::Monetary {
                amount: pa,
                currency: pc,
            },
        ) => {
            if cc != pc {
                return Err(SignetError::DecisionInvalid(format!(
                    "cross-currency monetary constraints are not comparable ({cc} vs {pc}); \
                     express constraints in a single currency"
                )));
            }
            Ok(decimal_lte(ca, pa)?)
        }
        // Different kinds do not interact: a call_count does not widen a
        // monetary limit and vice versa.
        _ => Ok(true),
    }
}

/// Check that every decision constraint narrows the token's constraints of
/// the same kind (spec §6.3, enforced by the chain gates).
pub fn check_narrowing(
    decision_constraints: &[Constraint],
    token_constraints: &[Constraint],
) -> Result<(), SignetError> {
    for dc in decision_constraints {
        for tc in token_constraints {
            if std::mem::discriminant(dc) == std::mem::discriminant(tc)
                && !constraint_narrows(dc, tc)?
            {
                return Err(SignetError::DecisionInvalid(format!(
                    "decision constraint widens the delegated scope: {dc:?} vs {tc:?}"
                )));
            }
        }
    }
    Ok(())
}
