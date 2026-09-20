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
