//! Canonical principal URIs — the identity reference used across receipts,
//! delegation identities, and (in later phases) authorization decisions.
//!
//! Grammar (spec: docs/specs/principal-authorization-spec.md §2.1):
//!
//! ```text
//! principal    := scheme "://" trust_domain [ "/" segment ( "/" segment )* ]
//! scheme       := "user" | "agent" | "agent-instance" | "service" | "org" | "x-" ext
//! trust_domain := [a-z0-9] [a-z0-9.-]{0,253}
//! segment      := [a-z0-9] [a-z0-9._-]{0,127}
//! ```
//!
//! The trust domain is mandatory and reserves the federation slot (SPIFFE
//! precedent): `alice` of tenant A and tenant B are `user://acme/alice` and
//! `user://globex/alice`, never colliding. An empty path (the trust-domain
//! principal itself) is valid only for the `org` scheme — `org://prismer` is
//! the root principal of the `prismer` domain. `x-` schemes are reserved for
//! private extension and always parse.
//!
//! On the wire a principal is always a plain string inside the signed payload;
//! the parsed `Principal` exists only for validation.

use crate::error::SignetError;

pub const KNOWN_SCHEMES: &[&str] = &["user", "agent", "agent-instance", "service", "org"];

const MAX_TRUST_DOMAIN_LEN: usize = 254; // 1 leading char + up to 253
const MAX_SEGMENT_LEN: usize = 128; // 1 leading char + up to 127

/// A parsed principal URI. Validation-only type — schemas carry the string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    pub scheme: String,
    pub trust_domain: String,
    pub path: Vec<String>,
}

fn invalid(uri: &str, msg: impl std::fmt::Display) -> SignetError {
    SignetError::InvalidPrincipal(format!("{msg}: '{uri}'"))
}

fn is_scheme_char(c: char) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'
}

fn is_trust_domain_char(c: char) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-'
}

fn is_segment_char(c: char) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '_' || c == '-'
}

/// Parse and validate a principal URI, returning its components.
pub fn parse_principal(uri: &str) -> Result<Principal, SignetError> {
    let (scheme, rest) = uri
        .split_once("://")
        .ok_or_else(|| invalid(uri, "expected 'scheme://trust-domain[/path]'"))?;

    if scheme.is_empty() {
        return Err(invalid(uri, "empty scheme"));
    }
    if !scheme.chars().all(is_scheme_char) {
        return Err(invalid(
            uri,
            "scheme must be lowercase [a-z0-9-] (no uppercase, digits-only leading is fine)",
        ));
    }
    if !KNOWN_SCHEMES.contains(&scheme) && !scheme.starts_with("x-") {
        return Err(invalid(
            uri,
            format!("unknown scheme '{scheme}' (known: {KNOWN_SCHEMES:?}, or 'x-…' for private extension)"),
        ));
    }

    let (trust_domain, path_str) = match rest.split_once('/') {
        Some((td, p)) => (td, Some(p)),
        None => (rest, None),
    };

    if trust_domain.is_empty() {
        return Err(invalid(uri, "empty trust domain"));
    }
    if !trust_domain.chars().all(is_trust_domain_char) {
        return Err(invalid(uri, "trust domain must be lowercase [a-z0-9.-]"));
    }
    if !trust_domain
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphanumeric())
    {
        return Err(invalid(uri, "trust domain must start with [a-z0-9]"));
    }
    if trust_domain.len() > MAX_TRUST_DOMAIN_LEN {
        return Err(invalid(
            uri,
            format!("trust domain exceeds {MAX_TRUST_DOMAIN_LEN} chars"),
        ));
    }

    let mut path = Vec::new();
    match path_str {
        Some(p) => {
            if p.is_empty() {
                return Err(invalid(uri, "trailing slash (empty final segment)"));
            }
            for seg in p.split('/') {
                if seg.is_empty() {
                    return Err(invalid(uri, "empty path segment (double slash)"));
                }
                if !seg.chars().all(is_segment_char) {
                    return Err(invalid(uri, "path segment must be lowercase [a-z0-9._-]"));
                }
                if !seg
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_alphanumeric())
                {
                    return Err(invalid(uri, "path segment must start with [a-z0-9]"));
                }
                if seg.len() > MAX_SEGMENT_LEN {
                    return Err(invalid(
                        uri,
                        format!("path segment exceeds {MAX_SEGMENT_LEN} chars"),
                    ));
                }
                path.push(seg.to_string());
            }
        }
        None => {
            // Trust-domain-only principal: the domain root itself, org only.
            if scheme != "org" {
                return Err(invalid(
                    uri,
                    format!("'{scheme}' principals require a path after the trust domain (only 'org' may be trust-domain-only, e.g. 'org://prismer')"),
                ));
            }
        }
    }

    Ok(Principal {
        scheme: scheme.to_string(),
        trust_domain: trust_domain.to_string(),
        path,
    })
}

/// Validate a principal URI without keeping the parsed form.
pub fn validate_principal(uri: &str) -> Result<(), SignetError> {
    parse_principal(uri).map(|_| ())
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(uri: &str) -> Principal {
        parse_principal(uri).unwrap_or_else(|e| panic!("{uri} should parse: {e}"))
    }

    fn reject(uri: &str) -> SignetError {
        parse_principal(uri).unwrap_err()
    }

    #[test]
    fn test_valid_schemes_parse() {
        assert_eq!(
            ok("user://prismer/alice"),
            Principal {
                scheme: "user".into(),
                trust_domain: "prismer".into(),
                path: vec!["alice".into()]
            }
        );
        assert_eq!(
            ok("agent://prismer/deploy-bot"),
            Principal {
                scheme: "agent".into(),
                trust_domain: "prismer".into(),
                path: vec!["deploy-bot".into()]
            }
        );
        let p = ok("agent-instance://prismer/sales-agent/93ab");
        assert_eq!(p.scheme, "agent-instance");
        assert_eq!(p.path, vec!["sales-agent".to_string(), "93ab".to_string()]);
        let svc = ok("service://github.com/default");
        assert_eq!(svc.trust_domain, "github.com");
        assert_eq!(svc.path, vec!["default".to_string()]);
    }

    #[test]
    fn test_org_trust_domain_only() {
        assert_eq!(
            ok("org://prismer"),
            Principal {
                scheme: "org".into(),
                trust_domain: "prismer".into(),
                path: vec![]
            }
        );
        // org with a path is also fine (a named principal inside the domain root).
        assert_eq!(ok("org://prismer/root").path, vec!["root".to_string()]);
    }

    #[test]
    fn test_extension_scheme_always_parses() {
        assert!(parse_principal("x-acme://internal/team-7").is_ok());
        assert!(parse_principal("x-anything://a/b").is_ok());
        // x- scheme still needs a path.
        assert!(parse_principal("x-acme://internal").is_err());
    }

    #[test]
    fn test_reject_trust_domain_only_non_org() {
        // The v1-spec flat form — must fail now that the trust-domain slot is mandatory.
        let err = reject("agent://deploy-bot");
        assert!(err.to_string().contains("only 'org'"));
        assert!(matches!(
            reject("user://prismer"),
            SignetError::InvalidPrincipal(_)
        ));
    }

    #[test]
    fn test_reject_uppercase() {
        assert!(parse_principal("Agent://prismer/deploy-bot").is_err());
        assert!(parse_principal("agent://Prismer/deploy-bot").is_err());
        assert!(parse_principal("agent://prismer/DeployBot").is_err());
    }

    #[test]
    fn test_reject_unknown_scheme() {
        let err = reject("unknown://a/b");
        assert!(err.to_string().contains("unknown scheme"));
        // digits-only leading scheme char is allowed by charset but unknown.
        assert!(parse_principal("42://a/b").is_err());
    }

    #[test]
    fn test_reject_malformed_separators() {
        assert!(parse_principal("agent:prismer/deploy-bot").is_err()); // missing //
        assert!(parse_principal("agent:///deploy-bot").is_err()); // empty trust domain
        assert!(parse_principal("agent://prismer/").is_err()); // trailing slash
        assert!(parse_principal("agent://prismer//deploy").is_err()); // empty segment
        assert!(parse_principal("agent://prismer/deploy bot").is_err()); // space
        assert!(parse_principal("agent://prismer/deploy?bot").is_err()); // query char
        assert!(parse_principal("agent://prismer/deploy#bot").is_err()); // fragment char
        assert!(parse_principal("agent://user@prismer/bot").is_err()); // userinfo
    }

    #[test]
    fn test_reject_length_limits() {
        let long_td = format!("a{}.com", "b".repeat(254));
        assert!(parse_principal(&format!("agent://{long_td}/bot")).is_err());

        let long_seg = format!("a{}", "b".repeat(128));
        assert!(parse_principal(&format!("agent://prismer/{long_seg}")).is_err());
    }

    #[test]
    fn test_reject_leading_punctuation() {
        assert!(parse_principal("agent://-prismer/bot").is_err()); // trust domain must start alnum
        assert!(parse_principal("agent://prismer/.bot").is_err()); // segment must start alnum
    }

    #[test]
    fn test_validate_principal_is_parse_alias() {
        assert!(validate_principal("user://prismer/alice").is_ok());
        assert!(validate_principal("nope").is_err());
    }

    #[test]
    fn test_max_lengths_accepted() {
        // Exactly at the limits: 254-char trust domain, 128-char segment.
        let td = format!("a{}", "b".repeat(253));
        let seg = format!("a{}", "b".repeat(127));
        assert!(parse_principal(&format!("agent://{td}/{seg}")).is_ok());
    }
}
