use std::collections::HashMap;
use std::time::Duration;

use chrono::Utc;

use crate::policy::{
    compute_policy_hash, MatchSpec, ParamMatchOp, ParamMatcher, Policy, PolicyEvalResult,
    RateLimitScope, Rule, RuleAction, StringMatchOp, StringMatcher,
};
use crate::receipt::Action;

// ─── String Matching ────────────────────────────────────────────────────────

fn matches_string(matcher: &StringMatcher, value: &str) -> bool {
    match matcher {
        StringMatcher::Exact(s) => s == value,
        StringMatcher::Operator(op) => matches_string_op(op, value),
    }
}

fn matches_string_op(op: &StringMatchOp, value: &str) -> bool {
    if let Some(ref list) = op.one_of {
        if !list.iter().any(|s| s == value) {
            return false;
        }
    }
    if let Some(ref list) = op.not_one_of {
        if list.iter().any(|s| s == value) {
            return false;
        }
    }
    if let Some(ref substr) = op.contains {
        if !value.contains(substr.as_str()) {
            return false;
        }
    }
    true
}

// ─── Param Matching ─────────────────────────────────────────────────────────

fn matches_param(matcher: &ParamMatcher, value: &serde_json::Value) -> bool {
    match matcher {
        ParamMatcher::Exact(expected) => value == expected,
        ParamMatcher::Operator(op) => matches_param_op(op, value),
    }
}

fn matches_param_op(op: &ParamMatchOp, value: &serde_json::Value) -> bool {
    // Numeric comparisons
    let as_f64 = value.as_f64();
    if let (Some(threshold), Some(v)) = (op.gt, as_f64) {
        if v <= threshold {
            return false;
        }
    }
    if let (Some(threshold), Some(v)) = (op.gte, as_f64) {
        if v < threshold {
            return false;
        }
    }
    if let (Some(threshold), Some(v)) = (op.lt, as_f64) {
        if v >= threshold {
            return false;
        }
    }
    if let (Some(threshold), Some(v)) = (op.lte, as_f64) {
        if v > threshold {
            return false;
        }
    }
    // If numeric operator is set but value is not numeric, no match
    if (op.gt.is_some() || op.gte.is_some() || op.lt.is_some() || op.lte.is_some())
        && as_f64.is_none()
    {
        return false;
    }
    // Exact equality
    if let Some(ref expected) = op.eq {
        if value != expected {
            return false;
        }
    }
    // one_of
    if let Some(ref list) = op.one_of {
        if !list.contains(value) {
            return false;
        }
    }
    // String contains
    if let Some(ref substr) = op.contains {
        let s = value.as_str().unwrap_or("");
        if !s.contains(substr.as_str()) {
            return false;
        }
    }
    true
}

// ─── MatchSpec ──────────────────────────────────────────────────────────────

fn matches_spec(spec: &MatchSpec, action: &Action, agent_name: &str) -> bool {
    // Tool
    if let Some(ref m) = spec.tool {
        if !matches_string(m, &action.tool) {
            return false;
        }
    }
    // Agent
    if let Some(ref m) = spec.agent {
        if !matches_string(m, agent_name) {
            return false;
        }
    }
    // Target
    if let Some(ref m) = spec.target {
        if !matches_string(m, &action.target) {
            return false;
        }
    }
    // Params
    if let Some(ref param_matchers) = spec.params {
        if let serde_json::Value::Object(ref obj) = action.params {
            for (key, matcher) in param_matchers {
                match obj.get(key) {
                    Some(value) => {
                        if !matches_param(matcher, value) {
                            return false;
                        }
                    }
                    None => return false, // param not present = no match
                }
            }
        } else {
            // params is not an object (null or other) but spec expects params
            return false;
        }
    }
    true
}

// ─── Rate Limiting ──────────────────────────────────────────────────────────

/// In-memory sliding window rate limiter.
pub struct RateLimitState {
    /// Key -> list of call timestamps (chrono UTC for WASM compat)
    buckets: HashMap<String, Vec<chrono::DateTime<Utc>>>,
}

impl RateLimitState {
    pub fn new() -> Self {
        Self {
            buckets: HashMap::new(),
        }
    }

    /// Record a call and check if rate limit is exceeded.
    /// Returns true if within limits, false if exceeded.
    pub fn check_and_record(&mut self, key: &str, max_calls: u32, window: Duration) -> bool {
        let now = Utc::now();
        let cutoff = now - chrono::Duration::from_std(window).unwrap_or(chrono::Duration::zero());

        let bucket = self.buckets.entry(key.to_string()).or_default();
        bucket.retain(|t| *t > cutoff);

        if bucket.len() >= max_calls as usize {
            return false;
        }
        bucket.push(now);
        true
    }

    pub fn reset(&mut self) {
        self.buckets.clear();
    }
}

impl Default for RateLimitState {
    fn default() -> Self {
        Self::new()
    }
}

fn rate_limit_scope_key(rule: &Rule, action: &Action, agent_name: &str) -> String {
    match rule
        .rate_limit
        .as_ref()
        .map(|r| r.scope)
        .unwrap_or(RateLimitScope::PerTool)
    {
        RateLimitScope::PerTool => format!("tool:{}:{}", action.tool, rule.id),
        RateLimitScope::PerAgent => format!("agent:{}:{}", agent_name, rule.id),
        RateLimitScope::Global => format!("global:{}", rule.id),
    }
}

// ─── Evaluate ───────────────────────────────────────────────────────────────

/// Evaluate all rules against an action. Returns the max-severity decision.
/// deny > require_approval > allow.
pub fn evaluate_policy(
    action: &Action,
    agent_name: &str,
    policy: &Policy,
    mut rate_state: Option<&mut RateLimitState>,
) -> PolicyEvalResult {
    let policy_hash = compute_policy_hash(policy).unwrap_or_else(|_| "sha256:error".to_string());
    let evaluated_at = crate::delegation::current_timestamp();

    let mut matched_rules: Vec<String> = Vec::new();
    let mut winning_rule: Option<String> = None;
    let mut max_action = RuleAction::Allow;
    let mut max_reason = String::new();

    for rule in &policy.rules {
        if !matches_spec(&rule.match_spec, action, agent_name) {
            continue;
        }

        // Rate limit check (if present and state provided)
        if let (Some(ref rl), Some(ref mut state)) = (&rule.rate_limit, rate_state.as_deref_mut()) {
            let key = rate_limit_scope_key(rule, action, agent_name);
            let window = Duration::from_secs(rl.window_seconds);
            let within_limit = state.check_and_record(&key, rl.max_calls, window);
            if within_limit {
                // Rate limit not exceeded — this rule's action does not trigger
                // (the rule matches structurally but the rate limit condition isn't met)
                continue;
            }
            // Rate limit exceeded — rule triggers with its action
        } else if rule.rate_limit.is_some() {
            // Rate limit rule but no state provided — skip rate check, match structurally
            // (treat as if rate limit is not exceeded)
            continue;
        }

        matched_rules.push(rule.id.clone());
        if rule.action > max_action {
            max_action = rule.action;
            winning_rule = Some(rule.id.clone());
            max_reason = rule.reason.clone();
        }
    }

    let (decision, reason) = if matched_rules.is_empty() {
        (
            policy.default_action,
            "no rules matched, using default action".to_string(),
        )
    } else {
        (max_action, max_reason)
    };

    PolicyEvalResult {
        decision,
        matched_rules,
        winning_rule,
        reason,
        evaluated_at,
        policy_name: policy.name.clone(),
        policy_hash,
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::*;
    use serde_json::json;

    fn test_action(tool: &str, params: serde_json::Value, target: &str) -> Action {
        Action {
            tool: tool.to_string(),
            params,
            params_hash: String::new(),
            target: target.to_string(),
            transport: "stdio".to_string(),
            session: None,
            call_id: None,
            response_hash: None,
        }
    }

    // ── String matching ──

    #[test]
    fn test_string_match_exact_hit() {
        let m = StringMatcher::Exact("Bash".into());
        assert!(matches_string(&m, "Bash"));
    }

    #[test]
    fn test_string_match_exact_miss() {
        let m = StringMatcher::Exact("Bash".into());
        assert!(!matches_string(&m, "Read"));
    }

    #[test]
    fn test_string_match_one_of_hit() {
        let m = StringMatcher::Operator(StringMatchOp {
            one_of: Some(vec!["Read".into(), "Grep".into()]),
            ..Default::default()
        });
        assert!(matches_string(&m, "Read"));
    }

    #[test]
    fn test_string_match_one_of_miss() {
        let m = StringMatcher::Operator(StringMatchOp {
            one_of: Some(vec!["Read".into(), "Grep".into()]),
            ..Default::default()
        });
        assert!(!matches_string(&m, "Bash"));
    }

    #[test]
    fn test_string_match_not_one_of_hit() {
        let m = StringMatcher::Operator(StringMatchOp {
            not_one_of: Some(vec!["prod".into()]),
            ..Default::default()
        });
        assert!(matches_string(&m, "staging"));
    }

    #[test]
    fn test_string_match_not_one_of_miss() {
        let m = StringMatcher::Operator(StringMatchOp {
            not_one_of: Some(vec!["prod".into()]),
            ..Default::default()
        });
        assert!(!matches_string(&m, "prod"));
    }

    #[test]
    fn test_string_match_contains_hit() {
        let m = StringMatcher::Operator(StringMatchOp {
            contains: Some("rm -rf".into()),
            ..Default::default()
        });
        assert!(matches_string(&m, "sudo rm -rf /"));
    }

    #[test]
    fn test_string_match_contains_miss() {
        let m = StringMatcher::Operator(StringMatchOp {
            contains: Some("rm -rf".into()),
            ..Default::default()
        });
        assert!(!matches_string(&m, "ls -la"));
    }

    // ── Param matching ──

    #[test]
    fn test_param_match_exact() {
        let m = ParamMatcher::Exact(json!("hello"));
        assert!(matches_param(&m, &json!("hello")));
        assert!(!matches_param(&m, &json!("world")));
    }

    #[test]
    fn test_param_match_gt() {
        let m = ParamMatcher::Operator(ParamMatchOp {
            gt: Some(1000.0),
            ..Default::default()
        });
        assert!(matches_param(&m, &json!(1500)));
        assert!(!matches_param(&m, &json!(1000)));
        assert!(!matches_param(&m, &json!(500)));
    }

    #[test]
    fn test_param_match_gte() {
        let m = ParamMatcher::Operator(ParamMatchOp {
            gte: Some(1000.0),
            ..Default::default()
        });
        assert!(matches_param(&m, &json!(1000)));
        assert!(!matches_param(&m, &json!(999)));
    }

    #[test]
    fn test_param_match_lt() {
        let m = ParamMatcher::Operator(ParamMatchOp {
            lt: Some(100.0),
            ..Default::default()
        });
        assert!(matches_param(&m, &json!(50)));
        assert!(!matches_param(&m, &json!(100)));
    }

    #[test]
    fn test_param_match_lte() {
        let m = ParamMatcher::Operator(ParamMatchOp {
            lte: Some(100.0),
            ..Default::default()
        });
        assert!(matches_param(&m, &json!(100)));
        assert!(!matches_param(&m, &json!(101)));
    }

    #[test]
    fn test_param_match_non_numeric_vs_gt() {
        let m = ParamMatcher::Operator(ParamMatchOp {
            gt: Some(100.0),
            ..Default::default()
        });
        assert!(!matches_param(&m, &json!("not a number")));
    }

    #[test]
    fn test_param_match_contains() {
        let m = ParamMatcher::Operator(ParamMatchOp {
            contains: Some("DROP".into()),
            ..Default::default()
        });
        assert!(matches_param(&m, &json!("DROP TABLE users")));
        assert!(!matches_param(&m, &json!("SELECT *")));
    }

    #[test]
    fn test_param_match_one_of() {
        let m = ParamMatcher::Operator(ParamMatchOp {
            one_of: Some(vec![json!("aws"), json!("gcp")]),
            ..Default::default()
        });
        assert!(matches_param(&m, &json!("aws")));
        assert!(!matches_param(&m, &json!("azure")));
    }

    // ── MatchSpec ──

    #[test]
    fn test_match_spec_tool_only() {
        let spec = MatchSpec {
            tool: Some(StringMatcher::Exact("Bash".into())),
            ..Default::default()
        };
        assert!(matches_spec(
            &spec,
            &test_action("Bash", json!({}), ""),
            "agent"
        ));
        assert!(!matches_spec(
            &spec,
            &test_action("Read", json!({}), ""),
            "agent"
        ));
    }

    #[test]
    fn test_match_spec_tool_and_agent() {
        let spec = MatchSpec {
            tool: Some(StringMatcher::Exact("Bash".into())),
            agent: Some(StringMatcher::Exact("bot".into())),
            ..Default::default()
        };
        assert!(matches_spec(
            &spec,
            &test_action("Bash", json!({}), ""),
            "bot"
        ));
        assert!(!matches_spec(
            &spec,
            &test_action("Bash", json!({}), ""),
            "other"
        ));
    }

    #[test]
    fn test_match_spec_target() {
        let spec = MatchSpec {
            target: Some(StringMatcher::Operator(StringMatchOp {
                not_one_of: Some(vec!["mcp://prod".into()]),
                ..Default::default()
            })),
            ..Default::default()
        };
        assert!(matches_spec(
            &spec,
            &test_action("Bash", json!({}), "mcp://staging"),
            "a"
        ));
        assert!(!matches_spec(
            &spec,
            &test_action("Bash", json!({}), "mcp://prod"),
            "a"
        ));
    }

    #[test]
    fn test_match_spec_params() {
        let mut params = HashMap::new();
        params.insert(
            "amount".into(),
            ParamMatcher::Operator(ParamMatchOp {
                gt: Some(1000.0),
                ..Default::default()
            }),
        );
        let spec = MatchSpec {
            tool: Some(StringMatcher::Exact("payment".into())),
            params: Some(params),
            ..Default::default()
        };
        assert!(matches_spec(
            &spec,
            &test_action("payment", json!({"amount": 5000}), ""),
            "a"
        ));
        assert!(!matches_spec(
            &spec,
            &test_action("payment", json!({"amount": 500}), ""),
            "a"
        ));
    }

    #[test]
    fn test_match_spec_missing_param() {
        let mut params = HashMap::new();
        params.insert(
            "amount".into(),
            ParamMatcher::Operator(ParamMatchOp {
                gt: Some(0.0),
                ..Default::default()
            }),
        );
        let spec = MatchSpec {
            params: Some(params),
            ..Default::default()
        };
        assert!(!matches_spec(&spec, &test_action("x", json!({}), ""), "a"));
    }

    #[test]
    fn test_match_spec_empty() {
        let spec = MatchSpec::default();
        assert!(matches_spec(
            &spec,
            &test_action("anything", json!({}), "anywhere"),
            "anyone"
        ));
    }

    // ── evaluate_policy max-severity ──

    fn simple_policy(rules: Vec<Rule>) -> Policy {
        Policy {
            version: 1,
            name: "test".into(),
            description: String::new(),
            default_action: RuleAction::Allow,
            rules,
        }
    }

    fn rule(id: &str, tool: &str, action: RuleAction) -> Rule {
        Rule {
            id: id.into(),
            description: String::new(),
            match_spec: MatchSpec {
                tool: Some(StringMatcher::Exact(tool.into())),
                ..Default::default()
            },
            action,
            reason: format!("rule {} triggered", id),
            rate_limit: None,
        }
    }

    #[test]
    fn test_eval_allow_default() {
        let policy = simple_policy(vec![]);
        let result = evaluate_policy(&test_action("Read", json!({}), ""), "agent", &policy, None);
        assert_eq!(result.decision, RuleAction::Allow);
        assert!(result.matched_rules.is_empty());
    }

    #[test]
    fn test_eval_deny_default() {
        let policy = Policy {
            default_action: RuleAction::Deny,
            ..simple_policy(vec![])
        };
        let result = evaluate_policy(&test_action("Read", json!({}), ""), "agent", &policy, None);
        assert_eq!(result.decision, RuleAction::Deny);
    }

    #[test]
    fn test_eval_single_deny_rule() {
        let policy = simple_policy(vec![rule("r1", "Bash", RuleAction::Deny)]);
        let result = evaluate_policy(&test_action("Bash", json!({}), ""), "agent", &policy, None);
        assert_eq!(result.decision, RuleAction::Deny);
        assert_eq!(result.matched_rules, vec!["r1"]);
    }

    #[test]
    fn test_eval_deny_wins_over_allow() {
        let policy = simple_policy(vec![
            rule("allow-rule", "Bash", RuleAction::Allow),
            rule("deny-rule", "Bash", RuleAction::Deny),
        ]);
        let result = evaluate_policy(&test_action("Bash", json!({}), ""), "agent", &policy, None);
        assert_eq!(result.decision, RuleAction::Deny);
        assert_eq!(result.matched_rules.len(), 2);
        assert_eq!(result.winning_rule, Some("deny-rule".into()));
    }

    #[test]
    fn test_eval_require_approval_between() {
        let policy = simple_policy(vec![
            rule("allow", "Bash", RuleAction::Allow),
            rule("approval", "Bash", RuleAction::RequireApproval),
        ]);
        let result = evaluate_policy(&test_action("Bash", json!({}), ""), "agent", &policy, None);
        assert_eq!(result.decision, RuleAction::RequireApproval);
    }

    #[test]
    fn test_eval_all_matched_rules_reported() {
        let policy = simple_policy(vec![
            rule("r1", "Bash", RuleAction::Allow),
            rule("r2", "Bash", RuleAction::Deny),
            rule("r3", "Read", RuleAction::Deny), // doesn't match
        ]);
        let result = evaluate_policy(&test_action("Bash", json!({}), ""), "agent", &policy, None);
        assert_eq!(result.matched_rules, vec!["r1", "r2"]);
    }

    #[test]
    fn test_eval_policy_hash_populated() {
        let policy = simple_policy(vec![]);
        let result = evaluate_policy(&test_action("Read", json!({}), ""), "agent", &policy, None);
        assert!(result.policy_hash.starts_with("sha256:"));
        assert_eq!(result.policy_name, "test");
    }

    // ── Rate limiting ──

    #[test]
    fn test_rate_limit_under_threshold() {
        let mut state = RateLimitState::new();
        for _ in 0..5 {
            assert!(state.check_and_record("key", 10, Duration::from_secs(60)));
        }
    }

    #[test]
    fn test_rate_limit_at_threshold() {
        let mut state = RateLimitState::new();
        for _ in 0..10 {
            assert!(state.check_and_record("key", 10, Duration::from_secs(60)));
        }
    }

    #[test]
    fn test_rate_limit_exceeded() {
        let mut state = RateLimitState::new();
        for _ in 0..10 {
            state.check_and_record("key", 10, Duration::from_secs(60));
        }
        assert!(!state.check_and_record("key", 10, Duration::from_secs(60)));
    }

    #[test]
    fn test_rate_limit_reset() {
        let mut state = RateLimitState::new();
        for _ in 0..10 {
            state.check_and_record("key", 10, Duration::from_secs(60));
        }
        state.reset();
        assert!(state.check_and_record("key", 10, Duration::from_secs(60)));
    }

    #[test]
    fn test_rate_limit_scope_per_tool() {
        let mut state = RateLimitState::new();
        for _ in 0..10 {
            state.check_and_record("tool:Bash:r1", 10, Duration::from_secs(60));
        }
        // Different tool — separate bucket
        assert!(state.check_and_record("tool:Read:r1", 10, Duration::from_secs(60)));
    }
}
