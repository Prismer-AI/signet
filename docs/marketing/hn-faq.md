# HN 预期问题 + 回答准备

发 Show HN 后，HN 用户会问的问题和准备好的回答。

---

## Q: "This only proves the client signed something. The server never sees or validates it."

A: Correct. v0.1 is client-side attestation, not bilateral verification. The receipt proves the agent *requested* an action, not that the server *executed* it. Server-side verification is v2.

Why ship without it: we want to validate that developers care about signing at all before building the server side. If nobody uses the client SDK, the server SDK is wasted work.

## Q: "What stops a compromised agent from signing malicious actions with its own key?"

A: Nothing — and that's by design. Signet answers "what did agent X do?" not "should agent X be allowed to do this?" Prevention is a different tool (Aegis, policy engines). Signet is the security camera, not the bouncer.

A compromised agent can sign whatever it wants, but it can't sign as a different agent (different key), and it can't retroactively change what it signed (signature is tamper-evident).

## Q: "Why not just use git-like signing on commits/logs?"

A: Git signing is per-commit, not per-action. An agent makes 50 tool calls in one session. We need per-call granularity, not per-session. Also, git signing doesn't integrate with MCP's transport layer.

## Q: "Why Rust + WASM instead of pure TypeScript?"

A: Two reasons. First, we want the same crypto implementation across Rust CLI and TypeScript middleware — one implementation, no divergence. Second, Rust gives us Python (PyO3) and Go bindings for free in the future. Pure TS would be a dead end.

The WASM overhead is ~1ms per sign. Worth it for cross-language consistency.

## Q: "The hash chain can be rewritten if the machine is compromised."

A: Yes. The local hash chain detects accidental or non-privileged tampering, not a full machine compromise. For that, you need off-host anchoring (planned for v2 — something like a transparency log or periodic anchoring to an external service).

We're honest about this in the docs: "tamper-evident (local)" not "tamper-proof."

## Q: "Why not use an existing standard like JOSE/JWS for signing?"

A: JOSE/JWS is designed for token-based auth (sign a claim, verify later). Signet's receipt format is designed for action-level signing (sign a tool call with all its context). The data model is different: we include tool name, params hash, target, nonce, and timestamp as first-class fields, not arbitrary claims.

Also, JCS (RFC 8785) for canonical JSON is simpler than JWS's base64url header.signature format for our use case.

## Q: "How is this different from Aegis/estoppl?"

A: Architecture model.

Aegis/estoppl are proxies — they sit between your agent and the MCP server, intercept traffic, and enforce policies. You deploy a Docker container or daemon.

Signet is an SDK — you add 3 lines of code to your existing MCP client. No extra infrastructure.

They're complementary. Aegis blocks bad actions (prevention). Signet proves what happened (attestation). Use both.

## Q: "Who is this for? Enterprise or developers?"

A: Developers building MCP-based agent applications. v0.1 is a developer tool. Enterprise features (compliance dashboard, policy engine, delegation chains) are v2+ if we see adoption signal.

## Q: "Argon2id with 64MB memory cost — isn't that slow for CI?"

A: Yes, that's why we support `--unencrypted` for CI and `SIGNET_PASSPHRASE` env var for automation. The 64MB Argon2id is for interactive use where you're protecting a long-lived agent key. In CI, use unencrypted keys with short lifetimes.

## Q: "Why Apache-2.0 + MIT dual license?"

A: Maximum compatibility. MIT for maximum permissiveness, Apache-2.0 for patent protection. Same approach as Rust, serde, and most of the Rust ecosystem.
