# `@signet-auth/openclaw-plugin` — Release Readiness Assessment

Date: 2026-04-26
Reviewer: deliverable for v0.1.0 ship

## Strategic context

OpenClaw is **363,994 stars / 74,535 forks / 8,497 open issues** as of today. ClawHub is "the canonical discovery surface" (per [docs/plugins/community.md](https://github.com/openclaw/openclaw/blob/main/docs/plugins/community.md)). Listed plugins today include Apify, Opik (Comet observability), Tencent's WeCom/QQbot/DingTalk, and several smaller ones — **no security/audit plugin exists yet**.

Signet on this list = first-mover position in the audit-and-compliance category for a 364K-star ecosystem.

## What's already in place ✅

- [x] `package.json` v0.1.0, MIT/Apache-2.0, complete `exports` and `files`
- [x] `openclaw.plugin.json` with full configSchema (`additionalProperties: false`)
- [x] [src/index.ts](src/index.ts) (271 LOC) implements `before_tool_call`, `after_tool_call`, and `registerSecurityAuditCollector`
- [x] Built `dist/` artifacts present
- [x] [README.md](README.md) (115 lines) covers prerequisites, install, config schema, hooks, verification, compat policy
- [x] Daily contract drift CI ([.github/workflows/openclaw-contract-check.yml](../../.github/workflows/openclaw-contract-check.yml)) against `openclaw/openclaw` main
- [x] Compat policy intentionally uses floor (not tracking target) — well documented
- [x] Security audit collector emits 5 findings (`signet:configured`, `signet:policy`, `signet:trust-bundle`, `signet:fail-mode`, `signet:params-encryption`)
- [x] Hash-chained audit + Ed25519 + policy + XChaCha20-Poly1305 encryption all wired
- [x] `signerOwner` deprecated cleanly (warns on use, kept in schema for backwards compat)
- [x] Fail-closed by default (`blockOnSignFailure: true`)

## Gaps blocking ship 🟥

### Critical — must do before announcing

1. **Not published to npm** — `https://registry.npmjs.org/@signet-auth/openclaw-plugin` returns 404. Until this ships, `openclaw plugins install @signet-auth/openclaw-plugin` will fail.
   - Action: `npm publish --access public` after final review

2. **`@signet-auth/node@0.10.0` dependency must be on npm** — confirmed: it's there ✅

3. **No demo evidence in README** — no GIF, no screenshot, no asciinema cast. ClawHub listings benefit from visual proof.
   - Action: record a 30-60s asciinema of `openclaw start` → tool call → `signet audit --verify` showing receipt count + green chain check

### High — should do before announcing

4. **No "60-second quickstart" at top of README** — current README leads with feature list. ClawHub browsers want copy-paste-runnable.
   - Suggested top section:
     ```
     ## 60-second quickstart
     1. signet identity create openclaw-agent
     2. openclaw plugins install @signet-auth/openclaw-plugin
     3. add { "signet": { "config": {} } } to ~/.openclaw/config.json
     4. openclaw start
     5. signet audit --verify
     ```

5. **No README badges** — npm version, license, OpenClaw compat range. Plugin listings without badges look unfinished next to Apify/Opik.

6. **No CHANGELOG.md** — for a 0.1.0 plugin not strictly required, but ClawHub may want one.

### Medium — nice to have

7. **No `tests/` directory** — `npm test` just runs `tsc`. Even one snapshot test of `signetOpenClawPlugin.register({...})` against a fake `OpenClawApiLike` would catch regressions.

8. **Main Signet README has no "Works with OpenClaw" mention yet** — see top-of-repo `/README.md`. Cross-link both directions.

9. **No GitHub release for plugin sub-package** — main repo tags `v0.9.1` but plugin has no per-package tag. Standard for monorepos but worth a `signet-openclaw-plugin/v0.1.0` tag at publish time.

## Submission path (verified against [openclaw/openclaw#docs/plugins/community.md](https://github.com/openclaw/openclaw/blob/main/docs/plugins/community.md))

OpenClaw's official process is:
1. **Publish to ClawHub (preferred) or npm** — `openclaw plugins install @signet-auth/openclaw-plugin` must work
2. **Host on GitHub** with public repo + issue tracker (already true)
3. **Do NOT open a docs-only PR** to add the plugin to community.md — ClawHub is the discovery surface

So the order of operations is:
1. Fix gaps 1 + 4 (publish + quickstart)
2. Publish to npm
3. (Optional) Publish to ClawHub — investigate `clawhub` CLI and credentials
4. Open a Discussion (NOT an Issue, NOT a docs PR) on `openclaw/openclaw` introducing the plugin
5. Tweet + dev.to tutorial + main Signet README update

## Recommended ship sequence

```
Day 0 (today):       Fix README quickstart + add badges + record demo GIF
Day 1 (tomorrow):    npm publish 0.1.0 + tag signet-openclaw-plugin/v0.1.0
Day 1:               Add "Works with OpenClaw" badge to main repo README
Day 1 evening:       Open openclaw/openclaw Discussion + tweet
Day 2:               dev.to tutorial publishes
Day 3-7:             Monitor install counts, issues, OpenClaw maintainer reaction
```

If OpenClaw maintainers respond positively, accelerate by submitting to ClawHub directly.

## Risks

- **Compat floor `>=2026.3.24-beta.2` is 5 weeks old** — most OpenClaw users are on much newer builds (calendar versioning ships daily). Floor satisfies them all but if anyone still on March beta tries to install, they should be unblocked. Drift CI catches the inverse problem.
- **`SIGNET_PASSPHRASE` env var as the only way to unlock encrypted keys** — fine for local dev, may be friction for users running OpenClaw via systemd/launchd. Consider documenting an alternative or accepting that "encrypt your key on a desktop assistant" is a niche.
- **Plugin shells out to `signet` CLI** — extra binary on `$PATH` is a friction point. Document `cargo install signet-cli` plus release-binary path clearly. Possible future: bundle a Node-native signing path so the CLI is optional.
- **OpenClaw is TypeScript-first** — plugin readers will look for tests in TS, not just `tsc` typecheck. Consider a node:test snapshot in v0.1.1.
