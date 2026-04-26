import { describe, it } from "node:test";
import assert from "node:assert";
import { execFile } from "node:child_process";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { signetOpenClawPlugin } from "../src/index.js";

const execFileAsync = promisify(execFile);
const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "../../../../");
const realSignetBin = join(repoRoot, "target/debug/signet");

interface CapturedFinding {
  checkId: string;
  severity: "info" | "warn" | "critical";
  title: string;
  detail: string;
  remediation?: string;
}

interface CapturedHookCall {
  hookName: string;
  result: unknown;
}

interface RegisterResult {
  api: ReturnType<typeof createFakeApi>;
  state: {
    hooks: Record<string, Function>;
    findings: CapturedFinding[];
    logs: { level: string; msg: string }[];
  };
  callBeforeToolCall: (
    event: { toolName: string; params: Record<string, unknown>; toolCallId?: string; runId?: string },
    ctx?: { sessionKey?: string; runId?: string },
  ) => Promise<{ block?: boolean; blockReason?: string } | void>;
  collectFindings: () => Promise<CapturedFinding[]>;
}

function createFakeApi(pluginConfig: Record<string, unknown>) {
  const hooks: Record<string, Function> = {};
  const collectors: Array<(ctx: any) => any> = [];
  const logs: { level: string; msg: string }[] = [];
  const logger = {
    info: (msg: string) => logs.push({ level: "info", msg }),
    warn: (msg: string) => logs.push({ level: "warn", msg }),
    error: (msg: string) => logs.push({ level: "error", msg }),
    debug: (msg: string) => logs.push({ level: "debug", msg }),
  };
  return {
    pluginConfig,
    logger,
    on(name: string, handler: Function) {
      hooks[name] = handler;
    },
    registerSecurityAuditCollector(collector: (ctx: any) => any) {
      collectors.push(collector);
    },
    _hooks: hooks,
    _collectors: collectors,
    _logs: logs,
  };
}

async function createSignetHome(): Promise<string> {
  return mkdtemp(join(tmpdir(), "signet-openclaw-test-"));
}

async function createIdentity(home: string, name: string, opts: { passphrase?: string } = {}) {
  const args = ["identity", "generate", "--name", name];
  const env: NodeJS.ProcessEnv = { ...process.env, SIGNET_HOME: home };
  if (opts.passphrase) {
    env.SIGNET_PASSPHRASE = opts.passphrase;
  } else {
    args.push("--unencrypted");
  }
  await execFileAsync(realSignetBin, args, { env });
}

async function loadPlugin(
  config: Record<string, unknown>,
): Promise<RegisterResult> {
  const api = createFakeApi(config);
  await signetOpenClawPlugin.register(api as any);
  return {
    api,
    state: { hooks: api._hooks, findings: [], logs: api._logs },
    async callBeforeToolCall(event, ctx = {}) {
      const handler = api._hooks["before_tool_call"];
      const fullCtx = { toolName: event.toolName, ...ctx };
      return handler(event as any, fullCtx as any);
    },
    async collectFindings() {
      const out: CapturedFinding[] = [];
      for (const c of api._collectors) {
        const r = await c({});
        out.push(...r);
      }
      return out;
    },
  };
}

describe("@signet-auth/openclaw-plugin", () => {
  it("(a) fail-closed default: no signet binary -> first tool call BLOCKED with actionable error", async () => {
    const home = await createSignetHome();
    // Point signetBin at a path that doesn't exist
    const plugin = await loadPlugin({
      signetBin: join(home, "no-such-signet"),
      auditDir: home,
      // blockOnSignFailure default true, allowDegraded default false
    });

    const result = await plugin.callBeforeToolCall({ toolName: "bash", params: { cmd: "ls" } });

    assert.equal(result?.block, true, "first tool call must be blocked when self-check failed");
    assert.match(
      String(result?.blockReason),
      /signet sign failed/,
      `blockReason must reference sign failure, got: ${result?.blockReason}`,
    );
    // Startup logs should already have surfaced the actionable error.
    const errorLogs = plugin.state.logs.filter((l) => l.level === "error");
    assert.ok(
      errorLogs.some((l) => /self-check FAILED/i.test(l.msg)),
      `expected startup self-check FAILED log, got: ${JSON.stringify(errorLogs)}`,
    );
    assert.ok(
      errorLogs.some((l) => /BLOCKED until you fix this/i.test(l.msg)),
      "expected explicit BLOCKED warning at startup",
    );
  });

  it("(b) allowDegraded=true with missing identity: PASSIVE mode, tool call allowed, audit collector emits signet:bypass=critical", async () => {
    const home = await createSignetHome();
    // Real binary, real home, but no identity created.
    const plugin = await loadPlugin({
      signetBin: realSignetBin,
      auditDir: home,
      allowDegraded: true,
    });

    const result = await plugin.callBeforeToolCall({ toolName: "bash", params: { cmd: "ls" } });
    assert.deepEqual(result, {}, "passive mode must allow tool call (return {})");

    const findings = await plugin.collectFindings();
    const bypass = findings.find((f) => f.checkId === "signet:bypass");
    assert.ok(bypass, "signet:bypass finding must be emitted in passive mode");
    assert.equal(bypass.severity, "critical");
    assert.match(bypass.detail, /UNSIGNED and UNAUDITED|allowDegraded=true/i);

    const readiness = findings.find((f) => f.checkId === "signet:readiness");
    assert.ok(readiness);
    assert.equal(readiness.severity, "critical");
    assert.match(readiness.title, /PASSIVE/);
  });

  it("(c) recovery: passive plugin transitions to active after operator fixes setup (next call after reprobe interval)", async () => {
    const home = await createSignetHome();
    const plugin = await loadPlugin({
      signetBin: realSignetBin,
      auditDir: home,
      allowDegraded: true,
      reprobeIntervalMs: 50, // tight to keep test fast
    });

    // Initial call: passive (no identity) -> allowed, unsigned.
    const r1 = await plugin.callBeforeToolCall({ toolName: "bash", params: { cmd: "ls" } });
    assert.deepEqual(r1, {});

    // Operator creates the identity
    await createIdentity(home, "openclaw-agent");

    // Wait past reprobe interval
    await new Promise((res) => setTimeout(res, 75));

    // Next call triggers sync reprobe -> active, then signs successfully
    const r2 = await plugin.callBeforeToolCall(
      { toolName: "bash", params: { cmd: "ls" }, toolCallId: "c-1" },
      { sessionKey: "session-1" },
    );
    assert.deepEqual(r2, {}, "first post-recovery call should sign successfully and return {}");

    const recoveryLogs = plugin.state.logs.filter((l) => /recovered to ACTIVE/i.test(l.msg));
    assert.ok(recoveryLogs.length >= 1, "recovery transition must be logged");

    // Audit findings should now report operational
    const findings = await plugin.collectFindings();
    const readiness = findings.find((f) => f.checkId === "signet:readiness");
    assert.ok(readiness);
    assert.equal(readiness.severity, "info");
    assert.match(readiness.title, /operational/);
    assert.equal(
      findings.find((f) => f.checkId === "signet:bypass"),
      undefined,
      "signet:bypass should not be emitted after recovery",
    );
  });

  it("(d) policy + allowDegraded REJECTED at register() time so passive cannot bypass policy", async () => {
    const home = await createSignetHome();
    const policyPath = join(home, "deny-all.yaml");
    await writeFile(
      policyPath,
      `name: deny-all
default_action: deny
rules: []
`,
    );

    await assert.rejects(
      () =>
        loadPlugin({
          signetBin: realSignetBin,
          auditDir: home,
          policy: policyPath,
          allowDegraded: true,
        }),
      (err: unknown) => {
        const message = err instanceof Error ? err.message : String(err);
        assert.match(
          message,
          /allowDegraded cannot be combined with a configured policy/,
          `expected explicit incompatibility error, got: ${message}`,
        );
        assert.match(
          message,
          /Passive mode bypasses the signet sign call where policy evaluation runs/,
        );
        return true;
      },
    );
  });

  it("happy path: real identity, healthy self-check -> ACTIVE mode, sign succeeds", async () => {
    const home = await createSignetHome();
    await createIdentity(home, "openclaw-agent");

    const plugin = await loadPlugin({
      signetBin: realSignetBin,
      auditDir: home,
    });

    const findings = await plugin.collectFindings();
    const readiness = findings.find((f) => f.checkId === "signet:readiness");
    assert.equal(readiness?.severity, "info", "ACTIVE mode readiness must be info");
    assert.match(String(readiness?.title), /operational/);

    const result = await plugin.callBeforeToolCall(
      { toolName: "bash", params: { cmd: "ls" }, toolCallId: "c-1" },
      { sessionKey: "session-1" },
    );
    assert.deepEqual(result, {}, "happy path sign returns {} (no block)");
  });

  it("(e) malformed policy file is caught by self-check, not by first tool call", async () => {
    const home = await createSignetHome();
    await createIdentity(home, "openclaw-agent");
    const policyPath = join(home, "broken-policy.yaml");
    await writeFile(policyPath, "this is: not valid: signet policy yaml: : :\n");

    const plugin = await loadPlugin({
      signetBin: realSignetBin,
      auditDir: home,
      policy: policyPath,
    });

    // Self-check should have failed at register() time; readiness=critical
    const findings = await plugin.collectFindings();
    const readiness = findings.find((f) => f.checkId === "signet:readiness");
    assert.equal(
      readiness?.severity,
      "critical",
      `broken policy should make readiness critical, got ${readiness?.severity}`,
    );
    const policyFinding = findings.find((f) => f.checkId === "signet:policy");
    assert.equal(
      policyFinding?.severity,
      "critical",
      "policy finding must escalate to critical when configured but plugin not operational",
    );
  });

  it("(f) blockOnSignFailure=false + failed self-check -> signet:bypass=critical fires", async () => {
    const home = await createSignetHome();
    // Real binary, real home, NO identity. blockOnSignFailure=false makes
    // sign errors fail-open. allowDegraded stays false (default), so plugin
    // loads in active mode but signActiveCall will silently swallow errors.
    const plugin = await loadPlugin({
      signetBin: realSignetBin,
      auditDir: home,
      blockOnSignFailure: false,
    });

    // Tool call should NOT block (because blockOnSignFailure=false)
    const result = await plugin.callBeforeToolCall({ toolName: "bash", params: { cmd: "ls" } });
    assert.deepEqual(
      result,
      {},
      "blockOnSignFailure=false must let the call through even on sign failure",
    );

    // But audit collector MUST surface the bypass even though we are in
    // active mode (not passive). This is the codex round 3 finding: prior
    // version only emitted signet:bypass when mode=passive.
    const findings = await plugin.collectFindings();
    const bypass = findings.find((f) => f.checkId === "signet:bypass");
    assert.ok(bypass, "signet:bypass must fire when sign fails AND blockOnSignFailure=false");
    assert.equal(bypass.severity, "critical");
    assert.match(bypass.detail, /blockOnSignFailure=false|UNSIGNED and UNAUDITED/i);
  });

  it("(g) fail-closed startup + later successful sign clears stale readiness state", async () => {
    const home = await createSignetHome();
    // Plugin loads with no identity -> active mode but startup self-check fails.
    const plugin = await loadPlugin({
      signetBin: realSignetBin,
      auditDir: home,
    });

    // Verify initial state is critical
    const findings1 = await plugin.collectFindings();
    assert.equal(findings1.find((f) => f.checkId === "signet:readiness")?.severity, "critical");

    // Operator fixes setup
    await createIdentity(home, "openclaw-agent");

    // First post-fix call: signActiveCall succeeds, state must clear
    const result = await plugin.callBeforeToolCall(
      { toolName: "bash", params: { cmd: "ls" }, toolCallId: "c-1" },
      { sessionKey: "s" },
    );
    assert.deepEqual(result, {}, "post-fix sign must succeed");

    const findings2 = await plugin.collectFindings();
    const readiness = findings2.find((f) => f.checkId === "signet:readiness");
    assert.equal(
      readiness?.severity,
      "info",
      `readiness must clear to info after successful sign, got ${readiness?.severity}`,
    );
    assert.match(String(readiness?.title), /operational/);

    const recoveryLogs = plugin.state.logs.filter((l) =>
      /readiness recovered after successful sign/i.test(l.msg),
    );
    assert.ok(recoveryLogs.length >= 1, "recovery via successful sign must be logged");
  });

  it("re-reads SIGNET_PASSPHRASE on every call (passphrase fix mid-session takes effect)", async () => {
    const home = await createSignetHome();
    // Encrypted identity
    await createIdentity(home, "openclaw-agent", { passphrase: "secret-pw" });

    const passphraseEnv = "SIGNET_TEST_PW_" + Date.now();
    delete process.env[passphraseEnv];

    const plugin = await loadPlugin({
      signetBin: realSignetBin,
      auditDir: home,
      passphraseEnv,
      allowDegraded: true,
      reprobeIntervalMs: 50,
    });

    // Initial: passive (passphrase missing), tool call allowed
    const r1 = await plugin.callBeforeToolCall({ toolName: "bash", params: { cmd: "ls" } });
    assert.deepEqual(r1, {});

    // Operator sets passphrase env
    process.env[passphraseEnv] = "secret-pw";

    // Wait past reprobe interval, next call should recover
    await new Promise((res) => setTimeout(res, 75));

    const r2 = await plugin.callBeforeToolCall(
      { toolName: "bash", params: { cmd: "ls" }, toolCallId: "c-2" },
      { sessionKey: "s" },
    );
    assert.deepEqual(r2, {}, "after passphrase set, next call must succeed");

    const recoveryLogs = plugin.state.logs.filter((l) => /recovered to ACTIVE/i.test(l.msg));
    assert.ok(recoveryLogs.length >= 1, "recovery from passphrase fix must be logged");

    delete process.env[passphraseEnv];
  });
});
