import {
  SignetCliError,
  SignetCliTimeoutError,
  SignetCliVersionError,
  SignetNodeClient,
} from "@signet-auth/node";

import {
  assertConfigCompatible,
  extractPolicyReason,
  isPolicyDenialError,
  resolveConfig,
  type ResolvedSignetPluginConfig,
  type SignetPluginConfig,
} from "./types.js";

interface PluginLoggerLike {
  info?: (msg: string) => void;
  warn?: (msg: string) => void;
  error?: (msg: string) => void;
  debug?: (msg: string) => void;
}

interface BeforeToolCallEvent {
  toolName: string;
  params: Record<string, unknown>;
  runId?: string;
  toolCallId?: string;
}

interface AfterToolCallEvent {
  toolName: string;
  params: Record<string, unknown>;
  runId?: string;
  toolCallId?: string;
  result?: unknown;
  error?: string;
  durationMs?: number;
}

interface ToolHookContext {
  agentId?: string;
  sessionKey?: string;
  sessionId?: string;
  runId?: string;
  toolName: string;
  toolCallId?: string;
}

interface BeforeToolCallResult {
  params?: Record<string, unknown>;
  block?: boolean;
  blockReason?: string;
}

type SecurityAuditSeverity = "info" | "warn" | "critical";

interface SecurityAuditFinding {
  checkId: string;
  severity: SecurityAuditSeverity;
  title: string;
  detail: string;
  remediation?: string;
}

interface SecurityAuditContextLike {
  stateDir?: string;
  configPath?: string;
}

interface OpenClawApiLike {
  pluginConfig?: Record<string, unknown>;
  logger: PluginLoggerLike;
  on: (
    hookName: string,
    handler: (
      event: BeforeToolCallEvent | AfterToolCallEvent,
      ctx: ToolHookContext,
    ) => Promise<BeforeToolCallResult | void> | BeforeToolCallResult | void,
    opts?: { priority?: number },
  ) => void;
  registerSecurityAuditCollector: (
    collector: (
      ctx: SecurityAuditContextLike,
    ) => SecurityAuditFinding[] | Promise<SecurityAuditFinding[]>,
  ) => void;
}

interface DefinedPluginEntryLike {
  id: string;
  name: string;
  description: string;
  configSchema: { type: "object"; additionalProperties?: boolean; properties?: Record<string, unknown> };
  register: (api: OpenClawApiLike) => void | Promise<void>;
}

type PluginMode = "active" | "passive";

interface SelfCheckOk {
  ok: true;
}

interface SelfCheckFail {
  ok: false;
  reason: string;
  remediation: string;
}

type SelfCheckResult = SelfCheckOk | SelfCheckFail;

interface PluginRuntimeState {
  mode: PluginMode;
  lastProbeAt: number;
  lastProbeStatus: SelfCheckResult;
  /** Internal: ensures only one inflight reprobe at a time. */
  reprobeInflight: Promise<SelfCheckResult> | null;
}

const PLUGIN_ID = "signet";
const PLUGIN_NAME = "Signet — Cryptographic Tool Receipts";
const PLUGIN_DESCRIPTION =
  "Sign every OpenClaw tool call with Ed25519, append to a hash-chained audit log, and optionally enforce a Signet policy.";

export const signetOpenClawPlugin: DefinedPluginEntryLike = {
  id: PLUGIN_ID,
  name: PLUGIN_NAME,
  description: PLUGIN_DESCRIPTION,
  configSchema: {
    type: "object",
    additionalProperties: false,
    properties: {
      keyName: { type: "string", default: "openclaw-agent" },
      target: { type: "string", default: "openclaw://gateway/local" },
      signerOwner: { type: "string", description: "Deprecated no-op; owner comes from identity metadata." },
      policy: { type: "string" },
      trustBundle: { type: "string" },
      auditDir: { type: "string" },
      passphraseEnv: { type: "string", default: "SIGNET_PASSPHRASE" },
      encryptParams: { type: "boolean", default: false },
      signetBin: { type: "string" },
      blockOnSignFailure: { type: "boolean", default: true },
      priority: { type: "number", default: 50 },
      allowDegraded: { type: "boolean", default: false },
      signetTimeoutMs: { type: "number", default: 5000 },
      reprobeIntervalMs: { type: "number", default: 30000 },
    },
  },
  async register(api) {
    const cfg = resolveConfig(api.pluginConfig as SignetPluginConfig | undefined);
    assertConfigCompatible(cfg);

    const log = api.logger;
    const client = createClient(cfg);

    const deprecated = api.pluginConfig as { signerOwner?: unknown } | undefined;
    if (deprecated && typeof deprecated.signerOwner === "string") {
      log.warn?.(
        "[signet] plugins.entries.signet.config.signerOwner is deprecated and ignored. Owner is read from identity metadata.",
      );
    }

    const initialStatus = await runSelfCheck(client, cfg);
    const state = createInitialState(initialStatus, cfg, log);

    api.on(
      "before_tool_call",
      async (event, ctx) =>
        handleBeforeToolCall(event as BeforeToolCallEvent, ctx, cfg, client, log, state),
      { priority: cfg.priority },
    );

    api.on(
      "after_tool_call",
      (event) => {
        const after = event as AfterToolCallEvent;
        if (after.error) {
          log.warn?.(
            `[signet] tool errored: ${after.toolName} (${after.toolCallId ?? "?"}): ${after.error}`,
          );
        }
      },
      { priority: cfg.priority },
    );

    api.registerSecurityAuditCollector(() => collectSecurityFindings(cfg, state));
  },
};

export default signetOpenClawPlugin;

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

function createClient(cfg: ResolvedSignetPluginConfig): SignetNodeClient {
  // Re-read passphrase env on every call (passphraseFromEnv) so a user fixing
  // SIGNET_PASSPHRASE mid-session takes effect on the next sign without
  // recreating the client. Bounded timeout protects the hot path against a
  // hung signet binary.
  return new SignetNodeClient({
    signetBin: cfg.signetBin,
    signetHome: cfg.auditDir,
    passphraseFromEnv: cfg.passphraseEnv,
    signetTimeoutMs: cfg.signetTimeoutMs,
  });
}

function createInitialState(
  status: SelfCheckResult,
  cfg: ResolvedSignetPluginConfig,
  log: PluginLoggerLike,
): PluginRuntimeState {
  const now = Date.now();
  if (status.ok) {
    log.info?.(
      `[signet] plugin ACTIVE: key=${cfg.keyName} target=${cfg.target} policy=${cfg.policy ?? "none"}`,
    );
    return { mode: "active", lastProbeAt: now, lastProbeStatus: status, reprobeInflight: null };
  }

  if (cfg.allowDegraded) {
    log.warn?.(
      `[signet] plugin loaded in PASSIVE mode (NOT signing, NOT enforcing): ${status.reason}`,
    );
    log.warn?.(`[signet] remediation: ${status.remediation}`);
    return { mode: "passive", lastProbeAt: now, lastProbeStatus: status, reprobeInflight: null };
  }

  // Fail-closed default: plugin loads in active mode but the first tool call
  // will block. Surface the actionable error eagerly so the operator sees
  // it in startup logs instead of waiting for the first failure.
  log.error?.(`[signet] startup self-check FAILED: ${status.reason}`);
  log.error?.(`[signet] tool calls will be BLOCKED until you fix this.`);
  log.error?.(`[signet] remediation: ${status.remediation}`);
  return { mode: "active", lastProbeAt: now, lastProbeStatus: status, reprobeInflight: null };
}

/**
 * Run a real `signet sign --no-log` against the configured identity. This is
 * the only probe that actually validates: (1) the binary is present, (2) the
 * configured identity exists, and (3) the identity is unlockable in the
 * current passphrase env. `--no-log` keeps the audit log untouched (we are
 * just probing), and we use a tiny dummy payload to keep the probe cheap.
 */
async function runSelfCheck(
  client: SignetNodeClient,
  cfg: ResolvedSignetPluginConfig,
): Promise<SelfCheckResult> {
  try {
    await client.sign({
      key: cfg.keyName,
      tool: "signet:self-check",
      target: cfg.target,
      params: {},
      noLog: true,
      // Pass policy so the probe surfaces missing/broken policy files at
      // startup. Without this a malformed policy yaml looks healthy until
      // the first real tool call. The probe must use the same code path
      // as production sign calls do.
      policy: cfg.policy,
    });
    return { ok: true };
  } catch (err) {
    // Policy denial is NOT a self-check failure — the plugin is healthy,
    // it just happens that "signet:self-check" was denied. The whole
    // point of having a policy is to deny stuff, so this is expected.
    if (isPolicyDenialError(err)) {
      return { ok: true };
    }
    return classifySelfCheckError(err, cfg);
  }
}

function classifySelfCheckError(
  err: unknown,
  cfg: ResolvedSignetPluginConfig,
): SelfCheckFail {
  const message = err instanceof Error ? err.message : String(err);
  const stderr = (err as { stderr?: string } | null)?.stderr ?? "";
  const haystack = `${message}\n${stderr}`;

  if (haystack.includes("ENOENT") || /command not found/i.test(haystack)) {
    return {
      ok: false,
      reason: "signet binary not found on PATH",
      remediation:
        "Install with `cargo install signet-cli` or download the latest GitHub release from https://github.com/Prismer-AI/signet/releases.",
    };
  }
  if (/SignetCliTimeoutError|aborted after/.test(haystack)) {
    return {
      ok: false,
      reason: `signet binary did not respond within ${cfg.signetTimeoutMs}ms`,
      remediation: "Check the binary at SIGNET_BIN / signetBin or raise signetTimeoutMs.",
    };
  }
  if (/identity .* not found|key .* not found|no such file/i.test(haystack)) {
    return {
      ok: false,
      reason: `signet identity '${cfg.keyName}' not found`,
      remediation: `Run \`signet identity create ${cfg.keyName}\` to create the signing identity.`,
    };
  }
  if (/decryption|passphrase/i.test(haystack)) {
    return {
      ok: false,
      reason: `failed to unlock signet identity '${cfg.keyName}'`,
      remediation: `Export ${cfg.passphraseEnv} with the correct passphrase before starting OpenClaw.`,
    };
  }
  return {
    ok: false,
    reason: `signet self-check failed: ${message.split("\n")[0]}`,
    remediation: `Run \`signet sign --key ${cfg.keyName} --tool ping --params '{}' --target ${cfg.target} --no-log\` from the gateway shell to triage.`,
  };
}

async function handleBeforeToolCall(
  event: BeforeToolCallEvent,
  ctx: ToolHookContext,
  cfg: ResolvedSignetPluginConfig,
  client: SignetNodeClient,
  log: PluginLoggerLike,
  state: PluginRuntimeState,
): Promise<BeforeToolCallResult> {
  if (state.mode === "passive") {
    // Try to recover. Sync reprobe on the transition, bounded by
    // signet timeout (5s default). If still failing, allow tool call through
    // with passive bypass. Reprobe coalesces across concurrent calls so a
    // burst does not multiply.
    const result = await maybeReprobePassive(state, client, cfg, log);
    if (!result.ok) {
      // Still passive: skip sign, allow the tool call.
      return {};
    }
    // Recovered: fall through to active path.
  }

  return signActiveCall(event, ctx, cfg, client, log, state);
}

async function maybeReprobePassive(
  state: PluginRuntimeState,
  client: SignetNodeClient,
  cfg: ResolvedSignetPluginConfig,
  log: PluginLoggerLike,
): Promise<SelfCheckResult> {
  const age = Date.now() - state.lastProbeAt;
  if (age < cfg.reprobeIntervalMs) {
    return state.lastProbeStatus;
  }

  if (!state.reprobeInflight) {
    state.reprobeInflight = (async () => {
      const r = await runSelfCheck(client, cfg);
      state.lastProbeAt = Date.now();
      state.lastProbeStatus = r;
      if (r.ok && state.mode === "passive") {
        state.mode = "active";
        log.info?.(`[signet] recovered to ACTIVE mode after self-check passed.`);
      }
      return r;
    })().finally(() => {
      state.reprobeInflight = null;
    });
  }

  return state.reprobeInflight;
}

async function signActiveCall(
  event: BeforeToolCallEvent,
  ctx: ToolHookContext,
  cfg: ResolvedSignetPluginConfig,
  client: SignetNodeClient,
  log: PluginLoggerLike,
  state: PluginRuntimeState,
): Promise<BeforeToolCallResult> {
  try {
    const receipt = (await client.sign({
      key: cfg.keyName,
      tool: event.toolName,
      target: cfg.target,
      params: event.params,
      policy: cfg.policy,
      auditEncryptParams: cfg.encryptParams,
      session: ctx.sessionKey,
      callId: event.toolCallId,
      traceId: ctx.runId,
    })) as { id?: unknown };

    const receiptId = typeof receipt.id === "string" ? receipt.id : "<unknown>";
    log.info?.(
      `[signet] signed ${event.toolName} (call=${event.toolCallId ?? "?"} session=${ctx.sessionKey ?? "?"}) → ${receiptId}`,
    );
    // A successful sign is the strongest possible readiness proof. Clear any
    // stale failed-self-check state so the audit collector and dashboards
    // reflect current operational reality.
    if (!state.lastProbeStatus.ok) {
      state.lastProbeStatus = { ok: true };
      state.lastProbeAt = Date.now();
      log.info?.(`[signet] readiness recovered after successful sign of ${event.toolName}.`);
    }
    return {};
  } catch (err) {
    if (isPolicyDenialError(err)) {
      const reason = extractPolicyReason(err);
      log.warn?.(`[signet] policy denied ${event.toolName}: ${reason}`);
      // Policy denial is a healthy outcome (the plugin is doing its job),
      // so it counts as a readiness success too.
      if (!state.lastProbeStatus.ok) {
        state.lastProbeStatus = { ok: true };
        state.lastProbeAt = Date.now();
      }
      return { block: true, blockReason: `signet policy: ${reason}` };
    }

    const message = err instanceof Error ? err.message : String(err);
    log.error?.(`[signet] sign failed for ${event.toolName}: ${message}`);
    // Reflect SYSTEM failures in runtime state so the audit collector
    // stays honest after a transient recovery breaks again. Per-call
    // payload errors (TypeError from JSON.stringify on BigInt /
    // circular refs, etc.) are NOT readiness failures — they prove
    // the tool call had bad params, not that signet is broken. Filter
    // by error class so only failures that originated in the spawned
    // CLI (or a hung binary, or ENOENT) flip readiness.
    if (isSignetSystemFailure(err)) {
      state.lastProbeStatus = classifySelfCheckError(err, cfg);
      state.lastProbeAt = Date.now();
    }
    if (cfg.blockOnSignFailure) {
      return { block: true, blockReason: `signet sign failed: ${message}` };
    }
    return {};
  }
}

function isSignetSystemFailure(err: unknown): boolean {
  // Distinguish per-call payload bugs (which prove nothing about signet
  // health) from operational/infra failures (which do). Use a blacklist
  // because the operational set is much larger than the payload set:
  //
  // - SignetCliError (CLI exited non-zero), SignetCliTimeoutError (binary
  //   hung), SignetCliVersionError (compat probe rejected) are obvious.
  // - ENOENT (binary missing) and EACCES (binary not executable) come
  //   through execFile as raw fs errors before any wrap class.
  // - parseJson failures (CLI exited 0 but produced non-JSON garbage)
  //   come through as a plain Error from @signet-auth/node.
  // - Any spawn-time fs error: also operational.
  //
  // Per-call payload errors thrown BEFORE the CLI is invoked are JS-side
  // type-system failures: TypeError (BigInt / circular ref via
  // JSON.stringify), RangeError (extreme nesting depth), SyntaxError
  // (manual JSON.parse on user input). Those propagate but do not
  // taint readiness.
  if (
    err instanceof TypeError ||
    err instanceof RangeError ||
    err instanceof SyntaxError
  ) {
    return false;
  }
  return err instanceof Error;
}

function collectSecurityFindings(
  cfg: ResolvedSignetPluginConfig,
  state: PluginRuntimeState,
): SecurityAuditFinding[] {
  const findings: SecurityAuditFinding[] = [];

  // Runtime readiness drives the headline check. Config-only "plugin
  // enabled" was misleading when the plugin loaded but signing was broken.
  const status = state.lastProbeStatus;

  // "Effectively bypassing" = sign attempts will not gate tool calls.
  // Two independent paths cause this:
  //   1. Passive mode (allowDegraded=true and startup probe failed) —
  //      hooks short-circuit before sign.
  //   2. Active mode + blockOnSignFailure=false + probe failed —
  //      signActiveCall catches the error and returns {} instead of
  //      blocking, so the tool call runs unsigned.
  // Both cases must surface as signet:bypass=critical.
  const effectivelyBypassing =
    !status.ok &&
    (state.mode === "passive" || cfg.blockOnSignFailure === false);

  let readinessTitle: string;
  let readinessDetail: string;
  if (status.ok) {
    readinessTitle = "Signet plugin operational";
    readinessDetail = `Tool calls are signed with identity '${cfg.keyName}' and emitted under target ${cfg.target}.`;
  } else if (state.mode === "passive") {
    readinessTitle = "Signet plugin in PASSIVE mode (not signing, not enforcing)";
    readinessDetail = `Reason: ${status.reason}.`;
  } else if (cfg.blockOnSignFailure === false) {
    readinessTitle = "Signet plugin armed but startup self-check failed (fail-open: tool calls run unsigned)";
    readinessDetail = `Reason: ${status.reason}.`;
  } else {
    readinessTitle = "Signet plugin armed but startup self-check failed (tool calls will block)";
    readinessDetail = `Reason: ${status.reason}.`;
  }

  findings.push({
    checkId: "signet:readiness",
    severity: status.ok ? "info" : "critical",
    title: readinessTitle,
    detail: readinessDetail,
    remediation: status.ok ? undefined : status.remediation,
  });

  if (effectivelyBypassing) {
    const cause = state.mode === "passive"
      ? "allowDegraded=true and the startup self-check failed"
      : "blockOnSignFailure=false and the startup self-check failed";
    findings.push({
      checkId: "signet:bypass",
      severity: "critical",
      title: "Signet bypass active — tool calls run UNSIGNED and UNAUDITED",
      detail:
        `${cause} (${status.reason}). ` +
        `Every OpenClaw tool call runs without a Signet receipt, without policy ` +
        `enforcement, and without an audit log entry. This deployment is currently ` +
        `unprotected.`,
      remediation: status.remediation,
    });
  }

  findings.push({
    checkId: "signet:policy",
    severity: cfg.policy ? (status.ok ? "info" : "critical") : "warn",
    title: cfg.policy
      ? status.ok
        ? "Signet policy enforced"
        : "Signet policy CONFIGURED but plugin not operational"
      : "No Signet policy configured",
    detail: cfg.policy
      ? status.ok
        ? `Policy file: ${cfg.policy}. Denied tool calls are blocked before execution.`
        : `Policy file: ${cfg.policy}. Plugin is not operational, so policy is NOT being enforced.`
      : "Every signed call is allowed. Tool execution is observable but not gated.",
    remediation: cfg.policy
      ? status.ok
        ? undefined
        : status.remediation
      : "Set plugins.entries.signet.config.policy to a Signet policy YAML to enforce deny rules.",
  });

  findings.push({
    checkId: "signet:trust-bundle",
    severity: cfg.trustBundle ? "info" : "warn",
    title: cfg.trustBundle ? "Trust bundle pinned" : "No trust bundle pinned",
    detail: cfg.trustBundle
      ? `Bundle file: ${cfg.trustBundle}. External verifiers can use the same bundle to anchor signatures.`
      : "Verifiers must supply a trust bundle out-of-band when validating receipts emitted by this gateway.",
    remediation: cfg.trustBundle
      ? undefined
      : "Set plugins.entries.signet.config.trustBundle to a published trust bundle path.",
  });

  findings.push({
    checkId: "signet:fail-mode",
    severity: cfg.allowDegraded ? "warn" : cfg.blockOnSignFailure ? "info" : "warn",
    title: cfg.allowDegraded
      ? "Sign failures fail-open (allowDegraded=true)"
      : cfg.blockOnSignFailure
        ? "Sign failures fail-closed"
        : "Sign failures fail-open",
    detail: cfg.allowDegraded
      ? "When the startup self-check fails, tool calls run unsigned. Audit log will have gaps."
      : cfg.blockOnSignFailure
        ? "If signing or policy evaluation errors, the tool call is blocked. Safe default."
        : "If signing or policy evaluation errors, the tool call still runs. Audit log may have gaps.",
    remediation: cfg.allowDegraded
      ? "Set allowDegraded=false unless you accept silent audit gaps. Combine with blockOnSignFailure=true to refuse to load on broken setup."
      : cfg.blockOnSignFailure
        ? undefined
        : "Set plugins.entries.signet.config.blockOnSignFailure=true unless you accept silent audit gaps.",
  });

  findings.push({
    checkId: "signet:params-encryption",
    severity: cfg.encryptParams ? "info" : "warn",
    title: cfg.encryptParams
      ? "Tool params encrypted at rest"
      : "Tool params stored in clear in audit log",
    detail: cfg.encryptParams
      ? "action.params is wrapped in an XChaCha20-Poly1305 envelope keyed off the signing key."
      : "Receipts include tool parameters in clear text. External auditors can read them without unlocking the signing key.",
    remediation: cfg.encryptParams
      ? undefined
      : "Set plugins.entries.signet.config.encryptParams=true if tool parameters may include secrets.",
  });

  return findings;
}
