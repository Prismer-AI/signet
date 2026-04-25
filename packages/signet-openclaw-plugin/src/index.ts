import { SignetNodeClient } from "@signet-auth/node";

import {
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
  register: (api: OpenClawApiLike) => void;
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
    },
  },
  register(api) {
    const cfg = resolveConfig(api.pluginConfig as SignetPluginConfig | undefined);
    const log = api.logger;
    const client = createClient(cfg);

    log.info?.(
      `[signet] plugin armed: key=${cfg.keyName} target=${cfg.target} policy=${cfg.policy ?? "none"}`,
    );

    const deprecated = api.pluginConfig as { signerOwner?: unknown } | undefined;
    if (deprecated && typeof deprecated.signerOwner === "string") {
      log.warn?.(
        "[signet] plugins.entries.signet.config.signerOwner is deprecated and ignored. Owner is read from identity metadata.",
      );
    }

    api.on(
      "before_tool_call",
      async (event, ctx) =>
        handleBeforeToolCall(event as BeforeToolCallEvent, ctx, cfg, client, log),
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

    api.registerSecurityAuditCollector(() => collectSecurityFindings(cfg));
  },
};

export default signetOpenClawPlugin;

function createClient(cfg: ResolvedSignetPluginConfig): SignetNodeClient {
  const passphrase = process.env[cfg.passphraseEnv];
  return new SignetNodeClient({
    signetBin: cfg.signetBin,
    signetHome: cfg.auditDir,
    passphrase: passphrase || undefined,
  });
}

async function handleBeforeToolCall(
  event: BeforeToolCallEvent,
  ctx: ToolHookContext,
  cfg: ResolvedSignetPluginConfig,
  client: SignetNodeClient,
  log: PluginLoggerLike,
): Promise<BeforeToolCallResult> {
  try {
    const receipt = (await client.sign({
      key: cfg.keyName,
      tool: event.toolName,
      target: cfg.target,
      params: event.params,
      policy: cfg.policy,
      auditEncryptParams: cfg.encryptParams,
    })) as { id?: unknown };

    const receiptId = typeof receipt.id === "string" ? receipt.id : "<unknown>";
    log.info?.(
      `[signet] signed ${event.toolName} (call=${event.toolCallId ?? "?"} session=${ctx.sessionKey ?? "?"}) → ${receiptId}`,
    );
    return {};
  } catch (err) {
    if (isPolicyDenialError(err)) {
      const reason = extractPolicyReason(err);
      log.warn?.(`[signet] policy denied ${event.toolName}: ${reason}`);
      return { block: true, blockReason: `signet policy: ${reason}` };
    }

    const message = err instanceof Error ? err.message : String(err);
    log.error?.(`[signet] sign failed for ${event.toolName}: ${message}`);
    if (cfg.blockOnSignFailure) {
      return { block: true, blockReason: `signet sign failed: ${message}` };
    }
    return {};
  }
}

function collectSecurityFindings(
  cfg: ResolvedSignetPluginConfig,
): SecurityAuditFinding[] {
  const findings: SecurityAuditFinding[] = [];

  findings.push({
    checkId: "signet:configured",
    severity: "info",
    title: "Signet plugin enabled",
    detail: `Tool calls are signed with identity '${cfg.keyName}' and emitted under target ${cfg.target}.`,
  });

  findings.push({
    checkId: "signet:policy",
    severity: cfg.policy ? "info" : "warn",
    title: cfg.policy ? "Signet policy enforced" : "No Signet policy configured",
    detail: cfg.policy
      ? `Policy file: ${cfg.policy}. Denied tool calls are blocked before execution.`
      : "Every signed call is allowed. Tool execution is observable but not gated.",
    remediation: cfg.policy
      ? undefined
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
    severity: cfg.blockOnSignFailure ? "info" : "warn",
    title: cfg.blockOnSignFailure
      ? "Sign failures fail-closed"
      : "Sign failures fail-open",
    detail: cfg.blockOnSignFailure
      ? "If signing or policy evaluation errors, the tool call is blocked. Safe default."
      : "If signing or policy evaluation errors, the tool call still runs. Audit log may have gaps.",
    remediation: cfg.blockOnSignFailure
      ? undefined
      : "Set plugins.entries.signet.config.blockOnSignFailure=true unless you accept silent audit gaps.",
  });

  findings.push({
    checkId: "signet:params-encryption",
    severity: cfg.encryptParams ? "info" : "info",
    title: cfg.encryptParams
      ? "Tool params encrypted at rest"
      : "Tool params stored in clear in audit log",
    detail: cfg.encryptParams
      ? "action.params is wrapped in an XChaCha20-Poly1305 envelope keyed off the signing key."
      : "Receipts include tool parameters in clear text. External auditors can read them without unlocking the signing key.",
  });

  return findings;
}
