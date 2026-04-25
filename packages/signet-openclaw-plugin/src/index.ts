import { SignetNodeClient } from "@signet-auth/node";

import {
  extractPolicyReason,
  isPolicyDenialError,
  resolveConfig,
  type ResolvedSignetPluginConfig,
  type SignetPluginConfig,
} from "./types.js";

interface OpenClawApiLike {
  pluginConfig?: Record<string, unknown>;
  logger?: { info?: (msg: string, meta?: unknown) => void; warn?: (msg: string, meta?: unknown) => void; error?: (msg: string, meta?: unknown) => void };
  registerHook?: (
    events: string | string[],
    handler: (event: BeforeToolCallEvent) => Promise<BeforeToolCallResult> | BeforeToolCallResult,
    opts?: Record<string, unknown>,
  ) => void;
  registerSecurityAuditCollector?: (collector: SecurityAuditCollectorLike) => void;
}

interface BeforeToolCallEvent {
  toolName: string;
  params: Record<string, unknown>;
  runId?: string;
  toolCallId?: string;
}

interface BeforeToolCallResult {
  params?: Record<string, unknown>;
  block?: boolean;
  blockReason?: string;
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

interface SecurityAuditCollectorLike {
  id: string;
  collect: () => Promise<SecurityAuditFinding[]> | SecurityAuditFinding[];
}

interface SecurityAuditFinding {
  checkId: string;
  status: "pass" | "warn" | "fail" | "info";
  message: string;
  details?: Record<string, unknown>;
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
      signerOwner: { type: "string", default: "openclaw" },
      target: { type: "string", default: "openclaw://gateway/local" },
      policy: { type: "string" },
      trustBundle: { type: "string" },
      auditDir: { type: "string" },
      passphraseEnv: { type: "string", default: "SIGNET_PASSPHRASE" },
      encryptParams: { type: "boolean", default: false },
      signetBin: { type: "string" },
      blockOnSignFailure: { type: "boolean", default: true },
    },
  },
  register(api) {
    const cfg = resolveConfig(api.pluginConfig as SignetPluginConfig | undefined);
    const log = api.logger ?? {};
    const client = createClient(cfg);

    log.info?.(`[signet] plugin armed: key=${cfg.keyName} target=${cfg.target} policy=${cfg.policy ?? "none"}`);

    api.registerHook?.(
      "before_tool_call",
      async (event) => handleBeforeToolCall(event, cfg, client, log),
      { pluginId: PLUGIN_ID },
    );

    api.registerHook?.(
      "after_tool_call",
      (event) => {
        const after = event as unknown as AfterToolCallEvent;
        if (after.error) {
          log.warn?.(
            `[signet] tool errored: ${after.toolName} (${after.toolCallId ?? "?"}): ${after.error}`,
          );
        }
        return {};
      },
      { pluginId: PLUGIN_ID },
    );

    api.registerSecurityAuditCollector?.({
      id: "signet:plugin",
      collect: () => collectSecurityFindings(cfg),
    });
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
  cfg: ResolvedSignetPluginConfig,
  client: SignetNodeClient,
  log: NonNullable<OpenClawApiLike["logger"]>,
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
      `[signet] signed ${event.toolName} (call=${event.toolCallId ?? "?"}) → ${receiptId}`,
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

async function collectSecurityFindings(
  cfg: ResolvedSignetPluginConfig,
): Promise<SecurityAuditFinding[]> {
  const findings: SecurityAuditFinding[] = [];

  findings.push({
    checkId: "signet:configured",
    status: "pass",
    message: `Signet plugin enabled (key=${cfg.keyName})`,
    details: { target: cfg.target, encryptParams: cfg.encryptParams },
  });

  findings.push({
    checkId: "signet:policy",
    status: cfg.policy ? "pass" : "info",
    message: cfg.policy
      ? `Policy enforced from ${cfg.policy}`
      : "No policy configured — every signed call is allowed",
  });

  findings.push({
    checkId: "signet:trust-bundle",
    status: cfg.trustBundle ? "pass" : "info",
    message: cfg.trustBundle
      ? `Trust bundle pinned at ${cfg.trustBundle}`
      : "No trust bundle pinned — verifiers must supply one out-of-band",
  });

  findings.push({
    checkId: "signet:fail-mode",
    status: cfg.blockOnSignFailure ? "pass" : "warn",
    message: cfg.blockOnSignFailure
      ? "Sign failures abort tool calls (fail-closed)"
      : "Sign failures are logged but tool calls proceed (fail-open)",
  });

  return findings;
}
