export interface SignetPluginConfig {
  keyName?: string;
  target?: string;
  /** @deprecated owner is taken from identity metadata; this field is ignored. */
  signerOwner?: string;
  policy?: string;
  trustBundle?: string;
  auditDir?: string;
  passphraseEnv?: string;
  encryptParams?: boolean;
  signetBin?: string;
  blockOnSignFailure?: boolean;
  priority?: number;
  /**
   * When true, a failed startup self-check puts the plugin into PASSIVE
   * mode: hooks register but tool calls run UNSIGNED and UNAUDITED until
   * the underlying setup error is resolved. Audit collector reports
   * signet:bypass=critical so the operator sees the plugin is not
   * protecting anything. Cannot be combined with `policy`: passive
   * mode skips the signet sign call where policy evaluation runs, so
   * silently bypassing policy is rejected at register() time.
   * Default: false (fail-closed; first tool call blocks with an
   * actionable error message until setup is fixed).
   */
  allowDegraded?: boolean;
  /**
   * Hard timeout (ms) for any single signet invocation. Default 5000.
   * Forwarded to SignetNodeClient. Bounded so a hung signet binary
   * cannot wedge the OpenClaw before_tool_call hook.
   */
  signetTimeoutMs?: number;
  /**
   * Min ms between background self-check probes when in PASSIVE mode.
   * Default 30000. Recovery from passive -> active runs synchronously
   * on the next before_tool_call after this interval (bounded by
   * signetTimeoutMs).
   */
  reprobeIntervalMs?: number;
}

export interface ResolvedSignetPluginConfig {
  keyName: string;
  target: string;
  policy?: string;
  trustBundle?: string;
  auditDir?: string;
  passphraseEnv: string;
  encryptParams: boolean;
  signetBin?: string;
  blockOnSignFailure: boolean;
  priority: number;
  allowDegraded: boolean;
  signetTimeoutMs: number;
  reprobeIntervalMs: number;
}

export const DEFAULT_KEY_NAME = "openclaw-agent";
export const DEFAULT_TARGET = "openclaw://gateway/local";
export const DEFAULT_PASSPHRASE_ENV = "SIGNET_PASSPHRASE";
export const DEFAULT_PRIORITY = 50;
export const DEFAULT_SIGNET_TIMEOUT_MS = 5000;
export const DEFAULT_REPROBE_INTERVAL_MS = 30000;

export function resolveConfig(input: SignetPluginConfig | undefined): ResolvedSignetPluginConfig {
  const cfg = input ?? {};
  return {
    keyName: cfg.keyName ?? DEFAULT_KEY_NAME,
    target: cfg.target ?? DEFAULT_TARGET,
    policy: cfg.policy,
    trustBundle: cfg.trustBundle,
    auditDir: cfg.auditDir,
    passphraseEnv: cfg.passphraseEnv ?? DEFAULT_PASSPHRASE_ENV,
    encryptParams: cfg.encryptParams ?? false,
    signetBin: cfg.signetBin,
    blockOnSignFailure: cfg.blockOnSignFailure ?? true,
    priority: cfg.priority ?? DEFAULT_PRIORITY,
    allowDegraded: cfg.allowDegraded ?? false,
    signetTimeoutMs: cfg.signetTimeoutMs ?? DEFAULT_SIGNET_TIMEOUT_MS,
    reprobeIntervalMs: cfg.reprobeIntervalMs ?? DEFAULT_REPROBE_INTERVAL_MS,
  };
}

/**
 * Reject a configuration that is structurally unsafe.
 *
 * Specifically: allowDegraded=true combined with a configured policy is
 * rejected because passive mode skips the signet sign call entirely,
 * which is where policy evaluation runs. Letting the operator opt into
 * "skip signing AND silently skip policy enforcement" defeats the
 * purpose of having the policy. Surface as a load-time error so the
 * misconfiguration cannot reach production.
 */
export function assertConfigCompatible(cfg: ResolvedSignetPluginConfig): void {
  if (cfg.policy && cfg.allowDegraded) {
    throw new Error(
      "signet: allowDegraded cannot be combined with a configured policy. " +
        "Passive mode bypasses the signet sign call where policy evaluation runs, " +
        "which would silently disable enforcement of every policy rule. " +
        "Either remove the policy, set allowDegraded=false, or fix the underlying setup error.",
    );
  }
}

export function isPolicyDenialError(err: unknown): boolean {
  const obj = err as { stderr?: unknown; message?: unknown } | null;
  const stderr = typeof obj?.stderr === "string" ? obj.stderr : "";
  const message = typeof obj?.message === "string" ? obj.message : "";
  const haystack = `${stderr}\n${message}`.toLowerCase();
  return haystack.includes("policy violation") || haystack.includes("requires approval");
}

export function extractPolicyReason(err: unknown): string {
  const obj = err as { stderr?: unknown; message?: unknown } | null;
  const stderr = typeof obj?.stderr === "string" ? obj.stderr : "";
  const message = typeof obj?.message === "string" ? obj.message : "";
  const text = stderr || message;
  const match = text.match(/policy violation:\s*(.+)/i) ?? text.match(/requires approval:\s*(.+)/i);
  return match ? match[1].trim() : "policy denied tool call";
}
