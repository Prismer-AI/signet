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
}

export const DEFAULT_KEY_NAME = "openclaw-agent";
export const DEFAULT_TARGET = "openclaw://gateway/local";
export const DEFAULT_PASSPHRASE_ENV = "SIGNET_PASSPHRASE";
export const DEFAULT_PRIORITY = 50;

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
  };
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
