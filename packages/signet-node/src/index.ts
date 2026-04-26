import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export interface SignetNodeClientOptions {
  signetBin?: string;
  signetHome?: string;
  /**
   * Static passphrase value passed to every signet invocation as
   * SIGNET_PASSPHRASE. Captured at construction time. Use
   * {@link passphraseFromEnv} instead if the user may set/change the
   * passphrase env var after the client is constructed.
   */
  passphrase?: string;
  /**
   * Name of an environment variable that holds the keystore passphrase.
   * Re-read on EVERY signet invocation, so a user fixing a missing
   * SIGNET_PASSPHRASE mid-session takes effect immediately on the next
   * call without recreating the client. Takes precedence over
   * {@link passphrase} when set.
   */
  passphraseFromEnv?: string;
  env?: NodeJS.ProcessEnv;
  maxBuffer?: number;
  /**
   * Hard timeout (ms) for any single signet invocation. Defaults to
   * 5000ms. A hung or wedged signet binary aborts via AbortController
   * and surfaces as a SignetCliTimeoutError so callers (e.g. plugin
   * hot paths) cannot stall indefinitely.
   */
  signetTimeoutMs?: number;
}

export interface SignReceiptOptions {
  key: string;
  tool: string;
  target: string;
  params?: unknown;
  hashOnly?: boolean;
  noLog?: boolean;
  policy?: string;
  auditEncryptParams?: boolean;
  session?: string;
  callId?: string;
  traceId?: string;
  parentReceiptId?: string;
}

export interface AuditFilterOptions {
  since?: string;
  tool?: string;
  signer?: string;
  limit?: number;
}

export interface AuditQueryOptions extends AuditFilterOptions {
  decryptParams?: boolean;
}

export interface AuditExportOptions extends AuditQueryOptions {
  output: string;
}

export interface AuditVerifyOptions extends AuditFilterOptions {
  trustBundle?: string;
  trustedAgentKeys?: string[];
  trustedServerKeys?: string[];
}

export interface SignetCommandResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

export interface AuditQueryRecord {
  receipt: Record<string, unknown>;
  prev_hash: string;
  record_hash: string;
  materialized_receipt?: Record<string, unknown>;
}

export interface AuditVerifyResult extends SignetCommandResult {
  total: number;
  valid: number;
  failed: number;
  warnings: string[];
}

export class SignetCliError extends Error {
  readonly args: readonly string[];
  readonly stdout: string;
  readonly stderr: string;
  readonly exitCode: number;

  constructor(message: string, details: {
    args: readonly string[];
    stdout: string;
    stderr: string;
    exitCode: number;
  }) {
    super(message);
    this.name = "SignetCliError";
    this.args = details.args;
    this.stdout = details.stdout;
    this.stderr = details.stderr;
    this.exitCode = details.exitCode;
  }
}

export class SignetCliVersionError extends Error {
  readonly cliVersion: string | null;
  readonly missingFlags: readonly string[];

  constructor(cliVersion: string | null, missingFlags: readonly string[]) {
    const found = cliVersion ?? "<unknown>";
    const flags = missingFlags.join(", ");
    super(
      `signet CLI is missing required flag(s) [${flags}] (found version ${found}). ` +
        "Upgrade to a build that supports them. " +
        "If you compiled from source, ensure your tree includes commit a66e748 or later.",
    );
    this.name = "SignetCliVersionError";
    this.cliVersion = cliVersion;
    this.missingFlags = [...missingFlags];
  }
}

export class SignetCliTimeoutError extends Error {
  readonly args: readonly string[];
  readonly timeoutMs: number;

  constructor(args: readonly string[], timeoutMs: number) {
    super(
      `signet ${args.join(" ")} aborted after ${timeoutMs}ms. ` +
        "Increase signetTimeoutMs or investigate why the signet binary is hanging.",
    );
    this.name = "SignetCliTimeoutError";
    this.args = args;
    this.timeoutMs = timeoutMs;
  }
}

/**
 * Thrown when JSON.stringify on the caller-supplied `params` fails before
 * the signet CLI is invoked. Wraps the original error so callers can tell
 * "user payload had a throwing toJSON / unsupported value" apart from
 * "signet binary or identity is broken". Plugin code that maintains
 * runtime readiness state must NOT treat this as a system failure.
 */
export class SignetParamsSerializationError extends Error {
  readonly originalError: unknown;

  constructor(cause: unknown) {
    const msg = cause instanceof Error ? cause.message : String(cause);
    super(`failed to serialize sign params: ${msg}`);
    this.name = "SignetParamsSerializationError";
    this.originalError = cause;
  }
}

const DEFAULT_SIGNET_TIMEOUT_MS = 5000;

const REQUIRED_SIGN_FLAGS = ["--session", "--call-id", "--trace-id", "--parent-receipt-id"] as const;

const UNKNOWN_FLAG_STDERR_RE = /(?:unexpected|unrecognized|unknown) argument/i;

function looksLikeUnknownFlagFailure(err: SignetCliError): boolean {
  // Wrapper shims sometimes coalesce stderr into stdout. Inspect both streams
  // so cached compat recovery still kicks in for those launchers.
  return UNKNOWN_FLAG_STDERR_RE.test(err.stderr) || UNKNOWN_FLAG_STDERR_RE.test(err.stdout);
}

export class SignetNodeClient {
  readonly signetBin: string;
  readonly signetHome?: string;
  readonly passphrase?: string;
  readonly passphraseFromEnv?: string;
  readonly env?: NodeJS.ProcessEnv;
  readonly maxBuffer: number;
  readonly signetTimeoutMs: number;
  private signCompatProbe: Promise<void> | null = null;

  constructor(options: SignetNodeClientOptions = {}) {
    this.signetBin = options.signetBin ?? process.env.SIGNET_BIN ?? "signet";
    this.signetHome = options.signetHome;
    this.passphrase = options.passphrase;
    this.passphraseFromEnv = options.passphraseFromEnv;
    this.env = options.env;
    this.maxBuffer = options.maxBuffer ?? 10 * 1024 * 1024;
    this.signetTimeoutMs = options.signetTimeoutMs ?? DEFAULT_SIGNET_TIMEOUT_MS;
  }

  async runRaw(args: readonly string[], allowFailure: boolean = false): Promise<SignetCommandResult> {
    // Re-read passphrase env on EVERY call so a user fixing
    // SIGNET_PASSPHRASE mid-session takes effect immediately, without
    // recreating the client.
    const resolvedPassphrase = this.passphraseFromEnv
      ? process.env[this.passphraseFromEnv] || undefined
      : this.passphrase;
    return runSignetCommand(this.signetBin, args, {
      signetHome: this.signetHome,
      passphrase: resolvedPassphrase,
      env: this.env,
      maxBuffer: this.maxBuffer,
      timeoutMs: this.signetTimeoutMs,
      allowFailure,
    });
  }

  async cliVersion(): Promise<string | null> {
    try {
      const result = await this.runRaw(["--version"]);
      const match = result.stdout.match(/signet\s+([0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.+-]+)?)/);
      return match ? match[1] : null;
    } catch {
      return null;
    }
  }

  /**
   * Verify the host `signet` binary supports the flags this wrapper relies on.
   *
   * Throws `SignetCliVersionError` when the local CLI is missing any required
   * `signet sign` flag (currently --session/--call-id/--trace-id/--parent-receipt-id).
   * The probe runs once per client instance and caches the result.
   */
  async assertSignCompatibility(): Promise<void> {
    if (this.signCompatProbe) {
      return this.signCompatProbe;
    }
    this.signCompatProbe = (async () => {
      const helpResult = await this.runRaw(["sign", "--help"], true);
      const help = `${helpResult.stdout}\n${helpResult.stderr}`;
      const missing = REQUIRED_SIGN_FLAGS.filter((flag) => !help.includes(flag));
      if (missing.length > 0) {
        const cliVersion = await this.cliVersion();
        throw new SignetCliVersionError(cliVersion, missing);
      }
    })();
    try {
      return await this.signCompatProbe;
    } catch (err) {
      this.signCompatProbe = null;
      throw err;
    }
  }

  async sign(options: SignReceiptOptions): Promise<Record<string, unknown>> {
    const args = [
      "sign",
      "--key",
      options.key,
      "--tool",
      options.tool,
      "--target",
      options.target,
    ];

    if (
      options.session !== undefined ||
      options.callId !== undefined ||
      options.traceId !== undefined ||
      options.parentReceiptId !== undefined
    ) {
      await this.assertSignCompatibility();
    }

    let paramsTempDir: string | undefined;
    if (options.params !== undefined) {
      // Serialize FIRST, before any spawn / fs work, so a payload-side
      // error (BigInt, circular ref, throwing toJSON, throwing property
      // getter, etc.) surfaces as SignetParamsSerializationError. This
      // lets callers cleanly distinguish "the tool call's args are
      // unserializable" (per-call payload bug) from "the signet binary
      // or identity is broken" (operational failure).
      let paramsJson: string;
      try {
        paramsJson = JSON.stringify(options.params);
      } catch (err) {
        throw new SignetParamsSerializationError(err);
      }
      paramsTempDir = await mkdtemp(join(tmpdir(), "signet-node-params-"));
      const paramsPath = join(paramsTempDir, "params.json");
      await writeFile(paramsPath, paramsJson, "utf8");
      args.push("--params", `@${paramsPath}`);
    }
    if (options.hashOnly) {
      args.push("--hash-only");
    }
    if (options.noLog) {
      args.push("--no-log");
    }
    if (options.policy) {
      args.push("--policy", options.policy);
    }
    if (options.auditEncryptParams) {
      args.push("--encrypt-params");
    }
    if (options.session) {
      args.push("--session", options.session);
    }
    if (options.callId) {
      args.push("--call-id", options.callId);
    }
    if (options.traceId) {
      args.push("--trace-id", options.traceId);
    }
    if (options.parentReceiptId) {
      args.push("--parent-receipt-id", options.parentReceiptId);
    }

    const sessionFieldsRequested =
      options.session !== undefined ||
      options.callId !== undefined ||
      options.traceId !== undefined ||
      options.parentReceiptId !== undefined;

    try {
      const result = await this.runRaw(args);
      return parseJson<Record<string, unknown>>(result.stdout, "sign receipt");
    } catch (err) {
      // Re-probe only when the failure looks like an unknown-flag clap error
      // and the caller asked for session-bound fields. This handles the
      // long-lived-process binary swap case without misclassifying real
      // sign() failures (missing key, policy deny, etc.) as version errors.
      if (
        sessionFieldsRequested &&
        err instanceof SignetCliError &&
        looksLikeUnknownFlagFailure(err)
      ) {
        this.signCompatProbe = null;
        await this.assertSignCompatibility();
      }
      throw err;
    } finally {
      if (paramsTempDir) {
        await rm(paramsTempDir, { recursive: true, force: true });
      }
    }
  }

  async auditQuery(options: AuditQueryOptions = {}): Promise<AuditQueryRecord[]> {
    const tempDir = await mkdtemp(join(tmpdir(), "signet-node-"));
    const output = join(tempDir, "audit.json");

    try {
      await this.auditExport({ ...options, output });
      const json = await readFile(output, "utf8");
      return parseJson<AuditQueryRecord[]>(json, "audit export");
    } finally {
      await rm(tempDir, { recursive: true, force: true });
    }
  }

  async auditExport(options: AuditExportOptions): Promise<void> {
    const args = ["audit", "--export", options.output];
    pushAuditFilters(args, options);
    if (options.decryptParams) {
      args.push("--decrypt-params");
    }
    await this.runRaw(args);
  }

  async auditVerify(options: AuditVerifyOptions = {}): Promise<AuditVerifyResult> {
    const args = ["audit", "--verify"];
    pushAuditFilters(args, options);
    if (options.trustBundle) {
      args.push("--trust-bundle", options.trustBundle);
    }
    if (options.trustedAgentKeys && options.trustedAgentKeys.length > 0) {
      args.push("--trusted-agent-key", options.trustedAgentKeys.join(","));
    }
    if (options.trustedServerKeys && options.trustedServerKeys.length > 0) {
      args.push("--trusted-server-key", options.trustedServerKeys.join(","));
    }

    const result = await this.runRaw(args, true);
    return parseAuditVerifyResult(result, args);
  }
}

function pushAuditFilters(args: string[], options: AuditFilterOptions): void {
  if (options.since) {
    args.push("--since", options.since);
  }
  if (options.tool) {
    args.push("--tool", options.tool);
  }
  if (options.signer) {
    args.push("--signer", options.signer);
  }
  if (options.limit !== undefined) {
    args.push("--limit", String(options.limit));
  }
}

async function runSignetCommand(
  signetBin: string,
  args: readonly string[],
  options: {
    signetHome?: string;
    passphrase?: string;
    env?: NodeJS.ProcessEnv;
    maxBuffer: number;
    timeoutMs: number;
    allowFailure: boolean;
  },
): Promise<SignetCommandResult> {
  const env: NodeJS.ProcessEnv = { ...process.env, ...options.env };
  if (options.signetHome) {
    env.SIGNET_HOME = options.signetHome;
  }
  if (options.passphrase) {
    env.SIGNET_PASSPHRASE = options.passphrase;
  }

  const controller = new AbortController();
  const timeoutHandle = setTimeout(() => controller.abort(), options.timeoutMs);

  try {
    const { stdout, stderr } = await execFileAsync(signetBin, [...args], {
      env,
      maxBuffer: options.maxBuffer,
      signal: controller.signal,
    });
    return {
      stdout: stdout.toString(),
      stderr: stderr.toString(),
      exitCode: 0,
    };
  } catch (error) {
    if (controller.signal.aborted) {
      throw new SignetCliTimeoutError(args, options.timeoutMs);
    }
    const parsed = parseExecFailure(error);
    if (parsed && options.allowFailure) {
      return parsed;
    }
    if (parsed) {
      throw new SignetCliError(
        `signet ${args.join(" ")} failed with exit code ${parsed.exitCode}`,
        { args, ...parsed },
      );
    }
    throw error;
  } finally {
    clearTimeout(timeoutHandle);
  }
}

function parseExecFailure(error: unknown): SignetCommandResult | null {
  if (!error || typeof error !== "object") {
    return null;
  }

  const maybe = error as {
    code?: number | string;
    stdout?: string | Buffer;
    stderr?: string | Buffer;
  };

  if (typeof maybe.code !== "number") {
    return null;
  }

  return {
    stdout: coerceOutput(maybe.stdout),
    stderr: coerceOutput(maybe.stderr),
    exitCode: maybe.code,
  };
}

function coerceOutput(value: string | Buffer | undefined): string {
  if (typeof value === "string") {
    return value;
  }
  if (value instanceof Buffer) {
    return value.toString("utf8");
  }
  return "";
}

function parseJson<T>(value: string, label: string): T {
  try {
    return JSON.parse(value) as T;
  } catch (error) {
    throw new Error(`failed to parse ${label} JSON: ${String(error)}`);
  }
}

function parseAuditVerifyResult(
  result: SignetCommandResult,
  args: readonly string[],
): AuditVerifyResult {
  const summary = result.stdout.match(/(\d+)\/(\d+) signatures valid(?:, (\d+) FAILED)?/);
  if (!summary) {
    if (result.exitCode !== 0) {
      throw new SignetCliError(
        `signet ${args.join(" ")} failed with exit code ${result.exitCode}`,
        { args, stdout: result.stdout, stderr: result.stderr, exitCode: result.exitCode },
      );
    }
    throw new Error("could not parse audit verification summary");
  }

  const warnings = extractWarnings(result.stdout);
  return {
    ...result,
    valid: Number(summary[1]),
    total: Number(summary[2]),
    failed: summary[3] ? Number(summary[3]) : 0,
    warnings,
  };
}

function extractWarnings(stdout: string): string[] {
  const marker = "\nWarnings:\n";
  const index = stdout.indexOf(marker);
  if (index === -1) {
    return [];
  }

  return stdout
    .slice(index + marker.length)
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
}
