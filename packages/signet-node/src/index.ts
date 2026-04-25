import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export interface SignetNodeClientOptions {
  signetBin?: string;
  signetHome?: string;
  passphrase?: string;
  env?: NodeJS.ProcessEnv;
  maxBuffer?: number;
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

export class SignetNodeClient {
  readonly signetBin: string;
  readonly signetHome?: string;
  readonly passphrase?: string;
  readonly env?: NodeJS.ProcessEnv;
  readonly maxBuffer: number;

  constructor(options: SignetNodeClientOptions = {}) {
    this.signetBin = options.signetBin ?? process.env.SIGNET_BIN ?? "signet";
    this.signetHome = options.signetHome;
    this.passphrase = options.passphrase;
    this.env = options.env;
    this.maxBuffer = options.maxBuffer ?? 10 * 1024 * 1024;
  }

  async runRaw(args: readonly string[], allowFailure: boolean = false): Promise<SignetCommandResult> {
    return runSignetCommand(this.signetBin, args, {
      signetHome: this.signetHome,
      passphrase: this.passphrase,
      env: this.env,
      maxBuffer: this.maxBuffer,
      allowFailure,
    });
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

    if (options.params !== undefined) {
      args.push("--params", JSON.stringify(options.params));
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

    const result = await this.runRaw(args);
    return parseJson<Record<string, unknown>>(result.stdout, "sign receipt");
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

  try {
    const { stdout, stderr } = await execFileAsync(signetBin, [...args], {
      env,
      maxBuffer: options.maxBuffer,
    });
    return {
      stdout: stdout.toString(),
      stderr: stderr.toString(),
      exitCode: 0,
    };
  } catch (error) {
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
