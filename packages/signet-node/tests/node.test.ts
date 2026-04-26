import { describe, it } from "node:test";
import assert from "node:assert";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { SignetCliError, SignetCliVersionError, SignetNodeClient } from "../src/index.js";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "../../../../");
const signetBin = join(repoRoot, "target/debug/signet");

async function createHome(): Promise<string> {
  return mkdtemp(join(tmpdir(), "signet-node-test-"));
}

function clientFor(home: string, passphrase?: string): SignetNodeClient {
  return new SignetNodeClient({
    signetBin,
    signetHome: home,
    passphrase,
  });
}

describe("@signet-auth/node", () => {
  it("signs and queries encrypted audit records", async () => {
    const home = await createHome();
    const client = clientFor(home);

    await client.runRaw(["identity", "generate", "--name", "node-agent", "--unencrypted"]);
    const receipt = await client.sign({
      key: "node-agent",
      tool: "bash",
      params: { secret: "value" },
      target: "mcp://local",
      auditEncryptParams: true,
    });

    const signer = receipt.signer as Record<string, unknown>;
    assert.equal(signer.name, "node-agent");

    const raw = await client.auditQuery({ signer: "node-agent" });
    assert.equal(raw.length, 1);
    const rawAction = raw[0].receipt.action as Record<string, unknown>;
    assert.equal(rawAction.params, undefined);
    assert.equal(
      (rawAction.params_encrypted as Record<string, unknown>).alg,
      "xchacha20poly1305",
    );

    const decrypted = await client.auditQuery({ signer: "node-agent", decryptParams: true });
    const materializedAction = decrypted[0].materialized_receipt?.action as Record<string, unknown>;
    assert.equal(
      (materializedAction.params as Record<string, unknown>).secret,
      "value",
    );
  });

  it("exports decrypted audit records with materialized_receipt", async () => {
    const home = await createHome();
    const client = clientFor(home);
    const output = join(home, "audit-export.json");

    await client.runRaw(["identity", "generate", "--name", "node-export", "--unencrypted"]);
    await client.sign({
      key: "node-export",
      tool: "bash",
      params: { secret: "top-secret" },
      target: "mcp://local",
      auditEncryptParams: true,
    });

    await client.auditExport({ output, decryptParams: true });
    const exported = JSON.parse(await readFile(output, "utf8")) as Array<Record<string, unknown>>;

    assert.equal(exported.length, 1);
    assert.equal(
      (((exported[0].materialized_receipt as Record<string, unknown>).action as Record<string, unknown>).params as Record<string, unknown>).secret,
      "top-secret",
    );
  });

  it("returns structured verification summaries on success", async () => {
    const home = await createHome();
    const client = clientFor(home);

    await client.runRaw(["identity", "generate", "--name", "node-verify", "--unencrypted"]);
    await client.sign({
      key: "node-verify",
      tool: "read_file",
      params: { path: "/tmp/file" },
      target: "mcp://fs",
    });
    await client.sign({
      key: "node-verify",
      tool: "write_file",
      params: { path: "/tmp/file" },
      target: "mcp://fs",
    });

    const result = await client.auditVerify({ signer: "node-verify" });

    assert.equal(result.exitCode, 0);
    assert.equal(result.total, 2);
    assert.equal(result.valid, 2);
    assert.equal(result.failed, 0);
    assert.deepEqual(result.warnings, []);
  });

  it("signs with session/callId/traceId fields", async () => {
    const home = await createHome();
    const client = clientFor(home);

    await client.runRaw(["identity", "generate", "--name", "node-session", "--unencrypted"]);
    const receipt = await client.sign({
      key: "node-session",
      tool: "bash",
      params: { cmd: "ls" },
      target: "openclaw://gateway/local",
      session: "agent:main:thread-42",
      callId: "tool-call-99",
      traceId: "trace-abc",
    });

    const action = receipt.action as Record<string, unknown>;
    assert.equal(action.session, "agent:main:thread-42");
    assert.equal(action.call_id, "tool-call-99");
    assert.equal(action.trace_id, "trace-abc");
  });

  it("re-probes after binary swap when sign() fails on session field", async () => {
    const home = await createHome();
    const goodBin = signetBin;
    const stubPath = join(home, "swappable-signet");

    // Start with a working binary by symlinking. Use copy for portability.
    const goodScript = `#!/usr/bin/env bash\nexec "${goodBin}" "$@"\n`;
    await writeFile(stubPath, goodScript, { mode: 0o755 });

    const client = new SignetNodeClient({ signetBin: stubPath, signetHome: home });
    await client.runRaw(["identity", "generate", "--name", "node-swap", "--unencrypted"]);

    // First sign succeeds and primes the compat cache.
    const ok = await client.sign({
      key: "node-swap",
      tool: "bash",
      params: { cmd: "ls" },
      target: "openclaw://gateway/local",
      session: "agent:swap:thread-1",
    });
    assert.equal((ok.action as Record<string, unknown>).session, "agent:swap:thread-1");

    // Swap to an old binary that has no session flag.
    const oldScript = `#!/usr/bin/env bash
case "$1" in
  --version) echo "signet 0.0.99-stub" ;;
  sign)
    if [ "$2" = "--help" ]; then
      echo "Usage: signet sign --key <KEY> --tool <TOOL> --target <TARGET>"
      exit 0
    fi
    echo "error: unexpected argument '--session'" >&2
    exit 2
    ;;
esac
`;
    await writeFile(stubPath, oldScript, { mode: 0o755 });

    await assert.rejects(
      () =>
        client.sign({
          key: "node-swap",
          tool: "bash",
          params: { cmd: "ls" },
          target: "openclaw://gateway/local",
          session: "agent:swap:thread-2",
        }),
      (err: unknown) => {
        assert.ok(
          err instanceof SignetCliVersionError,
          `expected SignetCliVersionError after binary swap, got ${err}`,
        );
        assert.equal(err.cliVersion, "0.0.99-stub");
        return true;
      },
    );
  });

  it("re-probes when wrapper shim coalesces stderr into stdout", async () => {
    const home = await createHome();
    const stubPath = join(home, "swappable-signet-3");

    // Working binary first.
    const goodScript = `#!/usr/bin/env bash\nexec "${signetBin}" "$@"\n`;
    await writeFile(stubPath, goodScript, { mode: 0o755 });

    const client = new SignetNodeClient({ signetBin: stubPath, signetHome: home });
    await client.runRaw(["identity", "generate", "--name", "node-shim", "--unencrypted"]);

    await client.sign({
      key: "node-shim",
      tool: "bash",
      params: { cmd: "ls" },
      target: "openclaw://gateway/local",
      session: "agent:shim:thread-1",
    });

    // Swap to a shim that redirects stderr to stdout (a common wrapper habit).
    const coalescingScript = `#!/usr/bin/env bash
case "$1" in
  --version) echo "signet 0.0.99-shim" ;;
  sign)
    if [ "$2" = "--help" ]; then
      echo "Usage: signet sign --key <KEY> --tool <TOOL> --target <TARGET>"
      exit 0
    fi
    # Coalesce stderr into stdout, like 'cmd 2>&1' wrappers.
    echo "error: unexpected argument '--session' found"
    exit 2
    ;;
esac
`;
    await writeFile(stubPath, coalescingScript, { mode: 0o755 });

    await assert.rejects(
      () =>
        client.sign({
          key: "node-shim",
          tool: "bash",
          params: { cmd: "ls" },
          target: "openclaw://gateway/local",
          session: "agent:shim:thread-2",
        }),
      (err: unknown) => {
        assert.ok(
          err instanceof SignetCliVersionError,
          `expected SignetCliVersionError when shim coalesces stderr, got ${err?.constructor?.name}`,
        );
        assert.equal(err.cliVersion, "0.0.99-shim");
        return true;
      },
    );
  });

  it("preserves real sign() error when binary swap is unrelated", async () => {
    const home = await createHome();
    const stubPath = join(home, "swappable-signet-2");

    // Working binary first.
    const goodScript = `#!/usr/bin/env bash\nexec "${signetBin}" "$@"\n`;
    await writeFile(stubPath, goodScript, { mode: 0o755 });

    const client = new SignetNodeClient({ signetBin: stubPath, signetHome: home });
    await client.runRaw(["identity", "generate", "--name", "node-real-fail", "--unencrypted"]);

    // Prime the cache with a successful session-bound sign.
    await client.sign({
      key: "node-real-fail",
      tool: "bash",
      params: { cmd: "ls" },
      target: "openclaw://gateway/local",
      session: "agent:rf:thread-1",
    });

    // Swap to a binary that fails sign for an unrelated reason (key not found),
    // but DOES support all required flags in --help.
    const realFailScript = `#!/usr/bin/env bash
case "$1" in
  --version) echo "signet 0.10.1-stub" ;;
  sign)
    if [ "$2" = "--help" ]; then
      echo "Usage: signet sign --key <KEY> --tool <TOOL> --target <TARGET> --session <SESSION> --call-id <CALL_ID> --trace-id <TRACE_ID> --parent-receipt-id <PARENT_RECEIPT_ID>"
      exit 0
    fi
    echo "error: identity 'node-real-fail' not found" >&2
    exit 1
    ;;
esac
`;
    await writeFile(stubPath, realFailScript, { mode: 0o755 });

    await assert.rejects(
      () =>
        client.sign({
          key: "node-real-fail",
          tool: "bash",
          params: { cmd: "ls" },
          target: "openclaw://gateway/local",
          session: "agent:rf:thread-2",
        }),
      (err: unknown) => {
        // Should NOT be a version error — it's a real sign() failure that
        // happens to coincide with a binary swap. The flag gate keeps us from
        // misreporting.
        assert.ok(
          err instanceof SignetCliError,
          `expected SignetCliError, got ${err?.constructor?.name}`,
        );
        assert.ok(
          !(err instanceof SignetCliVersionError),
          "must not promote real failure to SignetCliVersionError",
        );
        assert.match((err as SignetCliError).stderr, /identity 'node-real-fail' not found/);
        return true;
      },
    );
  });

  it("reports SignetCliVersionError when sign --help is missing required flags", async () => {
    const home = await createHome();
    const stubBin = join(home, "stub-signet");
    const stubScript = `#!/usr/bin/env bash
case "$1" in
  --version) echo "signet 0.0.99-stub" ;;
  sign)
    if [ "$2" = "--help" ]; then
      echo "Usage: signet sign --key <KEY> --tool <TOOL> --target <TARGET> [--params <PARAMS>] [--policy <POLICY>]"
      exit 0
    fi
    ;;
esac
`;
    await writeFile(stubBin, stubScript, { mode: 0o755 });

    const client = new SignetNodeClient({ signetBin: stubBin, signetHome: home });
    await assert.rejects(
      () =>
        client.sign({
          key: "node-stub",
          tool: "bash",
          params: { cmd: "ls" },
          target: "openclaw://gateway/local",
          session: "agent:main:thread-42",
        }),
      (err: unknown) => {
        assert.ok(err instanceof SignetCliVersionError, "expected SignetCliVersionError");
        assert.equal(err.cliVersion, "0.0.99-stub");
        assert.deepEqual(err.missingFlags, [
          "--session",
          "--call-id",
          "--trace-id",
          "--parent-receipt-id",
        ]);
        return true;
      },
    );
  });

  it("returns structured verification summaries when signatures fail", async () => {
    const home = await createHome();
    const client = clientFor(home);

    await client.runRaw(["identity", "generate", "--name", "node-bad", "--unencrypted"]);
    await client.sign({
      key: "node-bad",
      tool: "bash",
      params: { cmd: "echo hi" },
      target: "mcp://local",
    });

    const auditPath = join(home, "audit", `${new Date().toISOString().slice(0, 10)}.jsonl`);
    const lines = (await readFile(auditPath, "utf8")).trim().split("\n");
    const record = JSON.parse(lines[0]) as Record<string, unknown>;
    ((record.receipt as Record<string, unknown>).action as Record<string, unknown>).tool = "tampered";
    await writeFile(auditPath, `${JSON.stringify(record)}\n`, "utf8");

    const result = await client.auditVerify({ signer: "node-bad" });

    assert.equal(result.exitCode, 1);
    assert.equal(result.total, 1);
    assert.equal(result.valid, 0);
    assert.equal(result.failed, 1);
    assert.match(result.stderr, /signature mismatch/);
  });
});
