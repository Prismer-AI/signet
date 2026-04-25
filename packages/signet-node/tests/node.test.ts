import { describe, it } from "node:test";
import assert from "node:assert";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { SignetNodeClient } from "../src/index.js";

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
