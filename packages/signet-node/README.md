# `@signet-auth/node`

Node-only local operator helpers for Signet, backed by the `signet` CLI.

This package is intentionally separate from `@signet-auth/core`:

- `@signet-auth/core` stays as a pure TypeScript/WASM crypto wrapper
- `@signet-auth/node` handles local filesystem workflows such as audit export, audit verification, and encrypted audit parameter materialization

## Requirements

- Node.js 18+
- A local `signet` binary available on `PATH`, or pass `signetBin`

### CLI compatibility

This package shells out to `signet sign` and, since 0.10.0, may pass any of
`--session`, `--call-id`, `--trace-id`, `--parent-receipt-id`. When `client.sign(...)`
receives any of those options, the wrapper probes `signet sign --help` once per
client instance and throws `SignetCliVersionError` if the host binary is missing
the required flags. Build/install signet from a tree containing commit `a66e748`
or later. The error reports the detected `signet --version` so operators can size
the upgrade.

You can also run `await client.assertSignCompatibility()` eagerly at startup
(e.g. inside a plugin's `register(api)`) to fail fast instead of on first
session-bound sign call.

## Install

```bash
npm install @signet-auth/node
```

## Usage

```ts
import { SignetNodeClient } from "@signet-auth/node";

const client = new SignetNodeClient({
  signetHome: "/var/lib/signet",
  signetBin: "signet",
});

await client.sign({
  key: "agent-prod",
  tool: "write_file",
  params: { path: "/tmp/demo.txt", content: "hello" },
  target: "mcp://fs",
  auditEncryptParams: true,
});

const records = await client.auditQuery({
  signer: "agent-prod",
  decryptParams: true,
});

console.log(records[0].materialized_receipt);
```

## API

- `new SignetNodeClient(options)`
- `client.sign({ key, tool, target, params, auditEncryptParams })`
- `client.auditQuery({ since, tool, signer, limit, decryptParams })`
- `client.auditExport({ output, since, tool, signer, limit, decryptParams })`
- `client.auditVerify({ since, tool, signer, limit, trustBundle, trustedAgentKeys, trustedServerKeys })`
- `client.runRaw(args)` for direct CLI access

## Notes

- `auditQuery({ decryptParams: true })` is implemented through `signet audit --export ... --decrypt-params`
- decrypted queries preserve the original encrypted `receipt` and add `materialized_receipt`
- `auditVerify()` returns a structured summary even when signature verification fails, so operator code can inspect `failed`, `warnings`, and raw CLI output without scraping exceptions
