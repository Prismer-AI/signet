# `@signet-auth/node`

Node-only local operator helpers for Signet, backed by the `signet` CLI.

This package is intentionally separate from `@signet-auth/core`:

- `@signet-auth/core` stays as a pure TypeScript/WASM crypto wrapper
- `@signet-auth/node` handles local filesystem workflows such as audit export, audit verification, and encrypted audit parameter materialization

## Requirements

- Node.js 18+
- A local `signet` binary available on `PATH`, or pass `signetBin`

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
