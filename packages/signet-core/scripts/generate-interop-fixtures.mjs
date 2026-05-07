#!/usr/bin/env node

import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  generateKeypair,
  sign,
  signAuthorized,
  signBilateral,
  signCompound,
  signDelegation,
} from '../dist/src/index.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const packageRoot = join(__dirname, '..');
const outDir = join(packageRoot, 'tests', 'fixtures');
const outFile = join(outDir, 'ts-signed.json');

mkdirSync(outDir, { recursive: true });

const v1Keypair = generateKeypair();
const v1Receipt = sign(
  v1Keypair.secretKey,
  {
    tool: 'interop_v1',
    params: { k: 'v' },
    params_hash: '',
    target: 'mcp://test',
    transport: 'stdio',
  },
  'ts-signer-v1',
  'interop',
);

const v2Keypair = generateKeypair();
const v2Receipt = signCompound(
  v2Keypair.secretKey,
  {
    tool: 'interop_v2',
    params: { k: 'v' },
    params_hash: '',
    target: 'mcp://test',
    transport: 'stdio',
  },
  { result: 'ok' },
  'ts-signer-v2',
  'interop',
  '2026-04-21T12:00:00.000Z',
  '2026-04-21T12:00:00.000Z',
);

const v3AgentKeypair = generateKeypair();
const v3ServerKeypair = generateKeypair();
const v3AgentReceipt = sign(
  v3AgentKeypair.secretKey,
  {
    tool: 'interop_v3',
    params: { q: 'hi' },
    params_hash: '',
    target: 'mcp://test',
    transport: 'stdio',
  },
  'ts-agent-v3',
  'owner',
);
const v3ResponseTs = new Date().toISOString();
const v3Receipt = signBilateral(
  v3ServerKeypair.secretKey,
  JSON.stringify(v3AgentReceipt),
  { result: 'data' },
  'ts-server-v3',
  v3ResponseTs,
);

const v4OwnerKeypair = generateKeypair();
const v4DelegateKeypair = generateKeypair();
const v4Token = signDelegation(
  v4OwnerKeypair.secretKey,
  'ts-owner-v4',
  v4DelegateKeypair.publicKey,
  'ts-delegate-v4',
  {
    tools: ['*'],
    targets: ['*'],
    max_depth: 0,
  },
);
const v4Receipt = signAuthorized(
  v4DelegateKeypair.secretKey,
  {
    tool: 'interop_v4',
    params: {},
    params_hash: '',
    target: 'mcp://test',
    transport: 'stdio',
  },
  'ts-delegate-v4',
  [v4Token],
);

const fixtures = {
  v1: {
    receipt: v1Receipt,
    public_key: v1Keypair.publicKey,
  },
  v2: {
    receipt: v2Receipt,
    public_key: v2Keypair.publicKey,
  },
  v3: {
    receipt: v3Receipt,
    agent_public_key: v3AgentKeypair.publicKey,
    server_public_key: v3ServerKeypair.publicKey,
  },
  v4: {
    receipt: v4Receipt,
    delegate_public_key: v4DelegateKeypair.publicKey,
    owner_public_key: v4OwnerKeypair.publicKey,
  },
};

writeFileSync(outFile, `${JSON.stringify(fixtures, null, 2)}\n`);
console.log(`Wrote ${outFile}`);
