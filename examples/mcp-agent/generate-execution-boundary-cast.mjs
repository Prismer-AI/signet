import { writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, '..', '..');

const events = [];
let elapsedMs = 0;

function emit(delayMs, text) {
  elapsedMs += delayMs;
  events.push([
    Number((elapsedMs / 1000).toFixed(3)),
    'o',
    text.replace(/\n/g, '\r\n'),
  ]);
}

emit(500, [
  '╔══════════════════════════════════════════════════════╗',
  '║   Signet Execution Boundary — Reject Bad Requests   ║',
  '╚══════════════════════════════════════════════════════╝',
  '',
].join('\n'));

emit(1100, '$ cd examples/mcp-agent\n');
emit(700, '$ npm run execution-boundary-demo\n');

emit(700, [
  '',
  '> execution-boundary-demo',
  '> node demo-execution-boundary.mjs',
  '',
].join('\n'));

emit(900, [
  '=== Signet Execution-Boundary Demo ===',
  'Dangerous tool: delete_prod_env',
  'Server policy: reject requests before execution unless verification succeeds.',
  '',
].join('\n'));

emit(1200, [
  '[1/5] unsigned request       -> REJECTED unsigned request',
  '       BLOCKED  before execution',
  '',
].join('\n'));

emit(1400, [
  '[2/5] tampered arguments     -> REJECTED params mismatch: signed params differ from request arguments',
  '       BLOCKED  before execution',
  '',
].join('\n'));

emit(1400, [
  '[3/5] wrong target           -> REJECTED target mismatch: expected mcp://infra.staging, got mcp://infra.prod',
  '       BLOCKED  before execution',
  '',
].join('\n'));

emit(1200, [
  '[4/5] expired receipt        -> REJECTED receipt too old',
  '       BLOCKED  before execution',
  '',
].join('\n'));

emit(1400, [
  '[5/5] valid signed request   -> ALLOWED  signer=demo-agent',
  '       EXECUTE  delete_prod_env (simulated)',
  '',
].join('\n'));

emit(1000, 'Only verified requests reach the execution boundary.\n');
emit(1200, '✓ Unsigned, tampered, stale, or mis-targeted calls never run.\n');

const header = {
  version: 2,
  width: 108,
  height: 24,
  timestamp: Math.floor(Date.now() / 1000),
  env: {
    SHELL: '/bin/bash',
    TERM: 'xterm-256color',
  },
};

const lines = [JSON.stringify(header), ...events.map((event) => JSON.stringify(event))];
const outPath = resolve(repoRoot, 'demo-execution-boundary.cast');
writeFileSync(outPath, `${lines.join('\n')}\n`, 'utf8');
console.log(`Wrote ${outPath}`);
