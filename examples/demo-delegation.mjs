#!/usr/bin/env node
/**
 * Signet v0.6 Delegation Chain Demo
 * Generates a .cast (asciicast v2) file showing the full delegation flow:
 * 1. Generate identities (root + agent)
 * 2. Create delegation token
 * 3. Sign action with delegation chain (v4 receipt)
 * 4. Verify authorized receipt
 * 5. Show audit log
 */

import { writeFileSync } from 'fs';

const CAST_FILE = 'demo-delegation.cast';
const WIDTH = 100;
const HEIGHT = 36;

let time = 0;
const events = [];

function header() {
  return JSON.stringify({
    version: 2,
    width: WIDTH,
    height: HEIGHT,
    timestamp: Math.floor(Date.now() / 1000),
    env: { SHELL: '/bin/bash', TERM: 'xterm-256color' },
  });
}

function wait(secs) { time += secs; }

function type(text, charDelay = 0.04) {
  for (const ch of text) {
    events.push([time, 'o', ch]);
    time += charDelay;
  }
}

function print(text) {
  events.push([time, 'o', text]);
}

function println(text = '') {
  events.push([time, 'o', text + '\r\n']);
}

function prompt() {
  print('\x1b[1;32m$\x1b[0m ');
}

function cmd(text, delay = 0.6) {
  prompt();
  type(text);
  wait(0.2);
  println('');
  wait(delay);
}

function comment(text) {
  println(`\x1b[2m# ${text}\x1b[0m`);
  wait(0.3);
}

function section(title) {
  println('');
  println(`\x1b[1;33m━━━ ${title} ━━━\x1b[0m`);
  println('');
  wait(0.5);
}

// ── Scene 1: Title ──

println('');
println('\x1b[1;37m  ╔══════════════════════════════════════════════════════════════╗\x1b[0m');
println('\x1b[1;37m  ║       Signet v0.6 — Delegation Chain Demo                   ║\x1b[0m');
println('\x1b[1;37m  ║       Cryptographic authorization for AI agent tool calls    ║\x1b[0m');
println('\x1b[1;37m  ╚══════════════════════════════════════════════════════════════╝\x1b[0m');
println('');
wait(2);

// ── Scene 2: Generate identities ──

section('Step 1: Generate Identities');
comment('Create a root identity (the human/org that grants authority)');
cmd('signet identity generate --name alice --unencrypted');
println('\x1b[32m✓\x1b[0m Identity "alice" created');
println('  pubkey: ed25519:Abc123...def');
wait(0.8);

println('');
comment('Create an agent identity');
cmd('signet identity generate --name deploy-bot --unencrypted');
println('\x1b[32m✓\x1b[0m Identity "deploy-bot" created');
println('  pubkey: ed25519:Xyz789...ghi');
wait(1);

// ── Scene 3: Create delegation token ──

section('Step 2: Create Delegation Token');
comment('Alice delegates Bash + Read access to deploy-bot');
cmd('signet delegate create \\', 0.1);
println('    --from alice \\');
wait(0.1);
println('    --to deploy-bot \\');
wait(0.1);
println('    --to-name deploy-bot \\');
wait(0.1);
println('    --tools Bash,Read \\');
wait(0.1);
println('    --targets "mcp://github" \\');
wait(0.1);
println('    --max-depth 0 \\');
wait(0.1);
println('    --output /tmp/token.json');
wait(1);

println('');
println('\x1b[32m✓\x1b[0m Delegation token written to /tmp/token.json');
wait(0.5);
println('');
println('\x1b[2m{');
println('  "v": 1,');
println('  "id": "del_a1b2c3d4e5f6a7b8...",');
println('  "delegator": { "name": "alice", "pubkey": "ed25519:Abc..." },');
println('  "delegate": { "name": "deploy-bot", "pubkey": "ed25519:Xyz..." },');
println('  "scope": {');
println('    "tools": ["Bash", "Read"],');
println('    "targets": ["mcp://github"],');
println('    "max_depth": 0');
println('  },');
println('  "sig": "ed25519:..."');
println('}\x1b[0m');
wait(2);

// ── Scene 4: Verify the token ──

section('Step 3: Verify Delegation Token');
cmd('signet delegate verify /tmp/token.json');
println('\x1b[32m✓\x1b[0m Token valid. Delegator: alice, Delegate: deploy-bot');
wait(1.5);

// ── Scene 5: Sign with delegation chain (v4 receipt) ──

section('Step 4: Sign Action with Delegation Chain');
comment('deploy-bot signs an action, carrying the delegation proof');
cmd('echo \'[\'$(cat /tmp/token.json)\']\' > /tmp/chain.json', 0.3);
println('');
cmd('signet delegate sign \\', 0.1);
println('    --key deploy-bot \\');
wait(0.1);
println('    --tool Bash \\');
wait(0.1);
println('    --params \'{"cmd":"git pull"}\' \\');
wait(0.1);
println('    --target "mcp://github" \\');
wait(0.1);
println('    --chain /tmp/chain.json');
wait(1.2);

println('');
println('\x1b[1;37mReceipt (v4 — authorized):\x1b[0m');
println('\x1b[2m{');
println('  "v": 4,');
println('  "action": { "tool": "Bash", "params_hash": "sha256:e3b0..." },');
println('  "signer": { "name": "deploy-bot", "owner": "alice" },');
println('  "authorization": {');
println('    "chain": [ { "delegator": "alice", "delegate": "deploy-bot", ... } ],');
println('    "chain_hash": "sha256:7f2a...",');
println('    "root_pubkey": "ed25519:Abc..."');
println('  },');
println('  "sig": "ed25519:..."');
println('}\x1b[0m');
wait(2);

// ── Scene 6: Verify authorized receipt ──

section('Step 5: Verify Authorized Receipt');
comment('Verify: signature + chain + scope + root trust');
cmd('signet delegate verify-auth /tmp/receipt.json \\', 0.1);
println('    --trusted-roots alice');
wait(1.2);

println('');
println('\x1b[32m✓\x1b[0m Authorized receipt verified.');
println('  Signer: deploy-bot (owner: alice)');
println('  Root: ed25519:Abc123...def');
println('  Effective scope:');
println('\x1b[2m  {');
println('    "tools": ["Bash", "Read"],');
println('    "targets": ["mcp://github"],');
println('    "max_depth": 0');
println('  }\x1b[0m');
wait(2);

// ── Scene 7: Rejection ──

section('Step 6: Out-of-Scope Action Rejected');
comment('deploy-bot tries to call Write (not in scope)');
cmd('signet delegate sign \\', 0.1);
println('    --key deploy-bot \\');
wait(0.1);
println('    --tool Write \\');
wait(0.1);
println('    --params \'{"path":"/etc/passwd"}\' \\');
wait(0.1);
println('    --target "mcp://github" \\');
wait(0.1);
println('    --chain /tmp/chain.json');
wait(0.8);

println('');
comment('The receipt is signed (signing does not check scope).');
comment('But verification rejects it:');
println('');
cmd('signet delegate verify-auth /tmp/bad-receipt.json --trusted-roots alice');
wait(0.8);
println('\x1b[1;31m✗ Error: action not authorized: tool \'Write\' not in scope\x1b[0m');
println('  \x1b[2mScope allows: [Bash, Read]\x1b[0m');
println('  \x1b[2mRequested: Write\x1b[0m');
wait(2);

// ── Scene 8: Audit ──

section('Step 7: Audit Trail');
cmd('signet audit --since 1h');
wait(0.8);
println('');
println('  \x1b[2m2026-04-09T12:00:01Z\x1b[0m  \x1b[33mv4\x1b[0m  deploy-bot  Bash     mcp://github  rec_7f2a...');
println('  \x1b[2m2026-04-09T12:00:05Z\x1b[0m  \x1b[33mv4\x1b[0m  deploy-bot  Write    mcp://github  rec_9c1b...');
wait(1);
println('');
comment('Both calls are logged. Verification tells you which ones were authorized.');
wait(1.5);

// ── Scene 9: Dashboard ──

section('Step 8: Dashboard');
cmd('signet dashboard');
wait(0.5);
println('Signet Dashboard: http://localhost:9191');
println('');
println('\x1b[2m  ┌─────────────────────────────────────────┐');
println('  │  SIGNET AUDIT LEDGER                    │');
println('  │  Timeline | Chain | Signatures | Stats   │');
println('  ├─────────────────────────────────────────┤');
println('  │  12:00:01  v4  deploy-bot  Bash   ✓     │');
println('  │  12:00:05  v4  deploy-bot  Write  ✗     │');
println('  │                                         │');
println('  │  Delegation: alice → deploy-bot          │');
println('  │  Scope: tools:[Bash,Read] depth:0        │');
println('  └─────────────────────────────────────────┘\x1b[0m');
wait(2);

// ── Closing ──

println('');
println('\x1b[1;37m  Who authorized your AI agent to do that?\x1b[0m');
println('\x1b[1;37m  Now you can prove it.\x1b[0m');
println('');
println('  \x1b[2mgithub.com/Prismer-AI/signet\x1b[0m');
println('');
wait(3);

// ── Write .cast file ──

const lines = [header(), ...events.map(e => JSON.stringify(e))];
writeFileSync(CAST_FILE, lines.join('\n') + '\n');
console.error(`Wrote ${CAST_FILE} (${events.length} events, ${Math.ceil(time)}s)`);
