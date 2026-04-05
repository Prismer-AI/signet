#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

function main() {
  const signetDir = process.env.SIGNET_HOME
    || path.join(os.homedir(), '.signet');
  const keyPath = path.join(signetDir, 'keys', 'claude-agent.key');

  // Read stdin
  let raw;
  try {
    raw = fs.readFileSync(0, 'utf8');
  } catch {
    return;
  }
  if (!raw || !raw.trim()) return;

  // Parse stdin JSON
  let input;
  try {
    input = JSON.parse(raw);
  } catch {
    process.stderr.write('signet: failed to parse stdin JSON\n');
    return;
  }

  const toolName = input.tool_name || 'unknown';
  const toolInput = input.tool_input || {};

  // Load WASM wrapper (lazy)
  const signet = require('../lib/signet.cjs');
  const audit = require('../lib/audit.cjs');

  // Load or create key
  let key;
  try {
    key = signet.loadOrCreateKey(keyPath);
  } catch (err) {
    process.stderr.write('signet: ' + err.message + '\n');
    return;
  }

  // Sign the action
  const action = {
    tool: toolName,
    params: toolInput,
    params_hash: '',
    target: 'claude-code://local',
    transport: 'stdio',
  };

  let receipt;
  try {
    receipt = signet.sign(key.secretKey, action, 'claude-agent');
  } catch (err) {
    process.stderr.write('signet: signing failed: ' + err.message + '\n');
    return;
  }

  // Append to audit log
  try {
    audit.append(signetDir, receipt);
  } catch (err) {
    process.stderr.write('signet: audit append failed: ' + err.message + '\n');
  }
}

try {
  main();
} catch (err) {
  process.stderr.write('signet: unexpected error: ' + err.message + '\n');
}
